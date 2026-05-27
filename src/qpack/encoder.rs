use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::DerefMut,
    pin::{Pin, pin},
    sync::Arc,
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt, stream};
use snafu::{Report, Snafu};
use tokio::{
    io::{AsyncBufRead, AsyncReadExt, AsyncWrite},
    sync::Mutex as AsyncMutex,
};

use crate::{
    buflist::BufList,
    codec::{
        DecodeFrom, EncodeError, EncodeExt, EncodeInto, Feed, StreamDecodeError, StreamEncodeError,
    },
    connection::StreamError,
    dhttp::{frame::Frame, settings::Settings},
    error::{Code, H3ConnectionError, H3CriticalStreamClosed, H3FrameDecodeError, H3InternalError},
    qpack::{
        algorithm::Algorithm,
        decoder::DecoderInstruction,
        dynamic::DynamicTable,
        field::FieldLine,
        integer::{decode_integer, encode_integer},
        r#static,
        string::{decode_string, encode_string},
    },
    quic::{self, GetStreamId, GetStreamIdExt},
};

#[derive(Debug)]
pub struct EncoderState {
    pub(crate) settings: Arc<Settings>,
    pub(crate) dynamic_table: DynamicTable,
    /// Multiple entries may have the same name. The encoder can choose to use the most appropriate one.
    // ∀ n: Bytes: entries[name_indices[n]].name == n
    pub(crate) name_indices: BTreeMap<Bytes, BTreeSet<u64>>,
    /// Multiple entries may have the same value. The encoder can choose to use the most appropriate one.
    // ∀ v: Bytes: entries[value_indices[n]].value == v
    pub(crate) value_indices: BTreeMap<Bytes, BTreeSet<u64>>,

    // stream_id -> unacknowledged_sections: [section_max_referenced_index]
    pub(crate) blocking_streams: BTreeMap<u64, VecDeque<u64>>,

    pub(crate) pending_instructions: VecDeque<EncoderInstruction>,
}

impl EncoderState {
    pub const fn new(settings: Arc<Settings>) -> Self {
        Self {
            settings,
            dynamic_table: DynamicTable::new(),
            name_indices: BTreeMap::new(),
            value_indices: BTreeMap::new(),
            blocking_streams: BTreeMap::new(),
            pending_instructions: VecDeque::new(),
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum QPackDecoderStreamError {
    #[snafu(display("acknowledging non-existent or non-blocking stream"))]
    AcknowledgeNonExistSection { stream_id: u64 },
    #[snafu(display(
        "known received count increment overflow (known_received_count + increment > inserted_count)"
    ))]
    IncrementKnownReceivedCountOverflow,
    #[snafu(display("insert count increment of zero is not allowed"))]
    IncrementZero,
}

impl H3ConnectionError for QPackDecoderStreamError {
    fn code(&self) -> Code {
        Code::QPACK_DECODER_STREAM_ERROR
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum QPackEncoderError {
    #[snafu(display(
        "dynamic table capacity {capacity} exceeds SETTINGS_QPACK_MAX_TABLE_CAPACITY {max}"
    ))]
    CapacityExceedsMax { capacity: u64, max: u64 },
    #[snafu(display("cannot evict entries: no evictable entries in dynamic table"))]
    CannotEvict,
}

impl EncoderState {
    pub(crate) fn emit(&mut self, instruction: EncoderInstruction) {
        self.pending_instructions.push_back(instruction);
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn table_capacity(&self) -> u64 {
        self.dynamic_table.capacity
    }

    pub fn table_size(&self) -> u64 {
        self.dynamic_table.size
    }

    pub fn table_inserted_count(&self) -> u64 {
        self.dynamic_table.inserted_count
    }

    pub fn table_known_received_count(&self) -> u64 {
        self.dynamic_table.known_received_count
    }

    pub fn table_dropped_count(&self) -> u64 {
        self.dynamic_table.dropped_count
    }

    pub fn table_remaining(&self) -> u64 {
        self.table_capacity() - self.table_size()
    }

    pub fn get_entry(&self, index: u64) -> Option<&FieldLine> {
        self.dynamic_table.get(index)
    }

    pub fn find_name(&self, name: &Bytes) -> Option<&BTreeSet<u64>> {
        self.name_indices.get(name)
    }

    pub fn find_value(&self, value: &Bytes) -> Option<&BTreeSet<u64>> {
        self.value_indices.get(value)
    }

    pub fn pending_instructions(&self) -> &VecDeque<EncoderInstruction> {
        &self.pending_instructions
    }

    pub(crate) fn index(&mut self, field_line: FieldLine) -> u64 {
        let index = self.dynamic_table.index(field_line.clone());
        // update name_indices
        self.name_indices
            .entry(field_line.name)
            .or_default()
            .insert(index);
        // update value_indices
        self.value_indices
            .entry(field_line.value)
            .or_default()
            .insert(index);
        index
    }

    pub fn entries_evictable(&self) -> bool {
        self.dynamic_table.evictable()
    }

    pub(crate) fn evict_entry(&mut self) -> (u64, FieldLine) {
        use std::collections::btree_map::Entry::Occupied;
        let (absolute_index, entry) = self.dynamic_table.evict();
        // update name_indices
        if let Occupied(mut indices) = self.name_indices.entry(entry.name.clone()) {
            indices.get_mut().remove(&absolute_index);
            if indices.get().is_empty() {
                self.name_indices.remove(&entry.name);
            }
        }
        // update value_indices
        if let Occupied(mut indices) = self.value_indices.entry(entry.value.clone()) {
            indices.get_mut().remove(&absolute_index);
            if indices.get().is_empty() {
                self.value_indices.remove(&entry.value);
            }
        }

        (absolute_index, entry)
    }

    pub fn set_max_table_capacity(&mut self, new_capacity: u64) -> Result<(), QPackEncoderError> {
        // RFC 9204 §4.3.1: The encoder MUST NOT set a dynamic table capacity that exceeds SETTINGS_QPACK_MAX_TABLE_CAPACITY
        let max = self.settings.qpack_max_table_capacity().into_inner();
        if new_capacity > max {
            return Err(QPackEncoderError::CapacityExceedsMax {
                capacity: new_capacity,
                max,
            });
        }
        self.dynamic_table.capacity = new_capacity;
        while self.table_size() > new_capacity {
            // RFC 9204 §2.1.1: entries are evictable only when acknowledged
            if !self.entries_evictable() {
                return Err(QPackEncoderError::CannotEvict);
            }
            self.evict_entry();
        }
        self.emit(EncoderInstruction::SetDynamicTableCapacity {
            capacity: new_capacity,
        });
        Ok(())
    }

    pub fn insert_with_name_reference(
        &mut self,
        is_static: bool,
        name_index: u64,
        huffman: bool,
        value: Bytes,
    ) -> Result<u64, QPackEncoderError> {
        let name = match is_static {
            true => Bytes::from_static(
                r#static::get_name(name_index)
                    .unwrap_or_else(|| {
                        panic!(
                            "Referenced name index {name_index} does not exist in the static table"
                        )
                    })
                    .as_bytes(),
            ),
            false => self
                .get_entry(name_index)
                .unwrap_or_else(|| {
                    panic!("Referenced name index {name_index} does not exist in the dynamic table")
                })
                .name
                .clone(),
        };

        let entry = FieldLine { name, value };
        while self.table_remaining() < entry.size() {
            // RFC 9204 §2.1.1: entries are evictable only when acknowledged
            if !self.entries_evictable() {
                return Err(QPackEncoderError::CannotEvict);
            }
            self.evict_entry();
        }
        let new_entry_index = self.index(entry.clone());
        // RFC 9204 §3.2.4: Encoder instruction uses relative index.
        // relative = new_entry_index - absolute_name_index - 1
        let wire_name_index = if is_static {
            name_index
        } else {
            new_entry_index - name_index - 1
        };
        self.emit(EncoderInstruction::InsertWithNameReference {
            is_static,
            name_index: wire_name_index,
            huffman,
            value: entry.value,
        });
        Ok(new_entry_index)
    }

    pub fn insert_with_literal_name(
        &mut self,
        name_huffman: bool,
        name: Bytes,
        value_huffman: bool,
        value: Bytes,
    ) -> Result<u64, QPackEncoderError> {
        let entry = FieldLine { name, value };
        while self.table_remaining() < entry.size() {
            // RFC 9204 §2.1.1: entries are evictable only when acknowledged
            if !self.entries_evictable() {
                return Err(QPackEncoderError::CannotEvict);
            }
            self.evict_entry();
        }
        let new_entry_index = self.index(entry.clone());
        self.emit(EncoderInstruction::InsertWithLiteralName {
            name_huffman,
            name: entry.name,
            value_huffman,
            value: entry.value,
        });
        Ok(new_entry_index)
    }

    pub fn duplicate(&mut self, index: u64) -> Result<u64, QPackEncoderError> {
        let duplicated_entry = self
            .get_entry(index)
            .unwrap_or_else(|| {
                panic!("Referenced entry {index} does not exist in the dynamic table")
            })
            .clone();
        while self.table_remaining() < duplicated_entry.size() {
            // RFC 9204 §2.1.1: entries are evictable only when acknowledged
            if !self.entries_evictable() {
                return Err(QPackEncoderError::CannotEvict);
            }
            self.evict_entry();
        }
        let new_entry_index = self.index(duplicated_entry);
        // RFC 9204 §3.2.4: Encoder instruction uses relative index.
        // relative = new_entry_index - absolute_index - 1
        let wire_index = new_entry_index - index - 1;
        self.pending_instructions
            .push_back(EncoderInstruction::Duplicate { index: wire_index });
        Ok(new_entry_index)
    }

    pub fn entries(&self) -> impl Iterator<Item = (u64, &FieldLine)> {
        self.dynamic_table.entries()
    }

    pub(crate) fn on_section_acknowledgment(
        &mut self,
        stream_id: u64,
    ) -> Result<(), QPackDecoderStreamError> {
        use std::collections::btree_map::Entry::Occupied;

        let Occupied(mut blocking_stream) = self.blocking_streams.entry(stream_id) else {
            return Err(QPackDecoderStreamError::AcknowledgeNonExistSection { stream_id });
        };
        let max_referenced_index = blocking_stream
            .get_mut()
            .pop_front()
            .expect("blocking stream entry is non-empty");
        if blocking_stream.get().is_empty() {
            blocking_stream.remove();
        }

        if max_referenced_index >= self.table_known_received_count() {
            self.dynamic_table.known_received_count = max_referenced_index + 1;
        }

        Ok(())
    }

    pub(crate) fn on_stream_cancellation(&mut self, stream_id: u64) {
        self.blocking_streams.remove(&stream_id);
    }

    pub(crate) fn on_insert_count_increment(
        &mut self,
        increment: u64,
    ) -> Result<(), QPackDecoderStreamError> {
        // RFC 9204 §4.4.3: An increment of 0 is a connection error of type QPACK_DECODER_STREAM_ERROR
        if increment == 0 {
            return Err(QPackDecoderStreamError::IncrementZero);
        }
        if self.table_inserted_count() - self.table_known_received_count() < increment {
            return Err(QPackDecoderStreamError::IncrementKnownReceivedCountOverflow);
        }
        self.dynamic_table.increment_known_received_count(increment);
        Ok(())
    }
}

pub struct Encoder<Es, Ds> {
    pub(crate) state: AsyncMutex<EncoderState>,
    pub(crate) encoder_stream: AsyncMutex<Feed<Es, EncoderInstruction>>,
    pub(crate) decoder_stream: AsyncMutex<Ds>,
}

#[derive(Debug, Snafu)]
pub enum EncodeHeaderSectionError {
    #[snafu(transparent)]
    Stream { source: StreamError },
    #[snafu(transparent)]
    Encode { source: EncodeError },
}

impl From<quic::StreamError> for EncodeHeaderSectionError {
    fn from(error: quic::StreamError) -> Self {
        EncodeHeaderSectionError::Stream {
            source: error.into(),
        }
    }
}

impl<Es, Ds> Encoder<Es, Ds>
where
    Es: Sink<EncoderInstruction, Error = StreamError> + Unpin,
    Ds: Stream<Item = Result<DecoderInstruction, StreamError>> + Unpin,
{
    pub fn new(settings: Arc<Settings>, encoder_stream: Es, decoder_stream: Ds) -> Self {
        Self {
            state: AsyncMutex::new(EncoderState::new(settings)),
            encoder_stream: AsyncMutex::new(Feed::new(encoder_stream)),
            decoder_stream: AsyncMutex::new(decoder_stream),
        }
    }

    pub async fn apply_settings(&self, settings: Arc<Settings>) {
        {
            let mut state = self.state.lock().await;
            let peer_max_capacity = settings.qpack_max_table_capacity().into_inner();
            state.settings = settings;
            if peer_max_capacity > 0 && state.table_capacity() == 0 {
                let _ = state.set_max_table_capacity(peer_max_capacity);
            }
        }
        // Flush the SetDynamicTableCapacity instruction immediately so the
        // decoder knows the new capacity before any header sections arrive.
        let _ = self.flush_instructions().await;
    }

    pub async fn encode(
        &self,
        field_section: impl IntoIterator<Item = FieldLine> + Send,
        algorithm: &(impl Algorithm + ?Sized),
        stream: impl GetStreamId,
    ) -> Result<Frame<BufList>, EncodeHeaderSectionError> {
        tokio::pin!(stream);
        let stream_id = stream.stream_id().await?.into_inner();

        let (field_section_prefix, field_line_representations);
        {
            let mut state = self.state.lock().await;

            // RFC 9204 §2.1.2: Determine whether this stream may block the decoder.
            let already_tracked = state.blocking_streams.contains_key(&stream_id);
            let peer_max = state.settings.qpack_blocked_streams().into_inner();
            let may_block = already_tracked || (state.blocking_streams.len() as u64) < peer_max;

            let output = algorithm
                .compress(&mut state, field_section, may_block)
                .await;
            field_section_prefix = output.prefix;
            field_line_representations = output.representations;

            if let Some(max_referenced_index) = output.max_referenced_index {
                state
                    .blocking_streams
                    .entry(stream_id)
                    .or_default()
                    .push_back(max_referenced_index);
            }
        };

        let header_frame = BufList::new()
            .encode((field_section_prefix, field_line_representations))
            .await?;

        Ok(header_frame)
    }

    fn pending_instructions(&self) -> impl Stream<Item = EncoderInstruction> + '_ {
        stream::unfold(self, |this| async move {
            let instruction = {
                let mut state = this.state.lock().await;
                state.pending_instructions.pop_front()
            };
            instruction.map(|inst| (inst, this))
        })
    }

    pub async fn flush_instructions(&self) -> Result<(), StreamError> {
        let mut encoder_stream = self.encoder_stream.lock().await;
        let mut encoder_stream = Pin::new(encoder_stream.deref_mut());
        let instructions = self.pending_instructions();
        encoder_stream.as_mut().send_all(instructions).await?;
        encoder_stream.as_mut().flush().await?;
        Ok(())
    }

    pub async fn receive_instruction(&self) -> Result<(), StreamError> {
        let instruction = {
            let mut decoder_stream = self.decoder_stream.lock().await;
            let instruction = decoder_stream.next().await;
            instruction.ok_or(H3CriticalStreamClosed::QPackDecoder)??
        };
        let mut state = self.state.lock().await;
        match instruction {
            DecoderInstruction::SectionAcknowledgment { stream_id } => {
                state.on_section_acknowledgment(stream_id)?
            }
            DecoderInstruction::StreamCancellation { stream_id } => {
                state.on_stream_cancellation(stream_id)
            }
            DecoderInstruction::InsertCountIncrement { increment } => {
                state.on_insert_count_increment(increment)?
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderInstruction {
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 |   Capacity (5+)   |
    /// +---+---+---+-------------------+
    /// ```
    SetDynamicTableCapacity { capacity: u64 },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | T |    Name Index (6+)    |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    InsertWithNameReference {
        is_static: bool,
        name_index: u64,
        huffman: bool,
        value: Bytes,
    },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 | H | Name Length (5+)  |
    /// +---+---+---+-------------------+
    /// |  Name String (Length bytes)   |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    InsertWithLiteralName {
        name_huffman: bool,
        name: Bytes,
        value_huffman: bool,
        value: Bytes,
    },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 |    Index (5+)     |
    /// +---+---+---+-------------------+
    /// ```
    Duplicate { index: u64 },
}

impl<S: AsyncBufRead + Send> DecodeFrom<S> for EncoderInstruction {
    type Error = StreamError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let decode = async move {
            let mut stream = pin!(stream);
            let prefix = stream.read_u8().await?;
            match prefix {
                // 1xxxxxxx — Insert with Name Reference (6-bit prefix)
                prefix if prefix & 0b1000_0000 == 0b1000_0000 => {
                    let is_static = (prefix & 0b0100_0000) != 0;
                    let name_index = decode_integer(stream.as_mut(), prefix, 6).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(EncoderInstruction::InsertWithNameReference {
                        is_static,
                        name_index,
                        huffman,
                        value,
                    })
                }
                // 01xxxxxx — Insert with Literal Name (5-bit name prefix)
                prefix if prefix & 0b1100_0000 == 0b0100_0000 => {
                    let name_prefix = prefix;
                    let (name_huffman, name) =
                        decode_string(stream.as_mut(), name_prefix, 1 + 5).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (value_huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(EncoderInstruction::InsertWithLiteralName {
                        name_huffman,
                        name,
                        value_huffman,
                        value,
                    })
                }
                // 001xxxxx — Set Dynamic Table Capacity (5-bit prefix)
                prefix if prefix & 0b1110_0000 == 0b0010_0000 => {
                    let capacity = decode_integer(stream, prefix, 5).await?;
                    Ok(EncoderInstruction::SetDynamicTableCapacity { capacity })
                }
                // 000xxxxx — Duplicate (5-bit prefix)
                _ => {
                    let index = decode_integer(stream, prefix, 5).await?;
                    Ok(EncoderInstruction::Duplicate { index })
                }
            }
        };
        decode.await.map_err(|error: StreamDecodeError| {
            error
                .escalate_critical_close(|| H3CriticalStreamClosed::QPackEncoder.into())
                .into_stream_error(|decode_error| {
                    H3FrameDecodeError {
                        source: decode_error,
                    }
                    .into()
                })
        })
    }
}

impl<S> EncodeInto<S> for EncoderInstruction
where
    S: AsyncWrite + Sink<Bytes, Error = quic::StreamError> + Send,
{
    type Output = ();

    type Error = StreamError;

    async fn encode_into(self, stream: S) -> Result<Self::Output, Self::Error> {
        let inst = self;
        let encode = async move {
            let mut stream = pin!(stream);
            match inst {
                EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                    let prefix = 0b0010_0000;
                    encode_integer(stream, prefix, 5, capacity).await?;
                    Ok(())
                }
                EncoderInstruction::InsertWithNameReference {
                    is_static,
                    name_index,
                    huffman,
                    value,
                } => {
                    let mut prefix = 0b1000_0000;
                    if is_static {
                        prefix |= 0b0100_0000;
                    }
                    encode_integer(stream.as_mut(), prefix, 6, name_index).await?;
                    encode_string(stream.as_mut(), 0, 1 + 7, huffman, value).await?;
                    Ok(())
                }
                EncoderInstruction::InsertWithLiteralName {
                    name_huffman,
                    name,
                    value_huffman,
                    value,
                } => {
                    let name_prefix = 0b0100_0000;
                    encode_string(stream.as_mut(), name_prefix, 1 + 5, name_huffman, name).await?;
                    encode_string(stream.as_mut(), 0, 1 + 7, value_huffman, value).await?;
                    Ok(())
                }
                EncoderInstruction::Duplicate { index } => {
                    let prefix = 0b0000_0000;
                    encode_integer(stream.as_mut(), prefix, 5, index).await?;
                    Ok(())
                }
            }
        };
        encode.await.map_err(|error: StreamEncodeError| {
            error
                .escalate_reset(|_code| H3CriticalStreamClosed::QPackEncoder.into())
                .into_stream_error(|encode_error| {
                    tracing::error!(error = %Report::from_error(&encode_error), "this is likely a bug");
                    H3InternalError::QPackEncoderEncode {
                        source: encode_error,
                    }
                    .into()
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::Cursor,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{Sink, stream};
    use tokio::io::AsyncWrite;

    use crate::{
        codec::{DecodeFrom, EncodeInto},
        connection::StreamError,
        dhttp::settings::Settings,
        error::{Code, H3ConnectionError},
        qpack::{
            algorithm::{Algorithm, CompressOutput},
            decoder::DecoderInstruction,
            encoder::{
                Encoder, EncoderInstruction, EncoderState, QPackDecoderStreamError,
                QPackEncoderError,
            },
            field::{EncodedFieldSectionPrefix, FieldLine, FieldLineRepresentation},
        },
        quic::{self, GetStreamId},
        varint::VarInt,
    };

    fn get_dynamic_references<'r>(
        field_line_representations: impl IntoIterator<Item = &'r FieldLineRepresentation>,
    ) -> impl Iterator<Item = u64> {
        field_line_representations
            .into_iter()
            .filter_map(
                |field_line_representation| match field_line_representation {
                    FieldLineRepresentation::IndexedFieldLine {
                        is_static, index, ..
                    } => (!is_static).then_some(*index),
                    FieldLineRepresentation::LiteralFieldLineWithNameReference {
                        is_static,
                        name_index,
                        ..
                    } => (!is_static).then_some(*name_index),
                    FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                        name_index,
                        ..
                    } => Some(*name_index),
                    _ => None,
                },
            )
    }

    fn settings_with_capacity(capacity: u32) -> Arc<Settings> {
        settings_with_capacity_and_blocked_streams(capacity, 10)
    }

    fn settings_with_capacity_and_blocked_streams(
        capacity: u32,
        blocked_streams: u32,
    ) -> Arc<Settings> {
        let mut settings = Settings::default();
        settings.set(crate::qpack::settings::QpackMaxTableCapacity::setting(
            VarInt::from_u32(capacity),
        ));
        settings.set(crate::qpack::settings::QpackBlockedStreams::setting(
            VarInt::from_u32(blocked_streams),
        ));
        Arc::new(settings)
    }

    fn state_with_full_unacknowledged_entry() -> EncoderState {
        let mut state = EncoderState::new(settings_with_capacity(128));
        state
            .set_max_table_capacity(64)
            .expect("set capacity failed");
        state
            .insert_with_literal_name(
                false,
                Bytes::from(vec![b'x'; 16]),
                false,
                Bytes::from(vec![b'y'; 16]),
            )
            .expect("insert full-size entry");
        state
    }

    #[derive(Default)]
    struct RecordingSink {
        bytes: Vec<u8>,
    }

    impl AsyncWrite for RecordingSink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for RecordingSink {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.bytes.extend_from_slice(&item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone, Default)]
    struct RecordingInstructionSink {
        instructions: Arc<Mutex<Vec<EncoderInstruction>>>,
        flushes: Arc<Mutex<usize>>,
    }

    impl RecordingInstructionSink {
        fn instructions(&self) -> Vec<EncoderInstruction> {
            self.instructions
                .lock()
                .expect("instruction lock is not poisoned")
                .clone()
        }

        fn flushes(&self) -> usize {
            *self.flushes.lock().expect("flush lock is not poisoned")
        }
    }

    impl Sink<EncoderInstruction> for RecordingInstructionSink {
        type Error = StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: EncoderInstruction) -> Result<(), Self::Error> {
            self.instructions
                .lock()
                .expect("instruction lock is not poisoned")
                .push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            *self.flushes.lock().expect("flush lock is not poisoned") += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct TestStreamId(u32);

    impl GetStreamId for TestStreamId {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(VarInt::from_u32(self.0)))
        }
    }

    #[derive(Default)]
    struct MayBlockProbeAlgorithm {
        max_referenced_index: Option<u64>,
        observed_may_block: Arc<Mutex<Vec<bool>>>,
    }

    impl MayBlockProbeAlgorithm {
        fn with_max_referenced_index(max_referenced_index: u64) -> Self {
            Self {
                max_referenced_index: Some(max_referenced_index),
                observed_may_block: Arc::default(),
            }
        }

        fn observed_may_block(&self) -> Vec<bool> {
            self.observed_may_block
                .lock()
                .expect("may_block lock is not poisoned")
                .clone()
        }
    }

    impl Algorithm for MayBlockProbeAlgorithm {
        async fn compress(
            &self,
            _state: &mut EncoderState,
            _entries: impl IntoIterator<Item = FieldLine> + Send,
            may_block: bool,
        ) -> CompressOutput {
            self.observed_may_block
                .lock()
                .expect("may_block lock is not poisoned")
                .push(may_block);
            CompressOutput {
                prefix: EncodedFieldSectionPrefix {
                    encoded_insert_count: 0,
                    sign: false,
                    delta_base: 0,
                },
                representations: Vec::new(),
                max_referenced_index: self.max_referenced_index,
            }
        }
    }

    async fn encode_decode_roundtrip(
        instruction: EncoderInstruction,
    ) -> Result<EncoderInstruction, StreamError> {
        let mut sink = RecordingSink::default();
        instruction.clone().encode_into(&mut sink).await?;
        EncoderInstruction::decode_from(Cursor::new(sink.bytes)).await
    }

    // --- Core encoding tests ---

    #[test]
    fn decoder_stream_errors_report_qpack_decoder_stream_error_code() {
        let cases = [
            QPackDecoderStreamError::AcknowledgeNonExistSection { stream_id: 7 },
            QPackDecoderStreamError::IncrementKnownReceivedCountOverflow,
            QPackDecoderStreamError::IncrementZero,
        ];

        for error in cases {
            assert_eq!(error.code(), Code::QPACK_DECODER_STREAM_ERROR);
        }
    }

    #[test]
    fn encoder_state_accessors_expose_initial_and_capacity_state() {
        let settings = settings_with_capacity(128);
        let mut state = EncoderState::new(settings.clone());

        assert!(std::ptr::eq(state.settings(), settings.as_ref()));
        assert_eq!(state.table_capacity(), 0);
        assert_eq!(state.table_size(), 0);
        assert_eq!(state.table_inserted_count(), 0);
        assert_eq!(state.table_known_received_count(), 0);
        assert_eq!(state.table_dropped_count(), 0);
        assert_eq!(state.table_remaining(), 0);
        assert!(state.entries().next().is_none());
        assert!(state.find_name(&Bytes::from_static(b"missing")).is_none());
        assert!(state.find_value(&Bytes::from_static(b"missing")).is_none());
        assert!(state.pending_instructions().is_empty());

        state
            .set_max_table_capacity(64)
            .expect("capacity within peer setting");
        assert_eq!(state.table_capacity(), 64);
        assert_eq!(state.table_remaining(), 64);
        assert_eq!(
            state.pending_instructions().back(),
            Some(&EncoderInstruction::SetDynamicTableCapacity { capacity: 64 })
        );
    }

    #[tokio::test]
    async fn encoder_instruction_roundtrip_all_variants() {
        let instructions = [
            EncoderInstruction::SetDynamicTableCapacity { capacity: 123 },
            EncoderInstruction::InsertWithNameReference {
                is_static: true,
                name_index: 15,
                huffman: false,
                value: Bytes::from_static(b"value"),
            },
            EncoderInstruction::InsertWithLiteralName {
                name_huffman: false,
                name: Bytes::from_static(b"x-test"),
                value_huffman: false,
                value: Bytes::from_static(b"payload"),
            },
            EncoderInstruction::Duplicate { index: 7 },
        ];

        for instruction in instructions {
            let decoded = encode_decode_roundtrip(instruction.clone())
                .await
                .expect("instruction should roundtrip");
            assert_eq!(decoded, instruction);
        }
    }

    #[tokio::test]
    async fn encoder_instruction_encodes_huffman_and_static_flags_on_wire() {
        let mut sink = RecordingSink::default();
        EncoderInstruction::InsertWithNameReference {
            is_static: true,
            name_index: 10,
            huffman: true,
            value: Bytes::from_static(b"abc"),
        }
        .encode_into(&mut sink)
        .await
        .expect("instruction should encode");

        assert_eq!(sink.bytes[0], 0b1100_1010);
        assert_eq!(sink.bytes[1] & 0b1000_0000, 0b1000_0000);

        let decoded = EncoderInstruction::decode_from(Cursor::new(sink.bytes))
            .await
            .expect("instruction should decode");
        assert_eq!(
            decoded,
            EncoderInstruction::InsertWithNameReference {
                is_static: true,
                name_index: 10,
                huffman: true,
                value: Bytes::from_static(b"abc"),
            }
        );
    }

    #[tokio::test]
    async fn encoder_instruction_encodes_literal_name_huffman_flags_independently() {
        let mut sink = RecordingSink::default();
        EncoderInstruction::InsertWithLiteralName {
            name_huffman: true,
            name: Bytes::from_static(b"abc"),
            value_huffman: false,
            value: Bytes::from_static(b"xyz"),
        }
        .encode_into(&mut sink)
        .await
        .expect("instruction should encode");

        assert_eq!(sink.bytes[0] & 0b1110_0000, 0b0110_0000);
        assert_eq!(sink.bytes[3] & 0b1000_0000, 0);

        let decoded = EncoderInstruction::decode_from(Cursor::new(sink.bytes))
            .await
            .expect("instruction should decode");
        assert_eq!(
            decoded,
            EncoderInstruction::InsertWithLiteralName {
                name_huffman: true,
                name: Bytes::from_static(b"abc"),
                value_huffman: false,
                value: Bytes::from_static(b"xyz"),
            }
        );
    }

    #[test]
    fn on_insert_count_increment_zero_returns_err() {
        let mut state = EncoderState::new(settings_with_capacity(256));
        let result = state.on_insert_count_increment(0);
        assert!(
            matches!(result, Err(QPackDecoderStreamError::IncrementZero)),
            "Expected IncrementZero, got {result:?}"
        );
    }

    #[test]
    fn on_insert_count_increment_valid_returns_ok() {
        let mut state = EncoderState::new(settings_with_capacity(256));
        // Set up: capacity, then insert one entry so inserted_count == 1
        state
            .set_max_table_capacity(64)
            .expect("set capacity failed");
        state
            .insert_with_literal_name(
                false,
                Bytes::from_static(b"x-custom"),
                false,
                Bytes::from_static(b"val"),
            )
            .expect("insert failed");
        // inserted_count == 1, known_received_count == 0 → increment of 1 is valid
        let result = state.on_insert_count_increment(1);
        assert!(result.is_ok(), "Expected Ok, got {result:?}");
    }

    #[test]
    fn on_insert_count_increment_overflow_returns_err() {
        let mut state = EncoderState::new(settings_with_capacity(256));
        state
            .set_max_table_capacity(128)
            .expect("set capacity failed");
        state
            .insert_with_literal_name(
                false,
                Bytes::from_static(b"x-custom"),
                false,
                Bytes::from_static(b"value"),
            )
            .expect("insert failed");

        let result = state.on_insert_count_increment(2);

        assert!(
            matches!(
                result,
                Err(QPackDecoderStreamError::IncrementKnownReceivedCountOverflow)
            ),
            "Expected IncrementKnownReceivedCountOverflow, got {result:?}"
        );
    }

    #[test]
    fn on_section_acknowledgment_missing_stream_returns_err() {
        let mut state = EncoderState::new(settings_with_capacity(256));

        let result = state.on_section_acknowledgment(42);

        assert!(
            matches!(
                result,
                Err(QPackDecoderStreamError::AcknowledgeNonExistSection { stream_id: 42 })
            ),
            "Expected AcknowledgeNonExistSection, got {result:?}"
        );
    }

    #[test]
    fn on_section_acknowledgment_updates_known_received_count_and_clears_stream() {
        let mut state = EncoderState::new(settings_with_capacity(256));
        state.dynamic_table.known_received_count = 1;
        state.blocking_streams.insert(7, VecDeque::from([3]));

        state
            .on_section_acknowledgment(7)
            .expect("section acknowledgment should succeed");

        assert_eq!(state.dynamic_table.known_received_count, 4);
        assert!(!state.blocking_streams.contains_key(&7));
    }

    #[test]
    fn on_section_acknowledgment_removes_only_acknowledged_section() {
        let mut state = EncoderState::new(settings_with_capacity(256));
        state.blocking_streams.insert(7, VecDeque::from([1, 3]));

        state
            .on_section_acknowledgment(7)
            .expect("section acknowledgment should succeed");

        assert_eq!(state.blocking_streams.get(&7), Some(&VecDeque::from([3])));
        assert_eq!(state.table_known_received_count(), 2);
    }

    // --- Table management tests ---

    #[test]
    fn full_unacknowledged_table_blocks_capacity_reference_and_duplicate_mutations() {
        let mut shrink = state_with_full_unacknowledged_entry();
        assert!(matches!(
            shrink.set_max_table_capacity(32),
            Err(QPackEncoderError::CannotEvict)
        ));

        let mut static_reference = state_with_full_unacknowledged_entry();
        assert!(matches!(
            static_reference.insert_with_name_reference(
                true,
                0,
                false,
                Bytes::from_static(b"value"),
            ),
            Err(QPackEncoderError::CannotEvict)
        ));

        let mut dynamic_reference = state_with_full_unacknowledged_entry();
        assert!(matches!(
            dynamic_reference.insert_with_name_reference(
                false,
                0,
                false,
                Bytes::from_static(b"value"),
            ),
            Err(QPackEncoderError::CannotEvict)
        ));

        let mut duplicate = state_with_full_unacknowledged_entry();
        assert!(matches!(
            duplicate.duplicate(0),
            Err(QPackEncoderError::CannotEvict)
        ));
    }

    #[test]
    fn set_max_table_capacity_exceeds_max_returns_err() {
        let mut state = EncoderState::new(settings_with_capacity(50));
        let result = state.set_max_table_capacity(100);
        assert!(
            matches!(
                result,
                Err(QPackEncoderError::CapacityExceedsMax {
                    capacity: 100,
                    max: 50
                })
            ),
            "Expected CapacityExceedsMax, got {result:?}"
        );
    }

    #[test]
    fn set_max_table_capacity_equal_to_max_returns_ok() {
        let mut state = EncoderState::new(settings_with_capacity(50));
        let result = state.set_max_table_capacity(50);
        assert!(
            result.is_ok(),
            "Expected Ok for capacity == max, got {result:?}"
        );
    }

    #[test]
    fn set_max_table_capacity_below_max_returns_ok() {
        let mut state = EncoderState::new(settings_with_capacity(50));
        let result = state.set_max_table_capacity(30);
        assert!(
            result.is_ok(),
            "Expected Ok for capacity < max, got {result:?}"
        );
    }

    #[test]
    fn set_max_table_capacity_shrinks_by_evicting_acknowledged_entries() {
        let mut state = EncoderState::new(settings_with_capacity(128));
        state
            .set_max_table_capacity(128)
            .expect("set capacity failed");
        state
            .insert_with_literal_name(
                false,
                Bytes::from_static(b"header-1"),
                false,
                Bytes::from_static(b"value-1"),
            )
            .expect("first insert failed");
        state
            .insert_with_literal_name(
                false,
                Bytes::from_static(b"header-2"),
                false,
                Bytes::from_static(b"value-2"),
            )
            .expect("second insert failed");
        state.dynamic_table.known_received_count = state.dynamic_table.inserted_count;

        state
            .set_max_table_capacity(64)
            .expect("shrink should evict acknowledged entries");

        assert_eq!(state.table_capacity(), 64);
        assert_eq!(state.table_dropped_count(), 1);
        assert_eq!(state.table_inserted_count(), 2);
        assert_eq!(
            state
                .entries()
                .map(|(index, entry)| (index, entry.name.clone()))
                .collect::<Vec<_>>(),
            vec![(1, Bytes::from_static(b"header-2"))]
        );
        assert!(state.find_name(&Bytes::from_static(b"header-1")).is_none());
        assert!(state.find_value(&Bytes::from_static(b"value-1")).is_none());
    }

    // --- Eviction tests ---

    #[test]
    fn insert_with_literal_name_cannot_evict_when_unacknowledged() {
        // Fill the table with an entry that uses the full capacity
        // known_received_count stays 0, so no entries are evictable
        let mut state = EncoderState::new(settings_with_capacity(256));
        state
            .set_max_table_capacity(64)
            .expect("set capacity failed");
        // Entry size = name.len() + value.len() + 32 = 8 + 8 + 32 + 32 = 64 (fills table)
        // name = b"xxxxxxxx" (8), value = b"yyyyyyyy" (8) → size = 48, not enough
        // Use name = b"x" * 16 (16) + value = b"y" * 16 (16) → size = 64 (exact fill)
        state
            .insert_with_literal_name(
                false,
                Bytes::from(vec![b'x'; 16]),
                false,
                Bytes::from(vec![b'y'; 16]),
            )
            .expect("first insert failed");
        // Table is now full; trying to insert another entry should fail with CannotEvict
        let result = state.insert_with_literal_name(
            false,
            Bytes::from_static(b"overflow"),
            false,
            Bytes::from_static(b"data"),
        );
        assert!(
            matches!(result, Err(QPackEncoderError::CannotEvict)),
            "Expected CannotEvict, got {result:?}"
        );
    }

    #[test]
    fn insert_with_name_reference_uses_dynamic_relative_index() {
        let mut state = EncoderState::new(settings_with_capacity(256));
        state
            .set_max_table_capacity(256)
            .expect("set capacity failed");
        let referenced_index = state
            .insert_with_literal_name(
                false,
                Bytes::from_static(b"x-name"),
                false,
                Bytes::from_static(b"first"),
            )
            .expect("first insert failed");

        let new_index = state
            .insert_with_name_reference(
                false,
                referenced_index,
                false,
                Bytes::from_static(b"second"),
            )
            .expect("name reference insert failed");

        assert_eq!(new_index, 1);
        assert_eq!(
            state.pending_instructions().back(),
            Some(&EncoderInstruction::InsertWithNameReference {
                is_static: false,
                name_index: 0,
                huffman: false,
                value: Bytes::from_static(b"second"),
            })
        );
    }

    #[test]
    fn duplicate_uses_relative_index_and_preserves_entry() {
        let mut state = EncoderState::new(settings_with_capacity(256));
        state
            .set_max_table_capacity(256)
            .expect("set capacity failed");
        let original_index = state
            .insert_with_literal_name(
                false,
                Bytes::from_static(b"x-name"),
                false,
                Bytes::from_static(b"value"),
            )
            .expect("insert failed");

        let duplicated_index = state.duplicate(original_index).expect("duplicate failed");

        assert_eq!(duplicated_index, 1);
        assert_eq!(
            state.pending_instructions().back(),
            Some(&EncoderInstruction::Duplicate { index: 0 })
        );
        assert_eq!(
            state.get_entry(duplicated_index),
            Some(&FieldLine {
                name: Bytes::from_static(b"x-name"),
                value: Bytes::from_static(b"value"),
            })
        );
    }

    #[test]
    fn evict_entry_removes_only_the_evicted_duplicate_index() {
        let mut state = EncoderState::new(settings_with_capacity(256));
        state
            .set_max_table_capacity(256)
            .expect("set capacity failed");
        let first_index = state
            .insert_with_literal_name(
                false,
                Bytes::from_static(b"x-name"),
                false,
                Bytes::from_static(b"value"),
            )
            .expect("insert failed");
        let duplicated_index = state.duplicate(first_index).expect("duplicate failed");
        state.dynamic_table.known_received_count = 1;

        let (evicted_index, evicted_entry) = state.evict_entry();

        assert_eq!(evicted_index, first_index);
        assert_eq!(
            evicted_entry,
            FieldLine {
                name: Bytes::from_static(b"x-name"),
                value: Bytes::from_static(b"value"),
            }
        );
        assert_eq!(
            state
                .find_name(&Bytes::from_static(b"x-name"))
                .unwrap()
                .len(),
            1
        );
        assert!(
            state
                .find_name(&Bytes::from_static(b"x-name"))
                .unwrap()
                .contains(&duplicated_index)
        );
        assert_eq!(
            state
                .find_value(&Bytes::from_static(b"value"))
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![duplicated_index]
        );
    }

    #[tokio::test]
    async fn apply_settings_initializes_capacity_and_flushes_instruction() {
        let encoder_sink = RecordingInstructionSink::default();
        let recorded = encoder_sink.clone();
        let encoder = Encoder::new(
            settings_with_capacity(0),
            encoder_sink,
            stream::empty::<Result<DecoderInstruction, StreamError>>(),
        );

        encoder.apply_settings(settings_with_capacity(96)).await;

        assert_eq!(encoder.state.lock().await.table_capacity(), 96);
        assert_eq!(
            recorded.instructions(),
            vec![EncoderInstruction::SetDynamicTableCapacity { capacity: 96 }]
        );
        assert_eq!(recorded.flushes(), 1);
        assert!(encoder.state.lock().await.pending_instructions().is_empty());
    }

    #[tokio::test]
    async fn encode_tracks_blocking_sections_from_algorithm_output() {
        let encoder = Encoder::new(
            settings_with_capacity_and_blocked_streams(128, 1),
            RecordingInstructionSink::default(),
            stream::empty::<Result<DecoderInstruction, StreamError>>(),
        );
        let algorithm = MayBlockProbeAlgorithm::with_max_referenced_index(4);

        encoder
            .encode(Vec::new(), &algorithm, TestStreamId(11))
            .await
            .expect("header section should encode");

        assert_eq!(algorithm.observed_may_block(), vec![true]);
        assert_eq!(
            encoder.state.lock().await.blocking_streams.get(&11),
            Some(&VecDeque::from([4]))
        );
    }

    #[tokio::test]
    async fn encode_disallows_new_blocking_streams_after_peer_limit() {
        let encoder = Encoder::new(
            settings_with_capacity_and_blocked_streams(128, 1),
            RecordingInstructionSink::default(),
            stream::empty::<Result<DecoderInstruction, StreamError>>(),
        );
        {
            let mut state = encoder.state.lock().await;
            state.blocking_streams.insert(1, VecDeque::from([0]));
        }
        let algorithm = MayBlockProbeAlgorithm::default();

        encoder
            .encode(Vec::new(), &algorithm, TestStreamId(2))
            .await
            .expect("header section should encode");
        encoder
            .encode(Vec::new(), &algorithm, TestStreamId(1))
            .await
            .expect("header section should encode");

        assert_eq!(algorithm.observed_may_block(), vec![false, true]);
    }

    #[tokio::test]
    async fn receive_instruction_applies_decoder_stream_state_changes() {
        let encoder = Encoder::new(
            settings_with_capacity(128),
            RecordingInstructionSink::default(),
            stream::iter([
                Ok(DecoderInstruction::SectionAcknowledgment { stream_id: 7 }),
                Ok(DecoderInstruction::StreamCancellation { stream_id: 8 }),
                Ok(DecoderInstruction::InsertCountIncrement { increment: 1 }),
            ]),
        );
        {
            let mut state = encoder.state.lock().await;
            state
                .set_max_table_capacity(128)
                .expect("set capacity failed");
            state
                .insert_with_literal_name(
                    false,
                    Bytes::from_static(b"x-name"),
                    false,
                    Bytes::from_static(b"value"),
                )
                .expect("insert failed");
            state
                .insert_with_literal_name(
                    false,
                    Bytes::from_static(b"x-name-2"),
                    false,
                    Bytes::from_static(b"value-2"),
                )
                .expect("insert failed");
            state.blocking_streams.insert(7, VecDeque::from([0]));
            state.blocking_streams.insert(8, VecDeque::from([0]));
        }

        encoder
            .receive_instruction()
            .await
            .expect("section acknowledgment should be accepted");
        encoder
            .receive_instruction()
            .await
            .expect("stream cancellation should be accepted");
        encoder
            .receive_instruction()
            .await
            .expect("insert count increment should be accepted");

        let state = encoder.state.lock().await;
        assert!(!state.blocking_streams.contains_key(&7));
        assert!(!state.blocking_streams.contains_key(&8));
        assert_eq!(state.table_known_received_count(), 2);
    }

    // --- Edge case tests ---

    #[test]
    fn get_dynamic_references_finds_dynamic_indexed_field() {
        let reprs = vec![FieldLineRepresentation::IndexedFieldLine {
            is_static: false,
            index: 5,
        }];
        let refs: Vec<u64> = get_dynamic_references(&reprs).collect();
        assert_eq!(refs, vec![5]);
    }

    #[test]
    fn get_dynamic_references_ignores_static_indexed_field() {
        let reprs = vec![FieldLineRepresentation::IndexedFieldLine {
            is_static: true,
            index: 5,
        }];
        let refs: Vec<u64> = get_dynamic_references(&reprs).collect();
        assert!(refs.is_empty(), "Static references should be ignored");
    }

    #[test]
    fn get_dynamic_references_finds_dynamic_name_reference() {
        let reprs = vec![FieldLineRepresentation::LiteralFieldLineWithNameReference {
            never_dynamic: false,
            is_static: false,
            name_index: 7,
            huffman: false,
            value: Bytes::from_static(b"val"),
        }];
        let refs: Vec<u64> = get_dynamic_references(&reprs).collect();
        assert_eq!(refs, vec![7]);
    }

    #[test]
    fn get_dynamic_references_empty_for_literal_name() {
        let reprs = vec![FieldLineRepresentation::LiteralFieldLineWithLiteralName {
            never_dynamic: false,
            name_huffman: false,
            name: Bytes::from_static(b"x-header"),
            value_huffman: false,
            value: Bytes::from_static(b"value"),
        }];
        let refs: Vec<u64> = get_dynamic_references(&reprs).collect();
        assert!(refs.is_empty(), "Literal name has no dynamic reference");
    }
}
