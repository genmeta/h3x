use std::{
    collections::VecDeque,
    pin::{Pin, pin},
    sync::{Arc, Mutex as SyncMutex},
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt, stream};
use snafu::Snafu;
use tokio::{
    io::{AsyncBufRead, AsyncReadExt, AsyncWrite},
    sync::Mutex as AsyncMutex,
};

use crate::{
    codec::{DecodeExt, DecodeFrom, EncodeInto, Feed, StreamDecodeError},
    connection::StreamError,
    dhttp::settings::Settings,
    error::{
        Code, H3ConnectionError, H3CriticalStreamClosed, H3FrameDecodeError,
        QpackDecompressionFailed,
    },
    qpack::{
        dynamic::DynamicTable,
        encoder::EncoderInstruction,
        field::{EncodedFieldSectionPrefix, FieldLine, FieldLineRepresentation, FieldSection},
        integer::{decode_integer, encode_integer},
        r#static,
    },
    quic::{self, GetStreamId, GetStreamIdExt, ReadStream, StopStream},
    varint::VarInt,
};

#[derive(Debug)]
pub struct DecoderState {
    pub(crate) settings: Arc<Settings>,
    pub(crate) dynamic_table: DynamicTable,
    pub(crate) pending_instructions: VecDeque<DecoderInstruction>,
}

impl DecoderState {
    pub const fn new(settings: Arc<Settings>) -> Self {
        Self {
            settings,
            dynamic_table: DynamicTable::new(),
            pending_instructions: VecDeque::new(),
        }
    }

    pub fn table_inserted_count(&self) -> u64 {
        self.dynamic_table.inserted_count
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum QPackEncoderStreamError {
    #[snafu(display("setting dynamic table capacity exceeded maximum allowed"))]
    SetDynamicTableCapacityExceeded,
    #[snafu(display("no evictable entry for insertion, cannot insert new entry"))]
    NoEvictableEntryForInsertion,
    #[snafu(display("referenced static table entry {index} does not exist"))]
    ReferencedStaticEntryNotExisted { index: u64 },
    #[snafu(display("referenced dynamic table entry {index} does not exist"))]
    ReferencedDynamicEntryNotExisted { index: u64 },
}

impl H3ConnectionError for QPackEncoderStreamError {
    fn code(&self) -> Code {
        Code::QPACK_ENCODER_STREAM_ERROR
    }
}

impl DecoderState {
    pub fn emit(&mut self, instruction: DecoderInstruction) {
        use DecoderInstruction::*;
        match (self.pending_instructions.back_mut(), instruction) {
            // reduce redundant InsertCountIncrement instructions
            (
                Some(InsertCountIncrement { increment }),
                InsertCountIncrement {
                    increment: new_increment,
                },
            ) => {
                *increment += new_increment;
            }
            // reduce redundant StreamCancellation instructions
            (
                Some(StreamCancellation { stream_id }),
                StreamCancellation {
                    stream_id: another_stream_id,
                },
            ) if stream_id == &another_stream_id => {}
            (.., instruction) => self.pending_instructions.push_back(instruction),
        };
    }

    pub fn update_known_received_count(&mut self, new_count: u64) {
        debug_assert!(new_count > self.dynamic_table.known_received_count);
        if let Some(instruction) = self.pending_instructions.back_mut()
            && let DecoderInstruction::InsertCountIncrement { increment } = instruction
        {
            *increment += new_count - self.dynamic_table.known_received_count;
        } else {
            self.emit(DecoderInstruction::InsertCountIncrement {
                increment: new_count - self.dynamic_table.known_received_count,
            });
        }
        self.dynamic_table.known_received_count = new_count;
    }

    pub fn set_dynamic_table_capacity(
        &mut self,
        new_capacity: u64,
    ) -> Result<(), QPackEncoderStreamError> {
        if new_capacity > self.settings.qpack_max_table_capacity().into_inner() {
            return Err(QPackEncoderStreamError::SetDynamicTableCapacityExceeded);
        }
        self.dynamic_table.capacity = new_capacity;
        while self.dynamic_table.size > new_capacity {
            self.dynamic_table.evict();
        }
        Ok(())
    }

    pub fn insert_with_name_reference(
        &mut self,
        is_static: bool,
        name_index: u64,
        value: Bytes,
    ) -> Result<(), QPackEncoderStreamError> {
        use QPackEncoderStreamError::*;
        let name = match is_static {
            true => Bytes::from_static(
                r#static::get_name(name_index)
                    .ok_or(ReferencedStaticEntryNotExisted { index: name_index })?
                    .as_bytes(),
            ),
            false => self
                .dynamic_table
                .get(name_index)
                .ok_or(ReferencedDynamicEntryNotExisted { index: name_index })?
                .name
                .clone(),
        };

        let entry = FieldLine { name, value };

        while self.dynamic_table.size + entry.size() > self.dynamic_table.capacity {
            if self.dynamic_table.is_empty() {
                return Err(NoEvictableEntryForInsertion);
            }
            self.dynamic_table.evict();
        }
        self.dynamic_table.index(entry);
        if self.dynamic_table.inserted_count > self.dynamic_table.known_received_count {
            self.update_known_received_count(self.dynamic_table.inserted_count);
        }
        Ok(())
    }

    pub fn insert_with_literal_name(
        &mut self,
        name: Bytes,
        value: Bytes,
    ) -> Result<(), QPackEncoderStreamError> {
        use QPackEncoderStreamError::*;
        let entry = FieldLine { name, value };
        while self.dynamic_table.size + entry.size() > self.dynamic_table.capacity {
            if self.dynamic_table.is_empty() {
                return Err(NoEvictableEntryForInsertion);
            }
            self.dynamic_table.evict();
        }
        self.dynamic_table.index(entry);
        if self.dynamic_table.inserted_count > self.dynamic_table.known_received_count {
            self.update_known_received_count(self.dynamic_table.inserted_count);
        }
        Ok(())
    }

    pub fn duplicate(&mut self, index: u64) -> Result<(), QPackEncoderStreamError> {
        use QPackEncoderStreamError::*;
        let duplicated_entry = self
            .dynamic_table
            .get(index)
            .ok_or(ReferencedDynamicEntryNotExisted { index })?
            .clone();
        while self.dynamic_table.size + duplicated_entry.size() > self.dynamic_table.capacity {
            if self.dynamic_table.is_empty() {
                return Err(NoEvictableEntryForInsertion);
            }
            self.dynamic_table.evict();
        }
        self.dynamic_table.index(duplicated_entry);
        if self.dynamic_table.inserted_count > self.dynamic_table.known_received_count {
            self.update_known_received_count(self.dynamic_table.inserted_count);
        }
        Ok(())
    }

    pub fn decompress(
        &self,
        representation: &FieldLineRepresentation,
        base: u64,
    ) -> Result<FieldLine, InvalidDynamicTableReference> {
        decompression_field_line_representation(representation, base, &self.dynamic_table)
    }
}

pub struct Decoder<Ds, Es> {
    pub(crate) state: SyncMutex<DecoderState>,
    pub(crate) decoder_stream: AsyncMutex<Feed<Ds, DecoderInstruction>>,
    pub(crate) encoder_stream: AsyncMutex<Es>,
}

impl<Ds, Es> Decoder<Ds, Es> {
    pub(crate) fn emit(&self, instruction: DecoderInstruction) {
        self.state
            .lock()
            .expect("lock is not poisoned")
            .emit(instruction);
    }

    pub(crate) fn known_received_count(&self) -> u64 {
        self.state
            .lock()
            .expect("lock is not poisoned")
            .dynamic_table
            .known_received_count
    }
}

pub fn decompression_field_line_representation(
    representation: &FieldLineRepresentation,
    base: u64,
    dynamic_table: &DynamicTable,
) -> Result<FieldLine, InvalidDynamicTableReference> {
    use InvalidDynamicTableReference::*;
    // RFC 9204 §3.2.5: relative_index → absolute = base - relative - 1
    let resolve_relative = |index| {
        base.checked_sub(index)
            .ok_or(IndexOverflow)?
            .checked_sub(1)
            .ok_or(IndexOverflow)
    };
    // RFC 9204 §3.2.6: post_base_index → absolute = base + post_base
    let resolve_post_base = |index| base.checked_add(index).ok_or(IndexOverflow);
    match representation {
        FieldLineRepresentation::IndexedFieldLine { is_static, index } => match is_static {
            true => r#static::get(*index)
                .map(|(name, value)| FieldLine {
                    name: Bytes::from_static(name.as_bytes()),
                    value: Bytes::from_static(value.as_bytes()),
                })
                .ok_or(ReferencedStaticEntryNotExisted { index: *index }),
            false => dynamic_table
                .get(resolve_relative(*index)?)
                .cloned()
                .ok_or(ReferencedDynamicEntryNotExisted { index: *index }),
        },
        FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index } => {
            let index = resolve_post_base(*index)?;
            dynamic_table
                .get(index)
                .cloned()
                .ok_or(ReferencedDynamicEntryNotExisted { index })
        }
        FieldLineRepresentation::LiteralFieldLineWithNameReference {
            is_static,
            name_index,
            value,
            ..
        } => match is_static {
            true => Ok(FieldLine {
                name: Bytes::from_static(
                    r#static::get_name(*name_index)
                        .ok_or(ReferencedStaticEntryNotExisted { index: *name_index })?
                        .as_bytes(),
                ),
                value: value.clone(),
            }),
            false => {
                let name_index = resolve_relative(*name_index)?;
                let name = &dynamic_table
                    .get(name_index)
                    .ok_or(ReferencedDynamicEntryNotExisted { index: name_index })?
                    .name;
                Ok(FieldLine {
                    name: name.clone(),
                    value: value.clone(),
                })
            }
        },
        FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
            name_index,
            value,
            ..
        } => {
            let name_index = resolve_post_base(*name_index)?;
            let name = &dynamic_table
                .get(name_index)
                .ok_or(ReferencedDynamicEntryNotExisted { index: name_index })?
                .name;
            Ok(FieldLine {
                name: name.clone(),
                value: value.clone(),
            })
        }
        FieldLineRepresentation::LiteralFieldLineWithLiteralName { name, value, .. } => {
            Ok(FieldLine {
                name: name.clone(),
                value: value.clone(),
            })
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidDynamicTableReference {
    #[snafu(display("reference index overflow"))]
    IndexOverflow,
    #[snafu(display("referenced static table entry {index} does not exist"))]
    ReferencedStaticEntryNotExisted { index: u64 },
    #[snafu(display("referenced dynamic table entry {index} does not exist"))]
    ReferencedDynamicEntryNotExisted { index: u64 },
}

impl H3ConnectionError for InvalidDynamicTableReference {
    fn code(&self) -> Code {
        Code::QPACK_DECOMPRESSION_FAILED
    }
}

impl<Ds, Es> Decoder<Ds, Es>
where
    Ds: Sink<DecoderInstruction, Error = StreamError> + Unpin + Send,
    Es: Stream<Item = Result<EncoderInstruction, StreamError>> + Unpin + Send,
{
    pub fn new(settings: Arc<Settings>, decoder_stream: Ds, encoder_stream: Es) -> Self {
        Self {
            state: SyncMutex::new(DecoderState::new(settings)),
            decoder_stream: AsyncMutex::new(Feed::new(decoder_stream)),
            encoder_stream: AsyncMutex::new(encoder_stream),
        }
    }

    pub async fn decode(
        &self,
        header_frame: impl AsyncBufRead + GetStreamId + Send,
    ) -> Result<FieldSection, StreamError> {
        let mut header_frame = pin!(header_frame);
        let stream_id = header_frame.stream_id().await?.into_inner();
        let prefix: EncodedFieldSectionPrefix = header_frame.as_mut().decode_one().await?;

        // RFC 9204 §4.5.1.1: Decode the wire-encoded insert count to true RIC
        let (max_table_capacity, total_inserts) = {
            let state = self.state.lock().expect("lock is not poisoned");
            (
                state.settings.qpack_max_table_capacity().into_inner(),
                state.dynamic_table.inserted_count,
            )
        };
        let required_insert_count = EncodedFieldSectionPrefix::decode_ric(
            prefix.encoded_insert_count,
            max_table_capacity,
            total_inserts,
        )
        .map_err(|e| StreamError::from(QpackDecompressionFailed::Decode { source: e }))?;

        // RFC 9204 §4.5.1.2: Resolve the true base
        let base = EncodedFieldSectionPrefix::resolve_base(
            required_insert_count,
            prefix.sign,
            prefix.delta_base,
        )
        .map_err(|e| StreamError::from(QpackDecompressionFailed::Decode { source: e }))?;

        self.receive_instruction_until(required_insert_count)
            .await?;

        let max_field_section_size = self
            .state
            .lock()
            .expect("lock is not poisoned")
            .settings
            .max_field_section_size()
            .map(|v| v.into_inner());

        let representations =
            header_frame.into_decode_stream::<FieldLineRepresentation, StreamError>();
        let mut accumulated_size: u64 = 0;
        let field_lines = representations.map(|representation| {
            representation.and_then(|representation| {
                let field_line = decompression_field_line_representation(
                    &representation,
                    base,
                    &self
                        .state
                        .lock()
                        .expect("lock is not poisoned")
                        .dynamic_table,
                )
                .map_err(StreamError::from)?;

                accumulated_size += field_line.size();
                if let Some(limit) = max_field_section_size.filter(|&l| accumulated_size > l) {
                    return Err(StreamError::from(
                        crate::error::H3ExcessiveFieldSectionSize {
                            actual: accumulated_size,
                            limit,
                        },
                    ));
                }

                Ok(field_line)
            })
        });
        let header_section = field_lines.decode().await?;

        if required_insert_count > 0 {
            self.emit(DecoderInstruction::SectionAcknowledgment { stream_id });
        }
        _ = self.flush_instructions().await;

        Ok(header_section)
    }

    fn pending_instructions(&self) -> impl Iterator<Item = DecoderInstruction> {
        std::iter::from_fn(move || {
            self.state
                .lock()
                .expect("lock is not poisoned")
                .pending_instructions
                .pop_front()
        })
    }

    pub async fn flush_instructions(&self) -> Result<(), StreamError> {
        let mut decoder_stream = self.decoder_stream.lock().await;
        let mut decoder_stream = Pin::new(&mut *decoder_stream);
        let instructions = stream::iter(self.pending_instructions());
        decoder_stream.as_mut().send_all(instructions).await?;
        decoder_stream.as_mut().flush().await?;
        Ok(())
    }

    pub async fn receive_instruction_until(
        &self,
        known_received_count: u64,
    ) -> Result<(), StreamError> {
        loop {
            if self.known_received_count() >= known_received_count {
                return Ok(());
            }
            let instruction = {
                let mut encoder_stream = self.encoder_stream.lock().await;
                if self.known_received_count() >= known_received_count {
                    return Ok(());
                }
                let instruction = encoder_stream.next().await;
                instruction.ok_or(H3CriticalStreamClosed::QPackEncoder)??
            };

            let mut state = self.state.lock().expect("lock is not poisoned");
            match instruction {
                EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                    state.set_dynamic_table_capacity(capacity)?
                }
                EncoderInstruction::InsertWithNameReference {
                    is_static,
                    name_index,
                    value,
                    ..
                } => {
                    // RFC 9204 §3.2.4: Encoder instruction relative index →
                    // absolute = inserted_count - relative - 1
                    let abs_index = if is_static {
                        name_index
                    } else {
                        state.dynamic_table.inserted_count - name_index - 1
                    };
                    state.insert_with_name_reference(is_static, abs_index, value)?
                }
                EncoderInstruction::InsertWithLiteralName { name, value, .. } => {
                    state.insert_with_literal_name(name, value)?
                }
                EncoderInstruction::Duplicate { index } => {
                    // RFC 9204 §3.2.4: Encoder instruction relative index →
                    // absolute = inserted_count - relative - 1
                    let abs_index = state.dynamic_table.inserted_count - index - 1;
                    state.duplicate(abs_index)?
                }
            }
        }
    }
}

pin_project_lite::pin_project! {
    /// A read stream wrapper that emits stream cancellation instruction when reset is received or stop sending is called.
    pub struct MessageStreamReader<S: ReadStream, Ds, Es> {
        decoder: Arc<Decoder<Ds, Es>>,
        #[pin]
        stream: S,
    }

}

impl<S: ReadStream + Unpin, Ds, Es> MessageStreamReader<S, Ds, Es> {
    pub fn new(stream: S, decoder: Arc<Decoder<Ds, Es>>) -> Self {
        Self { stream, decoder }
    }
}

impl<S: ReadStream, Ds, Es> StopStream for MessageStreamReader<S, Ds, Es> {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let mut project = self.project();
        let stream_id = ready!(project.stream.as_mut().poll_stream_id(cx))?.into_inner();
        ready!(project.stream.poll_stop(cx, code))?;
        project
            .decoder
            .emit(DecoderInstruction::StreamCancellation { stream_id });
        Poll::Ready(Ok(()))
    }
}

impl<S: ReadStream, Ds, Es> GetStreamId for MessageStreamReader<S, Ds, Es> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.project().stream.poll_stream_id(cx)
    }
}

impl<S: ReadStream, Ds, Es> Stream for MessageStreamReader<S, Ds, Es> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut project = self.project();
        let stream_id = ready!(project.stream.as_mut().poll_stream_id(cx))?.into_inner();
        match project.stream.poll_next(cx) {
            poll @ Poll::Ready(Some(Err(quic::StreamError::Reset { .. }))) => {
                project
                    .decoder
                    .emit(DecoderInstruction::StreamCancellation { stream_id });
                poll
            }
            poll => poll,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderInstruction {
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 |      Stream ID (7+)       |
    /// +---+---------------------------+
    /// ```
    SectionAcknowledgment { stream_id: u64 },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 |     Stream ID (6+)    |
    /// +---+---+-----------------------+
    /// ```
    StreamCancellation { stream_id: u64 },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 |     Increment (6+)    |
    /// +---+---+-----------------------+
    /// ```
    InsertCountIncrement { increment: u64 },
}

impl<S: AsyncBufRead + Send> DecodeFrom<S> for DecoderInstruction {
    type Error = StreamError;

    async fn decode_from(stream: S) -> Result<Self, StreamError> {
        let decode = async move {
            let mut stream = pin!(stream);
            let prefix = stream.read_u8().await?;
            match prefix {
                // 1xxxxxxx — Section Acknowledgment (7-bit prefix)
                prefix if prefix & 0b1000_0000 == 0b1000_0000 => {
                    let stream_id = decode_integer(stream, prefix, 7).await?;
                    Ok(DecoderInstruction::SectionAcknowledgment { stream_id })
                }
                // 01xxxxxx — Stream Cancellation (6-bit prefix)
                prefix if prefix & 0b1100_0000 == 0b0100_0000 => {
                    let stream_id = decode_integer(stream, prefix, 6).await?;
                    Ok(DecoderInstruction::StreamCancellation { stream_id })
                }
                // 00xxxxxx — Insert Count Increment (6-bit prefix)
                _ => {
                    let increment = decode_integer(stream, prefix, 6).await?;
                    Ok(DecoderInstruction::InsertCountIncrement { increment })
                }
            }
        };
        decode.await.map_err(|error: StreamDecodeError| {
            error
                .escalate_critical_close(|| H3CriticalStreamClosed::QPackDecoder.into())
                .into_stream_error(|decode_error| {
                    H3FrameDecodeError {
                        source: decode_error,
                    }
                    .into()
                })
        })
    }
}

impl<S> EncodeInto<S> for DecoderInstruction
where
    S: AsyncWrite + Send,
{
    type Output = ();

    type Error = StreamError;

    async fn encode_into(self, stream: S) -> Result<Self::Output, Self::Error> {
        let inst = self;
        let encode = async move {
            let mut stream = pin!(stream);
            match inst {
                DecoderInstruction::SectionAcknowledgment { stream_id } => {
                    let prefix = 0b1000_0000;
                    encode_integer(stream.as_mut(), prefix, 7, stream_id).await?;
                    Ok(())
                }
                DecoderInstruction::StreamCancellation { stream_id } => {
                    let prefix = 0b0100_0000;
                    encode_integer(stream.as_mut(), prefix, 6, stream_id).await?;
                    Ok(())
                }
                DecoderInstruction::InsertCountIncrement { increment } => {
                    let prefix = 0b0000_0000;
                    encode_integer(stream.as_mut(), prefix, 6, increment).await?;
                    Ok(())
                }
            }
        };
        encode
            .await
            .map_err(|error: quic::StreamError| match error {
                quic::StreamError::Connection { .. } => error.into(),
                quic::StreamError::Reset { .. } => H3CriticalStreamClosed::QPackEncoder.into(),
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

    use bytes::{Buf, Bytes};
    use futures::{Sink, StreamExt, stream};
    use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

    use super::{
        Decoder, DecoderInstruction, DecoderState, InvalidDynamicTableReference,
        MessageStreamReader, QPackEncoderStreamError, decompression_field_line_representation,
    };
    use crate::{
        buflist::BufList,
        codec::{DecodeFrom, EncodeInto},
        connection::StreamError,
        dhttp::settings::Settings,
        error::{Code, H3ConnectionError},
        qpack::{
            dynamic::DynamicTable,
            encoder::EncoderInstruction,
            field::{EncodedFieldSectionPrefix, FieldLine, FieldLineRepresentation},
            settings::QpackMaxTableCapacity,
            r#static,
        },
        quic::{self, GetStreamId, StopStream, StopStreamExt},
        varint::VarInt,
    };

    fn test_settings(capacity: u32) -> Arc<Settings> {
        let mut settings = Settings::default();
        settings.set(QpackMaxTableCapacity::setting(VarInt::from_u32(capacity)));
        Arc::new(settings)
    }

    fn test_settings_with_max_field_section_size(capacity: u32, max_size: u32) -> Arc<Settings> {
        let mut settings = Settings::default();
        settings.set(QpackMaxTableCapacity::setting(VarInt::from_u32(capacity)));
        settings.set(crate::dhttp::settings::MaxFieldSectionSize::setting(
            VarInt::from_u32(max_size),
        ));
        Arc::new(settings)
    }

    fn assert_connection_h3_code(error: StreamError, expected: Code) {
        match error {
            StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source },
            } => assert_eq!(source.code(), expected),
            error => panic!("unexpected error: {error:?}"),
        }
    }

    async fn encode_decode_roundtrip(
        instruction: DecoderInstruction,
    ) -> Result<DecoderInstruction, crate::connection::StreamError> {
        let mut encoded = Vec::new();
        instruction.encode_into(Cursor::new(&mut encoded)).await?;
        DecoderInstruction::decode_from(Cursor::new(encoded)).await
    }

    fn dynamic_table_with_entries(entries: &[FieldLine]) -> DynamicTable {
        let mut table = DynamicTable::new();
        table.capacity = 512;
        for entry in entries {
            table.index(entry.clone());
        }
        table.known_received_count = table.inserted_count;
        table
    }

    #[derive(Clone, Default)]
    struct RecordingDecoderSink {
        instructions: Arc<Mutex<Vec<DecoderInstruction>>>,
    }

    type RecordedDecoderInstructions = Arc<Mutex<Vec<DecoderInstruction>>>;
    type TestEncoderStream =
        stream::Iter<std::vec::IntoIter<Result<EncoderInstruction, StreamError>>>;
    type TestDecoder = Decoder<RecordingDecoderSink, TestEncoderStream>;

    impl Sink<DecoderInstruction> for RecordingDecoderSink {
        type Error = StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: DecoderInstruction) -> Result<(), Self::Error> {
            self.instructions
                .lock()
                .expect("lock is not poisoned")
                .push(item);
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

    fn test_decoder(
        settings: Arc<Settings>,
        instructions: Vec<Result<EncoderInstruction, StreamError>>,
    ) -> (TestDecoder, RecordedDecoderInstructions) {
        let sink = RecordingDecoderSink::default();
        let sent = sink.instructions.clone();
        (
            Decoder::new(settings, sink, stream::iter(instructions)),
            sent,
        )
    }

    pin_project_lite::pin_project! {
        struct TestHeaderFrame {
            stream_id: VarInt,
            #[pin]
            payload: Cursor<Vec<u8>>,
        }
    }

    impl AsyncRead for TestHeaderFrame {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.project().payload.poll_read(cx, buf)
        }
    }

    impl AsyncBufRead for TestHeaderFrame {
        fn poll_fill_buf(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<&[u8]>> {
            self.project().payload.poll_fill_buf(cx)
        }

        fn consume(self: Pin<&mut Self>, amt: usize) {
            self.project().payload.consume(amt);
        }
    }

    impl GetStreamId for TestHeaderFrame {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            let this = self.project();
            Poll::Ready(Ok(*this.stream_id))
        }
    }

    async fn encode_header_payload(
        prefix: EncodedFieldSectionPrefix,
        representations: Vec<FieldLineRepresentation>,
    ) -> Vec<u8> {
        let mut payload = BufList::new();
        prefix
            .encode_into(&mut payload)
            .await
            .expect("prefix should encode");
        for representation in representations {
            representation
                .encode_into(&mut payload)
                .await
                .expect("field line representation should encode");
        }
        payload.copy_to_bytes(payload.remaining()).to_vec()
    }

    struct TestReadStream {
        stream_id: VarInt,
        stop_codes: Arc<Mutex<Vec<VarInt>>>,
        items: VecDeque<Result<Bytes, quic::StreamError>>,
    }

    impl futures::Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.items.pop_front())
        }
    }

    impl GetStreamId for TestReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl StopStream for TestReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.stop_codes
                .lock()
                .expect("lock is not poisoned")
                .push(code);
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn decoder_state_default_construction() {
        let state = DecoderState::new(test_settings(0));
        assert_eq!(state.dynamic_table.capacity, 0);
        assert_eq!(state.dynamic_table.inserted_count, 0);
        assert_eq!(state.dynamic_table.known_received_count, 0);
        assert!(state.pending_instructions.is_empty());
    }

    #[test]
    fn decoder_error_types_report_qpack_error_codes() {
        let encoder_stream_errors = [
            QPackEncoderStreamError::SetDynamicTableCapacityExceeded,
            QPackEncoderStreamError::NoEvictableEntryForInsertion,
            QPackEncoderStreamError::ReferencedStaticEntryNotExisted { index: 7 },
            QPackEncoderStreamError::ReferencedDynamicEntryNotExisted { index: 11 },
        ];

        for error in encoder_stream_errors {
            assert_eq!(error.code(), Code::QPACK_ENCODER_STREAM_ERROR);
        }

        let invalid_references = [
            InvalidDynamicTableReference::IndexOverflow,
            InvalidDynamicTableReference::ReferencedStaticEntryNotExisted { index: 7 },
            InvalidDynamicTableReference::ReferencedDynamicEntryNotExisted { index: 11 },
        ];

        for error in invalid_references {
            assert_eq!(error.code(), Code::QPACK_DECOMPRESSION_FAILED);
        }
    }

    #[test]
    fn decoder_wrapper_emit_and_known_received_count_delegate_to_state() {
        let (decoder, _) = test_decoder(test_settings(128), Vec::new());

        decoder.emit(DecoderInstruction::StreamCancellation { stream_id: 9 });

        assert_eq!(decoder.known_received_count(), 0);
        let state = decoder.state.lock().expect("lock is not poisoned");
        assert_eq!(
            state.pending_instructions.front(),
            Some(&DecoderInstruction::StreamCancellation { stream_id: 9 })
        );
    }

    #[test]
    fn emit_insert_count_increment() {
        let mut state = DecoderState::new(test_settings(256));
        state.emit(DecoderInstruction::InsertCountIncrement { increment: 1 });
        assert_eq!(state.pending_instructions.len(), 1);
        assert_eq!(
            state.pending_instructions[0],
            DecoderInstruction::InsertCountIncrement { increment: 1 }
        );
    }

    #[test]
    fn emit_merges_consecutive_insert_count_increments() {
        let mut state = DecoderState::new(test_settings(256));
        state.emit(DecoderInstruction::InsertCountIncrement { increment: 1 });
        state.emit(DecoderInstruction::InsertCountIncrement { increment: 3 });
        assert_eq!(state.pending_instructions.len(), 1);
        assert_eq!(
            state.pending_instructions[0],
            DecoderInstruction::InsertCountIncrement { increment: 4 }
        );
    }

    #[test]
    fn emit_deduplicates_stream_cancellation() {
        let mut state = DecoderState::new(test_settings(256));
        state.emit(DecoderInstruction::StreamCancellation { stream_id: 42 });
        state.emit(DecoderInstruction::StreamCancellation { stream_id: 42 });
        assert_eq!(state.pending_instructions.len(), 1);
    }

    #[test]
    fn emit_does_not_deduplicate_different_stream_cancellations() {
        let mut state = DecoderState::new(test_settings(256));
        state.emit(DecoderInstruction::StreamCancellation { stream_id: 1 });
        state.emit(DecoderInstruction::StreamCancellation { stream_id: 2 });
        assert_eq!(state.pending_instructions.len(), 2);
    }

    #[test]
    fn emit_section_acknowledgment() {
        let mut state = DecoderState::new(test_settings(256));
        state.emit(DecoderInstruction::SectionAcknowledgment { stream_id: 10 });
        assert_eq!(state.pending_instructions.len(), 1);
        assert_eq!(
            state.pending_instructions[0],
            DecoderInstruction::SectionAcknowledgment { stream_id: 10 }
        );
    }

    #[tokio::test]
    async fn decoder_instruction_roundtrip_all_variants() {
        let instructions = [
            DecoderInstruction::SectionAcknowledgment { stream_id: 7 },
            DecoderInstruction::StreamCancellation { stream_id: 11 },
            DecoderInstruction::InsertCountIncrement { increment: 5 },
        ];

        for instruction in instructions {
            let decoded = encode_decode_roundtrip(instruction)
                .await
                .expect("instruction should roundtrip");
            assert_eq!(decoded, instruction);
        }
    }

    #[test]
    fn set_dynamic_table_capacity_within_limit() {
        let mut state = DecoderState::new(test_settings(256));
        assert!(state.set_dynamic_table_capacity(128).is_ok());
        assert_eq!(state.dynamic_table.capacity, 128);
    }

    #[test]
    fn set_dynamic_table_capacity_exceeds_max() {
        let mut state = DecoderState::new(test_settings(256));
        assert!(state.set_dynamic_table_capacity(512).is_err());
    }

    #[test]
    fn update_known_received_count_merges_pending_increment() {
        let mut state = DecoderState::new(test_settings(256));

        state.update_known_received_count(1);
        state.update_known_received_count(3);

        assert_eq!(state.dynamic_table.known_received_count, 3);
        assert_eq!(state.pending_instructions.len(), 1);
        assert_eq!(
            state.pending_instructions[0],
            DecoderInstruction::InsertCountIncrement { increment: 3 }
        );
    }

    #[test]
    fn set_dynamic_table_capacity_evicts_entries_until_within_limit() {
        let mut state = DecoderState::new(test_settings(128));
        state.set_dynamic_table_capacity(128).unwrap();
        state
            .insert_with_literal_name(
                Bytes::from_static(b"header-1"),
                Bytes::from_static(b"value-1"),
            )
            .unwrap();
        state
            .insert_with_literal_name(
                Bytes::from_static(b"header-2"),
                Bytes::from_static(b"value-2"),
            )
            .unwrap();

        state.set_dynamic_table_capacity(64).unwrap();

        assert_eq!(state.dynamic_table.capacity, 64);
        assert_eq!(state.dynamic_table.dropped_count, 1);
        assert_eq!(
            state
                .dynamic_table
                .entries()
                .map(|(index, entry)| (index, entry.name.clone()))
                .collect::<Vec<_>>(),
            vec![(1, Bytes::from_static(b"header-2"))]
        );
    }

    #[test]
    fn insert_with_literal_name() {
        let mut state = DecoderState::new(test_settings(4096));
        state.set_dynamic_table_capacity(4096).unwrap();
        state
            .insert_with_literal_name(
                Bytes::from_static(b"x-custom"),
                Bytes::from_static(b"value"),
            )
            .unwrap();
        assert_eq!(state.dynamic_table.inserted_count, 1);
        let entry = state.dynamic_table.get(0).unwrap();
        assert_eq!(&entry.name[..], b"x-custom");
        assert_eq!(&entry.value[..], b"value");
    }

    #[test]
    fn insert_with_static_name_reference() {
        let mut state = DecoderState::new(test_settings(4096));
        state.set_dynamic_table_capacity(4096).unwrap();
        // Index 0 in static table is ":authority"
        state
            .insert_with_name_reference(true, 0, Bytes::from_static(b"example.com"))
            .unwrap();
        let entry = state.dynamic_table.get(0).unwrap();
        assert_eq!(&entry.name[..], b":authority");
        assert_eq!(&entry.value[..], b"example.com");
    }

    #[test]
    fn insert_with_dynamic_name_reference_reuses_existing_name() {
        let mut state = DecoderState::new(test_settings(128));
        state.set_dynamic_table_capacity(128).unwrap();
        state
            .insert_with_literal_name(Bytes::from_static(b"x-name"), Bytes::from_static(b"old"))
            .expect("seed entry should fit");

        state
            .insert_with_name_reference(false, 0, Bytes::from_static(b"new"))
            .expect("dynamic name reference should insert");

        let entry = state
            .dynamic_table
            .get(1)
            .expect("second entry should exist");
        assert_eq!(entry.name, Bytes::from_static(b"x-name"));
        assert_eq!(entry.value, Bytes::from_static(b"new"));
        assert_eq!(state.table_inserted_count(), 2);
    }

    #[test]
    fn insert_with_name_reference_evicts_acknowledged_entry_when_needed() {
        let mut state = DecoderState::new(test_settings(80));
        state.set_dynamic_table_capacity(80).unwrap();
        state
            .insert_with_literal_name(Bytes::from_static(b"x-old"), Bytes::from_static(b"old"))
            .expect("seed entry should fit");

        state
            .insert_with_name_reference(true, 1, Bytes::from_static(b"/very/long/path/value"))
            .expect("new entry should fit after eviction");

        assert_eq!(state.dynamic_table.dropped_count, 1);
        assert!(state.dynamic_table.get(0).is_none());
        let entry = state
            .dynamic_table
            .get(1)
            .expect("inserted entry should remain");
        assert_eq!(entry.name, Bytes::from_static(b":path"));
        assert_eq!(entry.value, Bytes::from_static(b"/very/long/path/value"));
    }

    #[test]
    fn insert_with_literal_name_evicts_acknowledged_entry_when_needed() {
        let mut state = DecoderState::new(test_settings(80));
        state.set_dynamic_table_capacity(80).unwrap();
        state
            .insert_with_literal_name(Bytes::from_static(b"x-old"), Bytes::from_static(b"old"))
            .expect("seed entry should fit");

        state
            .insert_with_literal_name(
                Bytes::from_static(b"x-new"),
                Bytes::from_static(b"larger-new-value"),
            )
            .expect("new literal should fit after eviction");

        assert_eq!(state.dynamic_table.dropped_count, 1);
        assert!(state.dynamic_table.get(0).is_none());
        let entry = state
            .dynamic_table
            .get(1)
            .expect("inserted entry should remain");
        assert_eq!(entry.name, Bytes::from_static(b"x-new"));
        assert_eq!(entry.value, Bytes::from_static(b"larger-new-value"));
    }

    #[test]
    fn insert_with_name_reference_errors_for_missing_references() {
        let mut state = DecoderState::new(test_settings(4096));
        state.set_dynamic_table_capacity(4096).unwrap();

        let missing_static =
            state.insert_with_name_reference(true, 9999, Bytes::from_static(b"value"));
        let missing_dynamic =
            state.insert_with_name_reference(false, 0, Bytes::from_static(b"value"));

        assert!(
            matches!(
                missing_static,
                Err(QPackEncoderStreamError::ReferencedStaticEntryNotExisted { index: 9999 })
            ),
            "unexpected static result: {missing_static:?}"
        );
        assert!(
            matches!(
                missing_dynamic,
                Err(QPackEncoderStreamError::ReferencedDynamicEntryNotExisted { index: 0 })
            ),
            "unexpected dynamic result: {missing_dynamic:?}"
        );
    }

    #[test]
    fn insert_fails_when_capacity_too_small() {
        let mut state = DecoderState::new(test_settings(4096));
        // Set capacity very small — a FieldLine has 32 bytes overhead + name + value
        state.set_dynamic_table_capacity(10).unwrap();
        let result =
            state.insert_with_literal_name(Bytes::from_static(b"name"), Bytes::from_static(b"v"));
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_errors_for_missing_dynamic_entry() {
        let mut state = DecoderState::new(test_settings(256));
        state.set_dynamic_table_capacity(256).unwrap();

        let result = state.duplicate(0);

        assert!(
            matches!(
                result,
                Err(QPackEncoderStreamError::ReferencedDynamicEntryNotExisted { index: 0 })
            ),
            "Expected missing dynamic entry error, got {result:?}"
        );
    }

    #[test]
    fn duplicate_existing_entry_evicts_when_needed_and_updates_count() {
        let mut state = DecoderState::new(test_settings(50));
        state.set_dynamic_table_capacity(50).unwrap();
        state
            .insert_with_literal_name(Bytes::from_static(b"x-name"), Bytes::from_static(b"value"))
            .expect("seed entry should fit");
        state.pending_instructions.clear();

        state
            .duplicate(0)
            .expect("duplicate should fit after eviction");

        assert_eq!(state.dynamic_table.dropped_count, 1);
        assert!(state.dynamic_table.get(0).is_none());
        let entry = state.dynamic_table.get(1).expect("duplicate should remain");
        assert_eq!(entry.name, Bytes::from_static(b"x-name"));
        assert_eq!(entry.value, Bytes::from_static(b"value"));
        assert_eq!(state.dynamic_table.known_received_count, 2);
        assert_eq!(
            state.pending_instructions.back(),
            Some(&DecoderInstruction::InsertCountIncrement { increment: 1 })
        );
    }

    #[tokio::test]
    async fn receive_instruction_until_applies_encoder_stream_mutations() {
        let instructions = vec![
            Ok(EncoderInstruction::SetDynamicTableCapacity { capacity: 128 }),
            Ok(EncoderInstruction::InsertWithLiteralName {
                name_huffman: false,
                name: Bytes::from_static(b"x-name"),
                value_huffman: false,
                value: Bytes::from_static(b"value"),
            }),
            Ok(EncoderInstruction::InsertWithNameReference {
                is_static: false,
                name_index: 0,
                huffman: false,
                value: Bytes::from_static(b"referenced"),
            }),
            Ok(EncoderInstruction::Duplicate { index: 0 }),
        ];
        let (decoder, _) = test_decoder(test_settings(128), instructions);

        decoder
            .receive_instruction_until(3)
            .await
            .expect("encoder instructions should be applied");

        let state = decoder.state.lock().expect("lock is not poisoned");
        assert_eq!(state.dynamic_table.capacity, 128);
        assert_eq!(state.dynamic_table.inserted_count, 3);
        assert_eq!(
            state.dynamic_table.get(1).expect("referenced entry").name,
            Bytes::from_static(b"x-name")
        );
        assert_eq!(
            state.dynamic_table.get(2).expect("duplicate entry").value,
            Bytes::from_static(b"referenced")
        );
    }

    #[tokio::test]
    async fn receive_instruction_until_returns_when_count_already_known() {
        let (decoder, _) = test_decoder(test_settings(128), Vec::new());

        decoder
            .receive_instruction_until(0)
            .await
            .expect("zero required count is already known");
    }

    #[tokio::test]
    async fn receive_instruction_until_reports_closed_encoder_stream() {
        let (decoder, _) = test_decoder(test_settings(128), Vec::new());

        let error = decoder
            .receive_instruction_until(1)
            .await
            .expect_err("missing encoder stream instruction should close the connection");

        assert_connection_h3_code(error, Code::H3_CLOSED_CRITICAL_STREAM);
    }

    #[tokio::test]
    async fn receive_instruction_until_propagates_encoder_stream_read_error() {
        let (decoder, _) = test_decoder(
            test_settings(128),
            vec![Err(StreamError::Reset {
                code: VarInt::from_u32(33),
            })],
        );

        let error = decoder
            .receive_instruction_until(1)
            .await
            .expect_err("encoder stream read error should propagate");

        assert!(matches!(
            error,
            StreamError::Reset { code } if code == VarInt::from_u32(33)
        ));
    }

    #[tokio::test]
    async fn receive_instruction_until_rejects_invalid_encoder_instructions() {
        let cases = [
            vec![Ok(EncoderInstruction::SetDynamicTableCapacity {
                capacity: 256,
            })],
            vec![
                Ok(EncoderInstruction::SetDynamicTableCapacity { capacity: 64 }),
                Ok(EncoderInstruction::InsertWithNameReference {
                    is_static: true,
                    name_index: 9999,
                    huffman: false,
                    value: Bytes::from_static(b"value"),
                }),
            ],
            vec![
                Ok(EncoderInstruction::SetDynamicTableCapacity { capacity: 0 }),
                Ok(EncoderInstruction::InsertWithLiteralName {
                    name_huffman: false,
                    name: Bytes::from_static(b"name"),
                    value_huffman: false,
                    value: Bytes::from_static(b"value"),
                }),
            ],
        ];

        for instructions in cases {
            let (decoder, _) = test_decoder(test_settings(128), instructions);
            let error = decoder
                .receive_instruction_until(1)
                .await
                .expect_err("invalid encoder instruction should close the connection");

            assert_connection_h3_code(error, Code::QPACK_ENCODER_STREAM_ERROR);
        }
    }

    #[tokio::test]
    async fn flush_instructions_sends_and_drains_pending_queue() {
        let (decoder, sent) = test_decoder(test_settings(128), Vec::new());
        decoder.emit(DecoderInstruction::StreamCancellation { stream_id: 1 });
        decoder.emit(DecoderInstruction::StreamCancellation { stream_id: 2 });

        decoder
            .flush_instructions()
            .await
            .expect("pending instructions should flush");

        assert_eq!(
            sent.lock().expect("lock is not poisoned").as_slice(),
            &[
                DecoderInstruction::StreamCancellation { stream_id: 1 },
                DecoderInstruction::StreamCancellation { stream_id: 2 },
            ]
        );
        assert!(
            decoder
                .state
                .lock()
                .expect("lock is not poisoned")
                .pending_instructions
                .is_empty()
        );
    }

    #[tokio::test]
    async fn decode_emits_section_acknowledgment_for_dynamic_reference() {
        let (decoder, sent) = test_decoder(test_settings(128), Vec::new());
        {
            let mut state = decoder.state.lock().expect("lock is not poisoned");
            state.set_dynamic_table_capacity(128).unwrap();
            state
                .insert_with_literal_name(Bytes::from_static(b"x-name"), Bytes::from_static(b"ok"))
                .expect("seed entry should fit");
            state.pending_instructions.clear();
        }

        let prefix = EncodedFieldSectionPrefix {
            encoded_insert_count: EncodedFieldSectionPrefix::encode_ric(1, 128),
            sign: false,
            delta_base: 0,
        };
        let payload = encode_header_payload(
            prefix,
            vec![FieldLineRepresentation::IndexedFieldLine {
                is_static: false,
                index: 0,
            }],
        )
        .await;
        let frame = TestHeaderFrame {
            stream_id: VarInt::from_u32(23),
            payload: Cursor::new(payload),
        };

        let section = decoder.decode(frame).await.expect("header should decode");

        assert_eq!(
            section.header_map.get("x-name").expect("x-name header"),
            "ok"
        );
        assert_eq!(
            sent.lock().expect("lock is not poisoned").as_slice(),
            &[DecoderInstruction::SectionAcknowledgment { stream_id: 23 }]
        );
    }

    #[tokio::test]
    async fn decode_rejects_field_section_that_exceeds_configured_limit() {
        let (decoder, _) = test_decoder(
            test_settings_with_max_field_section_size(128, 1),
            Vec::new(),
        );
        let payload = encode_header_payload(
            EncodedFieldSectionPrefix {
                encoded_insert_count: 0,
                sign: false,
                delta_base: 0,
            },
            vec![FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                never_dynamic: false,
                name_huffman: false,
                name: Bytes::from_static(b"x-large"),
                value_huffman: false,
                value: Bytes::from_static(b"value"),
            }],
        )
        .await;
        let frame = TestHeaderFrame {
            stream_id: VarInt::from_u32(31),
            payload: Cursor::new(payload),
        };

        let error = decoder
            .decode(frame)
            .await
            .expect_err("limit should reject field");

        match error {
            StreamError::H3 { source } => assert_eq!(source.code(), Code::H3_EXCESSIVE_LOAD),
            error => panic!("unexpected error: {error:?}"),
        }
    }

    #[tokio::test]
    async fn message_stream_reader_stop_and_reset_emit_stream_cancellation() {
        let (decoder, _) = test_decoder(test_settings(128), Vec::new());
        let decoder = Arc::new(decoder);
        let stop_codes = Arc::new(Mutex::new(Vec::new()));
        let mut stopped_reader = MessageStreamReader::new(
            TestReadStream {
                stream_id: VarInt::from_u32(41),
                stop_codes: stop_codes.clone(),
                items: VecDeque::new(),
            },
            decoder.clone(),
        );

        stopped_reader
            .stop(VarInt::from_u32(7))
            .await
            .expect("stop should be forwarded");

        assert_eq!(
            stop_codes.lock().expect("lock is not poisoned").as_slice(),
            &[VarInt::from_u32(7)]
        );
        assert_eq!(
            decoder
                .state
                .lock()
                .expect("lock is not poisoned")
                .pending_instructions
                .back(),
            Some(&DecoderInstruction::StreamCancellation { stream_id: 41 })
        );

        let mut reset_reader = MessageStreamReader::new(
            TestReadStream {
                stream_id: VarInt::from_u32(43),
                stop_codes,
                items: VecDeque::from([Err(quic::StreamError::Reset {
                    code: VarInt::from_u32(11),
                })]),
            },
            decoder.clone(),
        );

        let item = reset_reader
            .next()
            .await
            .expect("reset item should be yielded");
        assert!(matches!(
            item,
            Err(quic::StreamError::Reset { code }) if code == VarInt::from_u32(11)
        ));
        assert_eq!(
            decoder
                .state
                .lock()
                .expect("lock is not poisoned")
                .pending_instructions
                .back(),
            Some(&DecoderInstruction::StreamCancellation { stream_id: 43 })
        );
    }

    #[test]
    fn static_table_lookup() {
        // Verify well-known static table entries
        assert_eq!(r#static::get_name(0), Some(":authority"));
        assert_eq!(r#static::get_name(1), Some(":path"));
        assert_eq!(r#static::get(1), Some((":path", "/")));
        assert!(r#static::get(99).is_none());
    }

    #[test]
    fn decompression_static_indexed_field_line() {
        let dt = DynamicTable::new();
        let repr = FieldLineRepresentation::IndexedFieldLine {
            is_static: true,
            index: 1, // :path /
        };
        let fl = decompression_field_line_representation(&repr, 0, &dt).unwrap();
        assert_eq!(&fl.name[..], b":path");
        assert_eq!(&fl.value[..], b"/");
    }

    #[test]
    fn decompression_literal_with_literal_name() {
        let dt = DynamicTable::new();
        let repr = FieldLineRepresentation::LiteralFieldLineWithLiteralName {
            never_dynamic: false,
            name_huffman: false,
            value_huffman: false,
            name: Bytes::from_static(b"x-test"),
            value: Bytes::from_static(b"hello"),
        };
        let fl = decompression_field_line_representation(&repr, 0, &dt).unwrap();
        assert_eq!(&fl.name[..], b"x-test");
        assert_eq!(&fl.value[..], b"hello");
    }

    #[test]
    fn decompression_invalid_static_index() {
        let dt = DynamicTable::new();
        let repr = FieldLineRepresentation::IndexedFieldLine {
            is_static: true,
            index: 9999,
        };
        assert!(decompression_field_line_representation(&repr, 0, &dt).is_err());
    }

    #[test]
    fn decompression_dynamic_references_resolve_relative_and_post_base_indices() {
        let dt = dynamic_table_with_entries(&[
            FieldLine {
                name: Bytes::from_static(b"header-1"),
                value: Bytes::from_static(b"value-1"),
            },
            FieldLine {
                name: Bytes::from_static(b"header-2"),
                value: Bytes::from_static(b"value-2"),
            },
            FieldLine {
                name: Bytes::from_static(b"header-3"),
                value: Bytes::from_static(b"value-3"),
            },
        ]);

        let indexed = FieldLineRepresentation::IndexedFieldLine {
            is_static: false,
            index: 0,
        };
        let indexed_post_base =
            FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index: 0 };
        let literal_name_ref = FieldLineRepresentation::LiteralFieldLineWithNameReference {
            never_dynamic: false,
            is_static: false,
            name_index: 1,
            huffman: false,
            value: Bytes::from_static(b"patched"),
        };
        let literal_post_base =
            FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                never_dynamic: false,
                name_index: 0,
                huffman: false,
                value: Bytes::from_static(b"patched-post"),
            };

        assert_eq!(
            decompression_field_line_representation(&indexed, 3, &dt).unwrap(),
            FieldLine {
                name: Bytes::from_static(b"header-3"),
                value: Bytes::from_static(b"value-3"),
            }
        );
        assert_eq!(
            decompression_field_line_representation(&indexed_post_base, 2, &dt).unwrap(),
            FieldLine {
                name: Bytes::from_static(b"header-3"),
                value: Bytes::from_static(b"value-3"),
            }
        );
        assert_eq!(
            decompression_field_line_representation(&literal_name_ref, 3, &dt).unwrap(),
            FieldLine {
                name: Bytes::from_static(b"header-2"),
                value: Bytes::from_static(b"patched"),
            }
        );
        assert_eq!(
            decompression_field_line_representation(&literal_post_base, 2, &dt).unwrap(),
            FieldLine {
                name: Bytes::from_static(b"header-3"),
                value: Bytes::from_static(b"patched-post"),
            }
        );
    }

    #[test]
    fn decompression_reports_index_overflow_and_missing_dynamic_entry() {
        let dt = dynamic_table_with_entries(&[FieldLine {
            name: Bytes::from_static(b"header-1"),
            value: Bytes::from_static(b"value-1"),
        }]);

        let overflow = FieldLineRepresentation::IndexedFieldLine {
            is_static: false,
            index: 1,
        };
        let missing = FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index: 10 };

        assert!(
            matches!(
                decompression_field_line_representation(&overflow, 0, &dt),
                Err(InvalidDynamicTableReference::IndexOverflow)
            ),
            "expected relative index overflow"
        );
        assert!(
            matches!(
                decompression_field_line_representation(&missing, 1, &dt),
                Err(InvalidDynamicTableReference::ReferencedDynamicEntryNotExisted { index: 11 })
            ),
            "expected missing post-base entry"
        );
    }
}
