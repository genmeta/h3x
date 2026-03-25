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
    codec::{DecodeExt, DecodeFrom, DecodeStreamError, EncodeInto, Feed},
    connection::StreamError,
    dhttp::settings::Settings,
    error::{
        Code, ErrorScope, H3CriticalStreamClosed, H3Error, H3FrameDecodeError,
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

impl H3Error for QPackEncoderStreamError {
    fn code(&self) -> Code {
        Code::QPACK_ENCODER_STREAM_ERROR
    }
    fn scope(&self) -> ErrorScope {
        ErrorScope::Connection
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
        let new_entry_index = self.dynamic_table.index(entry);
        if new_entry_index > self.dynamic_table.known_received_count {
            self.update_known_received_count(new_entry_index);
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
        let new_entry_index = self.dynamic_table.index(entry);
        if new_entry_index > self.dynamic_table.known_received_count {
            self.update_known_received_count(new_entry_index);
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
        let new_entry_index = self.dynamic_table.index(duplicated_entry);
        if new_entry_index > self.dynamic_table.known_received_count {
            self.update_known_received_count(new_entry_index);
        }
        Ok(())
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

pub(crate) fn decompression_field_line_representation(
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

impl H3Error for InvalidDynamicTableReference {
    fn code(&self) -> Code {
        Code::QPACK_DECOMPRESSION_FAILED
    }
    fn scope(&self) -> ErrorScope {
        ErrorScope::Connection
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
        decode.await.map_err(|error: DecodeStreamError| {
            error.map_stream_closed(
                |_reset_code| H3CriticalStreamClosed::QPackDecoder.into(),
                |decode_error| {
                    H3FrameDecodeError {
                        source: decode_error,
                    }
                    .into()
                },
            )
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
    use std::sync::Arc;

    use bytes::Bytes;

    use super::{DecoderInstruction, DecoderState};
    use crate::{
        dhttp::settings::{QpackMaxTableCapacity, Settings},
        qpack::r#static,
        varint::VarInt,
    };

    fn test_settings(capacity: u32) -> Arc<Settings> {
        let mut settings = Settings::default();
        settings.set(QpackMaxTableCapacity::setting(VarInt::from_u32(capacity)));
        Arc::new(settings)
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
    fn insert_fails_when_capacity_too_small() {
        let mut state = DecoderState::new(test_settings(4096));
        // Set capacity very small — a FieldLine has 32 bytes overhead + name + value
        state.set_dynamic_table_capacity(10).unwrap();
        let result =
            state.insert_with_literal_name(Bytes::from_static(b"name"), Bytes::from_static(b"v"));
        assert!(result.is_err());
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
        use super::decompression_field_line_representation;
        use crate::qpack::{dynamic::DynamicTable, field::FieldLineRepresentation};

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
        use super::decompression_field_line_representation;
        use crate::qpack::{dynamic::DynamicTable, field::FieldLineRepresentation};

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
        use super::decompression_field_line_representation;
        use crate::qpack::{dynamic::DynamicTable, field::FieldLineRepresentation};

        let dt = DynamicTable::new();
        let repr = FieldLineRepresentation::IndexedFieldLine {
            is_static: true,
            index: 9999,
        };
        assert!(decompression_field_line_representation(&repr, 0, &dt).is_err());
    }
}
