use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex as SyncMutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt, stream};
use snafu::Snafu;
use tokio::{io::AsyncBufRead, sync::Mutex as AsyncMutex};

use crate::{
    codec::{
        Feed,
        error::{DecodeStreamError, EncodeStreamError},
        util::{DecodeFrom, decoder},
    },
    error::{Code, H3CriticalStreamClosed, HasErrorCode, StreamError},
    qpack::{
        dynamic::DynamicTable,
        field_section::{FieldLine, FieldSection},
        header_block::{EncodedFieldSectionPrefix, FieldLineRepresentation},
        instruction::{DecoderInstruction, EncoderInstruction},
        settings::Settings,
        r#static,
    },
    quic::{GetStreamId, ReadStream, StopSending},
};

#[derive(Debug)]
pub struct DecoderState {
    pub(crate) settings: Settings,
    pub(crate) dynamic_table: DynamicTable,
    pub(crate) pending_instructions: VecDeque<DecoderInstruction>,
}

impl DecoderState {
    pub const fn new(settings: Settings) -> Self {
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
    #[snafu(display("Setting dynamic table capacity exceeded maximum allowed"))]
    SetDynamicTableCapacityExceeded,
    #[snafu(display("No evictable entry for insertion, cannot insert new entry"))]
    NoEvictableEntryForInsertion,
    #[snafu(display("Referenced static table entry {index} not existed"))]
    ReferencedStaticEntryNotExisted { index: u64 },
    #[snafu(display("Referenced dynamic table entry {index} not existed"))]
    ReferencedDynamicEntryNotExisted { index: u64 },
}

impl HasErrorCode for QPackEncoderStreamError {
    const CODE: Code = Code::QPACK_ENCODER_STREAM_ERROR;
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
        self.state.lock().unwrap().emit(instruction);
    }

    pub(crate) fn known_received_count(&self) -> u64 {
        self.state
            .lock()
            .unwrap()
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
    let resolve_index = |index| base.checked_add(index).ok_or(IndexOverflow);
    let resolve_post_base_index = |index| {
        base.checked_sub(index)
            .ok_or(IndexOverflow)?
            .checked_sub(1)
            .ok_or(IndexOverflow)
    };
    match representation {
        FieldLineRepresentation::IndexedFieldLine { is_static, index } => match is_static {
            true => r#static::get(*index)
                .map(|(name, value)| FieldLine {
                    name: Bytes::from_static(name.as_bytes()),
                    value: Bytes::from_static(value.as_bytes()),
                })
                .ok_or(ReferencedStaticEntryNotExisted { index: *index }),
            false => dynamic_table
                .get(resolve_index(*index)?)
                .cloned()
                .ok_or(ReferencedDynamicEntryNotExisted { index: *index }),
        },
        FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index } => {
            let index = resolve_post_base_index(*index)?;
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
                let name_index = resolve_index(*name_index)?;
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
            let name_index = resolve_post_base_index(*name_index)?;
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
    #[snafu(display("Reference index overflow"))]
    IndexOverflow,
    #[snafu(display("Referenced static table entry {index} not existed"))]
    ReferencedStaticEntryNotExisted { index: u64 },
    #[snafu(display("Referenced dynamic table entry {index} not existed"))]
    ReferencedDynamicEntryNotExisted { index: u64 },
}

impl HasErrorCode for InvalidDynamicTableReference {
    const CODE: Code = Code::QPACK_DECOMPRESSION_FAILED;
}

impl<Ds, Es> Decoder<Ds, Es>
where
    Ds: Sink<DecoderInstruction> + Unpin,
    EncodeStreamError: From<<Ds as Sink<DecoderInstruction>>::Error>,
    Es: Stream<Item = Result<EncoderInstruction, DecodeStreamError>> + Unpin,
{
    pub fn new(settings: Settings, decoder_stream: Ds, encoder_stream: Es) -> Self {
        Self {
            state: SyncMutex::new(DecoderState::new(settings)),
            decoder_stream: AsyncMutex::new(Feed::new(decoder_stream)),
            encoder_stream: AsyncMutex::new(encoder_stream),
        }
    }

    pub async fn decode(
        &self,
        stream: impl AsyncBufRead + GetStreamId,
    ) -> Result<FieldSection, DecodeStreamError> {
        tokio::pin!(stream);
        let stream_id = stream.stream_id();
        let prefix = EncodedFieldSectionPrefix::decode_from(stream.as_mut()).await?;
        self.receive_instruction_until(prefix.required_insert_count)
            .await?;

        let header_section = FieldSection::decode_from(decoder(stream).map(|representation| {
            representation.and_then(|representation| {
                decompression_field_line_representation(
                    &representation,
                    prefix.base,
                    &self.state.lock().unwrap().dynamic_table,
                )
                .map_err(DecodeStreamError::from)
            })
        }))
        .await?;

        self.emit(DecoderInstruction::SectionAcknowledgment { stream_id });
        _ = self.flush_instructions().await;

        Ok(header_section)
    }

    fn pending_instructions(&self) -> impl Iterator<Item = DecoderInstruction> {
        std::iter::from_fn(move || self.state.lock().unwrap().pending_instructions.pop_front())
    }

    pub async fn flush_instructions(&self) -> Result<(), EncodeStreamError> {
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
    ) -> Result<(), DecodeStreamError> {
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
                instruction.ok_or(H3CriticalStreamClosed::QPackEncoderStream)??
            };

            let mut state = self.state.lock().unwrap();
            match instruction {
                EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                    state.set_dynamic_table_capacity(capacity)?
                }
                EncoderInstruction::InsertWithNameReference {
                    is_static,
                    name_index,
                    value,
                    ..
                } => state.insert_with_name_reference(is_static, name_index, value)?,
                EncoderInstruction::InsertWithLiteralName { name, value, .. } => {
                    state.insert_with_literal_name(name, value)?
                }
                EncoderInstruction::Duplicate { index } => state.duplicate(index)?,
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

    impl<S: ReadStream, Ds, Es> PinnedDrop for MessageStreamReader<S, Ds, Es> {
        fn drop(this: Pin<&mut Self>) {
        }
    }
}

impl<S: ReadStream, Ds, Es> MessageStreamReader<S, Ds, Es> {
    pub const fn new(stream: S, decoder: Arc<Decoder<Ds, Es>>) -> Self {
        Self { stream, decoder }
    }
}

impl<S: ReadStream, Ds, Es> StopSending for MessageStreamReader<S, Ds, Es> {
    fn stop_sending(self: Pin<&mut Self>, code: u64) {
        let mut project = self.project();
        project.stream.as_mut().stop_sending(code);
        project
            .decoder
            .emit(DecoderInstruction::StreamCancellation {
                stream_id: project.stream.stream_id(),
            });
    }
}

impl<S: ReadStream, Ds, Es> GetStreamId for MessageStreamReader<S, Ds, Es> {
    fn stream_id(&self) -> u64 {
        self.stream.stream_id()
    }
}

impl<S: ReadStream, Ds, Es> Stream for MessageStreamReader<S, Ds, Es> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.as_mut().project().stream.poll_next(cx) {
            poll @ Poll::Ready(Some(Err(StreamError::Reset { .. }))) => {
                self.decoder.emit(DecoderInstruction::StreamCancellation {
                    stream_id: self.stream.stream_id(),
                });
                poll
            }
            poll => poll,
        }
    }
}
