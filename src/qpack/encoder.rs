use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::DerefMut,
    pin::Pin,
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt, stream};
use snafu::Snafu;
use tokio::sync::Mutex as AsyncMutex;

use crate::{
    buflist::BufList,
    codec::{Encode, Feed},
    connection::{StreamError, settings::Settings},
    error::{Code, H3CriticalStreamClosed, HasErrorCode},
    frame::Frame,
    qpack::{
        algorithm::Algorithm,
        dynamic::DynamicTable,
        field_section::FieldLine,
        header_block::FieldLineRepresentation,
        instruction::{DecoderInstruction, EncoderInstruction},
        r#static,
    },
    quic::{GetStreamId, GetStreamIdExt},
};

#[derive(Debug)]
pub struct EncoderState {
    pub(crate) settings: Settings,
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
    pub const fn new(settings: Settings) -> Self {
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
    #[snafu(display("Acknowledging non-existent or non-blocking stream"))]
    AcknowledgeNonExistSection { stream_id: u64 },
    #[snafu(display(
        "Known received count increment overflow(known_received_count + increment > inserted_count )"
    ))]
    IncrementKnownReceivedCountOverflow,
}

impl HasErrorCode for QPackDecoderStreamError {
    fn code(&self) -> Code {
        Code::QPACK_DECODER_STREAM_ERROR
    }
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

    pub fn set_max_table_capacity(&mut self, new_capacity: u64) {
        assert!(
            new_capacity < self.settings.qpack_max_table_capacity().into_inner(),
            "The encoder MUST NOT set a dynamic table capacity that exceeds SETTINGS_QPACK_MAX_TABLE_CAPACITY"
        );
        self.dynamic_table.capacity = new_capacity;
        while self.table_size() > new_capacity {
            self.evict_entry();
        }
        self.emit(EncoderInstruction::SetDynamicTableCapacity {
            capacity: new_capacity,
        });
    }

    pub fn insert_with_name_reference(
        &mut self,
        is_static: bool,
        name_index: u64,
        huffman: bool,
        value: Bytes,
    ) -> u64 {
        let name = match is_static {
            true => Bytes::from_static(
                r#static::get_name(name_index)
                    .unwrap_or_else(|| {
                        panic!("Referenced name index {name_index} not existed in the static table")
                    })
                    .as_bytes(),
            ),
            false => self
                .get_entry(name_index)
                .unwrap_or_else(|| {
                    panic!("Referenced name index {name_index} not existed in the dynamic table")
                })
                .name
                .clone(),
        };

        let entry = FieldLine { name, value };
        while self.table_remaining() < entry.size() {
            self.evict_entry();
        }
        let new_entry_index = self.index(entry.clone());
        self.emit(EncoderInstruction::InsertWithNameReference {
            is_static,
            name_index,
            huffman,
            value: entry.value,
        });
        new_entry_index
    }

    pub fn insert_with_literal_name(
        &mut self,
        name_huffman: bool,
        name: Bytes,
        value_huffman: bool,
        value: Bytes,
    ) -> u64 {
        let entry = FieldLine { name, value };
        while self.table_remaining() < entry.size() {
            self.evict_entry();
        }
        let new_entry_index = self.index(entry.clone());
        self.emit(EncoderInstruction::InsertWithLiteralName {
            name_huffman,
            name: entry.name,
            value_huffman,
            value: entry.value,
        });
        new_entry_index
    }

    pub fn duplicate(&mut self, index: u64) -> u64 {
        let duplicated_entry = self
            .get_entry(index)
            .unwrap_or_else(|| panic!("Referenced entry {index} not existed in the dynamic table"))
            .clone();
        while self.table_remaining() < duplicated_entry.size() {
            self.evict_entry();
        }
        let new_entry_index = self.index(duplicated_entry);
        self.pending_instructions
            .push_back(EncoderInstruction::Duplicate { index });
        new_entry_index
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
        let max_referenced_index = blocking_stream.get_mut().pop_front().unwrap();
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

pub(crate) fn get_dynamic_references<'r>(
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

impl<Es, Ds> Encoder<Es, Ds>
where
    Es: Sink<EncoderInstruction, Error = StreamError> + Unpin,
    Ds: Stream<Item = Result<DecoderInstruction, StreamError>> + Unpin,
{
    pub fn new(settings: Settings, encoder_stream: Es, decoder_stream: Ds) -> Self {
        Self {
            state: AsyncMutex::new(EncoderState::new(settings)),
            encoder_stream: AsyncMutex::new(Feed::new(encoder_stream)),
            decoder_stream: AsyncMutex::new(decoder_stream),
        }
    }

    pub async fn apply_settings(&self, settings: Settings) {
        self.state.lock().await.settings = settings;
    }

    pub async fn encode(
        &self,
        field_section: impl IntoIterator<Item = FieldLine> + Send,
        algorithm: &(impl Algorithm + ?Sized),
        stream: impl GetStreamId,
    ) -> Result<Frame<BufList>, StreamError> {
        tokio::pin!(stream);
        let stream_id = stream.stream_id().await?.into_inner();

        let (field_section_prefix, field_line_representations);
        {
            let mut state = self.state.lock().await;

            (field_section_prefix, field_line_representations) =
                algorithm.compress(&mut state, field_section).await;

            let max_referenced_index = get_dynamic_references(&field_line_representations)
                .max()
                .unwrap_or(0);

            state
                .blocking_streams
                .entry(stream_id)
                .or_default()
                .push_back(max_referenced_index);
        };

        let Ok(header_frame) = BufList::new()
            .encode((field_section_prefix, field_line_representations))
            .await;

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
