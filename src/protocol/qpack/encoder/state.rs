//! Sending state and dynamic reference lifetime, RFC 9204 section 2.1.
use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use qbase::varint::VARINT_MAX;

use super::super::{
    Field, Settings,
    codec::{
        field::{FieldLine, FieldSectionPrefix, WriteField},
        instruction::{DecoderInstruction, EncoderInstruction, WriteInstruction},
    },
    should_never_index, table,
    table::DynamicTable,
};
use crate::{ErrorCode, Result, protocol::frame::MAX_BUFFERED_FRAME_PAYLOAD};

/// Budget for the estimated reference metadata retained until section ACKs arrive.
const MAX_UNACKED_SECTION_METADATA_BYTES: usize = 64 * 1024;

/// Connection-scoped encoder; contains no transport handles or async operations.
pub(super) struct State {
    table: DynamicTable,
    /// Cumulative insertions acknowledged by peer feedback, never table length.
    known_received_count: u64,
    max_blocked_streams: u64,
    max_field_section_size: u64,
    /// Key: QUIC stream ID. Value: its unacknowledged sections in sending order.
    /// Only sections with RIC > 0 retain dynamic references.
    unacked_sections_by_stream: HashMap<u64, VecDeque<UnackedSection>>,
    pub(super) on_instruction: super::OnInstruction,
}

/// A Section ACK releases the oldest such record on its stream.
struct UnackedSection {
    required_insert_count: u64,
    /// Distinct absolute indices, including references that use only an entry's name.
    references: Vec<u64>,
}

impl State {
    /// Start with an empty table, capacity 0, KRC 0, and no outstanding references.
    /// Pass default peer settings until SETTINGS arrives; all integer limits are 62-bit.
    pub(super) fn new(peer: Settings, on_instruction: super::OnInstruction) -> Result<Self> {
        if peer.blocked_streams > VARINT_MAX {
            return Err(ErrorCode::H3_SETTINGS_ERROR
                .reason("QPACK blocked-stream limit exceeds the QUIC variable-integer range"));
        }
        Ok(Self {
            table: DynamicTable::new(peer.max_table_capacity)?,
            known_received_count: 0,
            max_blocked_streams: peer.blocked_streams,
            max_field_section_size: VARINT_MAX,
            unacked_sections_by_stream: HashMap::new(),
            on_instruction,
        })
    }

    pub(super) fn configure(&mut self, peer: Settings, max_fields: u64) -> Result<()> {
        self.apply_peer_settings(peer)?;
        self.max_field_section_size = max_fields;
        if peer.max_table_capacity != 0 {
            self.queue_instruction(EncoderInstruction::SetDynamicTableCapacity(
                peer.max_table_capacity,
            ))?;
        }
        Ok(())
    }

    /// Apply peer limits after the connection validates SETTINGS sequencing and 0-RTT.
    fn apply_peer_settings(&mut self, peer: Settings) -> Result<()> {
        if peer.blocked_streams > VARINT_MAX
            || peer.blocked_streams < self.potentially_blocked_streams() as u64
        {
            return Err(ErrorCode::H3_SETTINGS_ERROR
                .reason("QPACK blocked-stream limit exceeds the QUIC variable-integer range"));
        }
        self.table.set_max_capacity(peer.max_table_capacity)?;
        self.max_blocked_streams = peer.blocked_streams;
        Ok(())
    }

    /// Encode a field section and retain its dynamic references; failure leaves state unchanged.
    pub(super) fn encode(
        &mut self,
        stream_id: u64,
        fields: impl IntoIterator<Item = Field>,
    ) -> Result<Bytes> {
        if stream_id > VARINT_MAX {
            return Err(ErrorCode::H3_INTERNAL_ERROR
                .reason("encoded stream ID exceeds the QUIC variable-integer range"));
        }
        let mut bounded = Vec::new();
        let mut size = 0usize;
        for mut field in fields {
            size = size
                .checked_add(field.name.len())
                .and_then(|v| v.checked_add(field.value.len()))
                .and_then(|v| v.checked_add(32))
                .filter(|&v| v as u64 <= self.max_field_section_size)
                .ok_or_else(|| {
                    ErrorCode::H3_EXCESSIVE_LOAD.reason("field section exceeds the peer size limit")
                })?;
            field.never_index |= should_never_index(&field.name);
            bounded.push(field);
        }
        // Keep rollback local to this synchronous call; Bytes clones share string storage.
        let original_table = self.table.clone();
        let original_sections = self
            .unacked_sections_by_stream
            .get(&stream_id)
            .map_or(0, VecDeque::len);
        let mut instructions = Vec::new();
        let mut queue_full = false;
        let result = self
            .encode_fields(stream_id, bounded.clone(), &mut instructions, true)
            .and_then(|wire| {
                if !instructions.is_empty()
                    && let Err(error) = (self.on_instruction)(instructions)
                {
                    queue_full = error.code == ErrorCode::H3_EXCESSIVE_LOAD;
                    return Err(error);
                }
                Ok(wire)
            });
        match result {
            Ok(wire) => Ok(wire),
            Err(error) => {
                self.table = original_table;
                if let Some(sections) = self.unacked_sections_by_stream.get_mut(&stream_id) {
                    sections.truncate(original_sections);
                    if sections.is_empty() {
                        self.unacked_sections_by_stream.remove(&stream_id);
                    }
                }
                if queue_full {
                    self.encode_fields(stream_id, bounded, &mut Vec::new(), false)
                } else {
                    Err(error)
                }
            }
        }
    }

    fn encode_fields(
        &mut self,
        stream_id: u64,
        fields: Vec<Field>,
        instructions: &mut Vec<EncoderInstruction>,
        queue_available: bool,
    ) -> Result<Bytes> {
        let base = self.table.insert_count();
        let mut lines = Vec::new();
        let mut references = Vec::new();
        // Bound retained metadata even when a peer confirms insertions but withholds ACKs.
        let retained: usize = self
            .unacked_sections_by_stream
            .values()
            .flatten()
            .map(|section| 32 + section.references.capacity() * 8)
            .sum();
        let allow_dynamic = queue_available
            && retained + 32 + fields.len() * 8 <= MAX_UNACKED_SECTION_METADATA_BYTES;
        for field in fields {
            if !field.never_index
                && let Some(index) = table::find_index(&field.name, &field.value)
            {
                lines.push(FieldLine::Indexed {
                    static_table: true,
                    index: index as u64,
                });
                continue;
            }
            let existing = self.table.find_index(&field.name, &field.value);
            let mut full_index = existing.filter(|&id| {
                allow_dynamic && !field.never_index && self.can_reference(stream_id, id)
            });
            if allow_dynamic
                && !field.never_index
                && existing.is_none()
                && field.name.len() as u64 + field.value.len() as u64 + 32 <= self.table.capacity()
                && self.table.insert_count() < VARINT_MAX
            {
                let instruction = if let Some(index) = table::find_name(&field.name) {
                    EncoderInstruction::InsertWithNameReference {
                        static_table: true,
                        index: index as u64,
                        value: field.value.clone(),
                    }
                } else if let Some(absolute) = self.table.find_name(&field.name) {
                    EncoderInstruction::InsertWithNameReference {
                        static_table: false,
                        index: self.table.insert_count() - 1 - absolute,
                        value: field.value.clone(),
                    }
                } else {
                    EncoderInstruction::InsertWithLiteralName {
                        name: field.name.clone(),
                        value: field.value.clone(),
                    }
                };
                let absolute = self.table.insert_count();
                if self.queue_update(instruction, &references, instructions)?
                    && self.can_reference(stream_id, absolute)
                {
                    full_index = Some(absolute);
                }
            }
            let line = if let Some(absolute) = full_index {
                references.push(absolute);
                if absolute < base {
                    FieldLine::Indexed {
                        static_table: false,
                        index: base - 1 - absolute,
                    }
                } else {
                    FieldLine::IndexedPostBase {
                        index: absolute - base,
                    }
                }
            } else if let Some(index) = table::find_name(&field.name) {
                FieldLine::LiteralWithNameReference {
                    never_index: field.never_index,
                    static_table: true,
                    index: index as u64,
                    value: field.value,
                }
            } else if let Some(absolute) = self
                .table
                .find_name(&field.name)
                .filter(|&id| allow_dynamic && self.can_reference(stream_id, id))
            {
                references.push(absolute);
                if absolute < base {
                    FieldLine::LiteralWithNameReference {
                        never_index: field.never_index,
                        static_table: false,
                        index: base - 1 - absolute,
                        value: field.value,
                    }
                } else {
                    FieldLine::LiteralWithPostBaseNameReference {
                        never_index: field.never_index,
                        index: absolute - base,
                        value: field.value,
                    }
                }
            } else {
                FieldLine::Literal(field)
            };
            lines.push(line);
        }
        references.sort_unstable();
        references.dedup();
        references.shrink_to_fit();
        let required_insert_count = references.last().map_or(0, |id| id + 1);
        let prefix = FieldSectionPrefix {
            required_insert_count,
            base: if required_insert_count == 0 { 0 } else { base },
        };
        let mut wire = Vec::new();
        wire.put_field_section_prefix(&prefix, self.table.max_capacity())?;
        for line in lines {
            wire.put_field_line(&line)?;
        }
        if wire.len() > MAX_BUFFERED_FRAME_PAYLOAD {
            return Err(ErrorCode::H3_EXCESSIVE_LOAD
                .reason("encoded field section exceeds the buffer limit"));
        }
        if required_insert_count != 0 {
            self.unacked_sections_by_stream
                .entry(stream_id)
                .or_default()
                .push_back(UnackedSection {
                    required_insert_count,
                    references,
                });
        }
        Ok(wire.into())
    }

    /// Commit and queue an update; Ok(false) means eviction is blocked by retained references.
    fn queue_instruction(&mut self, instruction: EncoderInstruction) -> Result<bool> {
        let original_table = self.table.clone();
        let mut instructions = Vec::new();
        let queued = self.queue_update(instruction, &[], &mut instructions)?;
        if queued && let Err(error) = (self.on_instruction)(instructions) {
            self.table = original_table;
            return Err(error);
        }
        Ok(queued)
    }

    fn queue_update(
        &mut self,
        instruction: EncoderInstruction,
        protected: &[u64],
        instructions: &mut Vec<EncoderInstruction>,
    ) -> Result<bool> {
        if self.table.max_capacity() == 0 {
            return Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR
                .reason("cannot update a dynamic table with zero maximum capacity"));
        }
        Vec::new().put_encoder_instruction(&instruction)?; // Validate wire limits before committing any table changes.
        // ponytail: preview on cloned table metadata; use an eviction plan if profiling warrants it.
        let mut next = self.table.clone();
        next.apply(instruction.clone())?;
        for absolute in self.table.oldest_index()..next.oldest_index() {
            if protected.contains(&absolute) || !self.is_evictable(absolute) {
                return Ok(false);
            }
        }
        self.table = next;
        instructions.push(instruction);
        Ok(true)
    }

    /// Apply QPACK feedback, update KRC, and release acknowledged or cancelled references.
    pub(super) fn on_decoder_instruction(
        &mut self,
        instruction: DecoderInstruction,
        completed_insert_count: u64,
    ) -> Result<()> {
        match instruction {
            DecoderInstruction::SectionAcknowledgment(stream_id) => {
                let sections = self
                    .unacked_sections_by_stream
                    .get_mut(&stream_id)
                    .ok_or_else(|| {
                        ErrorCode::QPACK_DECODER_STREAM_ERROR
                            .reason("acknowledgement refers to an unknown stream")
                    })?;
                let section = sections.front().ok_or_else(|| {
                    ErrorCode::QPACK_DECODER_STREAM_ERROR
                        .reason("acknowledgement has no outstanding field section")
                })?;
                if section.required_insert_count > completed_insert_count {
                    return Err(ErrorCode::QPACK_DECODER_STREAM_ERROR
                        .reason("acknowledgement refers to inserts that have not been written"));
                }
                self.known_received_count =
                    self.known_received_count.max(section.required_insert_count);
                sections.pop_front();
                if sections.is_empty() {
                    self.unacked_sections_by_stream.remove(&stream_id);
                }
            }
            DecoderInstruction::StreamCancellation(stream_id) => {
                if stream_id > VARINT_MAX {
                    return Err(ErrorCode::QPACK_DECODER_STREAM_ERROR
                        .reason("cancelled stream ID exceeds the QUIC variable-integer range"));
                }
                self.unacked_sections_by_stream.remove(&stream_id);
            }
            DecoderInstruction::InsertCountIncrement(increment) => {
                self.known_received_count = self
                    .known_received_count
                    .checked_add(increment)
                    .filter(|&count| increment != 0 && count <= completed_insert_count)
                    .ok_or_else(|| ErrorCode::QPACK_DECODER_STREAM_ERROR.reason("insert-count increment is zero, overflows, or exceeds completed writes"))?;
            }
        }
        Ok(())
    }

    /// Count distinct streams with any outstanding section whose RIC exceeds KRC.
    fn potentially_blocked_streams(&self) -> usize {
        self.unacked_sections_by_stream
            .values()
            .filter(|sections| {
                sections
                    .iter()
                    .any(|section| section.required_insert_count > self.known_received_count)
            })
            .count()
    }

    /// The entry must exist; unacknowledged entries additionally require a free blocked
    /// stream slot unless this stream already occupies one (section 2.1.2).
    fn can_reference(&self, stream_id: u64, absolute: u64) -> bool {
        self.table.get(absolute).is_some()
            && (absolute < self.known_received_count
                || self
                    .unacked_sections_by_stream
                    .get(&stream_id)
                    .is_some_and(|sections| {
                        sections.iter().any(|section| {
                            section.required_insert_count > self.known_received_count
                        })
                    })
                || (self.potentially_blocked_streams() as u64) < self.max_blocked_streams)
    }

    /// Entry exists, absolute < KRC, and no outstanding section references it (2.1.1).
    /// ponytail: scan outstanding references initially; add per-entry counts if profiling warrants it.
    fn is_evictable(&self, absolute: u64) -> bool {
        absolute < self.known_received_count
            && self.table.get(absolute).is_some()
            && !self
                .unacked_sections_by_stream
                .values()
                .flatten()
                .any(|section| section.references.contains(&absolute))
    }
}
