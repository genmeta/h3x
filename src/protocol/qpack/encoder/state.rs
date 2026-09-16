//! Sending state and dynamic reference lifetime, RFC 9204 section 2.1.
use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use qbase::varint::VARINT_MAX;
#[cfg(test)]
use tokio::sync::mpsc;

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
            return Err(ErrorCode::H3_SETTINGS_ERROR.with_reason(
                "QPACK blocked-stream limit exceeds the QUIC variable-integer range",
            ));
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
            return Err(ErrorCode::H3_SETTINGS_ERROR.with_reason(
                "QPACK blocked-stream limit exceeds the QUIC variable-integer range",
            ));
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
                .with_reason("encoded stream ID exceeds the QUIC variable-integer range"));
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
                    ErrorCode::H3_EXCESSIVE_LOAD
                        .with_reason("field section exceeds the peer size limit")
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
                if !instructions.is_empty() {
                    if let Err(error) = (self.on_instruction)(instructions) {
                        queue_full = error.code == ErrorCode::H3_EXCESSIVE_LOAD;
                        return Err(error);
                    }
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
                .with_reason("encoded field section exceeds the buffer limit"));
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
                .with_reason("cannot update a dynamic table with zero maximum capacity"));
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
                            .with_reason("acknowledgement refers to an unknown stream")
                    })?;
                let section = sections.front().ok_or_else(|| {
                    ErrorCode::QPACK_DECODER_STREAM_ERROR
                        .with_reason("acknowledgement has no outstanding field section")
                })?;
                if section.required_insert_count > completed_insert_count {
                    return Err(ErrorCode::QPACK_DECODER_STREAM_ERROR.with_reason(
                        "acknowledgement refers to inserts that have not been written",
                    ));
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
                    return Err(ErrorCode::QPACK_DECODER_STREAM_ERROR.with_reason(
                        "cancelled stream ID exceeds the QUIC variable-integer range",
                    ));
                }
                self.unacked_sections_by_stream.remove(&stream_id);
            }
            DecoderInstruction::InsertCountIncrement(increment) => {
                self.known_received_count = self
                    .known_received_count
                    .checked_add(increment)
                    .filter(|&count| increment != 0 && count <= completed_insert_count)
                    .ok_or_else(|| ErrorCode::QPACK_DECODER_STREAM_ERROR.with_reason("insert-count increment is zero, overflows, or exceeds completed writes"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Encoder {
        state: State,
        sent_insert_count: u64,
    }

    impl std::ops::Deref for Encoder {
        type Target = State;
        fn deref(&self) -> &State {
            &self.state
        }
    }

    impl std::ops::DerefMut for Encoder {
        fn deref_mut(&mut self) -> &mut State {
            &mut self.state
        }
    }

    impl Encoder {
        fn new(peer: Settings, sender: mpsc::Sender<Vec<EncoderInstruction>>) -> Result<Self> {
            Ok(Self {
                state: State::new(
                    peer,
                    Box::new(move |batch| {
                        sender
                            .try_send(batch)
                            .map_err(crate::protocol::connection::instruction_send_error)
                    }),
                )?,
                sent_insert_count: 0,
            })
        }

        fn on_decoder_instruction(&mut self, instruction: DecoderInstruction) -> Result<()> {
            self.state
                .on_decoder_instruction(instruction, self.sent_insert_count)
        }
    }
    use crate::protocol::qpack::decoder::Decoder as DecoderState;

    struct Decoder {
        state: DecoderState,
        receiver: crate::protocol::qpack::decoder::Instructions,
    }

    impl std::ops::Deref for Decoder {
        type Target = DecoderState;
        fn deref(&self) -> &DecoderState {
            &self.state
        }
    }

    impl Decoder {
        fn new(local: Settings, max_blocked_bytes: usize, max_fields: u64) -> Result<Self> {
            let (state, feedback_source) =
                DecoderState::with_channel(local, max_blocked_bytes, max_fields)?;
            Ok(Self {
                state,
                receiver: feedback_source,
            })
        }

        fn next_instruction(&mut self) -> Option<DecoderInstruction> {
            match DecoderState::poll_feedback(
                &mut self.receiver,
                &mut std::task::Context::from_waker(std::task::Waker::noop()),
            ) {
                std::task::Poll::Ready(result) => {
                    let mut batch = result.unwrap();
                    assert_eq!(batch.len(), 1);
                    batch.pop()
                }
                std::task::Poll::Pending => None,
            }
        }
    }

    fn field(name: &'static [u8], value: &'static [u8]) -> Field {
        Field {
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
            never_index: false,
        }
    }

    fn pair(
        capacity: u64,
        blocked_streams: u64,
    ) -> (Encoder, Decoder, mpsc::Receiver<Vec<EncoderInstruction>>) {
        let limits = Settings {
            max_table_capacity: capacity,
            blocked_streams,
        };
        let (sender, receiver) = mpsc::channel(crate::protocol::qpack::MAX_PENDING_INSTRUCTION);
        let mut encoder = Encoder::new(limits, sender).unwrap();
        encoder
            .queue_instruction(EncoderInstruction::SetDynamicTableCapacity(capacity))
            .unwrap();
        (
            encoder,
            Decoder::new(limits, 1024, VARINT_MAX).unwrap(),
            receiver,
        )
    }

    fn updates(
        encoder: &mut Encoder,
        decoder: &mut Decoder,
        receiver: &mut mpsc::Receiver<Vec<EncoderInstruction>>,
    ) {
        while let Ok(batch) = receiver.try_recv() {
            for instruction in batch {
                if !matches!(instruction, EncoderInstruction::SetDynamicTableCapacity(_)) {
                    encoder.sent_insert_count += 1;
                }
                decoder.on_encoder_instruction(instruction).unwrap();
            }
        }
    }

    #[derive(Debug, PartialEq)]
    enum DecodeResult {
        Decoded(Vec<Field>),
        Blocked { required_insert_count: u64 },
    }

    fn decode(decoder: &mut Decoder, id: u64, bytes: Bytes) -> Result<DecodeResult> {
        let (rest, prefix) = decoder.read_prefix(&bytes)?;
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match decoder.poll_decode(id, prefix, rest, &mut cx) {
            std::task::Poll::Ready(result) => result.map(DecodeResult::Decoded),
            std::task::Poll::Pending => Ok(DecodeResult::Blocked {
                required_insert_count: prefix.required_insert_count,
            }),
        }
    }

    fn feedback(encoder: &mut Encoder, decoder: &mut Decoder) {
        while let Some(instruction) = decoder.next_instruction() {
            encoder.on_decoder_instruction(instruction).unwrap();
        }
    }

    #[test]
    fn configured_limits_can_exceed_the_buffer_budget() {
        let (sender, _receiver) = mpsc::channel(crate::protocol::qpack::MAX_PENDING_INSTRUCTION);
        let mut encoder = State::new(
            Settings::default(),
            Box::new(move |batch| {
                sender
                    .try_send(batch)
                    .map_err(crate::protocol::connection::instruction_send_error)
            }),
        )
        .unwrap();
        let configured = 128 * 1024;
        encoder
            .configure(
                Settings {
                    max_table_capacity: configured,
                    blocked_streams: 0,
                },
                configured,
            )
            .unwrap();
        assert_eq!(encoder.max_field_section_size, configured);
        // Static references compress a field section larger than the buffer budget.
        let fields = vec![field(b":method", b"GET"); 2000];
        assert!(encoder.encode(0, fields.clone()).is_ok());
        encoder.max_field_section_size = 64 * 1024;
        assert_eq!(
            (encoder.encode(4, fields)).map_err(ErrorCode::from),
            Err(ErrorCode::H3_EXCESSIVE_LOAD)
        );
        assert_eq!(encoder.table.max_capacity(), configured);
    }

    #[test]
    fn settings_enable_dynamic_capacity_without_resetting_existing_state() {
        let (sender, _receiver) = mpsc::channel(crate::protocol::qpack::MAX_PENDING_INSTRUCTION);
        let mut encoder = Encoder::new(Settings::default(), sender).unwrap();
        assert_eq!(
            (encoder.queue_instruction(EncoderInstruction::SetDynamicTableCapacity(0)))
                .map_err(ErrorCode::from),
            Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
        );
        encoder
            .apply_peer_settings(Settings {
                max_table_capacity: 68,
                blocked_streams: 1,
            })
            .unwrap();
        assert_eq!(encoder.table.capacity(), 0);
        encoder
            .queue_instruction(EncoderInstruction::SetDynamicTableCapacity(68))
            .unwrap();
        encoder.encode(0, [field(b"x", b"a")]).unwrap();
        for peer in [
            Settings {
                max_table_capacity: 34,
                blocked_streams: 1,
            },
            Settings {
                max_table_capacity: 68,
                blocked_streams: 0,
            },
            Settings {
                max_table_capacity: VARINT_MAX + 1,
                blocked_streams: 1,
            },
            Settings {
                max_table_capacity: 68,
                blocked_streams: VARINT_MAX + 1,
            },
        ] {
            assert_eq!(
                (encoder.apply_peer_settings(peer)).map_err(ErrorCode::from),
                Err(ErrorCode::H3_SETTINGS_ERROR)
            );
            assert_eq!(encoder.table.max_capacity(), 68);
            assert_eq!(encoder.table.insert_count(), 1);
            assert_eq!(encoder.max_blocked_streams, 1);
        }
    }

    #[test]
    fn blocked_budget_is_per_stream_and_qpack_ack_releases_one_section() {
        let (mut encoder, mut decoder, mut receiver) = pair(68, 1);
        let a = field(b"x", b"a");
        let b = field(b"y", b"b");
        let first = encoder.encode(0, [a.clone()]).unwrap();
        let second = encoder.encode(0, [a.clone()]).unwrap();
        assert_eq!(encoder.potentially_blocked_streams(), 1);
        let independent = encoder.encode(4, [b.clone()]).unwrap();
        assert_eq!(
            decode(&mut decoder, 4, independent).unwrap(),
            DecodeResult::Decoded(vec![b])
        );
        assert!(matches!(
            decode(&mut decoder, 0, first.clone()).unwrap(),
            DecodeResult::Blocked {
                required_insert_count: 1
            }
        ));
        // Neither queueing nor handing instructions to the writer is a peer acknowledgement.
        assert_eq!(
            (encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0)))
                .map_err(ErrorCode::from),
            Err(ErrorCode::QPACK_DECODER_STREAM_ERROR)
        );
        assert_eq!(encoder.known_received_count, 0);
        updates(&mut encoder, &mut decoder, &mut receiver);
        assert_eq!(
            decode(&mut decoder, 0, first).unwrap(),
            DecodeResult::Decoded(vec![a.clone()])
        );
        assert_eq!(encoder.known_received_count, 0);
        // Increments precede the ACK; applying that ACK must not count them twice.
        feedback(&mut encoder, &mut decoder);
        assert_eq!(encoder.known_received_count, 2);
        assert_eq!(encoder.unacked_sections_by_stream[&0].len(), 1);
        assert!(!encoder.is_evictable(0));
        assert_eq!(
            decode(&mut decoder, 0, second).unwrap(),
            DecodeResult::Decoded(vec![a])
        );
        feedback(&mut encoder, &mut decoder);
        assert!(encoder.unacked_sections_by_stream.is_empty());
        assert_eq!(encoder.known_received_count, 2);
        assert!(encoder.is_evictable(0));
        for instruction in [
            DecoderInstruction::SectionAcknowledgment(0),
            DecoderInstruction::InsertCountIncrement(0),
            DecoderInstruction::InsertCountIncrement(1),
        ] {
            assert_eq!(
                (encoder.on_decoder_instruction(instruction)).map_err(ErrorCode::from),
                Err(ErrorCode::QPACK_DECODER_STREAM_ERROR)
            );
            assert_eq!(encoder.known_received_count, 2);
        }
    }

    #[test]
    fn zero_blocking_limit_seeds_table_then_reuses_acknowledged_entries() {
        let (mut encoder, mut decoder, mut receiver) = pair(68, 0);
        let fields = vec![field(b"x", b"a")];
        let first = encoder.encode(0, fields.clone()).unwrap();
        assert_eq!(
            decode(&mut decoder, 0, first).unwrap(),
            DecodeResult::Decoded(fields.clone())
        );
        assert!(encoder.unacked_sections_by_stream.is_empty());
        updates(&mut encoder, &mut decoder, &mut receiver);
        feedback(&mut encoder, &mut decoder);
        let second = encoder.encode(4, fields.clone()).unwrap();
        assert_eq!(
            encoder.unacked_sections_by_stream[&4][0].required_insert_count,
            1
        );
        assert_eq!(encoder.potentially_blocked_streams(), 0);
        assert_eq!(
            decode(&mut decoder, 4, second).unwrap(),
            DecodeResult::Decoded(fields)
        );
    }

    #[test]
    fn current_section_references_prevent_eviction_and_cancel_does_not_ack_insertions() {
        let (mut encoder, mut decoder, mut receiver) = pair(68, 1);
        encoder
            .queue_instruction(EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from_static(b"a"),
            })
            .unwrap();
        updates(&mut encoder, &mut decoder, &mut receiver);
        feedback(&mut encoder, &mut decoder);
        let fields = vec![field(b"x", b"a"), field(b"y", b"b"), field(b"z", b"c")];
        let wire = encoder.encode(0, fields.clone()).unwrap();
        assert!(encoder.table.get(0).is_some()); // The new z entry must not evict x.
        assert_eq!(encoder.table.insert_count(), 2);
        assert!(
            !encoder
                .queue_instruction(EncoderInstruction::SetDynamicTableCapacity(0))
                .unwrap()
        );
        assert!(matches!(
            decode(&mut decoder, 0, wire).unwrap(),
            DecodeResult::Blocked { .. }
        ));
        decoder.cancel(0).unwrap();
        encoder
            .on_decoder_instruction(decoder.next_instruction().unwrap())
            .unwrap();
        assert_eq!(encoder.known_received_count, 1);
        assert!(encoder.unacked_sections_by_stream.is_empty());
        // y is unreferenced but still cannot be evicted before its insertion is confirmed.
        assert!(
            !encoder
                .queue_instruction(EncoderInstruction::SetDynamicTableCapacity(0))
                .unwrap()
        );
        updates(&mut encoder, &mut decoder, &mut receiver);
        feedback(&mut encoder, &mut decoder);
        assert!(
            encoder
                .queue_instruction(EncoderInstruction::SetDynamicTableCapacity(0))
                .unwrap()
        );
        updates(&mut encoder, &mut decoder, &mut receiver);
        assert_eq!(encoder.table.size(), 0);
        assert_eq!(encoder.table.insert_count(), 2);
    }

    #[test]
    fn duplicate_and_invalid_updates_are_atomic_and_sensitive_fields_stay_literal() {
        let (mut encoder, mut decoder, mut receiver) = pair(34, 1);
        let wire = encoder.encode(0, [field(b"x", b"a")]).unwrap();
        updates(&mut encoder, &mut decoder, &mut receiver);
        assert_eq!(
            decode(&mut decoder, 0, wire).unwrap(),
            DecodeResult::Decoded(vec![field(b"x", b"a")])
        );
        assert!(
            !encoder
                .queue_instruction(EncoderInstruction::Duplicate(0))
                .unwrap()
        );
        feedback(&mut encoder, &mut decoder);
        assert!(
            encoder
                .queue_instruction(EncoderInstruction::Duplicate(0))
                .unwrap()
        );
        assert!(encoder.table.get(0).is_none());
        assert_eq!(encoder.table.get(1).unwrap().value, "a");
        let queued = receiver.len();
        for instruction in [
            EncoderInstruction::Duplicate(1),
            EncoderInstruction::SetDynamicTableCapacity(35),
        ] {
            assert_eq!(
                (encoder.queue_instruction(instruction)).map_err(ErrorCode::from),
                Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
            );
            assert_eq!(receiver.len(), queued);
            assert_eq!(encoder.table.insert_count(), 2);
        }
        let private = Field {
            never_index: true,
            ..field(b"secret", b"a")
        };
        let wire = encoder.encode(4, [private.clone()]).unwrap();
        assert_eq!(
            decode(&mut decoder, 4, wire).unwrap(),
            DecodeResult::Decoded(vec![private])
        );
        assert_eq!(receiver.len(), queued);
        assert!(
            encoder
                .encode(
                    8,
                    [Field {
                        value: Bytes::from(vec![0; MAX_BUFFERED_FRAME_PAYLOAD]),
                        ..field(b"x", b"a")
                    }]
                )
                .is_err()
        );
        assert_eq!(receiver.len(), queued);
        assert_eq!(encoder.table.insert_count(), 2);
    }

    #[test]
    fn retained_section_metadata_is_bounded_when_peer_withholds_section_acks() {
        let (mut encoder, mut decoder, mut receiver) = pair(34, 0);
        encoder.encode(0, [field(b"x", b"a")]).unwrap();
        updates(&mut encoder, &mut decoder, &mut receiver);
        feedback(&mut encoder, &mut decoder);
        encoder
            .encode(0, std::iter::repeat_n(field(b"x", b"a"), 1000))
            .unwrap();
        let references = &encoder.unacked_sections_by_stream[&0][0].references;
        assert_eq!(references, &[0]);
        assert_eq!(references.capacity(), 1);
        let mut last = Bytes::new();
        for _ in 0..1700 {
            last = encoder.encode(4, [field(b"x", b"a")]).unwrap();
        }
        let (_, prefix) =
            crate::protocol::qpack::codec::field::be_field_section_prefix(&last, 34, 1).unwrap();
        assert_eq!(prefix.required_insert_count, 0); // Falls back to literal at the local limit.
        assert!(
            encoder.unacked_sections_by_stream[&4].len() * 40 <= MAX_UNACKED_SECTION_METADATA_BYTES
        );
    }
    #[test]
    fn rejected_instruction_callback_rolls_back_table_and_references() {
        let (mut encoder, _decoder, mut receiver) = pair(68, 1);
        while receiver.try_recv().is_ok() {}
        drop(receiver);
        let inserts = encoder.table.insert_count();
        assert_eq!(
            (encoder.encode(0, [field(b"x", b"a")])).map_err(ErrorCode::from),
            Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
        );
        assert_eq!(encoder.table.insert_count(), inserts);
        assert!(encoder.unacked_sections_by_stream.is_empty());
    }

    #[test]
    fn full_encoder_channel_falls_back_without_committing_table_changes() {
        let limits = Settings {
            max_table_capacity: 68,
            blocked_streams: 1,
        };
        let (sender, mut receiver) = mpsc::channel(1);
        let mut encoder = Encoder::new(limits, sender).unwrap();
        let mut decoder = Decoder::new(limits, 1024, VARINT_MAX).unwrap();
        encoder
            .queue_instruction(EncoderInstruction::SetDynamicTableCapacity(68))
            .unwrap();
        let fields = vec![field(b"x", b"a")];
        let literal = encoder.encode(0, fields.clone()).unwrap();
        assert_eq!(literal[0], 0);
        assert_eq!(encoder.table.insert_count(), 0);
        updates(&mut encoder, &mut decoder, &mut receiver);
        let dynamic = encoder.encode(4, fields.clone()).unwrap();
        assert_ne!(dynamic[0], 0);
        assert_eq!(encoder.table.insert_count(), 1);
        let other = encoder.encode(8, [field(b"y", b"b")]).unwrap();
        assert_eq!(other[0], 0);
        assert_eq!(encoder.table.insert_count(), 1);
        assert_eq!(receiver.len(), 1);
        updates(&mut encoder, &mut decoder, &mut receiver);
        assert_eq!(
            decode(&mut decoder, 4, dynamic).unwrap(),
            DecodeResult::Decoded(fields)
        );
        drop(receiver);
        assert_eq!(
            (encoder.encode(12, [field(b"z", b"c")])).map_err(ErrorCode::from),
            Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
        );
        assert_eq!(encoder.table.insert_count(), 1);
    }
}
