//! Incoming headers, table updates from the peer encoder, and decoder-stream feedback.
use std::task::{Context, Poll, Waker};

use state::State;

use super::{
    Field, Settings,
    codec::{
        field::FieldSectionPrefix,
        instruction::{DecoderInstruction, EncoderInstruction},
    },
};
use crate::{ErrorCode, Result};

pub(crate) type Batch = Vec<DecoderInstruction>;
// Bound actual instruction storage, rather than a small number of producer batches.
// Half remains available for synchronous reset/Drop/GOAWAY cancellation.
pub(super) const MAX_PENDING_FEEDBACK: usize = 64 * 1024 / size_of::<DecoderInstruction>();
const MAX_PENDING_ACKS: usize = MAX_PENDING_FEEDBACK / 2;

pub(crate) struct Decoder {
    state: State,
}

impl Decoder {
    pub(super) fn new(local: Settings, max_blocked_bytes: usize, max_fields: u64) -> Result<Self> {
        Ok(Self {
            state: State::new(local, max_blocked_bytes, max_fields)?,
        })
    }

    pub(crate) fn take_feedback(&mut self) -> (Batch, Vec<Waker>) {
        self.state.take_feedback()
    }

    pub(super) fn take_waiters(&mut self) -> Vec<Waker> {
        self.state.take_waiters()
    }

    pub(super) fn begin_decode(
        &mut self,
        id: u64,
        payload: &[u8],
    ) -> Result<(usize, FieldSectionPrefix)> {
        if id > qbase::varint::VARINT_MAX {
            return Err(ErrorCode::InternalError.stream("invalid stream ID"));
        }
        if self.state.decoding_stream.contains(&id) {
            return Err(ErrorCode::RequestCancelled.stream("request cancelled"));
        }
        let (rest, prefix) = self.state.read_prefix(payload)?;
        let offset = payload.len() - rest.len();
        self.state.decoding_stream.insert(id);
        Ok((offset, prefix))
    }

    pub(super) fn poll_registered_decode(
        &mut self,
        id: u64,
        prefix: FieldSectionPrefix,
        payload: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<Vec<Field>>> {
        if !self.state.decoding_stream.contains(&id) {
            return Poll::Ready(Err(ErrorCode::RequestCancelled.stream("request cancelled")));
        }
        let result = self.state.poll_decode(id, prefix, payload, cx);
        if result.is_ready() {
            self.state.decoding_stream.remove(&id);
        }
        result
    }

    pub(super) fn cancel(&mut self, ids: Vec<u64>) -> Result<Vec<Waker>> {
        self.state.cancel_stream(ids)
    }

    pub(super) fn cancel_registered(&mut self, id: u64) -> Result<Vec<Waker>> {
        if !self.state.decoding_stream.remove(&id) {
            return Ok(Vec::new());
        }
        self.state.cancel_stream(vec![id])
    }

    pub(super) fn on_encoder_instruction(
        &mut self,
        instruction: EncoderInstruction,
    ) -> Result<Vec<Waker>> {
        self.state.on_encoder_instruction(instruction)
    }
}

mod state {
    //! Decoder state and bounded wait registrations; field bytes stay in the decoding future.
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        task::{Context, Poll, Waker},
    };

    use qbase::varint::VARINT_MAX;

    use super::super::{
        Field, Settings,
        codec::{
            field::{FieldSectionPrefix, be_field_line, be_field_section_prefix},
            instruction::{DecoderInstruction, EncoderInstruction},
        },
        table::DynamicTable,
    };
    use crate::{Error, ErrorCode, Result, frame::MAX_BUFFERED_FRAME_PAYLOAD};

    pub(super) struct State {
        table: DynamicTable,
        max_blocked_streams: u64,
        max_field_section_size: u64,
        waiting: HashMap<u64, (u64, usize, Waker)>,
        blocked_bytes: usize,
        max_blocked_bytes: usize,
        feedback: VecDeque<DecoderInstruction>,
        // Highest insertion count committed to the ordered feedback stream.
        // Pending progress is derived from table.insert_count() minus this value.
        reported_insert_count: u64,
        pub(super) decoding_stream: HashSet<u64>,
    }

    impl State {
        pub(super) fn new(
            local: Settings,
            max_blocked_bytes: usize,
            max_fields: u64,
        ) -> Result<Self> {
            if local.blocked_streams > VARINT_MAX {
                return Err(ErrorCode::SettingsError.connection(
                    "QPACK blocked-stream limit exceeds the QUIC variable-integer range",
                ));
            }
            Ok(Self {
                table: DynamicTable::new(local.max_table_capacity)?,
                max_blocked_streams: local.blocked_streams,
                max_field_section_size: max_fields,
                waiting: HashMap::new(),
                blocked_bytes: 0,
                max_blocked_bytes,
                feedback: VecDeque::new(),
                reported_insert_count: 0,
                decoding_stream: HashSet::new(),
            })
        }

        pub(super) fn read_prefix<'a>(
            &self,
            payload: &'a [u8],
        ) -> Result<(&'a [u8], FieldSectionPrefix)> {
            if payload.len() > MAX_BUFFERED_FRAME_PAYLOAD {
                return Err(ErrorCode::ExcessiveLoad
                    .stream("encoded field section exceeds the buffer limit"));
            }
            let (bytes, prefix) = be_field_section_prefix(
                payload,
                self.table.max_capacity(),
                self.table.insert_count(),
            )
            .map_err(Error::connection)?;
            if prefix.required_insert_count != 0 && bytes.is_empty() {
                return Err(ErrorCode::QpackDecompressionFailed
                    .connection("nonzero Required Insert Count in an empty field section"));
            }
            Ok((bytes, prefix))
        }

        pub(super) fn poll_decode(
            &mut self,
            id: u64,
            prefix: FieldSectionPrefix,
            bytes: &[u8],
            cx: &mut Context<'_>,
        ) -> Poll<Result<Vec<Field>>> {
            if prefix.required_insert_count <= self.table.insert_count() {
                let fields = self.decode_fields(prefix, bytes)?;
                if self.acknowledge(id, prefix.required_insert_count)? {
                    self.finish(id);
                    return Poll::Ready(Ok(fields));
                }
                // The field section is valid, but its mandatory ACK needs space.
                // Retain the caller's encoded bytes and waker; never await under the lock.
            }

            // A pending future may be polled again; only refresh its waker.
            if let Some((_, _, waker)) = self.waiting.get_mut(&id) {
                waker.clone_from(cx.waker());
                return Poll::Pending;
            }

            // Admit a newly blocked section within the advertised and local budgets.
            let insert_count = self.table.insert_count();
            let blocked = self
                .waiting
                .values()
                .filter(|(required, _, _)| *required > insert_count)
                .count();
            if prefix.required_insert_count > insert_count
                && blocked as u64 >= self.max_blocked_streams
            {
                return Poll::Ready(Err(ErrorCode::QpackDecompressionFailed
                    .connection("peer exceeded the advertised QPACK blocked-stream limit")));
            }
            if bytes.len() > self.max_blocked_bytes - self.blocked_bytes {
                return Poll::Ready(Err(ErrorCode::ExcessiveLoad
                    .stream("blocked field sections exceed the memory limit")));
            }
            self.waiting.insert(
                id,
                (
                    prefix.required_insert_count,
                    bytes.len(),
                    cx.waker().clone(),
                ),
            );
            self.blocked_bytes += bytes.len();
            Poll::Pending
        }

        pub(super) fn on_encoder_instruction(
            &mut self,
            instruction: EncoderInstruction,
        ) -> Result<Vec<Waker>> {
            if self.table.max_capacity() == 0 {
                return Err(ErrorCode::QpackEncoderStreamError.connection(
                    "dynamic-table instruction received with zero maximum table capacity",
                ));
            }
            self.table.apply(instruction)?;
            // Progress occupies one derived count, regardless of burst length.
            // It is flushed by the writer or immediately before any ACK/cancellation.
            let wakes = self
                .waiting
                .values()
                .filter(|(ric, _, _)| *ric <= self.table.insert_count())
                .map(|(_, _, waker)| waker.clone())
                .collect();
            Ok(wakes)
        }

        fn finish(&mut self, id: u64) {
            if let Some((_, bytes, _)) = self.waiting.remove(&id) {
                self.blocked_bytes -= bytes;
            }
        }

        pub(super) fn cancel_stream(&mut self, ids: Vec<u64>) -> Result<Vec<Waker>> {
            if ids.iter().any(|id| *id > VARINT_MAX) {
                return Err(ErrorCode::InternalError
                    .connection("cancelled stream ID exceeds the QUIC variable-integer range"));
            }
            if self.table.max_capacity() != 0 && !ids.is_empty() {
                self.send_feedback(
                    ids.iter()
                        .copied()
                        .map(DecoderInstruction::StreamCancellation)
                        .collect(),
                )?;
            }
            let mut wakes = Vec::new();
            for id in ids {
                self.decoding_stream.remove(&id);
                if let Some((_, bytes, waker)) = self.waiting.remove(&id) {
                    self.blocked_bytes -= bytes;
                    wakes.push(waker);
                }
            }
            Ok(wakes)
        }

        pub(super) fn take_waiters(&mut self) -> Vec<Waker> {
            self.waiting
                .drain()
                .map(|(_, (_, _, waker))| waker)
                .collect()
        }

        fn acknowledge(&mut self, stream_id: u64, required_insert_count: u64) -> Result<bool> {
            if required_insert_count == 0 {
                return Ok(true);
            }
            let progress = usize::from(self.table.insert_count() != self.reported_insert_count);
            if self.feedback.len() + progress + 1 > super::MAX_PENDING_ACKS {
                return Ok(false);
            }
            self.send_feedback(vec![DecoderInstruction::SectionAcknowledgment(stream_id)])?;
            Ok(true)
        }

        fn send_feedback(&mut self, instructions: super::Batch) -> Result<()> {
            let count = self.table.insert_count();
            let progress = usize::from(count != self.reported_insert_count);
            // Keep one slot for progress drained by take_feedback. ACK production
            // stops earlier, leaving bounded space for synchronous cancellation.
            if instructions.len()
                > (super::MAX_PENDING_FEEDBACK - 1).saturating_sub(self.feedback.len() + progress)
            {
                return Err(ErrorCode::ExcessiveLoad
                    .connection("unsent QPACK cancellation feedback exceeds the memory limit"));
            }
            if progress != 0 {
                self.feedback
                    .push_back(DecoderInstruction::InsertCountIncrement(
                        count - self.reported_insert_count,
                    ));
                self.reported_insert_count = count;
            }
            self.feedback.extend(instructions);
            Ok(())
        }

        pub(super) fn take_feedback(&mut self) -> (super::Batch, Vec<Waker>) {
            let mut instructions: super::Batch = self.feedback.drain(..).collect();
            let count = self.table.insert_count();
            if count != self.reported_insert_count {
                instructions.push(DecoderInstruction::InsertCountIncrement(
                    count - self.reported_insert_count,
                ));
                self.reported_insert_count = count;
            }
            let wakes = if instructions.is_empty() {
                Vec::new()
            } else {
                self.waiting
                    .values()
                    .map(|(_, _, waker)| waker.clone())
                    .collect()
            };
            (instructions, wakes)
        }

        /// Shared by immediate and resumed decoding: reject evicted/out-of-range references,
        /// check the highest referenced absolute index against RIC, and retain N flags.
        fn decode_fields(
            &self,
            prefix: FieldSectionPrefix,
            mut input: &[u8],
        ) -> Result<Vec<Field>> {
            let mut fields = Vec::new();
            let mut required_insert_count = 0;
            let mut decoded_size = 0usize;
            while !input.is_empty() {
                let (rest, line) = be_field_line(input).map_err(Error::connection)?;
                if let Some(absolute) = line.dynamic_index(prefix).map_err(Error::connection)? {
                    required_insert_count = required_insert_count.max(absolute + 1);
                }
                let field = line
                    .resolve(prefix, &self.table)
                    .map_err(Error::connection)?;
                // Use HTTP/3 field-section accounting (name + value + 32 per field) to bound
                // both decompressed strings and field count, including repeated table indices.
                decoded_size = decoded_size
                    .checked_add(field.name.len())
                    .and_then(|size| size.checked_add(field.value.len()))
                    .and_then(|size| size.checked_add(32))
                    .filter(|&size| size as u64 <= self.max_field_section_size)
                    .ok_or_else(|| {
                        ErrorCode::ExcessiveLoad
                            .stream("decoded field section exceeds the advertised size limit")
                    })?;
                fields.push(field);
                input = rest;
            }
            if required_insert_count != prefix.required_insert_count {
                return Err(ErrorCode::QpackDecompressionFailed.connection(
                    "Required Insert Count does not match the largest dynamic reference",
                ));
            }
            Ok(fields)
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/qpack/decoder.rs"]
mod tests;
