//! Decoder state and bounded wait registrations; field bytes stay in the decoding future.
use std::{
    collections::{HashMap, HashSet},
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
use crate::{ErrorCode, Result, protocol::frame::MAX_BUFFERED_FRAME_PAYLOAD};

pub(super) struct State {
    table: DynamicTable,
    max_blocked_streams: u64,
    max_field_section_size: u64,
    waiting: HashMap<u64, (u64, usize, Waker)>,
    blocked_bytes: usize,
    max_blocked_bytes: usize,
    pub(super) on_instruction: super::OnInstruction,
    pub(super) decoding_stream: HashSet<u64>,
}

impl State {
    pub(super) fn new(
        local: Settings,
        max_blocked_bytes: usize,
        max_fields: u64,
        on_instruction: super::OnInstruction,
    ) -> Result<Self> {
        if local.blocked_streams > VARINT_MAX {
            return Err(ErrorCode::H3_SETTINGS_ERROR
                .reason("QPACK blocked-stream limit exceeds the QUIC variable-integer range"));
        }
        Ok(Self {
            table: DynamicTable::new(local.max_table_capacity)?,
            max_blocked_streams: local.blocked_streams,
            max_field_section_size: max_fields,
            waiting: HashMap::new(),
            blocked_bytes: 0,
            max_blocked_bytes,
            on_instruction,
            decoding_stream: HashSet::new(),
        })
    }

    pub(super) fn read_prefix<'a>(
        &self,
        payload: &'a [u8],
    ) -> Result<(&'a [u8], FieldSectionPrefix)> {
        if payload.len() > MAX_BUFFERED_FRAME_PAYLOAD {
            return Err(ErrorCode::H3_EXCESSIVE_LOAD
                .reason("encoded field section exceeds the buffer limit"));
        }
        let (bytes, prefix) = be_field_section_prefix(
            payload,
            self.table.max_capacity(),
            self.table.insert_count(),
        )?;
        if prefix.required_insert_count != 0 && bytes.is_empty() {
            return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
                .reason("nonzero Required Insert Count in an empty field section"));
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
            self.finish(id);
            let fields = self.decode_fields(prefix, bytes)?;
            self.acknowledge(id, prefix.required_insert_count)?;
            return Poll::Ready(Ok(fields));
        }

        // A pending future may be polled again; only refresh its waker.
        if let Some((_, _, waker)) = self.waiting.get_mut(&id) {
            waker.clone_from(cx.waker());
            return Poll::Pending;
        }

        // Admit a newly blocked section within the advertised and local budgets.
        if self.waiting.len() as u64 >= self.max_blocked_streams {
            return Poll::Ready(Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
                .reason("peer exceeded the advertised QPACK blocked-stream limit")));
        }
        if bytes.len() > self.max_blocked_bytes - self.blocked_bytes {
            return Poll::Ready(Err(ErrorCode::H3_EXCESSIVE_LOAD
                .reason("blocked field sections exceed the memory limit")));
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
            return Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR
                .reason("dynamic-table instruction received with zero maximum table capacity"));
        }
        let previous_count = self.table.insert_count();
        self.table.apply(instruction)?;
        let increment = self.table.insert_count() - previous_count;
        if increment != 0 {
            // Queue progress before any ACK that can reference these insertions.
            // All producers hold the decoder state lock, preserving this wire order.
            self.send_feedback(DecoderInstruction::InsertCountIncrement(increment))?;
        }
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

    pub(super) fn cancel_stream(&mut self, id: u64) -> Result<Vec<Waker>> {
        if id > VARINT_MAX {
            return Err(ErrorCode::H3_INTERNAL_ERROR
                .reason("cancelled stream ID exceeds the QUIC variable-integer range"));
        }
        if self.table.max_capacity() != 0 {
            self.send_feedback(DecoderInstruction::StreamCancellation(id))?;
        }
        self.decoding_stream.remove(&id);
        let mut wakes = Vec::new();
        if let Some((_, bytes, waker)) = self.waiting.remove(&id) {
            self.blocked_bytes -= bytes;
            wakes.push(waker);
        }
        Ok(wakes)
    }

    pub(super) fn take_waiters(&mut self) -> Vec<Waker> {
        self.waiting
            .drain()
            .map(|(_, (_, _, waker))| waker)
            .collect()
    }

    fn acknowledge(&self, stream_id: u64, required_insert_count: u64) -> Result<()> {
        if required_insert_count != 0 {
            self.send_feedback(DecoderInstruction::SectionAcknowledgment(stream_id))?;
        }
        Ok(())
    }

    /// Feedback is required for QPACK correctness, so overload fails the
    /// connection instead of dropping an instruction or blocking under the
    /// decoder state lock.
    fn send_feedback(&self, instruction: DecoderInstruction) -> Result<()> {
        // Each current decoder operation produces at most one feedback instruction.
        (self.on_instruction)(vec![instruction])
    }

    /// Shared by immediate and resumed decoding: reject evicted/out-of-range references,
    /// check the highest referenced absolute index against RIC, and retain N flags.
    fn decode_fields(&self, prefix: FieldSectionPrefix, mut input: &[u8]) -> Result<Vec<Field>> {
        let mut fields = Vec::new();
        let mut required_insert_count = 0;
        let mut decoded_size = 0usize;
        while !input.is_empty() {
            let (rest, line) = be_field_line(input)?;
            if let Some(absolute) = line.dynamic_index(prefix)? {
                required_insert_count = required_insert_count.max(absolute + 1);
            }
            let field = line.resolve(prefix, &self.table)?;
            // Use HTTP/3 field-section accounting (name + value + 32 per field) to bound
            // both decompressed strings and field count, including repeated table indices.
            decoded_size = decoded_size
                .checked_add(field.name.len())
                .and_then(|size| size.checked_add(field.value.len()))
                .and_then(|size| size.checked_add(32))
                .filter(|&size| size as u64 <= self.max_field_section_size)
                .ok_or_else(|| {
                    ErrorCode::H3_EXCESSIVE_LOAD
                        .reason("decoded field section exceeds the advertised size limit")
                })?;
            fields.push(field);
            input = rest;
        }
        if required_insert_count != prefix.required_insert_count {
            return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
                .reason("Required Insert Count does not match the largest dynamic reference"));
        }
        Ok(fields)
    }
}
