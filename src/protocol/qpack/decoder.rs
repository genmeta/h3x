//! Decoder state and bounded wait registrations; field bytes stay in the decoding future.
use std::{
    collections::{HashMap, VecDeque},
    task::{Context, Poll, Waker},
};

use qbase::varint::VARINT_MAX;

use super::{
    Field, Settings,
    field::{FieldLine, FieldSectionPrefix},
    instruction::{DecoderInstruction, EncoderInstruction},
    table::DynamicTable,
};
use crate::{Error, Result, protocol::frame::MAX_BUFFERED_FRAME_PAYLOAD};

pub(crate) struct Decoder {
    table: DynamicTable,
    max_blocked_streams: u64,
    pub(super) max_field_section_size: u64,
    waiting: HashMap<u64, (u64, usize, Waker)>,
    blocked_bytes: usize,
    max_blocked_bytes: usize,
    known_received_count: u64,
    instructions: VecDeque<DecoderInstruction>,
}

impl Decoder {
    pub(crate) fn new(local: Settings, max_blocked_bytes: usize) -> Result<Self> {
        if local.blocked_streams > VARINT_MAX {
            return Err(Error::H3_SETTINGS_ERROR);
        }
        Ok(Self {
            table: DynamicTable::new(local.max_table_capacity)?,
            max_blocked_streams: local.blocked_streams,
            max_field_section_size: MAX_BUFFERED_FRAME_PAYLOAD as u64,
            waiting: HashMap::new(),
            blocked_bytes: 0,
            max_blocked_bytes,
            known_received_count: 0,
            instructions: VecDeque::new(),
        })
    }

    pub(super) fn read_prefix<'a>(
        &self,
        payload: &'a [u8],
    ) -> Result<(&'a [u8], FieldSectionPrefix)> {
        if payload.len() > MAX_BUFFERED_FRAME_PAYLOAD {
            return Err(Error::H3_EXCESSIVE_LOAD);
        }
        FieldSectionPrefix::read(
            payload,
            self.table.max_capacity(),
            self.table.insert_count(),
        )
    }

    pub(super) fn poll_decode(
        &mut self,
        id: u64,
        prefix: FieldSectionPrefix,
        bytes: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<Vec<Field>>> {
        if prefix.required_insert_count != 0 && bytes.is_empty() {
            return Poll::Ready(Err(Error::QPACK_DECOMPRESSION_FAILED));
        }
        if prefix.required_insert_count > self.table.insert_count() {
            if let Some((_, _, waker)) = self.waiting.get_mut(&id) {
                waker.clone_from(cx.waker());
            } else {
                if self.waiting.len() as u64 >= self.max_blocked_streams {
                    return Poll::Ready(Err(Error::QPACK_DECOMPRESSION_FAILED));
                }
                let Some(total) = self
                    .blocked_bytes
                    .checked_add(bytes.len())
                    .filter(|n| *n <= self.max_blocked_bytes)
                else {
                    return Poll::Ready(Err(Error::H3_EXCESSIVE_LOAD));
                };
                self.waiting.insert(
                    id,
                    (
                        prefix.required_insert_count,
                        bytes.len(),
                        cx.waker().clone(),
                    ),
                );
                self.blocked_bytes = total;
            }
            return Poll::Pending;
        }
        self.finish(id);
        let result = self.decode_fields(prefix, bytes);
        if result.is_ok() {
            self.acknowledge(id, prefix.required_insert_count);
        }
        Poll::Ready(result)
    }

    pub(crate) fn on_encoder_instruction(&mut self, instruction: EncoderInstruction) -> Result<()> {
        if self.table.max_capacity() == 0 {
            return Err(Error::QPACK_ENCODER_STREAM_ERROR);
        }
        self.table.apply(instruction)?;
        // ponytail: scan the bounded wait map; index by RIC if measured workloads require it.
        for (ric, _, waker) in self.waiting.values() {
            if *ric <= self.table.insert_count() {
                waker.wake_by_ref();
            }
        }
        Ok(())
    }

    pub(super) fn finish(&mut self, id: u64) {
        if let Some((_, bytes, _)) = self.waiting.remove(&id) {
            self.blocked_bytes -= bytes;
        }
    }

    pub(crate) fn cancel_stream(&mut self, id: u64) -> Result<()> {
        if id > VARINT_MAX {
            return Err(Error::H3_INTERNAL_ERROR);
        }
        if let Some((_, _, waker)) = self.waiting.get(&id) {
            waker.wake_by_ref();
        }
        self.finish(id);
        if self.table.max_capacity() != 0 {
            self.instructions
                .push_back(DecoderInstruction::StreamCancellation(id));
        }
        Ok(())
    }

    pub(super) fn wake_all(&self) {
        for (_, _, waker) in self.waiting.values() {
            waker.wake_by_ref();
        }
    }

    /// Drain queued feedback, then emit any insertion progress not already covered by ACKs.
    pub(crate) fn next_instruction(&mut self) -> Option<DecoderInstruction> {
        if let Some(instruction) = self.instructions.pop_front() {
            return Some(instruction);
        }
        let increment = self.table.insert_count() - self.known_received_count;
        if increment == 0 {
            return None;
        }
        self.known_received_count = self.table.insert_count();
        Some(DecoderInstruction::InsertCountIncrement(increment))
    }

    pub(super) fn acknowledge(&mut self, stream_id: u64, required_insert_count: u64) {
        if required_insert_count != 0 {
            self.instructions
                .push_back(DecoderInstruction::SectionAcknowledgment(stream_id));
            self.known_received_count = self.known_received_count.max(required_insert_count);
        }
    }

    /// Shared by immediate and resumed decoding: reject evicted/out-of-range references,
    /// check the highest referenced absolute index against RIC, and retain N flags.
    pub(super) fn decode_fields(
        &self,
        prefix: FieldSectionPrefix,
        mut input: &[u8],
    ) -> Result<Vec<Field>> {
        let mut fields = Vec::new();
        let mut required_insert_count = 0;
        let mut decoded_size = 0usize;
        while !input.is_empty() {
            let (rest, line) = FieldLine::read(input)?;
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
                .ok_or(Error::H3_EXCESSIVE_LOAD)?;
            fields.push(field);
            input = rest;
        }
        if required_insert_count != prefix.required_insert_count {
            return Err(Error::QPACK_DECOMPRESSION_FAILED);
        }
        Ok(fields)
    }
}
