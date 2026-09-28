//! Incoming headers, table updates from the peer encoder, and decoder-stream feedback.
use std::task::{Context, Poll, Waker};

use state::State;
use tokio::sync::mpsc;

use super::{
    Field, Settings,
    codec::{
        field::FieldSectionPrefix,
        instruction::{DecoderInstruction, EncoderInstruction},
    },
};
use crate::{ErrorCode, Result};

pub(crate) type Batch = Vec<DecoderInstruction>;
pub(super) type OnInstruction = Box<dyn Fn(Batch) -> Result<()> + Send + Sync>;
pub(crate) type Instructions = mpsc::Receiver<Batch>;

pub(crate) struct Decoder {
    state: State,
}

impl Decoder {
    pub(super) fn new(local: Settings, max_blocked_bytes: usize, max_fields: u64) -> Result<Self> {
        Ok(Self {
            state: State::new(
                local,
                max_blocked_bytes,
                max_fields,
                Box::new(|_| {
                    Err(ErrorCode::InternalError
                        .connection("instruction callback is not registered"))
                }),
            )?,
        })
    }

    pub(crate) fn on_instruction(
        &mut self,
        callback: impl Fn(Batch) -> Result<()> + Send + Sync + 'static,
    ) {
        self.state.on_instruction = Box::new(callback);
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
    use crate::{Error, ErrorCode, Result, frame::MAX_BUFFERED_FRAME_PAYLOAD};

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
                on_instruction,
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
                self.finish(id);
                let fields = self.decode_fields(prefix, bytes)?;
                self.acknowledge(id, prefix.required_insert_count)
                    .map_err(Error::connection)?;
                return Poll::Ready(Ok(fields));
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
            if blocked as u64 >= self.max_blocked_streams {
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
            let previous_count = self.table.insert_count();
            self.table.apply(instruction)?;
            let increment = self.table.insert_count() - previous_count;
            if increment != 0 {
                // Queue progress before any ACK that can reference these insertions.
                // All producers hold the decoder state lock, preserving this wire order.
                self.send_feedback(vec![DecoderInstruction::InsertCountIncrement(increment)])?;
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

        fn acknowledge(&self, stream_id: u64, required_insert_count: u64) -> Result<()> {
            if required_insert_count != 0 {
                self.send_feedback(vec![DecoderInstruction::SectionAcknowledgment(stream_id)])?;
            }
            Ok(())
        }

        /// Feedback is required for QPACK correctness, so overload fails the
        /// connection instead of dropping an instruction or blocking under the
        /// decoder state lock.
        fn send_feedback(&self, instructions: super::Batch) -> Result<()> {
            (self.on_instruction)(instructions)
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
