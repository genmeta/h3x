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

    pub(super) fn cancel(&mut self, id: u64) -> Result<Vec<Waker>> {
        self.state.cancel_stream(id)
    }

    pub(super) fn cancel_registered(&mut self, id: u64) -> Result<Vec<Waker>> {
        if !self.state.decoding_stream.remove(&id) {
            return Ok(Vec::new());
        }
        self.state.cancel_stream(id)
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
            if self.waiting.len() as u64 >= self.max_blocked_streams {
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
                return Err(ErrorCode::InternalError
                    .connection("cancelled stream ID exceeds the QUIC variable-integer range"));
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
mod tests {
    use std::{
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    use bytes::{Bytes, BytesMut};
    use qbase::varint::VARINT_MAX;

    use super::*;
    use crate::qpack::codec::field::{FieldLine, WriteField};

    fn settings(capacity: u64, blocked_streams: u64) -> Settings {
        Settings {
            max_table_capacity: capacity,
            blocked_streams,
        }
    }

    fn dynamic_wire(required_insert_count: u64, line: FieldLine) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.put_field_section_prefix(
            &FieldSectionPrefix {
                required_insert_count,
                base: 0,
            },
            128,
        )
        .unwrap();
        wire.put_field_line(&line).unwrap();
        wire
    }

    fn make_decoder(
        blocked_streams: u64,
        blocked_bytes: usize,
        max_fields: u64,
    ) -> (Decoder, Arc<Mutex<Vec<Batch>>>) {
        let feedback = Arc::new(Mutex::new(Vec::new()));
        let captured = feedback.clone();
        let mut decoder =
            Decoder::new(settings(128, blocked_streams), blocked_bytes, max_fields).unwrap();
        decoder.on_instruction(move |batch| {
            captured.lock().unwrap().push(batch);
            Ok(())
        });
        decoder
            .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
            .unwrap();
        (decoder, feedback)
    }

    #[test]
    fn blocked_decode_resumes_after_insert_and_emits_ordered_feedback() {
        let (mut decoder, feedback) = make_decoder(2, 1024, 1024);
        let wire = dynamic_wire(1, FieldLine::IndexedPostBase { index: 0 });
        let (offset, prefix) = decoder.begin_decode(0, &wire).unwrap();
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(
            decoder.poll_registered_decode(0, prefix, &wire[offset..], &mut cx),
            Poll::Pending
        ));
        assert!(matches!(
            decoder.poll_registered_decode(0, prefix, &wire[offset..], &mut cx),
            Poll::Pending
        ));

        let wakes = decoder
            .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x-dynamic"),
                value: Bytes::from_static(b"value"),
            })
            .unwrap();
        assert_eq!(wakes.len(), 1);
        let Poll::Ready(Ok(fields)) =
            decoder.poll_registered_decode(0, prefix, &wire[offset..], &mut cx)
        else {
            panic!("inserted section should decode")
        };
        assert_eq!(fields[0].name, "x-dynamic");
        assert_eq!(fields[0].value, "value");

        let feedback = feedback.lock().unwrap();
        assert!(matches!(
            feedback[0].as_slice(),
            [DecoderInstruction::InsertCountIncrement(1)]
        ));
        assert!(matches!(
            feedback[1].as_slice(),
            [DecoderInstruction::SectionAcknowledgment(0)]
        ));
    }

    #[test]
    fn cancellation_and_blocking_budgets_clean_up_waiters() {
        let wire = dynamic_wire(1, FieldLine::IndexedPostBase { index: 0 });
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let (mut decoder, feedback) = make_decoder(1, 1024, 1024);
        let (offset, prefix) = decoder.begin_decode(4, &wire).unwrap();
        assert!(decoder.begin_decode(4, &wire).is_err());
        assert!(
            decoder
                .poll_registered_decode(4, prefix, &wire[offset..], &mut cx)
                .is_pending()
        );
        assert_eq!(decoder.cancel_registered(4).unwrap().len(), 1);
        assert!(decoder.cancel_registered(4).unwrap().is_empty());
        assert!(matches!(
            feedback.lock().unwrap().last().unwrap().as_slice(),
            [DecoderInstruction::StreamCancellation(4)]
        ));
        assert!(
            decoder
                .poll_registered_decode(4, prefix, &wire[offset..], &mut cx)
                .is_ready()
        );
        assert_eq!(
            decoder.cancel(VARINT_MAX + 1).unwrap_err().code,
            ErrorCode::InternalError
        );

        let (mut no_stream_slots, _) = make_decoder(0, 1024, 1024);
        let (offset, prefix) = no_stream_slots.begin_decode(8, &wire).unwrap();
        let Poll::Ready(Err(error)) =
            no_stream_slots.poll_registered_decode(8, prefix, &wire[offset..], &mut cx)
        else {
            panic!("blocked-stream limit must reject")
        };
        assert_eq!(error.code, ErrorCode::QpackDecompressionFailed);

        let (mut no_bytes, _) = make_decoder(1, 0, 1024);
        let (offset, prefix) = no_bytes.begin_decode(12, &wire).unwrap();
        let Poll::Ready(Err(error)) =
            no_bytes.poll_registered_decode(12, prefix, &wire[offset..], &mut cx)
        else {
            panic!("blocked-byte limit must reject")
        };
        assert_eq!(error.code, ErrorCode::ExcessiveLoad);

        let (mut waiting, _) = make_decoder(2, 1024, 1024);
        for id in [16, 20] {
            let (offset, prefix) = waiting.begin_decode(id, &wire).unwrap();
            assert!(
                waiting
                    .poll_registered_decode(id, prefix, &wire[offset..], &mut cx)
                    .is_pending()
            );
        }
        assert_eq!(waiting.take_waiters().len(), 2);
    }

    #[test]
    fn malformed_sections_settings_and_callback_errors_are_rejected() {
        assert_eq!(
            Decoder::new(settings(0, VARINT_MAX + 1), 0, 0)
                .err()
                .unwrap()
                .code,
            ErrorCode::SettingsError
        );
        assert_eq!(
            Decoder::new(settings(VARINT_MAX + 1, 0), 0, 0)
                .err()
                .unwrap()
                .code,
            ErrorCode::SettingsError
        );

        let (mut decoder, _) = make_decoder(1, 1024, 50);
        assert_eq!(
            decoder
                .begin_decode(VARINT_MAX + 1, &[0, 0])
                .unwrap_err()
                .code,
            ErrorCode::InternalError
        );
        assert_eq!(
            decoder
                .begin_decode(0, &vec![0; crate::frame::MAX_BUFFERED_FRAME_PAYLOAD + 1])
                .unwrap_err()
                .code,
            ErrorCode::ExcessiveLoad
        );

        let mut empty_dynamic = Vec::new();
        empty_dynamic
            .put_field_section_prefix(
                &FieldSectionPrefix {
                    required_insert_count: 1,
                    base: 0,
                },
                128,
            )
            .unwrap();
        assert_eq!(
            decoder.begin_decode(0, &empty_dynamic).unwrap_err().code,
            ErrorCode::QpackDecompressionFailed
        );

        decoder
            .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from_static(b"y"),
            })
            .unwrap();
        let wire = dynamic_wire(
            1,
            FieldLine::Indexed {
                static_table: true,
                index: 17,
            },
        );
        let (offset, prefix) = decoder.begin_decode(4, &wire).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready(Err(error)) =
            decoder.poll_registered_decode(4, prefix, &wire[offset..], &mut cx)
        else {
            panic!("RIC mismatch must reject")
        };
        assert_eq!(error.code, ErrorCode::QpackDecompressionFailed);

        let mut oversized = BytesMut::new();
        oversized
            .put_field_section_prefix(
                &FieldSectionPrefix {
                    required_insert_count: 0,
                    base: 0,
                },
                128,
            )
            .unwrap();
        oversized
            .put_field_line(&FieldLine::Literal(Field {
                name: Bytes::from_static(b"long-name"),
                value: Bytes::from_static(b"long-value"),
                never_index: false,
            }))
            .unwrap();
        let (offset, prefix) = decoder.begin_decode(8, &oversized).unwrap();
        let Poll::Ready(Err(error)) =
            decoder.poll_registered_decode(8, prefix, &oversized[offset..], &mut cx)
        else {
            panic!("decoded size limit must reject")
        };
        assert_eq!(error.code, ErrorCode::ExcessiveLoad);

        let mut zero = Decoder::new(Settings::default(), 0, 0).unwrap();
        assert_eq!(
            zero.on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(0))
                .unwrap_err()
                .code,
            ErrorCode::QpackEncoderStreamError
        );

        let (mut callback_error, _) = make_decoder(1, 1024, 1024);
        callback_error
            .on_instruction(|_| Err(ErrorCode::ClosedCriticalStream.connection("feedback closed")));
        assert_eq!(
            callback_error
                .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                    name: Bytes::from_static(b"a"),
                    value: Bytes::from_static(b"b"),
                })
                .unwrap_err()
                .code,
            ErrorCode::ClosedCriticalStream
        );
    }
}
