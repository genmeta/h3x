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
            return Err(ErrorCode::H3_SETTINGS_ERROR.reason(
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
            return Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR.reason(
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
            return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED.reason(
                "Required Insert Count does not match the largest dynamic reference",
            ));
        }
        Ok(fields)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    use codec::instruction::{DecoderInstruction, EncoderInstruction};
    use tokio::sync::mpsc;

    use crate::protocol::qpack::*;

    #[tokio::test]
    async fn feedback_writer_preserves_order_within_and_between_batches() {
        let (tx, rx) = mpsc::channel(MAX_PENDING_INSTRUCTION);
        tx.try_send(vec![
            DecoderInstruction::InsertCountIncrement(1),
            DecoderInstruction::SectionAcknowledgment(4),
        ])
        .unwrap();
        tx.try_send(vec![DecoderInstruction::StreamCancellation(0)])
            .unwrap();
        drop(tx);
        let mut wire = Vec::new();
        assert_eq!(
            (ArcQpack::new(&crate::Settings::default())
                .unwrap()
                .write_decoder(rx, &mut wire)
                .await)
                .map_err(ErrorCode::from),
            Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM),
        );
        assert_eq!(wire, [0x03, 0x01, 0x84, 0x40]);
    }

    #[tokio::test]
    async fn insertion_feedback_uses_the_queue_and_capacity_changes_emit_nothing() {
        let (mut decoder, mut source) = Decoder::with_channel(
            Settings {
                max_table_capacity: 128,
                blocked_streams: 1,
            },
            128,
            1024,
        )
        .unwrap();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Decoder::poll_feedback(&mut source, &mut cx).is_pending());
        decoder
            .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
            .unwrap();
        assert!(source.try_recv().is_err());
        for value in [b"a", b"b"] {
            decoder
                .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                    name: Bytes::from_static(b"x"),
                    value: Bytes::from_static(value),
                })
                .unwrap();
        }
        assert!(wakes.0.load(std::sync::atomic::Ordering::SeqCst) > 0);
        for _ in 0..2 {
            assert_eq!(
                Decoder::poll_feedback(&mut source, &mut cx),
                Poll::Ready(Ok(vec![DecoderInstruction::InsertCountIncrement(1)]))
            );
        }
        assert!(Decoder::poll_feedback(&mut source, &mut cx).is_pending());
        drop(decoder);
        assert_eq!(
            (Decoder::poll_feedback(&mut source, &mut cx))
                .map(|result| result.map_err(ErrorCode::from)),
            Poll::Ready(Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM))
        );
    }

    #[tokio::test]
    async fn feedback_backlog_is_bounded_without_dropping_required_instructions() {
        let (mut decoder, mut source) = Decoder::with_channel(
            Settings {
                max_table_capacity: 128,
                blocked_streams: 1,
            },
            128,
            1024,
        )
        .unwrap();
        decoder
            .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
            .unwrap();

        for id in 0..MAX_PENDING_INSTRUCTION {
            decoder.cancel(id as u64).unwrap();
        }
        assert_eq!(source.len(), MAX_PENDING_INSTRUCTION);
        assert_eq!(
            (decoder.state.acknowledge(4096, 1)).map_err(ErrorCode::from),
            Err(ErrorCode::H3_EXCESSIVE_LOAD)
        );

        assert_eq!(
            source.recv().await,
            Some(vec![DecoderInstruction::StreamCancellation(0)])
        );
        decoder.state.acknowledge(4096, 1).unwrap();
        assert_eq!(
            (decoder.cancel(4097).map(|_| ())).map_err(ErrorCode::from),
            Err(ErrorCode::H3_EXCESSIVE_LOAD)
        );
    }

    #[tokio::test]
    async fn blocked_fields_live_in_future_and_resume_without_connection_results() {
        let qpack = Arc::new(
            Codec::new(
                Settings {
                    max_table_capacity: 128,
                    blocked_streams: 1,
                },
                Settings::default(),
                2,
            )
            .unwrap(),
        );
        {
            let decode = qpack.decode(0, Bytes::from_static(&[2, 0, 0x80]));
            tokio::pin!(decode);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(decode.as_mut().poll(&mut cx).is_pending());
            {
                let mut resource = qpack.lock().unwrap();
                let state = &mut resource.as_mut().unwrap().decoder.state;
                state
                    .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
                    .unwrap();
                state
                    .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                        name: Bytes::from_static(b"x"),
                        value: Bytes::from_static(b"y"),
                    })
                    .unwrap();
            }
            assert_eq!(decode.await.unwrap()[0].value, "y");
        }
        assert_eq!(
            qpack.next_instruction(),
            Some(DecoderInstruction::InsertCountIncrement(1))
        );
        assert_eq!(
            qpack.next_instruction(),
            Some(DecoderInstruction::SectionAcknowledgment(0))
        );
        assert!(qpack.next_instruction().is_none());
    }

    #[tokio::test]
    async fn cancellation_releases_registration_and_close_wakes_decode() {
        let qpack = Arc::new(
            Codec::new(
                Settings {
                    max_table_capacity: 128,
                    blocked_streams: 1,
                },
                Settings::default(),
                1,
            )
            .unwrap(),
        );
        {
            let decode = qpack.decode(0, Bytes::from_static(&[2, 0, 0x80]));
            tokio::pin!(decode);
            poll_fn(|cx| {
                assert!(decode.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            qpack.cancel(0).unwrap();
            assert_eq!(
                (decode.await).map_err(ErrorCode::from),
                Err(ErrorCode::H3_REQUEST_CANCELLED)
            );
        }
        assert_eq!(
            qpack.next_instruction(),
            Some(DecoderInstruction::StreamCancellation(0))
        );
        assert!(qpack.next_instruction().is_none());
        let decode = qpack.decode(4, Bytes::from_static(&[2, 0, 0x80]));
        tokio::pin!(decode);
        poll_fn(|cx| {
            assert!(decode.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        qpack
            .on_error(ErrorCode::H3_NO_ERROR.reason("test closes the decoder while decoding"));
        assert_eq!(
            (decode.await).map_err(ErrorCode::from),
            Err(ErrorCode::H3_NO_ERROR)
        );
        assert!(qpack.lock().unwrap().is_err());
    }

    #[tokio::test]
    async fn abandoned_decode_releases_registration_and_blocked_budget() {
        let qpack = Arc::new(
            Codec::new(
                Settings {
                    max_table_capacity: 128,
                    blocked_streams: 1,
                },
                Settings::default(),
                1,
            )
            .unwrap(),
        );
        let mut cx = Context::from_waker(Waker::noop());
        // An unpolled future never registered anything and needs no cancellation.
        drop(qpack.decode(0, Bytes::from_static(&[2, 0, 0x80])));
        {
            let mut resource = qpack.lock().unwrap();
            let state = &mut resource.as_mut().unwrap().decoder.state;
            assert!(state.decoding_stream.is_empty());
            assert!(qpack.next_instruction().is_none());
        }
        for (id, explicit_cancel) in [(0, false), (4, true), (8, false)] {
            let mut decode = Box::pin(qpack.decode(id, Bytes::from_static(&[2, 0, 0x80])));
            // Each decode consumes the only wait slot and the entire byte budget.
            assert!(decode.as_mut().poll(&mut cx).is_pending());
            let wakes = Arc::new(Wakes::default());
            let writer = Waker::from(wakes.clone());
            assert!(
                qpack
                    .poll_instruction(&mut Context::from_waker(&writer))
                    .is_pending()
            );
            if explicit_cancel {
                qpack.cancel(id).unwrap();
            }
            drop(decode);
            assert!(wakes.0.load(std::sync::atomic::Ordering::SeqCst) > 0);
            assert_eq!(qpack.error(), None);
            let mut resource = qpack.lock().unwrap();
            let state = &mut resource.as_mut().unwrap().decoder.state;
            assert!(state.decoding_stream.is_empty());
            assert_eq!(
                qpack.next_instruction(),
                Some(DecoderInstruction::StreamCancellation(id))
            );
            assert!(qpack.next_instruction().is_none());
        }

        let decode = qpack.decode(12, Bytes::from_static(&[2, 0, 0x80]));
        tokio::pin!(decode);
        assert!(decode.as_mut().poll(&mut cx).is_pending());
        {
            let mut resource = qpack.lock().unwrap();
            let state = &mut resource.as_mut().unwrap().decoder.state;
            state
                .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
                .unwrap();
            state
                .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                    name: Bytes::from_static(b"x"),
                    value: Bytes::from_static(b"y"),
                })
                .unwrap();
        }
        assert_eq!(decode.await.unwrap()[0].value, "y");
        let mut resource = qpack.lock().unwrap();
        let state = &mut resource.as_mut().unwrap().decoder.state;
        assert!(state.decoding_stream.is_empty());
        assert_eq!(
            qpack.next_instruction(),
            Some(DecoderInstruction::InsertCountIncrement(1))
        );
        assert_eq!(
            qpack.next_instruction(),
            Some(DecoderInstruction::SectionAcknowledgment(12))
        );
        assert!(qpack.next_instruction().is_none());
    }

    #[tokio::test]
    async fn rejected_decode_does_not_cancel_existing_registration() {
        let qpack = Codec::new(
            Settings {
                max_table_capacity: 128,
                blocked_streams: 1,
            },
            Settings::default(),
            1,
        )
        .unwrap();
        let mut decode = Box::pin(qpack.decode(0, Bytes::from_static(&[2, 0, 0x80])));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(decode.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            (qpack.decode(0, Bytes::from_static(&[0, 0, 0xd1])).await).map_err(ErrorCode::from),
            Err(ErrorCode::H3_REQUEST_CANCELLED)
        );
        assert!(decode.as_mut().poll(&mut cx).is_pending());
        assert!(qpack.next_instruction().is_none());
        drop(decode);
        let mut resource = qpack.lock().unwrap();
        let state = &mut resource.as_mut().unwrap().decoder.state;
        assert!(state.decoding_stream.is_empty());
        assert_eq!(
            qpack.next_instruction(),
            Some(DecoderInstruction::StreamCancellation(0))
        );
        assert!(qpack.next_instruction().is_none());
    }

    #[tokio::test]
    async fn invalid_prefix_fails_qpack_without_cancellation_feedback() {
        for payload in [&[][..], &[0][..], &[0, 0x80][..]] {
            let qpack = Codec::new(
                Settings {
                    max_table_capacity: 128,
                    blocked_streams: 1,
                },
                Settings::default(),
                1,
            )
            .unwrap();
            assert_eq!(
                (qpack.decode(0, Bytes::copy_from_slice(payload)).await).map_err(ErrorCode::from),
                Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
            );
            assert_eq!(
                qpack.error().map(ErrorCode::from),
                Some(ErrorCode::QPACK_DECOMPRESSION_FAILED)
            );
            assert!(matches!(
                qpack.feedback.lock().unwrap().try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            ));
        }
    }

    #[tokio::test]
    async fn invalid_dynamic_references_and_amplification_remain_bounded() {
        for payload in [
            &[3, 0, 0x81][..],
            &[2, 0, 0xd1][..],
            &[0, 0, 0x80][..],
            &[2, 0, 0x10][..],
            &[0, 0, 0xff, 36][..],
            &[0, 0, 0x50][..],
        ] {
            let qpack = Arc::new(
                Codec::new(
                    Settings {
                        max_table_capacity: 128,
                        blocked_streams: 1,
                    },
                    Settings::default(),
                    16,
                )
                .unwrap(),
            );
            {
                let mut resource = qpack.lock().unwrap();
                let state = &mut resource.as_mut().unwrap().decoder.state;
                state
                    .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
                    .unwrap();
                for value in [b"one", b"two"] {
                    state
                        .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                            name: Bytes::from_static(b"x"),
                            value: Bytes::copy_from_slice(value),
                        })
                        .unwrap();
                }
            }
            assert_eq!(
                (qpack.decode(0, Bytes::copy_from_slice(payload)).await).map_err(ErrorCode::from),
                Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
            );
        }
        let mut amplified = vec![0, 0];
        amplified.resize(2051, 0xc0);
        for payload in [
            Bytes::from(amplified),
            Bytes::from(vec![0; 65537]),
            Bytes::from_static(&[3, 0, 0x81, 0x80]),
        ] {
            let qpack = Arc::new(
                Codec::new(
                    Settings {
                        max_table_capacity: 128,
                        blocked_streams: 1,
                    },
                    Settings::default(),
                    1,
                )
                .unwrap(),
            );
            assert_eq!(
                (qpack.decode(0, payload).await).map_err(ErrorCode::from),
                Err(ErrorCode::H3_EXCESSIVE_LOAD)
            );
        }
    }

    #[tokio::test]
    async fn field_size_limits_are_enforced_by_each_direction_at_the_exact_boundary() {
        let fields = vec![Field {
            name: Bytes::from_static(b"x"),
            value: Bytes::from_static(b"y"),
            never_index: false,
        }];
        let wire = Codec::new(Settings::default(), Settings::default(), 0)
            .unwrap()
            .encode(0, fields.clone())
            .unwrap();
        for limit in [33, 34] {
            // name + value + 32 bytes of field overhead.
            let encoder = Codec::new(Settings::default(), Settings::default(), 0).unwrap();
            encoder.configure(Settings::default(), limit).unwrap();
            let encoded = encoder.encode(0, fields.clone());
            let decoder =
                Arc::new(Codec::new(Settings::default(), Settings::default(), 0).unwrap());
            decoder.local_limit(limit);
            let decoded = decoder.decode(0, wire.clone()).await;
            if limit == 33 {
                assert_eq!(
                    (encoded).map_err(ErrorCode::from),
                    Err(ErrorCode::H3_EXCESSIVE_LOAD)
                );
                assert_eq!(
                    (decoded).map_err(ErrorCode::from),
                    Err(ErrorCode::H3_EXCESSIVE_LOAD)
                );
            } else {
                assert_eq!(encoded.unwrap(), wire);
                assert_eq!(decoded.unwrap(), fields);
            }
        }
    }

    #[tokio::test]
    async fn qpack_fields_preserve_frame_envelopes_and_ack_order() {
        use qbase::varint::VarInt;
        use tokio::io::{AsyncWriteExt, duplex};

        use crate::protocol::frame::{self, Frame, H3Frame, Headers, PushPromise, Write as _};

        let limits = Settings {
            max_table_capacity: 128,
            blocked_streams: 1,
        };
        let sender = Arc::new(Codec::new(Settings::default(), Settings::default(), 1024).unwrap());
        sender.configure(limits, 1024).unwrap();
        let receiver = Arc::new(Codec::new(limits, Settings::default(), 1024).unwrap());
        let fields = vec![Field {
            name: Bytes::from_static(b"x-dynamic"),
            value: Bytes::from_static(b"value"),
            never_index: false,
        }];
        // HEADERS, another HEADERS (e.g. trailer), and PUSH_PROMISE share the carrying stream.
        for (index, promise) in [false, false, true].into_iter().enumerate() {
            let frame = if promise {
                H3Frame::PushPromise(
                    Frame::new(PushPromise {
                        push_id: VarInt::from_u32(64),
                        field_section: sender.encode(0, fields.clone()).unwrap(),
                    })
                    .unwrap(),
                )
            } else {
                H3Frame::Headers(
                    Frame::new(Headers {
                        field_section: sender.encode(0, fields.clone()).unwrap(),
                    })
                    .unwrap(),
                )
            };
            let compressed = match &frame {
                H3Frame::Headers(frame) => &frame.payload.field_section,
                H3Frame::PushPromise(frame) => &frame.payload.field_section,
                _ => unreachable!(),
            };
            assert_ne!(
                compressed[0], 0,
                "must reference the dynamic table, not silently use literals"
            );
            let mut wire = Vec::new();
            wire.put_frame(&frame);
            let (mut send, mut recv) = duplex(1);
            let (sent, parsed) = tokio::join!(send.write_all(&wire), frame::be_frame(&mut recv));
            sent.unwrap();
            let parsed = parsed.unwrap();
            assert_eq!(parsed, frame); // Includes the encoded length and the multi-byte push ID.
            let decode = async {
                match parsed {
                    H3Frame::Headers(frame) => {
                        receiver.decode(0, frame.payload.field_section).await
                    }
                    H3Frame::PushPromise(frame) => {
                        assert_eq!(frame.payload.push_id.into_u64(), 64);
                        receiver.decode(0, frame.payload.field_section).await
                    }
                    _ => unreachable!(),
                }
            };
            tokio::pin!(decode);
            if index == 0 {
                poll_fn(|cx| {
                    assert!(decode.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                // Deliver encoder instructions only after the full HEADERS frame has arrived.
                while let Ok(batch) = sender.instructions.lock().unwrap().try_recv() {
                    for instruction in batch {
                        if !matches!(instruction, EncoderInstruction::SetDynamicTableCapacity(_)) {
                            sender
                                .lock()
                                .unwrap()
                                .as_mut()
                                .unwrap()
                                .encoder
                                .record_insert_written();
                        }
                        receiver
                            .lock()
                            .unwrap()
                            .as_mut()
                            .unwrap()
                            .decoder
                            .state
                            .on_encoder_instruction(instruction)
                            .unwrap();
                    }
                }
            }
            assert_eq!(decode.await.unwrap(), fields);
            if index == 0 {
                let increment = receiver.next_instruction().unwrap();
                assert_eq!(increment, DecoderInstruction::InsertCountIncrement(1));
                sender
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .encoder
                    .on_decoder_instruction(increment)
                    .unwrap();
            }
            let feedback = receiver.next_instruction().unwrap();
            assert_eq!(feedback, DecoderInstruction::SectionAcknowledgment(0));
            sender
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .encoder
                .on_decoder_instruction(feedback)
                .unwrap();
            assert!(receiver.next_instruction().is_none());
        }
        // The same flow also supports a connection with no dynamic capacity.
        let frame = Frame::new(Headers {
            field_section: Codec::new(Settings::default(), Settings::default(), 0)
                .unwrap()
                .encode(0, fields.clone())
                .unwrap(),
        })
        .unwrap();
        assert_eq!(frame.payload.field_section[0], 0);
        assert_eq!(
            Codec::default()
                .decode(0, frame.payload.field_section)
                .await
                .unwrap(),
            fields
        );
    }

    type Feedback = decoder::Instructions;

    struct Codec {
        qpack: ArcQpack,
        instructions: Mutex<mpsc::Receiver<Vec<EncoderInstruction>>>,
        feedback: Mutex<Feedback>,
    }

    impl std::ops::Deref for Codec {
        type Target = ArcQpack;
        fn deref(&self) -> &Self::Target {
            &self.qpack
        }
    }

    impl Codec {
        fn new(local: Settings, peer: Settings, max_blocked_bytes: usize) -> Result<Self> {
            let (encoder, instruction_source) = Encoder::with_channel(peer)?;
            let (decoder, feedback_source) =
                Decoder::with_channel(local, max_blocked_bytes, 64 * 1024)?;
            Ok(Self {
                qpack: ArcQpack::from(Qpack { encoder, decoder }),
                instructions: Mutex::new(instruction_source),
                feedback: Mutex::new(feedback_source),
            })
        }
        fn poll_instruction(&self, cx: &mut Context<'_>) -> Poll<DecoderInstruction> {
            let mut feedback = self.feedback.lock().unwrap();
            Decoder::poll_feedback(&mut feedback, cx).map(|result| {
                let mut batch = result.unwrap();
                assert_eq!(batch.len(), 1);
                batch.pop().unwrap()
            })
        }

        fn next_instruction(&self) -> Option<DecoderInstruction> {
            match self.poll_instruction(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(instruction) => Some(instruction),
                Poll::Pending => None,
            }
        }

        fn local_limit(&self, limit: u64) {
            self.lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .decoder
                .state
                .max_field_section_size = limit;
        }
    }
    impl Default for Codec {
        fn default() -> Self {
            Self::new(Settings::default(), Settings::default(), 0).unwrap()
        }
    }

    #[derive(Default)]
    struct Wakes(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}
