use std::{
    future::poll_fn,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use codec::instruction::{DecoderInstruction, EncoderInstruction};
use tokio::sync::mpsc;

use crate::protocol::qpack::*;

#[tokio::test]
async fn insertion_feedback_uses_the_queue_and_capacity_changes_emit_nothing() {
    let (decoder, mut source) = Decoder::new(
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
            Poll::Ready(Ok(DecoderInstruction::InsertCountIncrement(1)))
        );
    }
    assert!(Decoder::poll_feedback(&mut source, &mut cx).is_pending());
    decoder.close(ErrorCode::H3_NO_ERROR);
    assert_eq!(
        Decoder::poll_feedback(&mut source, &mut cx),
        Poll::Ready(Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM))
    );
}

#[tokio::test]
async fn feedback_backlog_is_bounded_without_dropping_required_instructions() {
    let (decoder, mut source) = Decoder::new(
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

    for id in 0..super::super::MAX_PENDING_FEEDBACK {
        decoder.cancel(id as u64).unwrap();
    }
    assert_eq!(source.len(), super::super::MAX_PENDING_FEEDBACK);
    assert_eq!(
        decoder
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .acknowledge(4096, 1),
        Err(ErrorCode::H3_EXCESSIVE_LOAD)
    );

    assert_eq!(
        source.recv().await,
        Some(DecoderInstruction::StreamCancellation(0))
    );
    decoder
        .state
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .acknowledge(4096, 1)
        .unwrap();
    assert_eq!(decoder.cancel(4097), Err(ErrorCode::H3_EXCESSIVE_LOAD));
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
            let mut resource = qpack.decoder.state.lock().unwrap();
            let state = resource.as_mut().unwrap();
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
        assert_eq!(decode.await, Err(ErrorCode::H3_REQUEST_CANCELLED));
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
    qpack.close(ErrorCode::H3_NO_ERROR);
    assert_eq!(decode.await, Err(ErrorCode::H3_NO_ERROR));
    assert!(qpack.decoder.state.lock().unwrap().is_err());
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
        let mut resource = qpack.decoder.state.lock().unwrap();
        let state = resource.as_mut().unwrap();
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
        let mut resource = qpack.decoder.state.lock().unwrap();
        let state = resource.as_mut().unwrap();
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
        let mut resource = qpack.decoder.state.lock().unwrap();
        let state = resource.as_mut().unwrap();
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
    let mut resource = qpack.decoder.state.lock().unwrap();
    let state = resource.as_mut().unwrap();
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
        qpack.decode(0, Bytes::from_static(&[0, 0, 0xd1])).await,
        Err(ErrorCode::H3_REQUEST_CANCELLED)
    );
    assert!(decode.as_mut().poll(&mut cx).is_pending());
    assert!(qpack.next_instruction().is_none());
    drop(decode);
    let mut resource = qpack.decoder.state.lock().unwrap();
    let state = resource.as_mut().unwrap();
    assert!(state.decoding_stream.is_empty());
    assert_eq!(
        qpack.next_instruction(),
        Some(DecoderInstruction::StreamCancellation(0))
    );
    assert!(qpack.next_instruction().is_none());
}

#[tokio::test]
async fn invalid_prefix_releases_registration_without_cancellation_feedback() {
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
            qpack.decode(0, Bytes::copy_from_slice(payload)).await,
            Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
        );
        assert_eq!(qpack.error(), None);
        assert!(
            qpack
                .decoder
                .state
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .decoding_stream
                .is_empty()
        );
        assert!(qpack.next_instruction().is_none());
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
            let mut resource = qpack.decoder.state.lock().unwrap();
            let state = resource.as_mut().unwrap();
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
            qpack.decode(0, Bytes::copy_from_slice(payload)).await,
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
            qpack.decode(0, payload).await,
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
        let decoder = Arc::new(Codec::new(Settings::default(), Settings::default(), 0).unwrap());
        decoder.local_limit(limit);
        let decoded = decoder.decode(0, wire.clone()).await;
        if limit == 33 {
            assert_eq!(encoded, Err(ErrorCode::H3_EXCESSIVE_LOAD));
            assert_eq!(decoded, Err(ErrorCode::H3_EXCESSIVE_LOAD));
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
                H3Frame::Headers(frame) => receiver.decode(0, frame.payload.field_section).await,
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
                for (instruction, insert_count) in batch {
                    sender.encoder.on_instruction_sent(insert_count).unwrap();
                    receiver
                        .decoder
                        .state
                        .lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .on_encoder_instruction(instruction)
                        .unwrap();
                }
            }
        }
        assert_eq!(decode.await.unwrap(), fields);
        if index == 0 {
            let increment = receiver.next_instruction().unwrap();
            assert_eq!(increment, DecoderInstruction::InsertCountIncrement(1));
            sender.encoder.on_decoder_instruction(increment).unwrap();
        }
        let feedback = receiver.next_instruction().unwrap();
        assert_eq!(feedback, DecoderInstruction::SectionAcknowledgment(0));
        sender.encoder.on_decoder_instruction(feedback).unwrap();
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

type Feedback = mpsc::Receiver<DecoderInstruction>;

struct Codec {
    qpack: Qpack,
    instructions: Mutex<mpsc::Receiver<Vec<(EncoderInstruction, u64)>>>,
    feedback: Mutex<Feedback>,
}

impl std::ops::Deref for Codec {
    type Target = Qpack;
    fn deref(&self) -> &Self::Target {
        &self.qpack
    }
}

impl Codec {
    fn new(local: Settings, peer: Settings, max_blocked_bytes: usize) -> Result<Self> {
        let (encoder, instruction_source) = Encoder::new(peer)?;
        let (decoder, feedback_source) = Decoder::new(
            local,
            max_blocked_bytes,
            frame::MAX_BUFFERED_FRAME_PAYLOAD as u64,
        )?;
        Ok(Self {
            qpack: Qpack { encoder, decoder },
            instructions: Mutex::new(instruction_source.instructions),
            feedback: Mutex::new(feedback_source),
        })
    }
    fn poll_instruction(&self, cx: &mut Context<'_>) -> Poll<DecoderInstruction> {
        let mut feedback = self.feedback.lock().unwrap();
        Decoder::poll_feedback(&mut feedback, cx).map(Result::unwrap)
    }

    fn next_instruction(&self) -> Option<DecoderInstruction> {
        match self.poll_instruction(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(instruction) => Some(instruction),
            Poll::Pending => None,
        }
    }

    fn local_limit(&self, limit: u64) {
        self.decoder
            .state
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
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
