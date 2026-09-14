use std::{
    sync::Arc,
    task::{Context, Waker},
};

use instruction::EncoderInstruction;

use super::*;

#[tokio::test]
async fn blocked_fields_live_in_future_and_resume_without_connection_results() {
    let qpack = Arc::new(
        Qpack::new(
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
            let mut state = qpack.state.lock().unwrap();
            state
                .decoder
                .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
                .unwrap();
            state
                .decoder
                .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                    name: Bytes::from_static(b"x"),
                    value: Bytes::from_static(b"y"),
                })
                .unwrap();
        }
        assert_eq!(decode.await.unwrap()[0].value, "y");
    }
    assert_eq!(
        qpack.state.lock().unwrap().decoder.next_instruction(),
        Some(DecoderInstruction::SectionAcknowledgment(0))
    );
    assert!(
        qpack
            .state
            .lock()
            .unwrap()
            .decoder
            .next_instruction()
            .is_none()
    );
}

#[tokio::test]
async fn cancellation_releases_registration_and_close_wakes_decode() {
    let qpack = Arc::new(
        Qpack::new(
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
        assert_eq!(decode.await, Err(Error::H3_REQUEST_CANCELLED));
    }
    assert_eq!(
        qpack.state.lock().unwrap().decoder.next_instruction(),
        Some(DecoderInstruction::StreamCancellation(0))
    );
    assert!(
        qpack
            .state
            .lock()
            .unwrap()
            .decoder
            .next_instruction()
            .is_none()
    );
    let decode = qpack.decode(4, Bytes::from_static(&[2, 0, 0x80]));
    tokio::pin!(decode);
    poll_fn(|cx| {
        assert!(decode.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    qpack.close(Error::H3_NO_ERROR);
    assert_eq!(decode.await, Err(Error::H3_NO_ERROR));
    let mut state = qpack.state.lock().unwrap();
    assert!(state.decoding.is_empty());
    assert!(state.decoder.next_instruction().is_none());
}

#[tokio::test]
async fn abandoned_decode_releases_registration_and_blocked_budget() {
    let qpack = Arc::new(
        Qpack::new(
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
        let mut state = qpack.state.lock().unwrap();
        assert!(state.decoding.is_empty());
        assert!(state.decoder.next_instruction().is_none());
    }
    for (id, explicit_cancel) in [(0, false), (4, true), (8, false)] {
        let mut decode = Box::pin(qpack.decode(id, Bytes::from_static(&[2, 0, 0x80])));
        // Each decode consumes the only wait slot and the entire byte budget.
        assert!(decode.as_mut().poll(&mut cx).is_pending());
        let ready = qpack.decoder_ready.notified();
        tokio::pin!(ready);
        assert!(ready.as_mut().poll(&mut cx).is_pending());
        if explicit_cancel {
            qpack.cancel(id).unwrap();
        }
        drop(decode);
        assert!(ready.as_mut().poll(&mut cx).is_ready());
        assert_eq!(qpack.error(), None);
        let mut state = qpack.state.lock().unwrap();
        assert!(state.decoding.is_empty());
        assert_eq!(
            state.decoder.next_instruction(),
            Some(DecoderInstruction::StreamCancellation(id))
        );
        assert!(state.decoder.next_instruction().is_none());
    }

    let decode = qpack.decode(12, Bytes::from_static(&[2, 0, 0x80]));
    tokio::pin!(decode);
    assert!(decode.as_mut().poll(&mut cx).is_pending());
    {
        let mut state = qpack.state.lock().unwrap();
        state
            .decoder
            .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
            .unwrap();
        state
            .decoder
            .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from_static(b"y"),
            })
            .unwrap();
    }
    assert_eq!(decode.await.unwrap()[0].value, "y");
    let mut state = qpack.state.lock().unwrap();
    assert!(state.decoding.is_empty());
    assert_eq!(
        state.decoder.next_instruction(),
        Some(DecoderInstruction::SectionAcknowledgment(12))
    );
    assert!(state.decoder.next_instruction().is_none());
}

#[tokio::test]
async fn rejected_decode_does_not_cancel_existing_registration() {
    let qpack = Qpack::new(
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
        Err(Error::H3_REQUEST_CANCELLED)
    );
    assert!(decode.as_mut().poll(&mut cx).is_pending());
    assert!(
        qpack
            .state
            .lock()
            .unwrap()
            .decoder
            .next_instruction()
            .is_none()
    );
    drop(decode);
    let mut state = qpack.state.lock().unwrap();
    assert!(state.decoding.is_empty());
    assert_eq!(
        state.decoder.next_instruction(),
        Some(DecoderInstruction::StreamCancellation(0))
    );
    assert!(state.decoder.next_instruction().is_none());
}

#[tokio::test]
async fn invalid_prefix_releases_registration_without_cancellation_feedback() {
    for payload in [&[][..], &[0][..], &[0, 0x80][..]] {
        let qpack = Qpack::new(
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
            Err(Error::QPACK_DECOMPRESSION_FAILED)
        );
        assert_eq!(qpack.error(), Some(Error::QPACK_DECOMPRESSION_FAILED));
        let mut state = qpack.state.lock().unwrap();
        assert!(state.decoding.is_empty());
        assert!(state.decoder.next_instruction().is_none());
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
            Qpack::new(
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
            let mut state = qpack.state.lock().unwrap();
            state
                .decoder
                .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
                .unwrap();
            for value in [b"one", b"two"] {
                state
                    .decoder
                    .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                        name: Bytes::from_static(b"x"),
                        value: Bytes::copy_from_slice(value),
                    })
                    .unwrap();
            }
        }
        assert_eq!(
            qpack.decode(0, Bytes::copy_from_slice(payload)).await,
            Err(Error::QPACK_DECOMPRESSION_FAILED)
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
            Qpack::new(
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
            Err(Error::H3_EXCESSIVE_LOAD)
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
    let wire = Qpack::new(Settings::default(), Settings::default(), 0)
        .unwrap()
        .encode(0, fields.clone())
        .unwrap();
    for limit in [33, 34] {
        // name + value + 32 bytes of field overhead.
        let encoder = Qpack::new(Settings::default(), Settings::default(), 0).unwrap();
        encoder.configure(Settings::default(), limit).unwrap();
        let encoded = encoder.encode(0, fields.clone());
        let decoder = Arc::new(Qpack::new(Settings::default(), Settings::default(), 0).unwrap());
        decoder.local_limit(limit);
        let decoded = decoder.decode(0, wire.clone()).await;
        if limit == 33 {
            assert_eq!(encoded, Err(Error::H3_EXCESSIVE_LOAD));
            assert_eq!(decoded, Err(Error::H3_EXCESSIVE_LOAD));
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
    let sender = Arc::new(Qpack::new(Settings::default(), Settings::default(), 1024).unwrap());
    sender.configure(limits, 1024).unwrap();
    let receiver = Arc::new(Qpack::new(limits, Settings::default(), 1024).unwrap());
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
            let mut source = sender.state.lock().unwrap();
            let mut target = receiver.state.lock().unwrap();
            while let Some(instruction) = source.encoder.next_instruction() {
                source.encoder.on_instruction_sent(&instruction).unwrap();
                target.decoder.on_encoder_instruction(instruction).unwrap();
            }
        }
        assert_eq!(decode.await.unwrap(), fields);
        let feedback = receiver
            .state
            .lock()
            .unwrap()
            .decoder
            .next_instruction()
            .unwrap();
        assert_eq!(feedback, DecoderInstruction::SectionAcknowledgment(0));
        sender
            .state
            .lock()
            .unwrap()
            .encoder
            .on_decoder_instruction(feedback)
            .unwrap();
        assert!(
            receiver
                .state
                .lock()
                .unwrap()
                .decoder
                .next_instruction()
                .is_none()
        );
    }
    // The same flow also supports a connection with no dynamic capacity.
    let frame = Frame::new(Headers {
        field_section: Qpack::new(Settings::default(), Settings::default(), 0)
            .unwrap()
            .encode(0, fields.clone())
            .unwrap(),
    })
    .unwrap();
    assert_eq!(frame.payload.field_section[0], 0);
    assert_eq!(
        Qpack::default()
            .decode(0, frame.payload.field_section)
            .await
            .unwrap(),
        fields
    );
}
