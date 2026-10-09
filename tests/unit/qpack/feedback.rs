use tokio::io::AsyncReadExt;

use super::*;

#[tokio::test]
async fn buffered_insert_burst_coalesces_before_feedback_storage() {
    let qpack = ArcQpack::new(&crate::Settings::default()).unwrap();
    let mut wire = Vec::new();
    wire.put_encoder_instruction(&EncoderInstruction::SetDynamicTableCapacity(4096))
        .unwrap();
    for n in 0..4097 {
        wire.put_encoder_instruction(&EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x-burst"),
            value: Bytes::from(n.to_string()),
        })
        .unwrap();
    }
    assert_eq!(
        qpack
            .receive_encoder(&mut wire.as_slice())
            .await
            .unwrap_err()
            .code,
        ErrorCode::ClosedCriticalStream
    ); // Deliberate end of the test instruction input.
    let batch = qpack
        .with_state(|state| Ok(state.decoder.take_feedback().0))
        .unwrap();
    assert_eq!(batch, vec![DecoderInstruction::InsertCountIncrement(4097)]);
    assert!(
        qpack
            .with_state(|state| Ok(state.decoder.take_feedback().0))
            .unwrap()
            .is_empty()
    );
    assert!(qpack.error().is_none());
}

#[tokio::test]
async fn merged_counts_and_every_section_ack_are_accepted_by_the_real_encoder() {
    let local = Settings {
        max_table_capacity: 65536,
        blocked_streams: 2048,
    };
    let emitted = Arc::new(Mutex::new(Vec::new()));
    let captured = emitted.clone();
    let mut encoder = encoder::Encoder::new(local).unwrap();
    encoder.on_instruction(move |batch| {
        captured.lock().unwrap().extend(batch);
        Ok(())
    });
    encoder.configure(local, 65536).unwrap();
    let mut sections = Vec::new();
    for n in 0..1025 {
        sections.push((
            n * 4,
            encoder
                .encode(
                    n * 4,
                    vec![Field {
                        name: Bytes::from_static(b"x-merge"),
                        value: Bytes::from(n.to_string()),
                        never_index: false,
                    }],
                )
                .unwrap(),
        ));
    }
    let mut decoder = decoder::Decoder::new(local, 65536, 65536).unwrap();
    for instruction in std::mem::take(&mut *emitted.lock().unwrap()) {
        if !matches!(instruction, EncoderInstruction::SetDynamicTableCapacity(_)) {
            encoder.record_insert_written();
        }
        decoder.on_encoder_instruction(instruction).unwrap();
    }
    let mut cx = Context::from_waker(std::task::Waker::noop());
    for (id, payload) in sections {
        let (offset, prefix) = decoder.begin_decode(id, &payload).unwrap();
        assert!(matches!(
            decoder.poll_registered_decode(id, prefix, &payload[offset..], &mut cx),
            Poll::Ready(Ok(_))
        ));
    }
    decoder.cancel(vec![5000]).unwrap();
    let batch = decoder.take_feedback().0;
    assert_eq!(
        batch.first(),
        Some(&DecoderInstruction::InsertCountIncrement(1025))
    );
    assert_eq!(batch.len(), 1027);
    for instruction in batch {
        encoder.on_decoder_instruction(instruction).unwrap();
    }
    // Exact progress reached all completed insertions; neither undercount nor overcount.
    assert_eq!(
        encoder
            .on_decoder_instruction(DecoderInstruction::InsertCountIncrement(1))
            .unwrap_err()
            .code,
        ErrorCode::QpackDecoderStreamError
    );
}

#[tokio::test]
async fn count_progress_stays_before_ack_even_with_interleaved_insertions() {
    let mut decoder = decoder::Decoder::new(
        Settings {
            max_table_capacity: 128,
            blocked_streams: 1,
        },
        1024,
        1024,
    )
    .unwrap();
    decoder
        .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
        .unwrap();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    for n in 0..2 {
        decoder
            .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from(n.to_string()),
            })
            .unwrap();
        let mut payload = Vec::new();
        payload
            .put_field_section_prefix(
                &FieldSectionPrefix {
                    required_insert_count: n + 1,
                    base: 0,
                },
                128,
            )
            .unwrap();
        payload
            .put_field_line(&FieldLine::IndexedPostBase { index: n })
            .unwrap();
        let (offset, prefix) = decoder.begin_decode(n * 4, &payload).unwrap();
        assert!(matches!(
            decoder.poll_registered_decode(n * 4, prefix, &payload[offset..], &mut cx),
            Poll::Ready(Ok(_))
        ));
    }
    assert_eq!(
        decoder.take_feedback().0,
        vec![
            DecoderInstruction::InsertCountIncrement(1),
            DecoderInstruction::SectionAcknowledgment(0),
            DecoderInstruction::InsertCountIncrement(1),
            DecoderInstruction::SectionAcknowledgment(4),
        ]
    );
}

#[tokio::test]
async fn blocked_feedback_writer_backpressures_ack_burst_and_preserves_cancellations() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let qpack = ArcQpack::new(&crate::Settings::default()).unwrap();
        qpack
            .with_state(|state| {
                state
                    .decoder
                    .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(4096))?;
                state.decoder.on_encoder_instruction(
                    EncoderInstruction::InsertWithLiteralName {
                        name: Bytes::from_static(b"x"),
                        value: Bytes::from_static(b"value"),
                    },
                )?;
                Ok(())
            })
            .unwrap();
        let mut payload = Vec::new();
        payload
            .put_field_section_prefix(
                &FieldSectionPrefix {
                    required_insert_count: 1,
                    base: 0,
                },
                4096,
            )
            .unwrap();
        payload
            .put_field_line(&FieldLine::IndexedPostBase { index: 0 })
            .unwrap();
        let payload = Bytes::from(payload);
        let (mut writer, mut reader) = tokio::io::duplex(16);
        let writing = {
            let qpack = qpack.clone();
            tokio::spawn(async move { qpack.write_decoder(&mut writer).await })
        };
        let complete = Arc::new(AtomicUsize::new(0));
        let mut decoding = {
            let qpack = qpack.clone();
            let complete = complete.clone();
            tokio::spawn(async move {
                for n in 0..10000 {
                    qpack.decode(n * 4, payload.clone()).await?;
                    complete.store(n as usize + 1, Ordering::SeqCst);
                }
                Ok::<_, Error>(())
            })
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut decoding)
                .await
                .is_err()
        );
        assert!(complete.load(Ordering::SeqCst) < 10000);
        assert!(qpack.error().is_none());
        qpack
            .cancel_decode((0..512).map(|n| 1_000_000 + n * 4).collect())
            .unwrap();
        assert!(qpack.error().is_none());
        assert_eq!(
            reader.read_u8().await.unwrap(),
            StreamType::QpackDecoder as u8
        );
        let mut acks = 0;
        let mut cancellations = 0;
        let mut inserts = 0;
        while acks < 10000 || cancellations < 512 {
            match codec::instruction::be_decoder_instruction(&mut reader)
                .await
                .unwrap()
            {
                DecoderInstruction::InsertCountIncrement(n) => inserts += n,
                DecoderInstruction::SectionAcknowledgment(id) => {
                    assert_eq!(id, acks * 4);
                    acks += 1;
                }
                DecoderInstruction::StreamCancellation(id) => {
                    assert!(id >= 1_000_000);
                    cancellations += 1;
                }
            }
        }
        decoding.await.unwrap().unwrap();
        assert_eq!(inserts, 1);
        assert!(qpack.error().is_none());
        let ended = ErrorCode::NoError.connection("test complete");
        qpack.on_connection_error(ended.clone());
        assert_eq!(writing.await.unwrap().unwrap_err(), ended);
    })
    .await
    .unwrap();
}

#[test]
fn synchronous_cancellation_has_a_real_memory_limit() {
    let mut decoder = decoder::Decoder::new(
        Settings {
            max_table_capacity: 128,
            blocked_streams: 1,
        },
        1024,
        1024,
    )
    .unwrap();
    decoder
        .cancel(
            (0..decoder::MAX_PENDING_FEEDBACK - 1)
                .map(|n| n as u64 * 4)
                .collect(),
        )
        .unwrap();
    assert_eq!(
        decoder.cancel(vec![1_000_000]).unwrap_err().code,
        ErrorCode::ExcessiveLoad
    );
    assert_eq!(
        decoder.take_feedback().0.len(),
        decoder::MAX_PENDING_FEEDBACK - 1
    );
    decoder.cancel(vec![1_000_000]).unwrap();
}

#[test]
fn insertion_progress_remains_available_when_ack_storage_is_full() {
    let mut decoder = decoder::Decoder::new(
        Settings {
            max_table_capacity: 4096,
            blocked_streams: 0,
        },
        65536,
        65536,
    )
    .unwrap();
    decoder
        .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(4096))
        .unwrap();
    decoder
        .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x"),
            value: Bytes::from_static(b"first"),
        })
        .unwrap();
    let mut payload = Vec::new();
    payload
        .put_field_section_prefix(
            &FieldSectionPrefix {
                required_insert_count: 1,
                base: 0,
            },
            4096,
        )
        .unwrap();
    payload
        .put_field_line(&FieldLine::IndexedPostBase { index: 0 })
        .unwrap();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let filled = decoder::MAX_PENDING_FEEDBACK / 2 - 1;
    for n in 0..filled {
        let (offset, prefix) = decoder.begin_decode(n as u64 * 4, &payload).unwrap();
        assert!(matches!(
            decoder.poll_registered_decode(n as u64 * 4, prefix, &payload[offset..], &mut cx),
            Poll::Ready(Ok(_))
        ));
    }
    let id = filled as u64 * 4;
    let (offset, prefix) = decoder.begin_decode(id, &payload).unwrap();
    // An ACK-space waiter is not a dynamically blocked stream, even when the
    // advertised dynamic-blocked limit is zero.
    assert!(
        decoder
            .poll_registered_decode(id, prefix, &payload[offset..], &mut cx)
            .is_pending()
    );
    decoder
        .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"y"),
            value: Bytes::from_static(b"second"),
        })
        .unwrap();
    let (batch, wakes) = decoder.take_feedback();
    assert_eq!(
        batch.first(),
        Some(&DecoderInstruction::InsertCountIncrement(1))
    );
    assert_eq!(
        batch.last(),
        Some(&DecoderInstruction::InsertCountIncrement(1))
    );
    assert_eq!(wakes.len(), 1);
    assert!(matches!(
        decoder.poll_registered_decode(id, prefix, &payload[offset..], &mut cx),
        Poll::Ready(Ok(_))
    ));
    assert_eq!(
        decoder.take_feedback().0,
        vec![DecoderInstruction::SectionAcknowledgment(id)]
    );
}

#[tokio::test]
async fn concurrent_ack_pressure_waits_and_recovers_without_failing_connection() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let qpack = ArcQpack::new(&crate::Settings::default()).unwrap();
        qpack.with_state(|state| {
            state.decoder.on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(4096))?;
            state.decoder.on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"), value: Bytes::from_static(b"value"),
            })?;
            Ok(())
        }).unwrap();
        let mut payload = Vec::new();
        payload.put_field_section_prefix(&FieldSectionPrefix { required_insert_count: 1, base: 0 }, 4096).unwrap();
        payload.put_field_line(&FieldLine::IndexedPostBase { index: 0 }).unwrap();
        let payload = Bytes::from(payload);
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let writing = {
            let qpack = qpack.clone();
            tokio::spawn(async move { qpack.write_decoder(&mut writer).await })
        };
        let complete = Arc::new(AtomicUsize::new(0));
        let mut decoding = {
            let qpack = qpack.clone(); let complete = complete.clone();
            tokio::spawn(async move {
                futures::future::try_join_all((0..1000).map(|worker| {
                    let qpack = qpack.clone(); let complete = complete.clone(); let payload = payload.clone();
                    async move {
                        for sequence in 0..100 {
                            let id = (worker * 100 + sequence) * 4;
                            qpack.decode(id, payload.clone()).await?;
                            complete.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok::<_, Error>(())
                    }
                })).await
            })
        };
        // No consumer: a one-byte output window is deliberately blocked.
        assert!(tokio::time::timeout(std::time::Duration::from_millis(100), &mut decoding).await.is_err());
        let paused_at = complete.load(Ordering::SeqCst);
        assert!(paused_at < 100_000);
        assert!(qpack.error().is_none());
        qpack.cancel_decode((0..1024).map(|n| 2_000_000 + n * 4).collect()).unwrap();
        assert!(qpack.error().is_none());
        assert_eq!(reader.read_u8().await.unwrap(), StreamType::QpackDecoder as u8);
        let mut acks = std::collections::HashSet::new();
        let mut cancellations = std::collections::HashSet::new();
        let mut insert_count = 0;
        while acks.len() < 100_000 || cancellations.len() < 1024 {
            match codec::instruction::be_decoder_instruction(&mut reader).await.unwrap() {
                DecoderInstruction::InsertCountIncrement(n) => insert_count += n,
                DecoderInstruction::SectionAcknowledgment(id) => {
                    assert!(id < 400_000 && id % 4 == 0);
                    assert!(acks.insert(id), "duplicate ACK {id}");
                }
                DecoderInstruction::StreamCancellation(id) => {
                    assert!(id >= 2_000_000 && id < 2_004_096 && id % 4 == 0);
                    assert!(cancellations.insert(id), "duplicate cancellation {id}");
                }
            }
        }
        decoding.await.unwrap().unwrap();
        assert_eq!(complete.load(Ordering::SeqCst), 100_000);
        assert_eq!(insert_count, 1);
        assert!(qpack.error().is_none());
        println!("1000 concurrent producers, 100000 ACKs, 1024 cancellations, one-byte output: paused at {paused_at}; complete recovery without connection failure");
        let ended = ErrorCode::NoError.connection("test complete");
        qpack.on_connection_error(ended.clone());
        assert_eq!(writing.await.unwrap().unwrap_err(), ended);
    }).await.unwrap();
}

#[test]
fn cancellation_memory_exhaustion_still_fails_the_connection() {
    let qpack = ArcQpack::new(&crate::Settings::default()).unwrap();
    qpack
        .cancel_decode(
            (0..decoder::MAX_PENDING_FEEDBACK - 1)
                .map(|n| n as u64 * 4)
                .collect(),
        )
        .unwrap();
    assert!(qpack.error().is_none());
    let failure =
        qpack.on_stream_error(2_000_000, ErrorCode::RequestCancelled.stream("peer reset"));
    assert_eq!(failure.code, ErrorCode::ExcessiveLoad);
    assert!(qpack.error().is_some());
}

#[tokio::test]
async fn blocked_encoder_queue_falls_back_without_failure_and_resumes_dynamic_encoding() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let qpack = ArcQpack::new(&crate::Settings::default()).unwrap();
        let (sender, receiver) = tokio::sync::mpsc::channel(MAX_PENDING_INSTRUCTION);
        let full = Arc::new(AtomicUsize::new(0));
        let counted = full.clone();
        qpack.with_state(|state| {
            state.encoder.on_instruction(move |batch| match sender.try_send(batch) {
                Ok(()) => Ok(()),
                Err(error) => {
                    if matches!(error, tokio::sync::mpsc::error::TrySendError::Full(_)) {
                        counted.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(instruction_send_error(error))
                }
            });
            Ok(())
        }).unwrap();
        let peer_settings = Settings { max_table_capacity:4096, blocked_streams:32 };
        // Prior to SETTINGS, ordinary encoding cannot fill the instruction queue:
        // the dynamic table has zero capacity and no updates are generated.
        for n in 0..1000 {
            qpack.encode(1_000_000+n*4, vec![field(b"x-before-settings",b"value",false)]).unwrap();
        }
        assert_eq!(full.load(Ordering::SeqCst),0);
        qpack.configure(peer_settings,65536).unwrap();
        let mut peer=decoder::Decoder::new(peer_settings,65536,65536).unwrap();
        let mut dynamic=Vec::new();
        let mut cx=Context::from_waker(std::task::Waker::noop());
        for n in 0..100_000 {
            let expected=Field { name:Bytes::from_static(b"x-encoder-pressure"),value:Bytes::from(n.to_string()),never_index:false };
            let wire=qpack.encode(n*4,vec![expected.clone()]).unwrap();
            if n < (MAX_PENDING_INSTRUCTION-1) as u64 {
                dynamic.push((n*4,wire,expected));
            } else {
                // No writer has run. Every overflowed attempt must roll back its
                // table update and emit a self-contained literal field section.
                let (offset,prefix)=peer.begin_decode(n*4,&wire).unwrap();
                assert_eq!(prefix.required_insert_count,0);
                let Poll::Ready(Ok(fields))=peer.poll_registered_decode(n*4,prefix,&wire[offset..],&mut cx) else { panic!("literal fallback blocked or failed"); };
                assert_eq!(fields,vec![expected]);
            }
        }
        assert_eq!(full.load(Ordering::SeqCst),100_000-(MAX_PENDING_INSTRUCTION-1));
        assert!(qpack.error().is_none());
        assert!(peer.take_feedback().0.is_empty());
        let (mut writer,mut reader)=tokio::io::duplex(1);
        let writing={
            let qpack=qpack.clone();
            tokio::spawn(async move { qpack.write_encoder(receiver,&mut writer).await })
        };
        assert_eq!(reader.read_u8().await.unwrap(),StreamType::QpackEncoder as u8);
        for _ in 0..MAX_PENDING_INSTRUCTION {
            let instruction=codec::instruction::be_encoder_instruction(&mut reader).await.unwrap();
            peer.on_encoder_instruction(instruction).unwrap();
        }
        for (id,wire,expected) in dynamic {
            let (offset,prefix)=peer.begin_decode(id,&wire).unwrap();
            let Poll::Ready(Ok(fields))=peer.poll_registered_decode(id,prefix,&wire[offset..],&mut cx) else { panic!("queued dynamic section failed"); };
            assert_eq!(fields,vec![expected]);
        }
        for instruction in peer.take_feedback().0 {
            qpack.with_state(|state|state.encoder.on_decoder_instruction(instruction)).unwrap();
        }
        // Once the writer catches up, dynamic compression must remain usable.
        let expected=field(b"x-after-pressure",b"resumed",false);
        let wire=qpack.encode(400_000,vec![expected.clone()]).unwrap();
        let instruction=codec::instruction::be_encoder_instruction(&mut reader).await.unwrap();
        peer.on_encoder_instruction(instruction).unwrap();
        let (offset,prefix)=peer.begin_decode(400_000,&wire).unwrap();
        assert!(prefix.required_insert_count>0);
        let Poll::Ready(Ok(fields))=peer.poll_registered_decode(400_000,prefix,&wire[offset..],&mut cx) else { panic!("dynamic compression did not resume"); };
        assert_eq!(fields,vec![expected]);
        for instruction in peer.take_feedback().0 {
            qpack.with_state(|state|state.encoder.on_decoder_instruction(instruction)).unwrap();
        }
        assert!(qpack.error().is_none());
        println!("encoder queue blocked: 100000 encodings succeeded, {} literal fallbacks; actual one-byte writer drained updates and dynamic encoding resumed",full.load(Ordering::SeqCst));
        let ended=ErrorCode::NoError.connection("test complete");
        qpack.on_connection_error(ended.clone());
        assert_eq!(writing.await.unwrap().unwrap_err(),ended);
    }).await.unwrap();
}
