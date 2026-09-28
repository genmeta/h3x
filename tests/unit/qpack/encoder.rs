use std::sync::{Arc, Mutex};

use qbase::varint::VARINT_MAX;

use super::*;

fn field(name: &'static [u8], value: &'static [u8], never_index: bool) -> Field {
    Field {
        name: Bytes::from_static(name),
        value: Bytes::from_static(value),
        never_index,
    }
}

fn configured(capacity: u64, blocked_streams: u64) -> (Encoder, Arc<Mutex<Vec<Batch>>>) {
    let batches = Arc::new(Mutex::new(Vec::new()));
    let captured = batches.clone();
    let mut encoder = Encoder::new(Settings::default()).unwrap();
    encoder.on_instruction(move |batch| {
        captured.lock().unwrap().push(batch);
        Ok(())
    });
    encoder
        .configure(
            Settings {
                max_table_capacity: capacity,
                blocked_streams,
            },
            4096,
        )
        .unwrap();
    (encoder, batches)
}

#[test]
fn dynamic_encoding_queues_each_instruction_form_and_accepts_feedback() {
    let (mut encoder, batches) = configured(256, 4);
    let first = encoder
        .encode(
            0,
            vec![
                field(b":method", b"GET", false),
                field(b"content-type", b"custom", false),
                field(b"x-one", b"1", false),
                field(b"authorization", b"secret", false),
            ],
        )
        .unwrap();
    assert!(!first.is_empty());
    let queued = batches.lock().unwrap();
    assert!(matches!(
        queued[0].as_slice(),
        [EncoderInstruction::SetDynamicTableCapacity(256)]
    ));
    assert!(queued.iter().flatten().any(|instruction| matches!(
        instruction,
        EncoderInstruction::InsertWithNameReference {
            static_table: true,
            ..
        }
    )));
    assert!(queued.iter().flatten().any(|instruction| matches!(
        instruction,
        EncoderInstruction::InsertWithLiteralName { .. }
    )));
    drop(queued);

    encoder.record_insert_written();
    encoder.record_insert_written();
    encoder
        .on_decoder_instruction(DecoderInstruction::InsertCountIncrement(2))
        .unwrap();
    encoder
        .on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0))
        .unwrap();

    encoder
        .encode(
            4,
            vec![field(b"x-one", b"1", false), field(b"x-one", b"2", false)],
        )
        .unwrap();
    assert!(batches.lock().unwrap().iter().flatten().any(|instruction| {
        matches!(
            instruction,
            EncoderInstruction::InsertWithNameReference {
                static_table: false,
                ..
            }
        )
    }));
    encoder
        .on_decoder_instruction(DecoderInstruction::StreamCancellation(4))
        .unwrap();
}

#[test]
fn encoder_limits_feedback_and_callback_failures_are_transactional() {
    assert_eq!(
        Encoder::new(Settings {
            max_table_capacity: 0,
            blocked_streams: VARINT_MAX + 1,
        })
        .err()
        .unwrap()
        .code,
        ErrorCode::SettingsError
    );
    assert_eq!(
        Encoder::new(Settings {
            max_table_capacity: VARINT_MAX + 1,
            blocked_streams: 0,
        })
        .err()
        .unwrap()
        .code,
        ErrorCode::SettingsError
    );

    let (mut encoder, _) = configured(64, 1);
    assert_eq!(
        encoder.encode(VARINT_MAX + 1, vec![]).unwrap_err().code,
        ErrorCode::InternalError
    );
    encoder
        .configure(
            Settings {
                max_table_capacity: 64,
                blocked_streams: 1,
            },
            1,
        )
        .unwrap();
    assert_eq!(
        encoder
            .encode(0, vec![field(b"a", b"b", false)])
            .unwrap_err()
            .code,
        ErrorCode::ExcessiveLoad
    );
    assert_eq!(
        encoder
            .on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(99))
            .unwrap_err()
            .code,
        ErrorCode::QpackDecoderStreamError
    );
    for instruction in [
        DecoderInstruction::InsertCountIncrement(0),
        DecoderInstruction::InsertCountIncrement(1),
        DecoderInstruction::StreamCancellation(VARINT_MAX + 1),
    ] {
        assert_eq!(
            encoder
                .on_decoder_instruction(instruction)
                .unwrap_err()
                .code,
            ErrorCode::QpackDecoderStreamError
        );
    }

    let (mut fallback, _) = configured(128, 1);
    fallback.on_instruction(|_| Err(ErrorCode::ExcessiveLoad.connection("full instruction queue")));
    assert!(
        !fallback
            .encode(0, vec![field(b"x-fallback", b"value", false)])
            .unwrap()
            .is_empty()
    );

    fallback.on_instruction(|_| {
        Err(ErrorCode::ClosedCriticalStream.connection("closed instruction queue"))
    });
    assert_eq!(
        fallback
            .encode(4, vec![field(b"x-closed", b"value", false)])
            .unwrap_err()
            .code,
        ErrorCode::ClosedCriticalStream
    );
}

#[test]
fn blocked_references_prevent_limit_reduction_and_eviction() {
    let (mut encoder, batches) = configured(70, 1);
    encoder.encode(0, vec![field(b"aa", b"11", false)]).unwrap();
    assert_eq!(
        encoder
            .configure(
                Settings {
                    max_table_capacity: 70,
                    blocked_streams: 0,
                },
                4096,
            )
            .unwrap_err()
            .code,
        ErrorCode::SettingsError
    );

    let before = batches.lock().unwrap().len();
    assert!(
        !encoder
            .encode(4, vec![field(b"bb", b"22", false)])
            .unwrap()
            .is_empty()
    );
    assert_eq!(batches.lock().unwrap().len(), before);
}

#[test]
fn default_callback_oversized_wire_and_early_acknowledgment_fail_cleanly() {
    let mut unregistered = Encoder::new(Settings::default()).unwrap();
    assert_eq!(
        unregistered
            .configure(
                Settings {
                    max_table_capacity: 64,
                    blocked_streams: 1,
                },
                u64::MAX,
            )
            .unwrap_err()
            .code,
        ErrorCode::InternalError
    );

    let mut literal = Encoder::new(Settings::default()).unwrap();
    literal.configure(Settings::default(), u64::MAX).unwrap();
    assert_eq!(
        literal
            .encode(
                0,
                vec![Field {
                    name: Bytes::from_static(b"x"),
                    value: Bytes::from(vec![b'a'; crate::frame::MAX_BUFFERED_FRAME_PAYLOAD]),
                    never_index: false,
                }],
            )
            .unwrap_err()
            .code,
        ErrorCode::ExcessiveLoad
    );

    let (mut encoder, _) = configured(128, 1);
    encoder
        .encode(0, vec![field(b"x-ack", b"value", false)])
        .unwrap();
    assert_eq!(
        encoder
            .on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0))
            .unwrap_err()
            .code,
        ErrorCode::QpackDecoderStreamError
    );
    encoder.record_insert_written();
    encoder
        .on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0))
        .unwrap();
    assert_eq!(
        encoder
            .on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0))
            .unwrap_err()
            .code,
        ErrorCode::QpackDecoderStreamError
    );
}

#[test]
fn acknowledged_entries_can_be_evicted_and_dynamic_names_can_be_reused() {
    let (mut encoder, batches) = configured(72, 1);
    encoder.encode(0, vec![field(b"aa", b"11", false)]).unwrap();
    encoder.record_insert_written();
    encoder
        .on_decoder_instruction(DecoderInstruction::InsertCountIncrement(1))
        .unwrap();
    encoder
        .on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0))
        .unwrap();
    encoder.encode(4, vec![field(b"aa", b"22", false)]).unwrap();
    assert!(batches.lock().unwrap().iter().flatten().any(|instruction| {
        matches!(
            instruction,
            EncoderInstruction::InsertWithNameReference {
                static_table: false,
                ..
            }
        )
    }));
}

#[test]
fn oversized_value_reuses_an_existing_dynamic_name_without_inserting() {
    let (mut encoder, _) = configured(72, 1);
    encoder.encode(0, vec![field(b"aa", b"11", false)]).unwrap();
    let wire = encoder
        .encode(
            0,
            vec![Field {
                name: Bytes::from_static(b"aa"),
                value: Bytes::from(vec![b'x'; 80]),
                never_index: false,
            }],
        )
        .unwrap();
    assert!(!wire.is_empty());
}
