use std::task::{Context, Poll, Waker};

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

fn make_decoder(blocked_streams: u64, blocked_bytes: usize, max_fields: u64) -> Decoder {
    let mut decoder =
        Decoder::new(settings(128, blocked_streams), blocked_bytes, max_fields).unwrap();
    decoder
        .on_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(128))
        .unwrap();
    decoder
}

#[test]
fn blocked_decode_resumes_after_insert_and_emits_ordered_feedback() {
    let mut decoder = make_decoder(2, 1024, 1024);
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

    assert_eq!(
        decoder.take_feedback().0,
        vec![
            DecoderInstruction::InsertCountIncrement(1),
            DecoderInstruction::SectionAcknowledgment(0),
        ]
    );
}

#[test]
fn unblocked_unpolled_decode_does_not_consume_blocked_stream_slot() {
    let mut decoder = make_decoder(1, 1024, 1024);
    let first = dynamic_wire(1, FieldLine::IndexedPostBase { index: 0 });
    let (first_offset, first_prefix) = decoder.begin_decode(0, &first).unwrap();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(
        decoder
            .poll_registered_decode(0, first_prefix, &first[first_offset..], &mut cx)
            .is_pending()
    );

    let wakes = decoder
        .on_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x-first"),
            value: Bytes::from_static(b"value"),
        })
        .unwrap();
    assert_eq!(wakes.len(), 1);

    // Do not repoll stream 0. Its waiter is retained, but RIC=1 is now satisfied.
    let second = dynamic_wire(2, FieldLine::IndexedPostBase { index: 0 });
    let (second_offset, second_prefix) = decoder.begin_decode(4, &second).unwrap();
    assert!(
        decoder
            .poll_registered_decode(4, second_prefix, &second[second_offset..], &mut cx)
            .is_pending()
    );
}

#[test]
fn cancellation_and_blocking_budgets_clean_up_waiters() {
    let wire = dynamic_wire(1, FieldLine::IndexedPostBase { index: 0 });
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let mut decoder = make_decoder(1, 1024, 1024);
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
        decoder.take_feedback().0.last(),
        Some(DecoderInstruction::StreamCancellation(4))
    ));
    assert!(
        decoder
            .poll_registered_decode(4, prefix, &wire[offset..], &mut cx)
            .is_ready()
    );
    assert_eq!(
        decoder.cancel(vec![VARINT_MAX + 1]).unwrap_err().code,
        ErrorCode::InternalError
    );

    let mut no_stream_slots = make_decoder(0, 1024, 1024);
    let (offset, prefix) = no_stream_slots.begin_decode(8, &wire).unwrap();
    let Poll::Ready(Err(error)) =
        no_stream_slots.poll_registered_decode(8, prefix, &wire[offset..], &mut cx)
    else {
        panic!("blocked-stream limit must reject")
    };
    assert_eq!(error.code, ErrorCode::QpackDecompressionFailed);

    let mut no_bytes = make_decoder(1, 0, 1024);
    let (offset, prefix) = no_bytes.begin_decode(12, &wire).unwrap();
    let Poll::Ready(Err(error)) =
        no_bytes.poll_registered_decode(12, prefix, &wire[offset..], &mut cx)
    else {
        panic!("blocked-byte limit must reject")
    };
    assert_eq!(error.code, ErrorCode::ExcessiveLoad);

    let mut waiting = make_decoder(2, 1024, 1024);
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
fn malformed_sections_and_settings_are_rejected() {
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

    let mut decoder = make_decoder(1, 1024, 50);
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
}
