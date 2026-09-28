use super::*;

#[tokio::test]
async fn encoder_instructions_round_trip() {
    let instructions = [
        EncoderInstruction::SetDynamicTableCapacity(4096),
        EncoderInstruction::InsertWithNameReference {
            static_table: true,
            index: 1,
            value: Bytes::from_static(b"/resource"),
        },
        EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x-name"),
            value: Bytes::from_static(b"x-value"),
        },
        EncoderInstruction::Duplicate(37),
    ];
    let mut wire = Vec::new();
    for instruction in &instructions {
        wire.put_encoder_instruction(instruction).unwrap();
    }

    let mut input = wire.as_slice();
    for expected in instructions {
        assert_eq!(be_encoder_instruction(&mut input).await.unwrap(), expected);
    }
    assert!(input.is_empty());
}

#[tokio::test]
async fn decoder_instructions_round_trip_and_reject_zero_increment() {
    let instructions = [
        DecoderInstruction::SectionAcknowledgment(1337),
        DecoderInstruction::StreamCancellation(42),
        DecoderInstruction::InsertCountIncrement(9),
    ];
    let mut wire = Vec::new();
    for instruction in &instructions {
        wire.put_decoder_instruction(instruction).unwrap();
    }

    let mut input = wire.as_slice();
    for expected in instructions {
        assert_eq!(be_decoder_instruction(&mut input).await.unwrap(), expected);
    }
    assert!(input.is_empty());

    let mut invalid = Vec::new();
    assert_eq!(
        invalid
            .put_decoder_instruction(&DecoderInstruction::InsertCountIncrement(0))
            .unwrap_err()
            .code,
        ErrorCode::QpackDecoderStreamError
    );
    assert!(invalid.is_empty());
}

#[test]
fn encoder_instruction_rejects_unknown_static_name_without_writing() {
    let mut wire = vec![0xaa];
    let error = wire
        .put_encoder_instruction(&EncoderInstruction::InsertWithNameReference {
            static_table: true,
            index: 99,
            value: Bytes::new(),
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::QpackEncoderStreamError);
    assert_eq!(wire, [0xaa]);
}

#[tokio::test]
async fn instruction_limits_and_invalid_wire_values_are_rejected() {
    let oversized = Bytes::from(vec![0; MAX_BUFFERED_FRAME_PAYLOAD + 1]);
    for instruction in [
        EncoderInstruction::InsertWithNameReference {
            static_table: true,
            index: 0,
            value: oversized.clone(),
        },
        EncoderInstruction::InsertWithLiteralName {
            name: oversized.clone(),
            value: Bytes::new(),
        },
        EncoderInstruction::InsertWithLiteralName {
            name: Bytes::new(),
            value: oversized,
        },
        EncoderInstruction::SetDynamicTableCapacity(u64::MAX),
    ] {
        assert!(Vec::new().put_encoder_instruction(&instruction).is_err());
    }
    assert!(
        Vec::new()
            .put_decoder_instruction(&DecoderInstruction::StreamCancellation(u64::MAX))
            .is_err()
    );

    let mut invalid_static = Vec::new();
    invalid_static.put_prefixed_integer(99, 6, 0xc0).unwrap();
    invalid_static.push(0);
    assert_eq!(
        be_encoder_instruction(&mut invalid_static.as_slice())
            .await
            .unwrap_err()
            .code,
        ErrorCode::QpackEncoderStreamError
    );
    assert_eq!(
        be_decoder_instruction(&mut &[0][..])
            .await
            .unwrap_err()
            .code,
        ErrorCode::QpackDecoderStreamError
    );
}
