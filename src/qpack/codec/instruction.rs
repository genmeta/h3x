//! QPACK instruction wire format (RFC 9204 sections 4.3 and 4.4).
//! Dynamic-table and outstanding-section validation belongs to the codec state.
use bytes::{BufMut, Bytes};
use tokio::io::AsyncRead;

use super::{
    integer::{WritePrefixedInteger, be_byte, be_prefixed_integer_with_first},
    string_literal::{WriteStringLiteral, be_string_literal, be_string_literal_with_first},
};
use crate::{ErrorCode, Result, frame::MAX_BUFFERED_FRAME_PAYLOAD};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EncoderInstruction {
    SetDynamicTableCapacity(u64),
    InsertWithNameReference {
        static_table: bool,
        index: u64,
        value: Bytes,
    },
    InsertWithLiteralName {
        name: Bytes,
        value: Bytes,
    },
    Duplicate(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DecoderInstruction {
    SectionAcknowledgment(u64),
    StreamCancellation(u64),
    InsertCountIncrement(u64),
}

/// Append instructions to a caller-owned buffer, like frame::WriteControl.
pub(crate) trait WriteInstruction {
    fn put_encoder_instruction(&mut self, instruction: &EncoderInstruction) -> Result<()>;
    fn put_decoder_instruction(&mut self, instruction: &DecoderInstruction) -> Result<()>;
}

impl<B: BufMut> WriteInstruction for B {
    fn put_encoder_instruction(&mut self, instruction: &EncoderInstruction) -> Result<()> {
        let result =
            match instruction {
                EncoderInstruction::SetDynamicTableCapacity(capacity) => {
                    self.put_prefixed_integer(*capacity, 5, 0x20)
                }
                EncoderInstruction::Duplicate(index) => self.put_prefixed_integer(*index, 5, 0),
                EncoderInstruction::InsertWithNameReference {
                    static_table,
                    index,
                    value,
                } => {
                    if *static_table && super::super::table::get(*index).is_none() {
                        return Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR
                            .reason("invalid QPACK encoder instruction"));
                    }
                    if value.len() > MAX_BUFFERED_FRAME_PAYLOAD {
                        return Err(ErrorCode::H3_EXCESSIVE_LOAD
                            .reason("configured resource limit exceeded"));
                    }
                    self.put_prefixed_integer(*index, 6, 0x80 | (u8::from(*static_table) << 6))
                        .and_then(|()| self.put_string_literal(value, 8, 0))
                }
                EncoderInstruction::InsertWithLiteralName { name, value } => {
                    if name.len() > MAX_BUFFERED_FRAME_PAYLOAD
                        || value.len() > MAX_BUFFERED_FRAME_PAYLOAD
                    {
                        return Err(ErrorCode::H3_EXCESSIVE_LOAD
                            .reason("configured resource limit exceeded"));
                    }
                    self.put_string_literal(name, 6, 0x40)
                        .and_then(|()| self.put_string_literal(value, 8, 0))
                }
            };
        result.map_err(|error| {
            ErrorCode::QPACK_ENCODER_STREAM_ERROR
                .reason(format!("invalid QPACK encoder instruction: {error}"))
        })?;
        Ok(())
    }

    fn put_decoder_instruction(&mut self, instruction: &DecoderInstruction) -> Result<()> {
        let (value, bits, high) = match *instruction {
            DecoderInstruction::SectionAcknowledgment(id) => (id, 7, 0x80),
            DecoderInstruction::StreamCancellation(id) => (id, 6, 0x40),
            DecoderInstruction::InsertCountIncrement(0) => {
                return Err(ErrorCode::QPACK_DECODER_STREAM_ERROR
                    .reason("invalid QPACK decoder instruction"));
            }
            DecoderInstruction::InsertCountIncrement(count) => (count, 6, 0),
        };
        self.put_prefixed_integer(value, bits, high)
            .map_err(|error| {
                ErrorCode::QPACK_DECODER_STREAM_ERROR
                    .reason(format!("invalid QPACK decoder instruction: {error}"))
            })?;
        Ok(())
    }
}

/// Read one instruction; a partial instruction or EOF closes the critical stream.
pub(crate) async fn be_encoder_instruction<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
) -> Result<EncoderInstruction> {
    let first = be_byte(reader).await?;
    if first & 0x80 != 0 {
        let index =
            be_prefixed_integer_with_first(reader, first, 6, ErrorCode::QPACK_ENCODER_STREAM_ERROR)
                .await?;
        let static_table = first & 0x40 != 0;
        if static_table && super::super::table::get(index).is_none() {
            return Err(
                ErrorCode::QPACK_ENCODER_STREAM_ERROR.reason("invalid QPACK encoder instruction")
            );
        }
        let value = be_string_literal(reader, 8).await?;
        Ok(EncoderInstruction::InsertWithNameReference {
            static_table,
            index,
            value,
        })
    } else if first & 0x40 != 0 {
        let name = be_string_literal_with_first(reader, first, 6).await?;
        let value = be_string_literal(reader, 8).await?;
        Ok(EncoderInstruction::InsertWithLiteralName { name, value })
    } else {
        let value =
            be_prefixed_integer_with_first(reader, first, 5, ErrorCode::QPACK_ENCODER_STREAM_ERROR)
                .await?;
        Ok(if first & 0x20 != 0 {
            EncoderInstruction::SetDynamicTableCapacity(value)
        } else {
            EncoderInstruction::Duplicate(value)
        })
    }
}

/// Read one acknowledgment, cancellation, or insert-count increment.
pub(crate) async fn be_decoder_instruction<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
) -> Result<DecoderInstruction> {
    let first = be_byte(reader).await?;
    let bits = if first & 0x80 != 0 { 7 } else { 6 };
    let value =
        be_prefixed_integer_with_first(reader, first, bits, ErrorCode::QPACK_DECODER_STREAM_ERROR)
            .await?;
    if first & 0x80 != 0 {
        Ok(DecoderInstruction::SectionAcknowledgment(value))
    } else if first & 0x40 != 0 {
        Ok(DecoderInstruction::StreamCancellation(value))
    } else if value != 0 {
        Ok(DecoderInstruction::InsertCountIncrement(value))
    } else {
        Err(ErrorCode::QPACK_DECODER_STREAM_ERROR.reason("invalid QPACK decoder instruction"))
    }
}

#[cfg(test)]
mod tests {
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
            ErrorCode::QPACK_DECODER_STREAM_ERROR
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
        assert_eq!(error.code, ErrorCode::QPACK_ENCODER_STREAM_ERROR);
        assert_eq!(wire, [0xaa]);
    }
}
