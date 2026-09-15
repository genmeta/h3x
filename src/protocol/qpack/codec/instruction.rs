//! QPACK instruction wire format (RFC 9204 sections 4.3 and 4.4).
//! Dynamic-table and outstanding-section validation belongs to the codec state.
use bytes::{BufMut, Bytes};
use tokio::io::AsyncRead;

use super::{
    integer::{WritePrefixedInteger, be_byte, be_prefixed_integer_with_first},
    string_literal::{WriteStringLiteral, be_string_literal, be_string_literal_with_first},
};
use crate::{Error, Result, protocol::frame::MAX_BUFFERED_FRAME_PAYLOAD};

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
        let result = match instruction {
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
                    return Err(Error::QPACK_ENCODER_STREAM_ERROR);
                }
                if value.len() > MAX_BUFFERED_FRAME_PAYLOAD {
                    return Err(Error::H3_EXCESSIVE_LOAD);
                }
                self.put_prefixed_integer(*index, 6, 0x80 | (u8::from(*static_table) << 6))
                    .and_then(|()| self.put_string_literal(value, 8, 0))
            }
            EncoderInstruction::InsertWithLiteralName { name, value } => {
                if name.len() > MAX_BUFFERED_FRAME_PAYLOAD
                    || value.len() > MAX_BUFFERED_FRAME_PAYLOAD
                {
                    return Err(Error::H3_EXCESSIVE_LOAD);
                }
                self.put_string_literal(name, 6, 0x40)
                    .and_then(|()| self.put_string_literal(value, 8, 0))
            }
        };
        result.map_err(|_| Error::QPACK_ENCODER_STREAM_ERROR)?;
        Ok(())
    }

    fn put_decoder_instruction(&mut self, instruction: &DecoderInstruction) -> Result<()> {
        let (value, bits, high) = match *instruction {
            DecoderInstruction::SectionAcknowledgment(id) => (id, 7, 0x80),
            DecoderInstruction::StreamCancellation(id) => (id, 6, 0x40),
            DecoderInstruction::InsertCountIncrement(0) => {
                return Err(Error::QPACK_DECODER_STREAM_ERROR);
            }
            DecoderInstruction::InsertCountIncrement(count) => (count, 6, 0),
        };
        self.put_prefixed_integer(value, bits, high)
            .map_err(|_| Error::QPACK_DECODER_STREAM_ERROR)?;
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
            be_prefixed_integer_with_first(reader, first, 6, Error::QPACK_ENCODER_STREAM_ERROR)
                .await?;
        let static_table = first & 0x40 != 0;
        if static_table && super::super::table::get(index).is_none() {
            return Err(Error::QPACK_ENCODER_STREAM_ERROR);
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
            be_prefixed_integer_with_first(reader, first, 5, Error::QPACK_ENCODER_STREAM_ERROR)
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
        be_prefixed_integer_with_first(reader, first, bits, Error::QPACK_DECODER_STREAM_ERROR)
            .await?;
    if first & 0x80 != 0 {
        Ok(DecoderInstruction::SectionAcknowledgment(value))
    } else if first & 0x40 != 0 {
        Ok(DecoderInstruction::StreamCancellation(value))
    } else if value != 0 {
        Ok(DecoderInstruction::InsertCountIncrement(value))
    } else {
        Err(Error::QPACK_DECODER_STREAM_ERROR)
    }
}

#[cfg(test)]
mod tests {
    use qbase::varint::VARINT_MAX;

    use super::*;

    #[tokio::test]
    async fn wire_vectors_and_invalid_instructions() {
        let encoder = [
            (
                EncoderInstruction::SetDynamicTableCapacity(220),
                vec![0x3f, 0xbd, 1],
            ),
            (
                EncoderInstruction::InsertWithNameReference {
                    static_table: true,
                    index: 0,
                    value: Bytes::from_static(b"x"),
                },
                vec![0xc0, 1, b'x'],
            ),
            (
                EncoderInstruction::InsertWithNameReference {
                    static_table: false,
                    index: 0,
                    value: Bytes::new(),
                },
                vec![0x80, 0],
            ),
            (
                EncoderInstruction::InsertWithLiteralName {
                    name: Bytes::from_static(b"x"),
                    value: Bytes::from_static(b"y"),
                },
                vec![0x41, b'x', 1, b'y'],
            ),
            (EncoderInstruction::Duplicate(0), vec![0]),
        ];
        for (instruction, wire) in encoder {
            let mut encoded = Vec::new();
            encoded.put_encoder_instruction(&instruction).unwrap();
            assert_eq!(encoded, wire);
            let mut input = wire.as_slice();
            assert_eq!(
                be_encoder_instruction(&mut input).await.unwrap(),
                instruction
            );
            assert!(input.is_empty());
            for end in 0..wire.len() {
                assert_eq!(
                    be_encoder_instruction(&mut &wire[..end]).await,
                    Err(Error::H3_CLOSED_CRITICAL_STREAM)
                );
            }
        }
        for (instruction, wire) in [
            (DecoderInstruction::SectionAcknowledgment(4), vec![0x84]),
            (DecoderInstruction::StreamCancellation(64), vec![0x7f, 1]),
            (DecoderInstruction::InsertCountIncrement(1), vec![1]),
        ] {
            let mut encoded = Vec::new();
            encoded.put_decoder_instruction(&instruction).unwrap();
            assert_eq!(encoded, wire);
            assert_eq!(
                be_decoder_instruction(&mut wire.as_slice()).await.unwrap(),
                instruction
            );
            for end in 0..wire.len() {
                assert_eq!(
                    be_decoder_instruction(&mut &wire[..end]).await,
                    Err(Error::H3_CLOSED_CRITICAL_STREAM)
                );
            }
        }
        for value in [31, 63, 127, 128, 16384, VARINT_MAX] {
            let instruction = EncoderInstruction::Duplicate(value);
            let mut encoded = Vec::new();
            encoded.put_encoder_instruction(&instruction).unwrap();
            assert_eq!(
                be_encoder_instruction(&mut encoded.as_slice())
                    .await
                    .unwrap(),
                instruction
            );
            let instruction = DecoderInstruction::SectionAcknowledgment(value);
            let mut encoded = Vec::new();
            encoded.put_decoder_instruction(&instruction).unwrap();
            assert_eq!(
                be_decoder_instruction(&mut encoded.as_slice())
                    .await
                    .unwrap(),
                instruction
            );
        }
        // Independently encoded HPACK Huffman string "www.example.com", name and value.
        let encoded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let mut wire = vec![0x6c];
        wire.extend_from_slice(&encoded);
        wire.push(0x8c);
        wire.extend_from_slice(&encoded);
        assert_eq!(
            be_encoder_instruction(&mut wire.as_slice()).await.unwrap(),
            EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"www.example.com"),
                value: Bytes::from_static(b"www.example.com")
            }
        );
        assert_eq!(
            be_decoder_instruction(&mut &[0][..]).await,
            Err(Error::QPACK_DECODER_STREAM_ERROR)
        );
        assert!(
            Vec::new()
                .put_decoder_instruction(&DecoderInstruction::InsertCountIncrement(0))
                .is_err()
        );
        assert!(
            Vec::new()
                .put_encoder_instruction(&EncoderInstruction::Duplicate(VARINT_MAX + 1))
                .is_err()
        );
        for wire in [vec![0xff; 10], vec![0xff, 36], vec![0x61, 0xff, 0]] {
            assert_eq!(
                be_encoder_instruction(&mut wire.as_slice()).await,
                Err(Error::QPACK_ENCODER_STREAM_ERROR)
            );
        }
        assert_eq!(
            be_decoder_instruction(&mut &[0xff; 10][..]).await,
            Err(Error::QPACK_DECODER_STREAM_ERROR)
        );
        let mut oversized = Vec::new();
        oversized
            .put_prefixed_integer(MAX_BUFFERED_FRAME_PAYLOAD as u64 + 1, 5, 0x40)
            .unwrap();
        assert_eq!(
            be_encoder_instruction(&mut oversized.as_slice()).await,
            Err(Error::H3_EXCESSIVE_LOAD)
        );
    }
}
