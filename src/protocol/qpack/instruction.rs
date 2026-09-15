//! QPACK instruction wire format (RFC 9204 sections 4.3 and 4.4).
//! Dynamic-table and outstanding-section validation belongs to the codec state.
use bytes::{BufMut, Bytes};
use qbase::varint::VARINT_MAX;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::string_literal::{WriteStringLiteral, be_string_literal, be_string_literal_with_first};
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

impl EncoderInstruction {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let result = match self {
            Self::SetDynamicTableCapacity(capacity) => {
                put_prefixed_integer(&mut out, *capacity, 5, 0x20)
            }
            Self::Duplicate(index) => put_prefixed_integer(&mut out, *index, 5, 0),
            Self::InsertWithNameReference {
                static_table,
                index,
                value,
            } => {
                if *static_table && super::table::get(*index).is_none() {
                    return Err(Error::QPACK_ENCODER_STREAM_ERROR);
                }
                if value.len() > MAX_BUFFERED_FRAME_PAYLOAD {
                    return Err(Error::H3_EXCESSIVE_LOAD);
                }
                put_prefixed_integer(&mut out, *index, 6, 0x80 | (u8::from(*static_table) << 6))
                    .and_then(|()| out.put_string_literal(value, 8, 0))
            }
            Self::InsertWithLiteralName { name, value } => {
                if name.len() > MAX_BUFFERED_FRAME_PAYLOAD
                    || value.len() > MAX_BUFFERED_FRAME_PAYLOAD
                {
                    return Err(Error::H3_EXCESSIVE_LOAD);
                }
                out.put_string_literal(name, 6, 0x40)
                    .and_then(|()| out.put_string_literal(value, 8, 0))
            }
        };
        result.map_err(|_| Error::QPACK_ENCODER_STREAM_ERROR)?;
        Ok(out)
    }

    pub(crate) async fn read(reader: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        let first = read_byte(reader).await?;
        if first & 0x80 != 0 {
            let index = read_integer(reader, first, 6, Error::QPACK_ENCODER_STREAM_ERROR).await?;
            let static_table = first & 0x40 != 0;
            if static_table && super::table::get(index).is_none() {
                return Err(Error::QPACK_ENCODER_STREAM_ERROR);
            }
            let value = be_string_literal(reader, 8).await?;
            Ok(Self::InsertWithNameReference {
                static_table,
                index,
                value,
            })
        } else if first & 0x40 != 0 {
            let name = be_string_literal_with_first(reader, first, 6).await?;
            let value = be_string_literal(reader, 8).await?;
            Ok(Self::InsertWithLiteralName { name, value })
        } else {
            let value = read_integer(reader, first, 5, Error::QPACK_ENCODER_STREAM_ERROR).await?;
            Ok(if first & 0x20 != 0 {
                Self::SetDynamicTableCapacity(value)
            } else {
                Self::Duplicate(value)
            })
        }
    }
}

impl DecoderInstruction {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let (value, bits, high) = match *self {
            Self::SectionAcknowledgment(id) => (id, 7, 0x80),
            Self::StreamCancellation(id) => (id, 6, 0x40),
            Self::InsertCountIncrement(0) => return Err(Error::QPACK_DECODER_STREAM_ERROR),
            Self::InsertCountIncrement(count) => (count, 6, 0),
        };
        let mut out = Vec::new();
        put_prefixed_integer(&mut out, value, bits, high)
            .map_err(|_| Error::QPACK_DECODER_STREAM_ERROR)?;
        Ok(out)
    }

    pub(crate) async fn read(reader: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        let first = read_byte(reader).await?;
        let bits = if first & 0x80 != 0 { 7 } else { 6 };
        let value = read_integer(reader, first, bits, Error::QPACK_DECODER_STREAM_ERROR).await?;
        if first & 0x80 != 0 {
            Ok(Self::SectionAcknowledgment(value))
        } else if first & 0x40 != 0 {
            Ok(Self::StreamCancellation(value))
        } else if value != 0 {
            Ok(Self::InsertCountIncrement(value))
        } else {
            Err(Error::QPACK_DECODER_STREAM_ERROR)
        }
    }
}

pub(super) async fn read_byte<T: AsyncRead + Unpin + ?Sized>(reader: &mut T) -> Result<u8> {
    reader
        .read_u8()
        .await
        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)
}

pub(super) async fn read_integer<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    first: u8,
    bits: u8,
    error: Error,
) -> Result<u64> {
    let mut wire = [0u8; 10];
    wire[0] = first;
    let mask = (1u8 << bits) - 1;
    let mut len = 1;
    if first & mask == mask {
        loop {
            if len == wire.len() {
                return Err(error);
            }
            let byte = read_byte(reader).await?;
            wire[len] = byte;
            len += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    be_prefixed_integer(&wire[..len], bits)
        .map(|(_, value)| value)
        .map_err(|_| error)
}

/// RFC 9204 section 4.1.1; RFC 7541 section 5.1. Not a QUIC varint.
pub(super) fn put_prefixed_integer(
    output: &mut impl BufMut,
    mut value: u64,
    prefix_bits: u8,
    high_bits: u8,
) -> Result<()> {
    if value > VARINT_MAX {
        return Err(Error::QPACK_DECOMPRESSION_FAILED);
    }
    let limit = (1u64 << prefix_bits) - 1;
    if value < limit {
        output.put_u8(high_bits | value as u8);
        return Ok(());
    }
    output.put_u8(high_bits | limit as u8);
    value -= limit;
    while value >= 128 {
        output.put_u8((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.put_u8(value as u8);
    Ok(())
}

/// RFC 9204 section 4.1.1: decode a prefixed integer, limited to 62 bits.
pub(super) fn be_prefixed_integer(mut input: &[u8], prefix_bits: u8) -> Result<(&[u8], u64)> {
    let (&first, rest) = input
        .split_first()
        .ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
    input = rest;
    let limit = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first) & limit;
    if value < limit {
        return Ok((input, value));
    }
    for shift in (0..63).step_by(7) {
        let (&byte, rest) = input
            .split_first()
            .ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
        input = rest;
        value = value
            .checked_add(u64::from(byte & 0x7f) << shift)
            .filter(|&value| value <= VARINT_MAX)
            .ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
        if byte & 0x80 == 0 {
            return Ok((input, value));
        }
    }
    Err(Error::QPACK_DECOMPRESSION_FAILED)
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
            assert_eq!(instruction.encode().unwrap(), wire);
            let mut input = wire.as_slice();
            assert_eq!(
                EncoderInstruction::read(&mut input).await.unwrap(),
                instruction
            );
            assert!(input.is_empty());
            for end in 0..wire.len() {
                assert_eq!(
                    EncoderInstruction::read(&mut &wire[..end]).await,
                    Err(Error::H3_CLOSED_CRITICAL_STREAM)
                );
            }
        }
        for (instruction, wire) in [
            (DecoderInstruction::SectionAcknowledgment(4), vec![0x84]),
            (DecoderInstruction::StreamCancellation(64), vec![0x7f, 1]),
            (DecoderInstruction::InsertCountIncrement(1), vec![1]),
        ] {
            assert_eq!(instruction.encode().unwrap(), wire);
            assert_eq!(
                DecoderInstruction::read(&mut wire.as_slice())
                    .await
                    .unwrap(),
                instruction
            );
            for end in 0..wire.len() {
                assert_eq!(
                    DecoderInstruction::read(&mut &wire[..end]).await,
                    Err(Error::H3_CLOSED_CRITICAL_STREAM)
                );
            }
        }
        for value in [31, 63, 127, 128, 16384, VARINT_MAX] {
            let instruction = EncoderInstruction::Duplicate(value);
            assert_eq!(
                EncoderInstruction::read(&mut instruction.encode().unwrap().as_slice())
                    .await
                    .unwrap(),
                instruction
            );
            let instruction = DecoderInstruction::SectionAcknowledgment(value);
            assert_eq!(
                DecoderInstruction::read(&mut instruction.encode().unwrap().as_slice())
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
            EncoderInstruction::read(&mut wire.as_slice())
                .await
                .unwrap(),
            EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"www.example.com"),
                value: Bytes::from_static(b"www.example.com")
            }
        );
        assert_eq!(
            DecoderInstruction::read(&mut &[0][..]).await,
            Err(Error::QPACK_DECODER_STREAM_ERROR)
        );
        assert!(
            DecoderInstruction::InsertCountIncrement(0)
                .encode()
                .is_err()
        );
        assert!(
            EncoderInstruction::Duplicate(VARINT_MAX + 1)
                .encode()
                .is_err()
        );
        for wire in [vec![0xff; 10], vec![0xff, 36], vec![0x61, 0xff, 0]] {
            assert_eq!(
                EncoderInstruction::read(&mut wire.as_slice()).await,
                Err(Error::QPACK_ENCODER_STREAM_ERROR)
            );
        }
        assert_eq!(
            DecoderInstruction::read(&mut &[0xff; 10][..]).await,
            Err(Error::QPACK_DECODER_STREAM_ERROR)
        );
        let mut oversized = Vec::new();
        put_prefixed_integer(
            &mut oversized,
            MAX_BUFFERED_FRAME_PAYLOAD as u64 + 1,
            5,
            0x40,
        )
        .unwrap();
        assert_eq!(
            EncoderInstruction::read(&mut oversized.as_slice()).await,
            Err(Error::H3_EXCESSIVE_LOAD)
        );
    }

    #[test]
    fn prefixed_integers_preserve_suffixes_and_reject_overflow() {
        for bits in [3, 4, 6, 7, 8] {
            for value in [0, (1 << bits) - 1, 127, 128, VARINT_MAX] {
                let mut output = Vec::new();
                put_prefixed_integer(&mut output, value, bits, 0).unwrap();
                output.push(42);
                let (input, decoded) = be_prefixed_integer(output.as_slice(), bits).unwrap();
                assert_eq!(decoded, value);
                assert_eq!(input, &[42]);
            }
        }
        assert!(be_prefixed_integer(&[0xff; 12][..], 8).is_err());
        assert!(put_prefixed_integer(&mut Vec::new(), VARINT_MAX + 1, 8, 0).is_err());
    }
}
