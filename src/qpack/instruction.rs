use bytes::Bytes;
use httlib_huffman::DecoderSpeed;

use crate::{Code, Error, stream_id::MAX_VARINT};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EncoderInstruction {
    SetCapacity(u64),
    InsertNameReference {
        is_static: bool,
        index: u64,
        value: Bytes,
    },
    InsertLiteral {
        name: Bytes,
        value: Bytes,
    },
    Duplicate(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DecoderInstruction {
    SectionAcknowledgement(u64),
    StreamCancellation(u64),
    InsertCountIncrement(u64),
}

pub(super) fn encode_encoder(instruction: &EncoderInstruction) -> Result<Bytes, Error> {
    let mut output = Vec::new();
    match instruction {
        EncoderInstruction::SetCapacity(capacity) => {
            encode_integer(*capacity, 5, 0x20, &mut output)?;
        }
        EncoderInstruction::InsertNameReference {
            is_static,
            index,
            value,
        } => {
            encode_integer(
                *index,
                6,
                0x80 | if *is_static { 0x40 } else { 0 },
                &mut output,
            )?;
            encode_string(value, 7, 0, &mut output)?;
        }
        EncoderInstruction::InsertLiteral { name, value } => {
            encode_integer(name.len() as u64, 5, 0x40, &mut output)?;
            output.extend_from_slice(name);
            encode_string(value, 7, 0, &mut output)?;
        }
        EncoderInstruction::Duplicate(index) => {
            encode_integer(*index, 5, 0, &mut output)?;
        }
    }
    Ok(Bytes::from(output))
}

pub(super) fn encode_decoder(instruction: DecoderInstruction) -> Result<Bytes, Error> {
    let mut output = Vec::new();
    match instruction {
        DecoderInstruction::SectionAcknowledgement(stream_id) => {
            encode_integer(stream_id, 7, 0x80, &mut output)?;
        }
        DecoderInstruction::StreamCancellation(stream_id) => {
            encode_integer(stream_id, 6, 0x40, &mut output)?;
        }
        DecoderInstruction::InsertCountIncrement(increment) => {
            encode_integer(increment, 6, 0, &mut output)?;
        }
    }
    Ok(Bytes::from(output))
}

pub(super) fn decode_encoder(encoded: &[u8]) -> Result<Option<(EncoderInstruction, usize)>, Error> {
    decode_encoder_inner(encoded).map_err(encoder_stream_error)
}

pub(super) fn decode_decoder(encoded: &[u8]) -> Result<Option<(DecoderInstruction, usize)>, Error> {
    decode_decoder_inner(encoded).map_err(decoder_stream_error)
}

fn decode_encoder_inner(
    encoded: &[u8],
) -> Result<Option<(EncoderInstruction, usize)>, &'static str> {
    let Some(first) = encoded.first().copied() else {
        return Ok(None);
    };

    if first & 0x80 != 0 {
        let Some((index, prefix_len)) = decode_integer(encoded, 6)? else {
            return Ok(None);
        };
        let Some((value, value_len)) = decode_string(&encoded[prefix_len..], 7)? else {
            return Ok(None);
        };
        return Ok(Some((
            EncoderInstruction::InsertNameReference {
                is_static: first & 0x40 != 0,
                index,
                value,
            },
            prefix_len + value_len,
        )));
    }

    if first & 0xc0 == 0x40 {
        let Some((name, name_len)) = decode_string(encoded, 5)? else {
            return Ok(None);
        };
        let Some((value, value_len)) = decode_string(&encoded[name_len..], 7)? else {
            return Ok(None);
        };
        return Ok(Some((
            EncoderInstruction::InsertLiteral { name, value },
            name_len + value_len,
        )));
    }

    if first & 0xe0 == 0x20 {
        let Some((capacity, consumed)) = decode_integer(encoded, 5)? else {
            return Ok(None);
        };
        return Ok(Some((EncoderInstruction::SetCapacity(capacity), consumed)));
    }

    let Some((index, consumed)) = decode_integer(encoded, 5)? else {
        return Ok(None);
    };
    Ok(Some((EncoderInstruction::Duplicate(index), consumed)))
}

fn decode_decoder_inner(
    encoded: &[u8],
) -> Result<Option<(DecoderInstruction, usize)>, &'static str> {
    let Some(first) = encoded.first().copied() else {
        return Ok(None);
    };
    if first & 0x80 != 0 {
        let Some((stream_id, consumed)) = decode_integer(encoded, 7)? else {
            return Ok(None);
        };
        return Ok(Some((
            DecoderInstruction::SectionAcknowledgement(stream_id),
            consumed,
        )));
    }
    if first & 0xc0 == 0x40 {
        let Some((stream_id, consumed)) = decode_integer(encoded, 6)? else {
            return Ok(None);
        };
        return Ok(Some((
            DecoderInstruction::StreamCancellation(stream_id),
            consumed,
        )));
    }

    let Some((increment, consumed)) = decode_integer(encoded, 6)? else {
        return Ok(None);
    };
    if increment == 0 {
        return Err("QPACK Insert Count Increment cannot be zero");
    }
    Ok(Some((
        DecoderInstruction::InsertCountIncrement(increment),
        consumed,
    )))
}

fn encode_integer(
    mut value: u64,
    prefix_bits: u8,
    high_bits: u8,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    if value > MAX_VARINT {
        return Err(Error::connection_protocol(
            Code::QPACK_DECODER_STREAM_ERROR,
            "QPACK integer exceeds 62 bits",
        ));
    }
    let limit = (1u64 << prefix_bits) - 1;
    if value < limit {
        output.push(high_bits | value as u8);
        return Ok(());
    }

    output.push(high_bits | limit as u8);
    value -= limit;
    while value >= 128 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
    Ok(())
}

fn decode_integer(encoded: &[u8], prefix_bits: u8) -> Result<Option<(u64, usize)>, &'static str> {
    let Some(first) = encoded.first().copied() else {
        return Ok(None);
    };
    let limit = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first) & limit;
    if value < limit {
        return Ok(Some((value, 1)));
    }

    let mut shift = 0u32;
    for (offset, byte) in encoded[1..].iter().copied().enumerate() {
        if shift >= 63 {
            return Err("QPACK prefixed integer is too long");
        }
        let term = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or("QPACK prefixed integer overflow")?;
        value = value
            .checked_add(term)
            .ok_or("QPACK prefixed integer overflow")?;
        if value > MAX_VARINT {
            return Err("QPACK integer exceeds 62 bits");
        }
        if byte & 0x80 == 0 {
            return Ok(Some((value, offset + 2)));
        }
        shift += 7;
    }
    Ok(None)
}

fn encode_string(
    value: &[u8],
    prefix_bits: u8,
    high_bits: u8,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    encode_integer(value.len() as u64, prefix_bits, high_bits, output)?;
    output.extend_from_slice(value);
    Ok(())
}

fn decode_string(encoded: &[u8], prefix_bits: u8) -> Result<Option<(Bytes, usize)>, &'static str> {
    let Some(first) = encoded.first().copied() else {
        return Ok(None);
    };
    let Some((len, prefix_len)) = decode_integer(encoded, prefix_bits)? else {
        return Ok(None);
    };
    let len = usize::try_from(len).map_err(|_| "QPACK string is too large")?;
    let end = prefix_len
        .checked_add(len)
        .ok_or("QPACK string length overflow")?;
    if encoded.len() < end {
        return Ok(None);
    }
    let value = if first & (1 << prefix_bits) == 0 {
        Bytes::copy_from_slice(&encoded[prefix_len..end])
    } else {
        let mut decoded = Vec::new();
        httlib_huffman::decode(
            &encoded[prefix_len..end],
            &mut decoded,
            DecoderSpeed::FourBits,
        )
        .map_err(|_| "invalid QPACK Huffman string")?;
        Bytes::from(decoded)
    };
    Ok(Some((value, end)))
}

fn encoder_stream_error(message: &'static str) -> Error {
    Error::connection_protocol(Code::QPACK_ENCODER_STREAM_ERROR, message)
}

fn decoder_stream_error(message: &'static str) -> Error {
    Error::connection_protocol(Code::QPACK_DECODER_STREAM_ERROR, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_instructions_round_trip_and_wait_for_complete_input() {
        let instructions = [
            EncoderInstruction::SetCapacity(4096),
            EncoderInstruction::InsertNameReference {
                is_static: true,
                index: 1,
                value: Bytes::from_static(b"/index.html"),
            },
            EncoderInstruction::InsertLiteral {
                name: Bytes::from_static(b"x-test"),
                value: Bytes::from_static(b"value"),
            },
            EncoderInstruction::Duplicate(42),
        ];

        for expected in instructions {
            let bytes = encode_encoder(&expected).unwrap();
            for split in 0..bytes.len() {
                assert_eq!(decode_encoder(&bytes[..split]).unwrap(), None);
            }
            assert_eq!(
                decode_encoder(&bytes).unwrap(),
                Some((expected, bytes.len()))
            );
        }
    }

    #[test]
    fn decoder_instruction_wire_prefixes_are_stable() {
        for (instruction, expected) in [
            (DecoderInstruction::SectionAcknowledgement(4), vec![0x84]),
            (DecoderInstruction::StreamCancellation(4), vec![0x44]),
            (DecoderInstruction::InsertCountIncrement(1), vec![0x01]),
        ] {
            let encoded = encode_decoder(instruction).unwrap();
            assert_eq!(encoded.as_ref(), expected);
            assert_eq!(
                decode_decoder(&encoded).unwrap(),
                Some((instruction, encoded.len()))
            );
        }
    }

    #[test]
    fn matches_rfc_9204_appendix_b_instruction_vectors() {
        assert_eq!(
            encode_encoder(&EncoderInstruction::SetCapacity(220))
                .unwrap()
                .as_ref(),
            &[0x3f, 0xbd, 0x01]
        );
        assert_eq!(
            encode_encoder(&EncoderInstruction::InsertNameReference {
                is_static: true,
                index: 0,
                value: Bytes::from_static(b"www.example.com"),
            })
            .unwrap()
            .as_ref(),
            b"\xc0\x0fwww.example.com"
        );
        assert_eq!(
            encode_encoder(&EncoderInstruction::InsertLiteral {
                name: Bytes::from_static(b"custom-key"),
                value: Bytes::from_static(b"custom-value"),
            })
            .unwrap()
            .as_ref(),
            b"\x4acustom-key\x0ccustom-value"
        );
        assert_eq!(
            encode_decoder(DecoderInstruction::StreamCancellation(8))
                .unwrap()
                .as_ref(),
            &[0x48]
        );
    }

    #[test]
    fn zero_insert_increment_is_a_decoder_stream_error() {
        let error = decode_decoder(&[0]).unwrap_err();
        assert_eq!(error.code(), Some(Code::QPACK_DECODER_STREAM_ERROR));
    }
}
