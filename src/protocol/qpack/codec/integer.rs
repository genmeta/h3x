//! Shared QPACK integer wire primitives (RFC 9204 section 4.1.1).
use bytes::BufMut;
use qbase::varint::VARINT_MAX;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{ErrorCode, Result};

pub(super) async fn be_byte<T: AsyncRead + Unpin + ?Sized>(reader: &mut T) -> Result<u8> {
    reader
        .read_u8()
        .await
        .map_err(|_| ErrorCode::H3_CLOSED_CRITICAL_STREAM)
}

pub(super) async fn be_prefixed_integer_with_first<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    first: u8,
    bits: u8,
    error: ErrorCode,
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
            let byte = be_byte(reader).await?;
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

/// RFC 9204 section 4.1.1: decode a prefixed integer, limited to 62 bits.
pub(super) fn be_prefixed_integer(mut input: &[u8], prefix_bits: u8) -> Result<(&[u8], u64)> {
    let (&first, rest) = input
        .split_first()
        .ok_or(ErrorCode::QPACK_DECOMPRESSION_FAILED)?;
    input = rest;
    let limit = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first) & limit;
    if value < limit {
        return Ok((input, value));
    }
    for shift in (0..63).step_by(7) {
        let (&byte, rest) = input
            .split_first()
            .ok_or(ErrorCode::QPACK_DECOMPRESSION_FAILED)?;
        input = rest;
        value = value
            .checked_add(u64::from(byte & 0x7f) << shift)
            .filter(|&value| value <= VARINT_MAX)
            .ok_or(ErrorCode::QPACK_DECOMPRESSION_FAILED)?;
        if byte & 0x80 == 0 {
            return Ok((input, value));
        }
    }
    Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
}

/// Append a QPACK prefixed integer (not a QUIC varint).
pub(super) trait WritePrefixedInteger {
    fn put_prefixed_integer(&mut self, value: u64, prefix_bits: u8, high_bits: u8) -> Result<()>;
}

impl<B: BufMut> WritePrefixedInteger for B {
    fn put_prefixed_integer(
        &mut self,
        mut value: u64,
        prefix_bits: u8,
        high_bits: u8,
    ) -> Result<()> {
        if value > VARINT_MAX {
            return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED);
        }
        let limit = (1u64 << prefix_bits) - 1;
        if value < limit {
            self.put_u8(high_bits | value as u8);
            return Ok(());
        }
        self.put_u8(high_bits | limit as u8);
        value -= limit;
        while value >= 128 {
            self.put_u8((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        self.put_u8(value as u8);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_integers_preserve_suffixes_and_reject_overflow() {
        for bits in [3, 4, 6, 7, 8] {
            for value in [0, (1 << bits) - 1, 127, 128, VARINT_MAX] {
                let mut output = Vec::new();
                output.put_prefixed_integer(value, bits, 0).unwrap();
                output.push(42);
                let (input, decoded) = be_prefixed_integer(output.as_slice(), bits).unwrap();
                assert_eq!(decoded, value);
                assert_eq!(input, &[42]);
            }
        }
        assert!(be_prefixed_integer(&[0xff; 12][..], 8).is_err());
        assert!(
            Vec::new()
                .put_prefixed_integer(VARINT_MAX + 1, 8, 0)
                .is_err()
        );
    }

    #[test]
    fn known_wire_vectors_cover_prefix_and_continuation_boundaries() {
        for (value, expected) in [
            (10, &[0xea][..]),
            (31, &[0xff, 0][..]),
            (1337, &[0xff, 0x9a, 0x0a][..]),
        ] {
            let mut wire = Vec::new();
            wire.put_prefixed_integer(value, 5, 0xe0).unwrap();
            assert_eq!(wire, expected);
            assert_eq!(be_prefixed_integer(expected, 5), Ok((&[][..], value)));
        }
        let mut wire = vec![42];
        assert_eq!(
            wire.put_prefixed_integer(VARINT_MAX + 1, 5, 0),
            Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
        );
        assert_eq!(wire, [42]);
    }

    #[tokio::test]
    async fn stream_integer_preserves_suffix_and_distinguishes_eof_from_overflow() {
        for bits in 1..=7 {
            for value in [0, (1 << bits) - 1, 128, VARINT_MAX] {
                let mut wire = Vec::new();
                wire.put_prefixed_integer(value, bits, 0x80).unwrap();
                wire.push(42);
                let mut input = &wire[1..];
                assert_eq!(
                    be_prefixed_integer_with_first(
                        &mut input,
                        wire[0],
                        bits,
                        ErrorCode::QPACK_DECODER_STREAM_ERROR
                    )
                    .await,
                    Ok(value)
                );
                assert_eq!(input, &[42]);
            }
        }
        for wire in [&[0x1f][..], &[0x1f, 0x80][..]] {
            assert_eq!(
                be_prefixed_integer(wire, 5),
                Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
            );
            assert_eq!(
                be_prefixed_integer_with_first(
                    &mut &wire[1..],
                    wire[0],
                    5,
                    ErrorCode::QPACK_DECODER_STREAM_ERROR
                )
                .await,
                Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
            );
        }
        for error in [
            ErrorCode::QPACK_ENCODER_STREAM_ERROR,
            ErrorCode::QPACK_DECODER_STREAM_ERROR,
        ] {
            assert_eq!(
                be_prefixed_integer_with_first(&mut &[0xff; 9][..], 0xff, 7, error).await,
                Err(error)
            );
        }
    }
}
