//! Shared QPACK integer wire primitives (RFC 9204 section 4.1.1).
use bytes::BufMut;
use qbase::varint::VARINT_MAX;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{ErrorCode, Result};

pub(super) async fn be_byte<T: AsyncRead + Unpin + ?Sized>(reader: &mut T) -> Result<u8> {
    reader
        .read_u8()
        .await
        .map_err(|error| crate::Error::from_io(error, ErrorCode::ClosedCriticalStream))
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
                return Err(error.connection("prefixed integer has too many continuation bytes"));
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
        .map_err(|cause| error.connection(format!("invalid instruction integer: {cause}")))
}

/// RFC 9204 section 4.1.1: decode a prefixed integer, limited to 62 bits.
pub(super) fn be_prefixed_integer(mut input: &[u8], prefix_bits: u8) -> Result<(&[u8], u64)> {
    let (&first, rest) = input.split_first().ok_or_else(|| {
        ErrorCode::QpackDecompressionFailed.connection("prefixed integer is missing its first byte")
    })?;
    input = rest;
    let limit = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first) & limit;
    if value < limit {
        return Ok((input, value));
    }
    for shift in (0..63).step_by(7) {
        let (&byte, rest) = input.split_first().ok_or_else(|| {
            ErrorCode::QpackDecompressionFailed.connection("prefixed integer is truncated")
        })?;
        input = rest;
        value = value
            .checked_add(u64::from(byte & 0x7f) << shift)
            .filter(|&value| value <= VARINT_MAX)
            .ok_or_else(|| {
                ErrorCode::QpackDecompressionFailed
                    .stream("prefixed integer exceeds the implementation limit")
            })?;
        if byte & 0x80 == 0 {
            return Ok((input, value));
        }
    }
    Err(ErrorCode::QpackDecompressionFailed
        .stream("prefixed integer exceeds the implementation limit"))
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
            return Err(ErrorCode::QpackDecompressionFailed
                .connection("invalid prefixed-integer width, value, or high bits"));
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
    fn prefixed_integer_round_trips_rfc_examples_and_preserves_suffix() {
        for (value, expected) in [
            (10, vec![0x0a]),
            (31, vec![0x1f, 0x00]),
            (42, vec![0x1f, 0x0b]),
            (1337, vec![0x1f, 0x9a, 0x0a]),
        ] {
            let mut wire = Vec::new();
            wire.put_prefixed_integer(value, 5, 0xa0).unwrap();
            assert_eq!(
                wire,
                expected
                    .iter()
                    .enumerate()
                    .map(|(i, byte)| if i == 0 { byte | 0xa0 } else { *byte })
                    .collect::<Vec<_>>()
            );

            wire.push(0xff);
            let (rest, decoded) = be_prefixed_integer(&wire, 5).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(rest, &[0xff]);
        }
    }

    #[test]
    fn prefixed_integer_rejects_truncation_overflow_and_out_of_range_values() {
        let truncated = be_prefixed_integer(&[0x1f], 5).unwrap_err();
        assert_eq!(truncated.code, ErrorCode::QpackDecompressionFailed);
        assert!(matches!(truncated, crate::Error::Connection(_)));

        let oversized = be_prefixed_integer(&[0xff; 10], 8).unwrap_err();
        assert_eq!(oversized.code, ErrorCode::QpackDecompressionFailed);
        assert!(matches!(oversized, crate::Error::Stream(_)));

        let mut wire = Vec::new();
        assert_eq!(
            wire.put_prefixed_integer(VARINT_MAX + 1, 8, 0)
                .unwrap_err()
                .code,
            ErrorCode::QpackDecompressionFailed
        );
        assert!(wire.is_empty());
    }
}
