//! Shared QPACK integer wire primitives (RFC 9204 section 4.1.1).
use bytes::BufMut;
use qbase::varint::VARINT_MAX;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{Error, Result};

pub(super) async fn be_byte<T: AsyncRead + Unpin + ?Sized>(reader: &mut T) -> Result<u8> {
    reader
        .read_u8()
        .await
        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)
}

pub(super) async fn be_prefixed_integer_with_first<T: AsyncRead + Unpin + ?Sized>(
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
            return Err(Error::QPACK_DECOMPRESSION_FAILED);
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
