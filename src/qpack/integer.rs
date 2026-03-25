use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::DecodeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Integer(u64);

impl Integer {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0
    }
}

/// Pseudocode to decode an integer I is as follows:
///
/// ```code
/// decode I from the next N bits
///   if I < 2^N - 1, return I
///   else
///       M = 0
///       repeat
///           B = next octet
///           I = I + (B & 127) * 2^M
///           M = M + 7
///       while B & 128 == 128
///       return I
/// ```
pub async fn decode_integer(stream: impl AsyncRead, prefix: u8, n: u8) -> io::Result<u64> {
    tokio::pin!(stream);
    let mut i = prefix as u64 & ((1 << n) - 1);
    if i < (1 << n) - 1 {
        Ok(i)
    } else {
        let mut m = 0u32;
        loop {
            let b = stream.read_u8().await? as u64;
            let power = 1u64.checked_shl(m).ok_or(DecodeError::IntegerOverflow)?;
            let term = (b & 127)
                .checked_mul(power)
                .ok_or(DecodeError::IntegerOverflow)?;
            i = i.checked_add(term).ok_or(DecodeError::IntegerOverflow)?;
            m += 7;
            if b & 128 == 128 {
                continue;
            } else {
                return Ok(i);
            }
        }
    }
}

/// Pseudocode to represent an integer I is as follows:
///
/// ``` code
/// if I < 2^N - 1, encode I on N bits
/// else
///     encode (2^N - 1) on N bits
///     I = I - (2^N - 1)
///     while I >= 128
///          encode (I % 128 + 128) on 8 bits
///          I = I / 128
///     encode I on 8 bits
/// ```
pub async fn encode_integer(
    stream: impl AsyncWrite,
    prefix: u8,
    n: u8,
    mut i: u64,
) -> io::Result<()> {
    tokio::pin!(stream);
    let limit = (1 << n) - 1;
    if i < limit as u64 {
        stream.write_u8(prefix | i as u8).await?;
        Ok(())
    } else {
        stream.write_u8(prefix | limit as u8).await?;
        i -= limit as u64;
        while i >= 128 {
            stream.write_u8((i % 128 + 128) as u8).await?;
            i /= 128; // SHR 7
        }
        stream.write_u8(i as u8).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    async fn round_trip(n: u8, value: u64) {
        let mut buf = Vec::new();
        encode_integer(Cursor::new(&mut buf), 0, n, value)
            .await
            .unwrap();
        let decoded = decode_integer(Cursor::new(&buf[1..]), buf[0], n)
            .await
            .unwrap();
        assert_eq!(decoded, value, "round-trip failed for n={n}, value={value}");
    }

    #[tokio::test]
    async fn prefix_5_fits_in_prefix() {
        // values < 2^5 - 1 = 31 fit in the prefix byte
        round_trip(5, 0).await;
        round_trip(5, 10).await;
        round_trip(5, 30).await;
    }

    #[tokio::test]
    async fn prefix_5_boundary() {
        // 2^5 - 1 = 31: threshold requiring multi-byte
        round_trip(5, 31).await;
        round_trip(5, 32).await;
    }

    #[tokio::test]
    async fn prefix_5_large() {
        round_trip(5, 1337).await;
        round_trip(5, 100_000).await;
    }

    #[tokio::test]
    async fn prefix_6_various() {
        round_trip(6, 0).await;
        round_trip(6, 62).await; // 2^6 - 2
        round_trip(6, 63).await; // 2^6 - 1 = boundary
        round_trip(6, 64).await;
        round_trip(6, 10000).await;
    }

    #[tokio::test]
    async fn prefix_7_various() {
        round_trip(7, 0).await;
        round_trip(7, 126).await; // 2^7 - 2
        round_trip(7, 127).await; // boundary
        round_trip(7, 128).await;
        round_trip(7, 50000).await;
    }

    #[tokio::test]
    async fn prefix_8_various() {
        round_trip(8, 0).await;
        round_trip(8, 254).await; // 2^8 - 2
        round_trip(8, 255).await; // boundary
        round_trip(8, 256).await;
        round_trip(8, 1_000_000).await;
    }

    #[tokio::test]
    async fn preserves_prefix_bits() {
        // High bits outside the prefix width should be preserved
        let prefix_high_bits: u8 = 0b1110_0000; // upper 3 bits set
        let n: u8 = 5;
        let value: u64 = 10;
        let mut buf = Vec::new();
        encode_integer(Cursor::new(&mut buf), prefix_high_bits, n, value)
            .await
            .unwrap();
        // The high 3 bits should be preserved
        assert_eq!(buf[0] & 0b1110_0000, 0b1110_0000);
        let decoded = decode_integer(Cursor::new(&buf[1..]), buf[0], n)
            .await
            .unwrap();
        assert_eq!(decoded, value);
    }

    #[tokio::test]
    async fn single_byte_encoding_length() {
        let mut buf = Vec::new();
        encode_integer(Cursor::new(&mut buf), 0, 5, 10)
            .await
            .unwrap();
        assert_eq!(buf.len(), 1);
    }

    #[tokio::test]
    async fn multi_byte_encoding_length() {
        let mut buf = Vec::new();
        encode_integer(Cursor::new(&mut buf), 0, 5, 31)
            .await
            .unwrap();
        assert!(buf.len() > 1);
    }

    mod proptest_roundtrip {
        use std::io::Cursor;

        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn qpack_integer_roundtrip(n in 1u8..8, value in 0u64..=(u64::MAX >> 1)) {
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                rt.block_on(async {
                    let mut buf = Vec::new();
                    encode_integer(Cursor::new(&mut buf), 0, n, value).await.unwrap();
                    let decoded = decode_integer(Cursor::new(&buf[1..]), buf[0], n).await.unwrap();
                    prop_assert_eq!(decoded, value);
                    Ok(())
                })?;
            }
        }
    }
}
