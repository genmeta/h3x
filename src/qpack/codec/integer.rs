use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::error::{DecodeStreamError, EncodeStreamError};

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
pub async fn decode_integer(
    stream: &mut (impl AsyncRead + Unpin),
    prefix: u8,
    n: u8,
) -> Result<u64, DecodeStreamError> {
    let mut i = prefix as u64 & ((1 << n) - 1);
    if i < (1 << n) - 1 {
        Ok(i)
    } else {
        let mut m = 0;
        loop {
            let b = stream.read_u8().await? as u64;
            i += (b & 127) * 2u64.pow(m);
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
    stream: &mut (impl AsyncWrite + Unpin),
    prefix: u8,
    n: u8,
    mut i: u64,
) -> Result<(), EncodeStreamError> {
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
