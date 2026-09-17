//! QPACK string literals (RFC 9204 section 4.1.2; RFC 7541 section 5.2).
use bytes::{BufMut, Bytes};
use httlib_huffman::DecoderSpeed;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::integer::{
    WritePrefixedInteger, be_byte, be_prefixed_integer, be_prefixed_integer_with_first,
};
use crate::{ErrorCode, Result, protocol::frame::MAX_BUFFERED_FRAME_PAYLOAD};

/// Read one string literal from the QPACK encoder stream, including its first byte.
/// `prefix_bits` is 2..=8 and includes the Huffman flag; the remaining low bits
/// begin the encoded byte length. High bits belonging to the instruction are ignored.
/// EOF, including a partial literal, closes the critical stream.
/// Cancellation may consume a prefix; keep polling the same future.
pub(super) async fn be_string_literal<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    prefix_bits: u8,
) -> Result<Bytes> {
    validate_prefix_bits(prefix_bits).map_err(|error| {
        ErrorCode::QPACK_ENCODER_STREAM_ERROR
            .reason(format!("invalid encoder string prefix width: {error}"))
    })?;
    let first = be_byte(reader).await?;
    be_string_literal_with_first(reader, first, prefix_bits).await
}

/// Continue a literal whose first byte was consumed to identify the instruction.
pub(super) async fn be_string_literal_with_first<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    first: u8,
    prefix_bits: u8,
) -> Result<Bytes> {
    validate_prefix_bits(prefix_bits).map_err(|error| {
        ErrorCode::QPACK_ENCODER_STREAM_ERROR
            .reason(format!("invalid encoder string prefix width: {error}"))
    })?;
    let length = be_prefixed_integer_with_first(
        reader,
        first,
        prefix_bits - 1,
        ErrorCode::QPACK_ENCODER_STREAM_ERROR,
    )
    .await?;
    if length > MAX_BUFFERED_FRAME_PAYLOAD as u64 {
        return Err(
            ErrorCode::H3_EXCESSIVE_LOAD.reason("encoded string literal exceeds the buffer limit")
        );
    }
    let mut encoded = vec![0; length as usize];
    reader
        .read_exact(&mut encoded)
        .await
        .map_err(|error| crate::Error::from_io(error, ErrorCode::H3_CLOSED_CRITICAL_STREAM))?;
    let value = if first & (1 << (prefix_bits - 1)) != 0 {
        decode_huffman(&encoded).map_err(|error| {
            ErrorCode::QPACK_ENCODER_STREAM_ERROR
                .reason(format!("invalid encoder Huffman string: {error}"))
        })?
    } else {
        Bytes::from(encoded)
    };
    if value.len() > MAX_BUFFERED_FRAME_PAYLOAD {
        return Err(
            ErrorCode::H3_EXCESSIVE_LOAD.reason("decoded string literal exceeds the buffer limit")
        );
    }
    Ok(value)
}

/// Parse a literal in an already buffered field section, retaining its suffix.
pub(super) fn be_string_literal_slice(input: &[u8], prefix_bits: u8) -> Result<(&[u8], Bytes)> {
    validate_prefix_bits(prefix_bits)?;
    let first = *input.first().ok_or_else(|| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED.reason("string literal is missing its first byte")
    })?;
    let (input, length) = be_prefixed_integer(input, prefix_bits - 1)?;
    let length = usize::try_from(length).map_err(|error| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED
            .reason(format!("string length does not fit in memory: {error}"))
    })?;
    let (encoded, rest) = input.split_at_checked(length).ok_or_else(|| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED
            .reason("string literal is shorter than its declared length")
    })?;
    let value = if first & (1 << (prefix_bits - 1)) != 0 {
        decode_huffman(encoded)?
    } else {
        Bytes::copy_from_slice(encoded)
    };
    Ok((rest, value))
}

/// Write string literals to a byte buffer, using the same extension-trait style as frames.
pub(super) trait WriteStringLiteral: BufMut {
    /// Write H=0, a prefixed byte length, and the unmodified bytes.
    /// `prefix_bits` is 2..=8 and includes H. `high_bits` contains only the
    /// instruction bits above that prefix; its H and length bits must be zero.
    /// Validate the arguments before writing any bytes.
    fn put_string_literal(&mut self, value: &[u8], prefix_bits: u8, high_bits: u8) -> Result<()>;
}

impl<B: BufMut> WriteStringLiteral for B {
    fn put_string_literal(&mut self, value: &[u8], prefix_bits: u8, high_bits: u8) -> Result<()> {
        validate_prefix_bits(prefix_bits)?;
        let prefix_mask = (1u16 << prefix_bits) - 1;
        if u16::from(high_bits) & prefix_mask != 0 {
            return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
                .reason("string literal high bits overlap its prefix"));
        }
        self.put_prefixed_integer(value.len() as u64, prefix_bits - 1, high_bits)?;
        self.put_slice(value);
        Ok(())
    }
}

fn validate_prefix_bits(prefix_bits: u8) -> Result<()> {
    if !(2..=8).contains(&prefix_bits) {
        return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
            .reason("string literal prefix width must be between 2 and 8"));
    }
    Ok(())
}

fn decode_huffman(encoded: &[u8]) -> Result<Bytes> {
    let mut decoded = Vec::new();
    httlib_huffman::decode(encoded, &mut decoded, DecoderSpeed::FourBits).map_err(|error| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED
            .reason(format!("invalid Huffman string encoding: {error}"))
    })?;
    Ok(Bytes::from(decoded))
}
