//! QPACK string literals (RFC 9204 section 4.1.2; RFC 7541 section 5.2).
use bytes::{BufMut, Bytes};
use httlib_huffman::DecoderSpeed;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::integer::{
    WritePrefixedInteger, be_byte, be_prefixed_integer, be_prefixed_integer_with_first,
};
use crate::{ErrorCode, Result, frame::MAX_BUFFERED_FRAME_PAYLOAD};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_round_trips_for_each_supported_prefix_width() {
        for prefix_bits in 2..=8 {
            let high_bits = if prefix_bits == 8 {
                0
            } else {
                !((1u16 << prefix_bits) - 1) as u8
            };
            let mut wire = Vec::new();
            wire.put_string_literal(b"custom-value", prefix_bits, high_bits)
                .unwrap();
            wire.extend_from_slice(b"tail");

            let (rest, value) = be_string_literal_slice(&wire, prefix_bits).unwrap();
            assert_eq!(value, Bytes::from_static(b"custom-value"));
            assert_eq!(rest, b"tail");
        }
    }

    #[test]
    fn literal_validation_does_not_partially_write() {
        for (prefix_bits, high_bits) in [(1, 0), (9, 0), (4, 0x01)] {
            let mut wire = vec![0xaa];
            assert_eq!(
                wire.put_string_literal(b"value", prefix_bits, high_bits)
                    .unwrap_err()
                    .code,
                ErrorCode::QPACK_DECOMPRESSION_FAILED
            );
            assert_eq!(wire, [0xaa]);
        }

        assert_eq!(
            be_string_literal_slice(&[5, b'a'], 8).unwrap_err().code,
            ErrorCode::QPACK_DECOMPRESSION_FAILED
        );
    }

    #[tokio::test]
    async fn async_literals_validate_prefix_lengths_truncation_and_huffman() {
        for prefix_bits in [1, 9] {
            assert_eq!(
                be_string_literal(&mut &[][..], prefix_bits)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::QPACK_ENCODER_STREAM_ERROR
            );
            assert_eq!(
                be_string_literal_with_first(&mut &[][..], 0, prefix_bits)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::QPACK_ENCODER_STREAM_ERROR
            );
        }

        let mut oversized = Vec::new();
        oversized
            .put_prefixed_integer(MAX_BUFFERED_FRAME_PAYLOAD as u64 + 1, 7, 0)
            .unwrap();
        let first = oversized.remove(0);
        assert_eq!(
            be_string_literal_with_first(&mut oversized.as_slice(), first, 8)
                .await
                .unwrap_err()
                .code,
            ErrorCode::H3_EXCESSIVE_LOAD
        );
        assert_eq!(
            be_string_literal(&mut &[2, b'a'][..], 8)
                .await
                .unwrap_err()
                .code,
            ErrorCode::H3_CLOSED_CRITICAL_STREAM
        );

        let mut huffman = Vec::new();
        httlib_huffman::encode(b"hello", &mut huffman).unwrap();
        let mut wire = Vec::new();
        wire.put_prefixed_integer(huffman.len() as u64, 7, 0x80)
            .unwrap();
        wire.extend_from_slice(&huffman);
        assert_eq!(
            be_string_literal(&mut wire.as_slice(), 8).await.unwrap(),
            Bytes::from_static(b"hello")
        );
        let (rest, value) = be_string_literal_slice(&wire, 8).unwrap();
        assert!(rest.is_empty());
        assert_eq!(value, Bytes::from_static(b"hello"));

        assert_eq!(
            be_string_literal(&mut &[0x81, 0xff][..], 8)
                .await
                .unwrap_err()
                .code,
            ErrorCode::QPACK_ENCODER_STREAM_ERROR
        );
        assert_eq!(
            be_string_literal_slice(&[0x81, 0xff], 8).unwrap_err().code,
            ErrorCode::QPACK_DECOMPRESSION_FAILED
        );
    }

    #[tokio::test]
    async fn huffman_expansion_respects_decoded_buffer_limit() {
        let decoded = vec![b'0'; MAX_BUFFERED_FRAME_PAYLOAD + 1];
        let mut huffman = Vec::new();
        httlib_huffman::encode(&decoded, &mut huffman).unwrap();
        assert!(huffman.len() <= MAX_BUFFERED_FRAME_PAYLOAD);
        let mut wire = Vec::new();
        wire.put_prefixed_integer(huffman.len() as u64, 7, 0x80)
            .unwrap();
        wire.extend_from_slice(&huffman);
        assert_eq!(
            be_string_literal(&mut wire.as_slice(), 8)
                .await
                .unwrap_err()
                .code,
            ErrorCode::H3_EXCESSIVE_LOAD
        );
    }

    #[test]
    fn buffered_literal_rejects_missing_or_invalid_prefix() {
        assert_eq!(
            be_string_literal_slice(&[], 8).unwrap_err().code,
            ErrorCode::QPACK_DECOMPRESSION_FAILED
        );
        assert_eq!(
            be_string_literal_slice(&[0], 1).unwrap_err().code,
            ErrorCode::QPACK_DECOMPRESSION_FAILED
        );
    }
}
