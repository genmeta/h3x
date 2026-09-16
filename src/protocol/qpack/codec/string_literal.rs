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
            .with_reason(format!("invalid encoder string prefix width: {error}"))
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
            .with_reason(format!("invalid encoder string prefix width: {error}"))
    })?;
    let length = be_prefixed_integer_with_first(
        reader,
        first,
        prefix_bits - 1,
        ErrorCode::QPACK_ENCODER_STREAM_ERROR,
    )
    .await?;
    if length > MAX_BUFFERED_FRAME_PAYLOAD as u64 {
        return Err(ErrorCode::H3_EXCESSIVE_LOAD
            .with_reason("encoded string literal exceeds the buffer limit"));
    }
    let mut encoded = vec![0; length as usize];
    reader.read_exact(&mut encoded).await.map_err(|error| {
        let error = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<std::sync::Arc<std::io::Error>>())
            .map_or(&error, std::sync::Arc::as_ref);
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<crate::Error>())
            .cloned()
            .unwrap_or_else(|| {
                let code = ErrorCode::H3_CLOSED_CRITICAL_STREAM;
                code.with_reason(error.to_string())
            })
    })?;
    let value = if first & (1 << (prefix_bits - 1)) != 0 {
        decode_huffman(&encoded).map_err(|error| {
            ErrorCode::QPACK_ENCODER_STREAM_ERROR
                .with_reason(format!("invalid encoder Huffman string: {error}"))
        })?
    } else {
        Bytes::from(encoded)
    };
    if value.len() > MAX_BUFFERED_FRAME_PAYLOAD {
        return Err(ErrorCode::H3_EXCESSIVE_LOAD
            .with_reason("decoded string literal exceeds the buffer limit"));
    }
    Ok(value)
}

/// Parse a literal in an already buffered field section, retaining its suffix.
pub(super) fn be_string_literal_slice(input: &[u8], prefix_bits: u8) -> Result<(&[u8], Bytes)> {
    validate_prefix_bits(prefix_bits)?;
    let first = *input.first().ok_or_else(|| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED
            .with_reason("string literal is missing its first byte")
    })?;
    let (input, length) = be_prefixed_integer(input, prefix_bits - 1)?;
    let length = usize::try_from(length).map_err(|error| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED
            .with_reason(format!("string length does not fit in memory: {error}"))
    })?;
    let (encoded, rest) = input.split_at_checked(length).ok_or_else(|| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED
            .with_reason("string literal is shorter than its declared length")
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
                .with_reason("string literal high bits overlap its prefix"));
        }
        self.put_prefixed_integer(value.len() as u64, prefix_bits - 1, high_bits)?;
        self.put_slice(value);
        Ok(())
    }
}

fn validate_prefix_bits(prefix_bits: u8) -> Result<()> {
    if !(2..=8).contains(&prefix_bits) {
        return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
            .with_reason("string literal prefix width must be between 2 and 8"));
    }
    Ok(())
}

fn decode_huffman(encoded: &[u8]) -> Result<Bytes> {
    let mut decoded = Vec::new();
    httlib_huffman::decode(encoded, &mut decoded, DecoderSpeed::FourBits).map_err(|error| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED
            .with_reason(format!("invalid Huffman string encoding: {error}"))
    })?;
    Ok(Bytes::from(decoded))
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn wire_vectors_preserve_suffixes_and_read_fragmented_literals() {
        let cases: &[(u8, u8, usize, &[u8])] = &[
            (8, 0, 0, &[0]),
            (8, 0, 5, &[5]),
            (8, 0, 126, &[0x7e]),
            (8, 0, 127, &[0x7f, 0]),
            (8, 0, 128, &[0x7f, 1]),
            (8, 0, 254, &[0x7f, 0x7f]),
            (8, 0, 255, &[0x7f, 0x80, 1]),
            (8, 0, 300, &[0x7f, 0xad, 1]),
            (6, 0x40, 30, &[0x5e]),
            (6, 0x40, 31, &[0x5f, 0]),
            (6, 0x40, 300, &[0x5f, 0x8d, 2]),
            (4, 0x20, 6, &[0x26]),
            (4, 0x20, 7, &[0x27, 0]),
            (4, 0x20, 300, &[0x27, 0xa5, 2]),
            (4, 0x30, 3, &[0x33]),
            (2, 0xfc, 1, &[0xfd, 0]),
        ];
        for &(bits, high, length, prefix) in cases {
            let value = vec![b'a'; length];
            let mut expected = prefix.to_vec();
            expected.extend_from_slice(&value);
            let mut wire = Vec::new();
            wire.put_string_literal(&value, bits, high).unwrap();
            assert_eq!(wire, expected);
            wire.push(42);
            let (rest, decoded) = be_string_literal_slice(&wire, bits).unwrap();
            assert_eq!(decoded.as_ref(), value);
            assert_eq!(rest, &[42]);

            // One-byte capacity fragments both the length prefix and the payload.
            let (mut writer, mut reader) = tokio::io::duplex(1);
            let write = async {
                writer.write_all(&wire).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let read = async {
                let reader: &mut (dyn AsyncRead + Unpin) = &mut reader;
                assert_eq!(
                    be_string_literal(reader, bits).await.unwrap().as_ref(),
                    value
                );
                assert_eq!(reader.read_u8().await.unwrap(), 42);
            };
            tokio::join!(write, read);
        }
    }

    #[tokio::test]
    async fn huffman_literals_use_encoded_byte_lengths() {
        // RFC 7541 C.4.1: 12 encoded bytes decode to the 15-byte "www.example.com".
        let encoded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        for (bits, prefix) in [(8, &[0x8c][..]), (6, &[0x6c][..]), (4, &[0x2f, 5][..])] {
            let mut wire = prefix.to_vec();
            wire.extend_from_slice(&encoded);
            wire.push(42);
            let (rest, value) = be_string_literal_slice(&wire, bits).unwrap();
            assert_eq!(value, "www.example.com");
            assert_eq!(rest, &[42]);
            let mut input = wire.as_slice();
            assert_eq!(
                be_string_literal(&mut input, bits).await.unwrap(),
                "www.example.com"
            );
            assert_eq!(input, &[42]);
        }
    }

    #[tokio::test]
    async fn rejects_truncation_invalid_huffman_overflow_and_excessive_lengths() {
        for wire in [&[][..], &[0x7f], &[0x7f, 0x80], &[3, b'a', b'b']] {
            assert_eq!(
                (be_string_literal(&mut &wire[..], 8).await).map_err(ErrorCode::from),
                Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
            );
            assert_eq!(
                (be_string_literal_slice(wire, 8)).map_err(ErrorCode::from),
                Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
            );
        }
        // Too much Huffman padding, an EOS symbol, and an overflowing length.
        for wire in [
            &[0x81, 0xff][..],
            &[0x84, 0xff, 0xff, 0xff, 0xff],
            &[0xff; 10],
        ] {
            assert_eq!(
                (be_string_literal(&mut &wire[..], 8).await).map_err(ErrorCode::from),
                Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
            );
            assert_eq!(
                (be_string_literal_slice(wire, 8)).map_err(ErrorCode::from),
                Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
            );
        }
        let mut wire = Vec::new();
        wire.put_prefixed_integer(MAX_BUFFERED_FRAME_PAYLOAD as u64 + 1, 7, 0)
            .unwrap();
        wire.push(42);
        let mut input = wire.as_slice();
        assert_eq!(
            (be_string_literal(&mut input, 8).await).map_err(ErrorCode::from),
            Err(ErrorCode::H3_EXCESSIVE_LOAD)
        );
        assert_eq!(input, &[42]);
    }

    #[tokio::test]
    async fn validates_prefix_and_flags_before_io() {
        for bits in [0, 1, 9, 255] {
            let mut input = &[0, 42][..];
            assert_eq!(
                (be_string_literal(&mut input, bits).await).map_err(ErrorCode::from),
                Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
            );
            assert_eq!(input, &[0, 42]);
            assert!(be_string_literal_slice(input, bits).is_err());
            let mut output = vec![42];
            assert!(output.put_string_literal(b"a", bits, 0).is_err());
            assert_eq!(output, &[42]);
        }
        for (bits, high) in [(8, 0x80), (6, 0x60), (4, 0x28), (4, 0x21)] {
            let mut output = vec![42];
            assert!(output.put_string_literal(b"a", bits, high).is_err());
            assert_eq!(output, &[42]);
        }
    }
}
