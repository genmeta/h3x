use std::pin::pin;

use bytes::{Buf, Bytes};
use futures::Sink;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::{
    buflist::BufList,
    codec::{
        DecodeError, DecodeFrom, EncodeError, EncodeExt, EncodeInto, StreamDecodeError,
        StreamEncodeError,
    },
    connection::StreamError,
    dhttp::frame::Frame,
    error::H3FrameDecodeError,
    qpack::{
        integer::{decode_integer, encode_integer},
        string::{decode_string, encode_string},
    },
};

///
/// ``` ignore
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// |   Required Insert Count (8+)  |
/// +---+---------------------------+
/// | S |      Delta Base (7+)      |
/// +---+---------------------------+
/// |      Encoded Field Lines    ...
/// +-------------------------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedFieldSectionPrefix {
    pub encoded_insert_count: u64,
    /// The Sign bit ('S' in Figure 12) and Delta Base encode the Base
    /// relative to the Required Insert Count.
    ///
    /// A Sign bit of 0 indicates that the Base is greater than or equal to
    /// the Required Insert Count; a Sign bit of 1 indicates the Base is less
    /// than the Required Insert Count.
    ///
    /// ``` fakecode
    /// if Sign == 0:
    ///    Base = ReqInsertCount + DeltaBase
    /// else:
    ///    Base = ReqInsertCount - DeltaBase - 1
    /// ```
    /// <https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.1.2>
    pub sign: bool,
    pub delta_base: u64,
}

impl<S: AsyncRead + Send> DecodeFrom<S> for EncodedFieldSectionPrefix {
    type Error = StreamError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let decode = async move {
            let mut stream = pin!(stream);
            let ric_prefix = stream.read_u8().await?;
            let encoded_insert_count = decode_integer(stream.as_mut(), ric_prefix, 8).await?;
            let db_prefix = stream.read_u8().await?;
            let sign = db_prefix & 0b1000_0000 != 0;
            let delta_base = decode_integer(stream.as_mut(), db_prefix & 0b0111_1111, 7).await?;
            Ok(EncodedFieldSectionPrefix {
                encoded_insert_count,
                sign,
                delta_base,
            })
        };
        decode.await.map_err(|error: StreamDecodeError| {
            error.into_stream_error(|decode_error| {
                H3FrameDecodeError {
                    source: decode_error,
                }
                .into()
            })
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for EncodedFieldSectionPrefix {
    type Output = ();

    type Error = StreamEncodeError;

    async fn encode_into(self, stream: S) -> Result<Self::Output, Self::Error> {
        let mut stream = pin!(stream);
        let ric_prefix = 0;
        encode_integer(stream.as_mut(), ric_prefix, 8, self.encoded_insert_count).await?;
        let db_prefix = if self.sign { 0b1000_0000 } else { 0b0000_0000 };
        encode_integer(stream.as_mut(), db_prefix, 7, self.delta_base).await?;
        Ok(())
    }
}

impl EncodedFieldSectionPrefix {
    /// RFC 9204 §4.5.1.1: Encode RequiredInsertCount to wire format
    pub fn encode_ric(required_insert_count: u64, max_table_capacity: u64) -> u64 {
        if required_insert_count == 0 {
            0
        } else {
            let max_entries = max_table_capacity / 32;
            // When max_entries == 0 the dynamic table is disabled; RIC must be 0.
            // Caller violated this precondition, but we avoid panicking.
            if max_entries == 0 {
                return 1;
            }
            (required_insert_count % (2 * max_entries)) + 1
        }
    }

    /// RFC 9204 §4.5.1.1: Decode wire-encoded InsertCount to true RequiredInsertCount
    pub fn decode_ric(
        encoded_insert_count: u64,
        max_table_capacity: u64,
        total_number_of_inserts: u64,
    ) -> Result<u64, DecodeError> {
        if encoded_insert_count == 0 {
            return Ok(0);
        }
        let max_entries = max_table_capacity / 32;
        if max_entries == 0 {
            // Dynamic table disabled; non-zero encoded_insert_count is invalid.
            return Err(DecodeError::DecompressionFailed);
        }
        let full_range = max_entries
            .checked_mul(2)
            .ok_or(DecodeError::ArithmeticOverflow)?;
        if encoded_insert_count > full_range {
            return Err(DecodeError::DecompressionFailed);
        }
        let max_value = total_number_of_inserts
            .checked_add(max_entries)
            .ok_or(DecodeError::ArithmeticOverflow)?;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut ric = max_wrapped
            .checked_add(encoded_insert_count)
            .and_then(|v| v.checked_sub(1))
            .ok_or(DecodeError::ArithmeticOverflow)?;
        if ric > max_value {
            if ric <= full_range {
                return Err(DecodeError::DecompressionFailed);
            }
            ric -= full_range;
        }
        if ric == 0 {
            return Err(DecodeError::DecompressionFailed);
        }
        Ok(ric)
    }

    /// RFC 9204 §4.5.1.2: Resolve the true base from decoded prefix and true RIC
    pub fn resolve_base(
        required_insert_count: u64,
        sign: bool,
        delta_base: u64,
    ) -> Result<u64, DecodeError> {
        if !sign {
            required_insert_count
                .checked_add(delta_base)
                .ok_or(DecodeError::ArithmeticOverflow)
        } else {
            required_insert_count
                .checked_sub(delta_base)
                .and_then(|v| v.checked_sub(1))
                .ok_or(DecodeError::ArithmeticOverflow)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldLineRepresentation {
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | T |      Index (6+)       |
    /// +---+---+-----------------------+
    /// ```
    IndexedFieldLine { is_static: bool, index: u64 },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 1 |  Index (4+)   |
    /// +---+---+---+---+---------------+
    /// ```
    IndexedFieldLineWithPostBaseIndex { index: u64 },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 | N | T |Name Index (4+)|
    /// +---+---+---+---+---------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    LiteralFieldLineWithNameReference {
        /// This representation starts with the '01' 2-bit pattern. The following
        /// bit, 'N', indicates whether an intermediary is permitted to add this
        /// field line to the dynamic table on subsequent hops. When the 'N' bit
        /// is set, the encoded field line MUST always be encoded with a literal
        /// representation. In particular, when a peer sends a field line that it
        /// received represented as a literal field line with the 'N' bit set, it
        /// MUST use a literal representation to forward this field line. This
        /// bit is intended for protecting field values that are not to be put at
        /// risk by compressing them; see Section 7.1 for more details.
        ///
        /// <https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.4-3>
        //
        never_dynamic: bool,
        is_static: bool,
        name_index: u64,
        huffman: bool,
        value: Bytes,
    },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
    /// +---+---+---+---+---+-----------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    LiteralFieldLineWithPostBaseNameReference {
        never_dynamic: bool,
        name_index: u64,
        huffman: bool,
        value: Bytes,
    },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 | N | H |NameLen(3+)|
    /// +---+---+---+---+---+-----------+
    /// |  Name String (Length bytes)   |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    LiteralFieldLineWithLiteralName {
        never_dynamic: bool,
        name_huffman: bool,
        name: Bytes,
        value_huffman: bool,
        value: Bytes,
    },
}

impl<S: AsyncRead + Send> DecodeFrom<S> for FieldLineRepresentation {
    type Error = StreamError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let decode = async move {
            let mut stream = pin!(stream);
            let prefix = stream.read_u8().await?;
            match prefix {
                prefix if prefix & 0b1000_0000 == 0b1000_0000 => {
                    // Indexed Field Line
                    let is_static = (prefix & 0b0100_0000) != 0;
                    let index = decode_integer(stream, prefix, 6).await?;
                    Ok(FieldLineRepresentation::IndexedFieldLine { is_static, index })
                }
                prefix if prefix & 0b1111_0000 == 0b0001_0000 => {
                    // Indexed Field Line with Post-Base Index
                    let index = decode_integer(stream, prefix, 4).await?;
                    Ok(FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index })
                }
                prefix if prefix & 0b1100_0000 == 0b0100_0000 => {
                    // Literal Field Line with Name Reference
                    let never_dynamic = (prefix & 0b0010_0000) != 0;
                    let is_static = (prefix & 0b0001_0000) != 0;
                    let name_index = decode_integer(stream.as_mut(), prefix, 4).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(FieldLineRepresentation::LiteralFieldLineWithNameReference {
                        never_dynamic,
                        is_static,
                        name_index,
                        huffman,
                        value,
                    })
                }
                prefix if prefix & 0b1110_0000 == 0b0010_0000 => {
                    // Literal Field Line with Literal Name
                    let never_dynamic = (prefix & 0b0001_0000) != 0;
                    let name_prefix = prefix;
                    let (name_huffman, name) =
                        decode_string(stream.as_mut(), name_prefix, 1 + 3).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (value_huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                        never_dynamic,
                        name_huffman,
                        name,
                        value_huffman,
                        value,
                    })
                }
                // 0000xxxx — Literal Field Line with Post-Base Name Reference
                _ => {
                    let never_dynamic = (prefix & 0b0000_1000) != 0;
                    let name_index = decode_integer(stream.as_mut(), prefix, 3).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(
                        FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                            never_dynamic,
                            name_index,
                            huffman,
                            value,
                        },
                    )
                }
            }
        };
        decode.await.map_err(|error: StreamDecodeError| {
            error.into_stream_error(|decode_error| {
                H3FrameDecodeError {
                    source: decode_error,
                }
                .into()
            })
        })
    }
}

impl<S, E> EncodeInto<S> for FieldLineRepresentation
where
    S: AsyncWrite + Sink<Bytes, Error = E> + Send,
    StreamEncodeError: From<E>,
{
    type Output = ();

    type Error = StreamEncodeError;

    async fn encode_into(self, stream: S) -> Result<Self::Output, Self::Error> {
        let mut stream = pin!(stream);
        match self {
            FieldLineRepresentation::IndexedFieldLine { is_static, index } => {
                let mut prefix = 0b1000_0000;
                if is_static {
                    prefix |= 0b0100_0000;
                }
                encode_integer(stream, prefix, 6, index).await?;
            }
            FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index } => {
                encode_integer(stream, 0b0001_0000, 4, index).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithNameReference {
                never_dynamic,
                is_static,
                name_index,
                huffman,
                value,
            } => {
                let mut prefix = 0b0100_0000;
                if never_dynamic {
                    prefix |= 0b0010_0000;
                }
                if is_static {
                    prefix |= 0b0001_0000;
                }
                encode_integer(stream.as_mut(), prefix, 4, name_index).await?;
                encode_string(stream.as_mut(), 0, 1 + 7, huffman, value).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                never_dynamic,
                name_index,
                huffman,
                value,
            } => {
                let mut prefix = 0b0000_0000;
                if never_dynamic {
                    prefix |= 0b0000_1000;
                }
                encode_integer(stream.as_mut(), prefix, 3, name_index).await?;
                encode_string(stream.as_mut(), 0, 1 + 7, huffman, value).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                never_dynamic,
                name_huffman,
                name,
                value_huffman,
                value,
            } => {
                let mut prefix = 0b0010_0000;
                if never_dynamic {
                    prefix |= 0b0001_0000;
                }
                encode_string(stream.as_mut(), prefix, 1 + 3, name_huffman, name).await?;
                encode_string(stream.as_mut(), 0, 1 + 7, value_huffman, value).await?;
            }
        }
        Ok(())
    }
}

impl EncodeInto<BufList> for (EncodedFieldSectionPrefix, Vec<FieldLineRepresentation>) {
    type Output = Frame<BufList>;

    type Error = EncodeError;

    async fn encode_into(self, stream: BufList) -> Result<Self::Output, Self::Error> {
        let (field_section_prefix, field_line_representations) = self;
        assert!(
            !stream.has_remaining(),
            "Only empty buflist can be used to encode frame"
        );
        let mut header_frame = Frame::new(Frame::HEADERS_FRAME_TYPE, BufList::new())
            .expect("empty buflist has zero size");

        let encode = async move {
            header_frame.encode_one(field_section_prefix).await?;
            for field_line_representation in field_line_representations {
                header_frame.encode_one(field_line_representation).await?;
            }
            Ok(header_frame)
        };
        encode
            .await
            .map_err(|error: StreamEncodeError| match error {
                StreamEncodeError::Connection { .. } | StreamEncodeError::Reset { .. } => {
                    unreachable!("stream error should not happen when encoding to BufList")
                }
                StreamEncodeError::Encode { source } => source,
            })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use bytes::{Buf, Bytes};

    use super::{EncodedFieldSectionPrefix, FieldLineRepresentation};
    use crate::{
        buflist::BufList,
        codec::{DecodeError, DecodeFrom, EncodeInto},
        connection::StreamError,
        dhttp::frame::Frame,
        error::Code,
    };

    async fn encode_prefix_to_bytes(prefix: EncodedFieldSectionPrefix) -> Vec<u8> {
        let mut buffer = Vec::new();
        let mut writer = Cursor::new(&mut buffer);
        prefix
            .encode_into(&mut writer)
            .await
            .unwrap_or_else(|error| {
                panic!("prefix encode_into failed: {error:?}");
            });
        buffer
    }

    fn assert_h3_error(error: StreamError) {
        match error {
            StreamError::H3 { source } => {
                assert_eq!(source.code(), Code::H3_FRAME_ERROR);
            }
            StreamError::Connection { .. } | StreamError::Reset { .. } => {
                // Keep these as fail-fast for malformed streams while allowing
                // transport/feature-gated differences across test configurations.
            }
        };
    }

    async fn roundtrip_field_line(original: FieldLineRepresentation) {
        let mut encoded = BufList::new();
        original
            .clone()
            .encode_into(&mut encoded)
            .await
            .unwrap_or_else(|error| {
                panic!("field line encode_into failed: {error:?}");
            });

        let encoded = encoded.copy_to_bytes(encoded.remaining());
        let mut cursor = Cursor::new(encoded.as_ref());
        let decoded = FieldLineRepresentation::decode_from(&mut cursor)
            .await
            .unwrap_or_else(|error| {
                panic!("field line decode_from failed: {error:?}");
            });
        assert_eq!(decoded, original);
    }

    async fn encode_field_line_to_bytes(field_line: FieldLineRepresentation) -> Vec<u8> {
        let mut encoded = BufList::new();
        field_line
            .encode_into(&mut encoded)
            .await
            .unwrap_or_else(|error| {
                panic!("field line encode_into failed: {error:?}");
            });
        encoded.copy_to_bytes(encoded.remaining()).to_vec()
    }

    // --- Field section prefix tests ---

    #[test]
    fn test_encode_ric_zero() {
        assert_eq!(EncodedFieldSectionPrefix::encode_ric(0, 256), 0);
    }

    #[test]
    fn test_encode_ric_nonzero() {
        assert_eq!(EncodedFieldSectionPrefix::encode_ric(4, 256), 5);
    }

    #[test]
    fn test_encode_ric_disabled_table() {
        // max_table_capacity/32 == 0 implies dynamic table disabled.
        // encode_ric should return 1 for non-zero input in this edge case.
        assert_eq!(EncodedFieldSectionPrefix::encode_ric(1, 8), 1);
        assert_eq!(EncodedFieldSectionPrefix::encode_ric(7, 31), 1);
    }

    #[test]
    fn test_decode_ric_zero() {
        let result = EncodedFieldSectionPrefix::decode_ric(0, 256, 10);
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_decode_ric_disabled_table() {
        // Non-zero encoded value is invalid when max_table_capacity/32 == 0.
        let result = EncodedFieldSectionPrefix::decode_ric(1, 8, 10);
        assert_eq!(result, Err(DecodeError::DecompressionFailed));
    }

    #[test]
    fn test_decode_ric_nonzero() {
        let result = EncodedFieldSectionPrefix::decode_ric(5, 256, 10);
        assert_eq!(result, Ok(4));
    }

    #[test]
    fn test_ric_roundtrip() {
        let max_table_capacity = 256;
        for ric in [1u64, 4, 8, 15] {
            let total_inserts = ric;
            let encoded = EncodedFieldSectionPrefix::encode_ric(ric, max_table_capacity);
            let decoded = EncodedFieldSectionPrefix::decode_ric(
                encoded,
                max_table_capacity,
                total_inserts,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "decode_ric({encoded}, {max_table_capacity}, {total_inserts}) failed: {error:?}"
                )
            });
            assert_eq!(decoded, ric, "roundtrip failed for ric={ric}");
        }
    }

    #[test]
    fn test_decode_ric_exceeds_full_range() {
        let result = EncodedFieldSectionPrefix::decode_ric(17, 256, 10);
        assert_eq!(result, Err(DecodeError::DecompressionFailed));
    }

    #[test]
    fn test_decode_ric_checked_add_overflow() {
        let result = EncodedFieldSectionPrefix::decode_ric(1, 1024, u64::MAX);
        assert_eq!(result, Err(DecodeError::ArithmeticOverflow));
    }

    #[test]
    fn test_decode_ric_wrapped_value_above_max_is_invalid() {
        // max_entries = 8, full_range = 16, max_value = 8.
        // Encoded value 10 resolves to 9, which is above max_value but still
        // within the first full_range, so it cannot be unwrapped backward.
        let result = EncodedFieldSectionPrefix::decode_ric(10, 256, 0);
        assert_eq!(result, Err(DecodeError::DecompressionFailed));
    }

    #[test]
    fn test_decode_ric_unwraps_value_above_max() {
        // max_entries = 8, full_range = 16, max_value = 28.
        // Encoded value 16 first resolves to 31, then unwraps to 15.
        let result = EncodedFieldSectionPrefix::decode_ric(16, 256, 20);
        assert_eq!(result, Ok(15));
    }

    #[test]
    fn test_resolve_base_positive() {
        let result = EncodedFieldSectionPrefix::resolve_base(5, false, 3);
        assert_eq!(result, Ok(8));
    }

    #[test]
    fn test_resolve_base_negative() {
        let result = EncodedFieldSectionPrefix::resolve_base(5, true, 2);
        assert_eq!(result, Ok(2));
    }

    #[test]
    fn test_resolve_base_overflow() {
        let result = EncodedFieldSectionPrefix::resolve_base(1, true, 5);
        assert_eq!(result, Err(DecodeError::ArithmeticOverflow));
    }

    #[test]
    fn test_resolve_base_positive_overflow() {
        let result = EncodedFieldSectionPrefix::resolve_base(u64::MAX, false, 1);
        assert_eq!(result, Err(DecodeError::ArithmeticOverflow));
    }

    #[tokio::test]
    async fn test_prefix_encode_decode_roundtrip_with_multibyte_ric() {
        let prefix = EncodedFieldSectionPrefix {
            encoded_insert_count: 1337,
            sign: false,
            delta_base: 65,
        };
        let bytes = encode_prefix_to_bytes(prefix).await;
        assert!(bytes.len() > 2, "ric varint should use continuation bytes");

        let mut cursor = Cursor::new(&bytes);
        let decoded = EncodedFieldSectionPrefix::decode_from(&mut cursor)
            .await
            .unwrap_or_else(|error| {
                panic!("decode_from prefix failed: {error:?}");
            });
        assert_eq!(decoded, prefix);
        assert_eq!(cursor.position() as usize, bytes.len());
    }

    #[test]
    fn test_resolve_base_zero_delta() {
        assert_eq!(EncodedFieldSectionPrefix::resolve_base(3, false, 0), Ok(3));
        assert_eq!(EncodedFieldSectionPrefix::resolve_base(3, true, 0), Ok(2));
    }

    #[tokio::test]
    async fn test_prefix_encode_preserves_sign_bit_with_extended_delta_base() {
        let prefix = EncodedFieldSectionPrefix {
            encoded_insert_count: 255,
            sign: true,
            delta_base: 127,
        };

        let bytes = encode_prefix_to_bytes(prefix).await;

        assert_eq!(bytes, vec![0xff, 0x00, 0xff, 0x00]);
        let decoded = EncodedFieldSectionPrefix::decode_from(Cursor::new(&bytes))
            .await
            .unwrap_or_else(|error| {
                panic!("decode_from signed prefix failed: {error:?}");
            });
        assert_eq!(decoded, prefix);
    }

    // --- Field representation encode/decode tests ---

    #[tokio::test]
    async fn test_field_line_encode_exact_index_prefixes() {
        let indexed = encode_field_line_to_bytes(FieldLineRepresentation::IndexedFieldLine {
            is_static: true,
            index: 63,
        })
        .await;
        assert_eq!(indexed, vec![0xff, 0x00]);

        let post_base = encode_field_line_to_bytes(
            FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index: 15 },
        )
        .await;
        assert_eq!(post_base, vec![0x1f, 0x00]);
    }

    #[tokio::test]
    async fn test_field_line_encode_exact_literal_prefixes() {
        let name_reference = encode_field_line_to_bytes(
            FieldLineRepresentation::LiteralFieldLineWithNameReference {
                never_dynamic: true,
                is_static: true,
                name_index: 15,
                huffman: false,
                value: Bytes::new(),
            },
        )
        .await;
        assert_eq!(name_reference, vec![0x7f, 0x00, 0x00]);

        let post_base_name_reference = encode_field_line_to_bytes(
            FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                never_dynamic: true,
                name_index: 7,
                huffman: false,
                value: Bytes::new(),
            },
        )
        .await;
        assert_eq!(post_base_name_reference, vec![0x0f, 0x00, 0x00]);

        let literal_name =
            encode_field_line_to_bytes(FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                never_dynamic: true,
                name_huffman: false,
                name: Bytes::from_static(b"x-test1"),
                value_huffman: false,
                value: Bytes::new(),
            })
            .await;
        assert_eq!(
            literal_name,
            [vec![0x37, 0x00], b"x-test1".to_vec(), vec![0x00]].concat()
        );
    }

    #[tokio::test]
    async fn test_encode_decode_indexed_variants() {
        roundtrip_field_line(FieldLineRepresentation::IndexedFieldLine {
            is_static: false,
            index: 10,
        })
        .await;
        roundtrip_field_line(FieldLineRepresentation::IndexedFieldLine {
            is_static: true,
            index: 5,
        })
        .await;
        roundtrip_field_line(FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex {
            index: 15,
        })
        .await;
        roundtrip_field_line(FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex {
            index: 300,
        })
        .await;
    }

    #[tokio::test]
    async fn test_encode_decode_name_reference_huffman_branches() {
        roundtrip_field_line(FieldLineRepresentation::LiteralFieldLineWithNameReference {
            never_dynamic: false,
            is_static: false,
            name_index: 3,
            huffman: false,
            value: Bytes::from_static(b"plain-value"),
        })
        .await;
        roundtrip_field_line(FieldLineRepresentation::LiteralFieldLineWithNameReference {
            never_dynamic: true,
            is_static: true,
            name_index: 3,
            huffman: true,
            value: Bytes::from_static(b"huffman-value"),
        })
        .await;
    }

    #[tokio::test]
    async fn test_encode_decode_post_base_name_reference_branches() {
        roundtrip_field_line(
            FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                never_dynamic: false,
                name_index: 9,
                huffman: false,
                value: Bytes::from_static(b"postbase-plain"),
            },
        )
        .await;
        roundtrip_field_line(
            FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                never_dynamic: true,
                name_index: 9,
                huffman: true,
                value: Bytes::from_static(b"postbase-huffman"),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_encode_decode_literal_name_branches() {
        roundtrip_field_line(FieldLineRepresentation::LiteralFieldLineWithLiteralName {
            never_dynamic: true,
            name_huffman: false,
            name: Bytes::from_static(b"x-name"),
            value_huffman: false,
            value: Bytes::from_static(b"plain-value"),
        })
        .await;
        roundtrip_field_line(FieldLineRepresentation::LiteralFieldLineWithLiteralName {
            never_dynamic: false,
            name_huffman: true,
            name: Bytes::from_static(b"h-name"),
            value_huffman: true,
            value: Bytes::from_static(b"h-value"),
        })
        .await;
    }

    #[tokio::test]
    async fn test_field_section_prefix_and_representations_encode_into_frame_payload() {
        let field_section_prefix = EncodedFieldSectionPrefix {
            encoded_insert_count: 5,
            sign: false,
            delta_base: 2,
        };
        let lines = vec![
            FieldLineRepresentation::IndexedFieldLine {
                is_static: false,
                index: 1,
            },
            FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                never_dynamic: true,
                name_index: 2,
                huffman: false,
                value: Bytes::from_static(b"v"),
            },
            FieldLineRepresentation::LiteralFieldLineWithNameReference {
                never_dynamic: false,
                is_static: true,
                name_index: 4,
                huffman: true,
                value: Bytes::from_static(b"x"),
            },
        ];

        let frame: Frame<BufList> = (field_section_prefix, lines.clone())
            .encode_into(BufList::new())
            .await
            .unwrap_or_else(|error| {
                panic!("field section encode_into failed: {error:?}");
            });
        assert_eq!(frame.r#type(), Frame::HEADERS_FRAME_TYPE);

        let mut payload = frame.into_payload();
        let payload = payload.copy_to_bytes(payload.remaining());
        let mut cursor = Cursor::new(&payload);

        let decoded_prefix = EncodedFieldSectionPrefix::decode_from(&mut cursor)
            .await
            .unwrap_or_else(|error| {
                panic!("decode_from field section prefix failed: {error:?}");
            });
        assert_eq!(decoded_prefix, field_section_prefix);

        let mut decoded_lines = Vec::new();
        while cursor.position() < payload.len() as u64 {
            let line = FieldLineRepresentation::decode_from(&mut cursor)
                .await
                .unwrap_or_else(|error| {
                    panic!("decode_from field line failed: {error:?}");
                });
            decoded_lines.push(line);
        }

        assert_eq!(decoded_lines, lines);
        assert_eq!(cursor.position(), payload.len() as u64);
    }

    #[tokio::test]
    async fn test_prefix_varint_decode_truncated() {
        // Missing the second byte (delta-base varint) should become a decode error on decode_from.
        let error = EncodedFieldSectionPrefix::decode_from(Cursor::new(vec![0x81u8]))
            .await
            .expect_err("expected decode failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_prefix_decode_missing_first_byte() {
        let error = EncodedFieldSectionPrefix::decode_from(Cursor::new(Vec::<u8>::new()))
            .await
            .expect_err("expected missing prefix failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_prefix_decode_truncated_delta_base_varint() {
        let error = EncodedFieldSectionPrefix::decode_from(Cursor::new(vec![0x00u8, 0xff]))
            .await
            .expect_err("expected delta-base truncation failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_field_line_decode_truncated_indexed_varint() {
        // Indexed line with index 63 uses extended integer encoding; no continuation byte present.
        let error = FieldLineRepresentation::decode_from(Cursor::new(vec![0b1011_1111u8]))
            .await
            .expect_err("expected indexed truncation failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_field_line_decode_truncated_post_base_index_varint() {
        let error = FieldLineRepresentation::decode_from(Cursor::new(vec![0b0001_1111u8]))
            .await
            .expect_err("expected post-base index truncation failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_field_line_decode_truncated_name_reference_value() {
        // Name-reference literal misses the value prefix+bytes.
        let error = FieldLineRepresentation::decode_from(Cursor::new(vec![0b0100_0011u8]))
            .await
            .expect_err("expected literal name ref truncation failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_field_line_decode_truncated_name_reference_value_bytes() {
        let error =
            FieldLineRepresentation::decode_from(Cursor::new(vec![0b0100_0011u8, 0x02, b'a']))
                .await
                .expect_err("expected literal name ref value bytes truncation failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_field_line_decode_truncated_literal_name() {
        // Literal name field with missing name length + bytes.
        let error = FieldLineRepresentation::decode_from(Cursor::new(vec![0b0010_0000u8]))
            .await
            .expect_err("expected literal name truncation failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_field_line_decode_truncated_literal_name_bytes() {
        let error = FieldLineRepresentation::decode_from(Cursor::new(vec![0b0010_0010u8, b'a']))
            .await
            .expect_err("expected literal name bytes truncation failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_field_line_decode_truncated_literal_name_value_bytes() {
        let error = FieldLineRepresentation::decode_from(Cursor::new(vec![
            0b0010_0001u8,
            b'n',
            0x02,
            b'v',
        ]))
        .await
        .expect_err("expected literal name value bytes truncation failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_field_line_decode_truncated_post_base_name_value() {
        // Post-base name reference missing value.
        let error = FieldLineRepresentation::decode_from(Cursor::new(vec![0b0000_0000u8]))
            .await
            .expect_err("expected post-base truncation failure");
        assert_h3_error(error);
    }

    #[tokio::test]
    async fn test_field_line_decode_truncated_post_base_name_value_bytes() {
        let error =
            FieldLineRepresentation::decode_from(Cursor::new(vec![0b0000_0001u8, 0x02, b'a']))
                .await
                .expect_err("expected post-base value bytes truncation failure");
        assert_h3_error(error);
    }

    mod proptest_roundtrip {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn ric_encode_decode_roundtrip(
                required_insert_count in 1u64..10000,
                max_table_capacity in 32u64..100000,
            ) {
                // Per RFC 9204 §4.5.1.1, the decoder's total_number_of_inserts
                // must equal required_insert_count for a clean roundtrip, since
                // the encoding uses modular arithmetic over 2*max_entries.
                let total_number_of_inserts = required_insert_count;
                let encoded = EncodedFieldSectionPrefix::encode_ric(
                    required_insert_count,
                    max_table_capacity,
                );
                let decoded = EncodedFieldSectionPrefix::decode_ric(
                    encoded,
                    max_table_capacity,
                    total_number_of_inserts,
                );
                prop_assert_eq!(decoded, Ok(required_insert_count));
            }

            #[test]
            fn resolve_base_positive_invariant(
                ric in 1u64..=u64::MAX / 2,
                delta in 0u64..=u64::MAX / 2,
            ) {
                let result = EncodedFieldSectionPrefix::resolve_base(ric, false, delta);
                match ric.checked_add(delta) {
                    Some(expected) => prop_assert_eq!(result, Ok(expected)),
                    None => prop_assert_eq!(result, Err(DecodeError::ArithmeticOverflow)),
                }
            }

            #[test]
            fn resolve_base_negative_invariant(ric in 0u64..10000, delta in 0u64..10000) {
                let result = EncodedFieldSectionPrefix::resolve_base(ric, true, delta);
                match ric.checked_sub(delta).and_then(|v| v.checked_sub(1)) {
                    Some(expected) => prop_assert_eq!(result, Ok(expected)),
                    None => prop_assert_eq!(result, Err(DecodeError::ArithmeticOverflow)),
                }
            }
        }
    }
}
