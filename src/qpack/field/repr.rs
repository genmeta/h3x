use std::pin::pin;

use bytes::{Buf, Bytes};
use futures::Sink;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::{
    buflist::BufList,
    codec::{
        DecodeError, DecodeFrom, DecodeStreamError, EncodeError, EncodeExt, EncodeInto,
        EncodeStreamError,
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
        decode.await.map_err(|error: DecodeStreamError| {
            error.map_decode_error(|decode_error| {
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

    type Error = EncodeStreamError;

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
        let full_range = 2 * max_entries;
        if encoded_insert_count > full_range {
            return Err(DecodeError::DecompressionFailed);
        }
        let max_value = total_number_of_inserts + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut ric = max_wrapped + encoded_insert_count - 1;
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
                prefix if prefix & 0b1111_0000 == 0b0000_0000 => {
                    // Literal Field Line with Post-Base Name Reference
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
                prefix => unreachable!(
                    "unreachable branch(LiteralFieldLineWithPostBaseNameReference should match all other cases)(prefix={prefix:#010b})",
                ),
            }
        };
        decode.await.map_err(|error: DecodeStreamError| {
            error.map_decode_error(|decode_error| {
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
    EncodeStreamError: From<E>,
{
    type Output = ();

    type Error = EncodeStreamError;

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
            .map_err(|error: EncodeStreamError| match error {
                EncodeStreamError::Stream { .. } => {
                    unreachable!("Stream error should not happen when encoding to BufList")
                }
                EncodeStreamError::Encode { source } => source,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::EncodedFieldSectionPrefix;
    use crate::codec::DecodeError;

    // --- Fix 6: RIC modular encoding ---

    #[test]
    fn test_encode_ric_zero() {
        // RFC 9204 §4.5.1.1: RIC == 0 encodes as 0
        assert_eq!(EncodedFieldSectionPrefix::encode_ric(0, 256), 0);
    }

    #[test]
    fn test_encode_ric_nonzero() {
        // max_table_capacity=256, MaxEntries=256/32=8, FullRange=16
        // encode_ric(4, 256) = (4 % 16) + 1 = 5
        assert_eq!(EncodedFieldSectionPrefix::encode_ric(4, 256), 5);
    }

    #[test]
    fn test_decode_ric_zero() {
        // encoded_insert_count == 0 → RIC == 0 (no dynamic references)
        let result = EncodedFieldSectionPrefix::decode_ric(0, 256, 10);
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_decode_ric_nonzero() {
        // decode_ric(5, 256, 10) should return 4 (reverse of encode_ric(4, 256) == 5)
        // MaxEntries=8, FullRange=16, max_value=10+8=18, max_wrapped=(18/16)*16=16
        // ric = 16 + 5 - 1 = 20 > 18 → ric -= 16 → ric = 4
        let result = EncodedFieldSectionPrefix::decode_ric(5, 256, 10);
        assert_eq!(result, Ok(4));
    }

    #[test]
    fn test_ric_roundtrip() {
        // For RIC values 1, 4, 8, 15: encode then decode should recover original
        // total_inserts must satisfy: ric <= total_inserts < ric + MaxEntries
        // Use total_inserts = ric so constraint is met for all test values
        let max_table_capacity = 256;
        for ric in [1u64, 4, 8, 15] {
            let total_inserts = ric; // ric <= total_inserts < ric + 8 satisfied
            let encoded = EncodedFieldSectionPrefix::encode_ric(ric, max_table_capacity);
            let decoded = EncodedFieldSectionPrefix::decode_ric(
                encoded,
                max_table_capacity,
                total_inserts,
            )
            .unwrap_or_else(|e| {
                panic!("decode_ric({encoded}, {max_table_capacity}, {total_inserts}) failed: {e:?}")
            });
            assert_eq!(decoded, ric, "roundtrip failed for ric={ric}");
        }
    }

    #[test]
    fn test_decode_ric_exceeds_full_range() {
        // max_table_capacity=256 → MaxEntries=8, FullRange=16
        // encoded_insert_count=17 > 16 → DecompressionFailed
        let result = EncodedFieldSectionPrefix::decode_ric(17, 256, 10);
        assert_eq!(result, Err(DecodeError::DecompressionFailed));
    }

    #[test]
    fn test_resolve_base_positive() {
        // sign=false: base = required_insert_count + delta_base = 5 + 3 = 8
        let result = EncodedFieldSectionPrefix::resolve_base(5, false, 3);
        assert_eq!(result, Ok(8));
    }

    #[test]
    fn test_resolve_base_negative() {
        // sign=true: base = required_insert_count - delta_base - 1 = 5 - 2 - 1 = 2
        let result = EncodedFieldSectionPrefix::resolve_base(5, true, 2);
        assert_eq!(result, Ok(2));
    }

    #[test]
    fn test_resolve_base_overflow() {
        // sign=true: 1 - 5 - 1 would underflow → ArithmeticOverflow
        let result = EncodedFieldSectionPrefix::resolve_base(1, true, 5);
        assert_eq!(result, Err(DecodeError::ArithmeticOverflow));
    }
}
