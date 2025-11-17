use bytes::Bytes;
use futures::Sink;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite};

use crate::{
    codec::{
        error::{DecodeError, DecodeStreamError, EncodeStreamError},
        util::{DecodeFrom, EncodeInto},
    },
    error::Code,
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
    pub required_insert_count: u64,
    /// The Base is used to resolve references in the dynamic table as
    /// described in Section 3.2.5.
    ///
    /// To save space, the Base is encoded relative to the Required Insert
    /// Count using a one-bit Sign ('S' in Figure 12) and the Delta Base
    /// value. A Sign bit of 0 indicates that the Base is greater than or
    /// equal to the value of the Required Insert Count; the decoder adds the
    /// value of Delta Base to the Required Insert Count to determine the
    /// value of the Base. A Sign bit of 1 indicates that the Base is less
    /// than the Required Insert Count; the decoder subtracts the value of
    /// Delta Base from the Required Insert Count and also subtracts one to
    /// determine the value of the Base. That is:
    ///
    /// ``` fakecode
    /// if Sign == 0:
    ///    Base = ReqInsertCount + DeltaBase
    /// else:
    ///    Base = ReqInsertCount - DeltaBase - 1
    /// ```
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.1.2
    // sign: bool,
    // delta_base: u64,
    pub base: u64,
}

impl<S> DecodeFrom<S> for EncodedFieldSectionPrefix
where
    S: AsyncBufRead,
{
    async fn decode_from(stream: S) -> Result<Self, DecodeStreamError> {
        tokio::pin!(stream);

        let ric_prefix = stream.read_u8().await?;
        let required_insert_count = decode_integer(stream.as_mut(), ric_prefix, 8).await?;
        let db_prefix = stream.read_u8().await?;
        let sign = db_prefix & 0b1000_0000;
        let delta_base = decode_integer(stream.as_mut(), db_prefix & 0b0111_1111, 7).await?;
        // The value of Base MUST NOT be negative. Though the protocol might
        // operate correctly with a negative Base using post-Base indexing, it
        // is unnecessary and inefficient. An endpoint MUST treat a field block
        // with a Sign bit of 1 as invalid if the value of Required Insert Count
        // is less than or equal to the value of Delta Base.
        //
        // https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.1.2-5
        let base = if sign == 0 {
            required_insert_count
                .checked_add(delta_base)
                .ok_or(DecodeError::ArithmeticOverflow)?
        } else {
            required_insert_count
                .checked_sub(delta_base)
                .ok_or(DecodeError::ArithmeticOverflow)?
                .checked_sub(1)
                .ok_or(DecodeError::ArithmeticOverflow)?
        };
        Ok(EncodedFieldSectionPrefix {
            required_insert_count,
            base,
        })
    }
}

impl<S> EncodeInto<S> for EncodedFieldSectionPrefix
where
    S: AsyncWrite,
{
    async fn encode_into(self, stream: S) -> Result<(), EncodeStreamError> {
        tokio::pin!(stream);
        let ric_prefix = 0;
        encode_integer(stream.as_mut(), ric_prefix, 8, self.required_insert_count).await?;
        // if Sign == 0:
        //    Base = ReqInsertCount + DeltaBase
        //    -> DeltaBase = Base - ReqInsertCount (Base >= ReqInsertCount)
        // else:
        //    Base = ReqInsertCount - DeltaBase - 1
        //    -> DeltaBase = ReqInsertCount - Base - 1 (Base < ReqInsertCount)
        let (sign, db_value) = if self.base >= self.required_insert_count {
            (false, self.base - self.required_insert_count)
        } else {
            (true, self.required_insert_count - self.base - 1)
        };
        let db_prefix = if sign { 0b1000_0000 } else { 0b0000_0000 };
        encode_integer(stream.as_mut(), db_prefix, 7, db_value).await?;
        Ok(())
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
        /// https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.4-3
        //
        // TODO: implement this?
        no_dynamic: bool,
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
        no_dynamic: bool,
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
        no_dynamic: bool,
        name_huffman: bool,
        name: Bytes,
        value_huffman: bool,
        value: Bytes,
    },
}

impl<S> DecodeFrom<S> for FieldLineRepresentation
where
    S: AsyncBufRead,
{
    async fn decode_from(stream: S) -> Result<Self, DecodeStreamError> {
        let decode = async move {
            tokio::pin!(stream);
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
                    let no_dynamic = (prefix & 0b0010_0000) != 0;
                    let is_static = (prefix & 0b0001_0000) != 0;
                    let name_index = decode_integer(stream.as_mut(), prefix, 4).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(FieldLineRepresentation::LiteralFieldLineWithNameReference {
                        no_dynamic,
                        is_static,
                        name_index,
                        huffman,
                        value,
                    })
                }
                prefix if prefix & 0b1110_0000 == 0b0010_0000 => {
                    // Literal Field Line with Literal Name
                    let no_dynamic = (prefix & 0b0001_0000) != 0;
                    let name_prefix = prefix;
                    let (name_huffman, name) =
                        decode_string(stream.as_mut(), name_prefix, 1 + 3).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (value_huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                        no_dynamic,
                        name_huffman,
                        name,
                        value_huffman,
                        value,
                    })
                }
                prefix if prefix & 0b1111_0000 == 0b0000_0000 => {
                    // Literal Field Line with Post-Base Name Reference
                    let no_dynamic = (prefix & 0b0000_1000) != 0;
                    let name_index = decode_integer(stream.as_mut(), prefix, 3).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(
                        FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                            no_dynamic,
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
            error.map_decode_error(|decode_error| Code::H3_MESSAGE_ERROR.with(decode_error).into())
        })
    }
}

impl<S> EncodeInto<S> for FieldLineRepresentation
where
    S: AsyncWrite + Sink<Bytes>,
    EncodeStreamError: From<<S as Sink<Bytes>>::Error>,
{
    async fn encode_into(self, stream: S) -> Result<(), EncodeStreamError> {
        tokio::pin!(stream);
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
                no_dynamic,
                is_static,
                name_index,
                huffman,
                value,
            } => {
                let mut prefix = 0b0100_0000;
                if no_dynamic {
                    prefix |= 0b0010_0000;
                }
                if is_static {
                    prefix |= 0b0001_0000;
                }
                encode_integer(stream.as_mut(), prefix, 4, name_index).await?;
                encode_string(stream.as_mut(), 0, 1 + 7, huffman, value).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                no_dynamic,
                name_index,
                huffman,
                value,
            } => {
                let mut prefix = 0b0000_0000;
                if no_dynamic {
                    prefix |= 0b0000_1000;
                }
                encode_integer(stream.as_mut(), prefix, 3, name_index).await?;
                encode_string(stream.as_mut(), 0, 1 + 7, huffman, value).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                no_dynamic,
                name_huffman,
                name,
                value_huffman,
                value,
            } => {
                let mut prefix = 0b0010_0000;
                if no_dynamic {
                    prefix |= 0b0001_0000;
                }
                encode_string(stream.as_mut(), prefix, 1 + 3, name_huffman, name).await?;
                encode_string(stream.as_mut(), 0, 1 + 7, value_huffman, value).await?;
            }
        }
        Ok(())
    }
}
