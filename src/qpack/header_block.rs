use bytes::Bytes;
use futures::{Sink, Stream};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite};

use crate::{
    codec::{
        StreamReader,
        error::{DecodeStreamError, EncodeStreamError},
    },
    qpack::codec::{
        integer::{decode_integer, encode_integer},
        string::{decode_string, encode_string},
    },
};

/// ``` no_run
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
    required_insert_count: u64,
    delta_base: i64,
}

impl EncodedFieldSectionPrefix {
    pub async fn decode(
        stream: &mut (impl AsyncBufRead + Unpin),
    ) -> Result<Self, DecodeStreamError> {
        let ric_prefix = stream.read_u8().await?;
        let required_insert_count = decode_integer(stream, ric_prefix, 8).await?;
        let db_prefix = stream.read_u8().await?;
        let sign = (db_prefix & 0b1000_0000) != 0;
        let delta_base = decode_integer(stream, db_prefix & 0b0111_1111, 7).await?;
        // TODO: correctness check
        let delta_base = match sign {
            true => -(delta_base as i64),
            false => delta_base as i64,
        };
        Ok(EncodedFieldSectionPrefix {
            required_insert_count,
            delta_base,
        })
    }

    pub async fn encode(
        &self,
        stream: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), EncodeStreamError> {
        let ric_prefix = 0;
        encode_integer(stream, ric_prefix, 8, self.required_insert_count).await?;
        let (sign, db_value) = if self.delta_base < 0 {
            (0b1000_0000, (-self.delta_base) as u64)
        } else {
            (0, self.delta_base as u64)
        };
        let db_prefix = sign;
        encode_integer(stream, db_prefix, 7, db_value).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldLineRepresentation {
    /// ``` no_run
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | T |      Index (6+)       |
    /// +---+---+-----------------------+
    /// ```
    IndexedFieldLine { is_static: bool, index: u64 },
    /// ``` no_run
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 1 |  Index (4+)   |
    /// +---+---+---+---+---------------+
    /// ```
    IndexedFieldLineWithPostBaseIndex { is_static: bool, index: u64 },
    /// ``` no_run
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
        no_dynamic: bool,
        is_static: bool,
        name_index: u64,
        huffman: bool,
        value: Bytes,
    },
    /// ``` no_run
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
    /// ``` no_run
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

impl FieldLineRepresentation {
    pub async fn decode(
        stream: &mut (impl AsyncBufRead + Unpin),
    ) -> Result<Self, DecodeStreamError> {
        let prefix = stream.read_u8().await?;
        match prefix {
            prefix if prefix & 0b1000_0000 == 0b1000_0000 => {
                // Indexed Field Line
                let is_static = (prefix & 0b0100_0000) != 0;
                let index = decode_integer(stream, prefix & 0b0011_1111, 6).await?;
                Ok(FieldLineRepresentation::IndexedFieldLine { is_static, index })
            }
            prefix if prefix & 0b1111_0000 == 0b0001_0000 => {
                // Indexed Field Line with Post-Base Index
                let is_static = (prefix & 0b0000_1000) != 0;
                let index = decode_integer(stream, prefix & 0b0000_0111, 4).await?;
                Ok(FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { is_static, index })
            }
            prefix if prefix & 0b1110_0000 == 0b0100_0000 => {
                // Literal Field Line with Name Reference
                let no_dynamic = (prefix & 0b0001_0000) != 0;
                let is_static = (prefix & 0b0000_1000) != 0;
                let name_index = decode_integer(stream, prefix & 0b0000_0111, 4).await?;
                let value_prefix = stream.read_u8().await?;
                let (huffman, value) = decode_string(stream, value_prefix, 1 + 7).await?;
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
                let name_prefix = prefix & 0b0000_1111;
                let (name_huffman, name) = decode_string(stream, name_prefix, 1 + 3).await?;
                let value_prefix = stream.read_u8().await?;
                let (value_huffman, value) = decode_string(stream, value_prefix, 1 + 7).await?;
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
                let name_index = decode_integer(stream, prefix & 0b0000_0111, 3).await?;
                let value_prefix = stream.read_u8().await?;
                let (huffman, value) = decode_string(stream, value_prefix, 1 + 7).await?;
                Ok(
                    FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                        no_dynamic,
                        name_index,
                        huffman,
                        value,
                    },
                )
            }
            _ => unreachable!(
                "unreachable branch(LiteralFieldLineWithPostBaseNameReference should match all other cases)"
            ),
        }
    }

    pub async fn encode<E>(
        &self,
        stream: &mut (impl AsyncWrite + Sink<Bytes, Error = E> + Unpin),
    ) -> Result<(), EncodeStreamError>
    where
        EncodeStreamError: From<E>,
    {
        match self {
            FieldLineRepresentation::IndexedFieldLine { is_static, index } => {
                let mut prefix = 0b1000_0000;
                if *is_static {
                    prefix |= 0b0100_0000;
                }
                encode_integer(stream, prefix, 6, *index).await?;
            }
            FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { is_static, index } => {
                let mut prefix = 0b0001_0000;
                if *is_static {
                    prefix |= 0b0000_1000;
                }
                encode_integer(stream, prefix, 4, *index).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithNameReference {
                no_dynamic,
                is_static,
                name_index,
                huffman,
                value,
            } => {
                let mut prefix = 0b0100_0000;
                if *no_dynamic {
                    prefix |= 0b0001_0000;
                }
                if *is_static {
                    prefix |= 0b0000_1000;
                }
                encode_integer(stream, prefix, 4, *name_index).await?;
                encode_string(stream, 0, 1 + 7, *huffman, value.clone()).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                no_dynamic,
                name_index,
                huffman,
                value,
            } => {
                let mut prefix = 0b0000_0000;
                if *no_dynamic {
                    prefix |= 0b0000_1000;
                }
                encode_integer(stream, prefix, 3, *name_index).await?;
                encode_string(stream, 0, 1 + 7, *huffman, value.clone()).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                no_dynamic,
                name_huffman,
                name,
                value_huffman,
                value,
            } => {
                let mut prefix = 0b0010_0000;
                if *no_dynamic {
                    prefix |= 0b0001_0000;
                }
                let name_prefix =
                    if *name_huffman { 0b1000_0000 } else { 0 } | (prefix & 0b0000_0111);
                encode_string(stream, name_prefix, 1 + 3, *name_huffman, name.clone()).await?;
                encode_string(stream, 0, 1 + 7, *value_huffman, value.clone()).await?;
            }
        }
        Ok(())
    }
}

pub struct HeaderBlockDecoder<S> {
    prefix: Option<EncodedFieldSectionPrefix>,
    stream: StreamReader<S>,
}

impl<S> HeaderBlockDecoder<S>
where
    S: Stream<Item = Result<Bytes, DecodeStreamError>> + Unpin,
{
    pub const fn new(stream: S) -> Self {
        Self {
            prefix: None,
            stream: StreamReader::new(stream),
        }
    }

    pub async fn prefix(&mut self) -> Result<EncodedFieldSectionPrefix, DecodeStreamError> {
        match self.prefix {
            Some(prefix) => Ok(prefix),
            None => {
                let prefix = EncodedFieldSectionPrefix::decode(&mut self.stream).await?;
                self.prefix = Some(prefix);
                Ok(prefix)
            }
        }
    }

    pub async fn next(&mut self) -> Option<Result<FieldLineRepresentation, DecodeStreamError>> {
        if let Err(error) = self.prefix().await {
            return Some(Err(error));
        }
        match self.stream.fill_buf().await {
            Ok([]) => return None,
            Ok(_) => {}
            Err(error) => return Some(Err(DecodeStreamError::from(error))),
        }
        Some(FieldLineRepresentation::decode(&mut self.stream).await)
    }
}
