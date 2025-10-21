use bytes::Bytes;
use futures::Sink;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite};

use crate::{
    codec::error::{DecodeStreamError, EncodeStreamError},
    qpack::codec::{
        integer::{decode_integer, encode_integer},
        string::{decode_string, encode_string},
    },
};

pub enum EncoderInstruction {
    /// ``` no_rn
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 |   Capacity (5+)   |
    /// +---+---+---+-------------------+
    /// ```
    SetDynamicTableCapacity { capacity: u64 },
    /// ``` no_run
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | T |    Name Index (6+)    |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    InsertWithNameReference {
        is_static: bool,
        name_index: u64,
        huffman: bool,
        value: Bytes,
    },
    /// ``` no_run
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 | H | Name Length (5+)  |
    /// +---+---+---+-------------------+
    /// |  Name String (Length bytes)   |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    InsertWithLiteralName {
        name_huffman: bool,
        name: Bytes,
        value_huffman: bool,
        value: Bytes,
    },
    /// ``` no_run
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 |    Index (5+)     |
    /// +---+---+---+-------------------+
    /// ```
    Duplicate { index: u64 },
}

impl EncoderInstruction {
    pub async fn decode(
        stream: &mut (impl AsyncBufRead + Unpin),
    ) -> Result<Self, DecodeStreamError> {
        let prefix = stream.read_u8().await?;
        match prefix {
            prefix if prefix & 0b1110_0000 == 0b0010_0000 => {
                let capacity = decode_integer(stream, prefix, 5).await?;
                Ok(EncoderInstruction::SetDynamicTableCapacity { capacity })
            }
            prefix if prefix & 0b1100_0000 == 0b1100_0000 => {
                // decode name index
                let is_static = (prefix & 0b0010_0000) != 0;
                let name_index = decode_integer(stream, prefix, 6).await?;
                // decode value
                let value_prefix = stream.read_u8().await?;
                let (huffman, value) = decode_string(stream, value_prefix, 1 + 7).await?;
                Ok(EncoderInstruction::InsertWithNameReference {
                    is_static,
                    name_index,
                    huffman,
                    value,
                })
            }
            prefix if prefix & 0b1110_0000 == 0b0100_0000 => {
                // decode name
                let name_prefix = prefix;
                let (name_huffman, name) = decode_string(stream, name_prefix, 1 + 5).await?;
                // decode value
                let value_prefix = stream.read_u8().await?;
                let (value_huffman, value) = decode_string(stream, value_prefix, 1 + 7).await?;
                Ok(EncoderInstruction::InsertWithLiteralName {
                    name_huffman,
                    name,
                    value_huffman,
                    value,
                })
            }
            prefix if prefix & 0b1110_0000 == 0b0000_0000 => {
                let index = decode_integer(stream, prefix, 5).await?;
                Ok(EncoderInstruction::Duplicate { index })
            }
            _ => unreachable!("unreachable branch(Duplicate should match all other cases)"),
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
            EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                let prefix = 0b0010_0000;
                encode_integer(stream, prefix, 5, *capacity).await
            }
            EncoderInstruction::InsertWithNameReference {
                is_static,
                name_index,
                huffman,
                value,
            } => {
                let mut prefix = 0b1100_0000;
                if *is_static {
                    prefix |= 0b0010_0000;
                }
                encode_integer(stream, prefix, 6, *name_index).await?;
                encode_string(stream, 0, 1 + 7, *huffman, value.clone()).await?;
                Ok(())
            }
            EncoderInstruction::InsertWithLiteralName {
                name_huffman,
                name,
                value_huffman,
                value,
            } => {
                let name_prefix = 0b0100_0000;
                encode_string(stream, name_prefix, 1 + 5, *name_huffman, name.clone()).await?;
                encode_string(stream, 0, 1 + 7, *value_huffman, value.clone()).await?;
                Ok(())
            }
            EncoderInstruction::Duplicate { index } => {
                let prefix = 0b0000_0000;
                encode_integer(stream, prefix, 5, *index).await
            }
        }
    }
}

pub enum DecoderInstruction {
    /// ``` no_run
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 |      Stream ID (7+)       |
    /// +---+---------------------------+
    /// ```
    SectionAcknowledgment { stream_id: u64 },
    /// ``` no_run
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 |     Stream ID (6+)    |
    /// +---+---+-----------------------+
    /// ```
    StreamCancellation { stream_id: u64 },
    /// ``` no_run
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 |     Increment (6+)    |
    /// +---+---+-----------------------+
    /// ```
    InsertCountIncrement { increment: u64 },
}

impl DecoderInstruction {
    pub async fn decode(
        stream: &mut (impl AsyncBufRead + Unpin),
    ) -> Result<Self, DecodeStreamError> {
        let prefix = stream.read_u8().await?;
        match prefix {
            prefix if prefix & 0b1000_0000 == 0b1000_0000 => {
                let stream_id = decode_integer(stream, prefix, 7).await?;
                Ok(DecoderInstruction::SectionAcknowledgment { stream_id })
            }
            prefix if prefix & 0b1100_0000 == 0b0100_0000 => {
                let stream_id = decode_integer(stream, prefix, 6).await?;
                Ok(DecoderInstruction::StreamCancellation { stream_id })
            }
            prefix if prefix & 0b1100_0000 == 0b0000_0000 => {
                let increment = decode_integer(stream, prefix, 6).await?;
                Ok(DecoderInstruction::InsertCountIncrement { increment })
            }
            _ => unreachable!(
                "unreachable branch(InsertCountIncrement should match all other cases)"
            ),
        }
    }

    pub async fn encode(
        &self,
        stream: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), EncodeStreamError> {
        match self {
            DecoderInstruction::SectionAcknowledgment { stream_id } => {
                let prefix = 0b1000_0000;
                encode_integer(stream, prefix, 7, *stream_id).await
            }
            DecoderInstruction::StreamCancellation { stream_id } => {
                let prefix = 0b0100_0000;
                encode_integer(stream, prefix, 6, *stream_id).await
            }
            DecoderInstruction::InsertCountIncrement { increment } => {
                let prefix = 0b0000_0000;
                encode_integer(stream, prefix, 6, *increment).await
            }
        }
    }
}
