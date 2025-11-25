use std::pin::pin;

use bytes::Bytes;
use futures::Sink;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite};

use crate::{
    codec::{Decode, DecodeStreamError, Encode},
    connection::StreamError,
    error::H3CriticalStreamClosed,
    qpack::{
        integer::{decode_integer, encode_integer},
        string::{decode_string, encode_string},
    },
    quic,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderInstruction {
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 |   Capacity (5+)   |
    /// +---+---+---+-------------------+
    /// ```
    SetDynamicTableCapacity { capacity: u64 },
    /// ``` ignore
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
    /// ``` ignore
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
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 |    Index (5+)     |
    /// +---+---+---+-------------------+
    /// ```
    Duplicate { index: u64 },
}

impl<S: AsyncBufRead> Decode<EncoderInstruction> for S {
    type Error = StreamError;

    async fn decode(self) -> Result<EncoderInstruction, Self::Error> {
        let decode = async move {
            let mut stream = pin!(self);
            let prefix = stream.read_u8().await?;
            match prefix {
                prefix if prefix & 0b1110_0000 == 0b0010_0000 => {
                    let capacity = decode_integer(stream, prefix, 5).await?;
                    Ok(EncoderInstruction::SetDynamicTableCapacity { capacity })
                }
                prefix if prefix & 0b1000_0000 == 0b1000_0000 => {
                    // decode name index
                    let is_static = (prefix & 0b0100_0000) != 0;
                    let name_index = decode_integer(stream.as_mut(), prefix, 6).await?;
                    // decode value
                    let value_prefix = stream.read_u8().await?;
                    let (huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
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
                    let (name_huffman, name) =
                        decode_string(stream.as_mut(), name_prefix, 1 + 5).await?;
                    // decode value
                    let value_prefix = stream.read_u8().await?;
                    let (value_huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
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
        };
        decode.await.map_err(|error: DecodeStreamError| {
            error.map_stream_closed(|| H3CriticalStreamClosed::QPackEncoder.into())
        })
    }
}

impl<S> Encode<EncoderInstruction> for S
where
    S: AsyncWrite + Sink<Bytes, Error = quic::StreamError>,
{
    type Output = ();

    type Error = StreamError;

    async fn encode(self, inst: EncoderInstruction) -> Result<Self::Output, Self::Error> {
        let encode = async move {
            let mut stream = pin!(self);
            match inst {
                EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                    let prefix = 0b0010_0000;
                    encode_integer(stream, prefix, 5, capacity).await?;
                    Ok(())
                }
                EncoderInstruction::InsertWithNameReference {
                    is_static,
                    name_index,
                    huffman,
                    value,
                } => {
                    let mut prefix = 0b1000_0000;
                    if is_static {
                        prefix |= 0b0100_0000;
                    }
                    encode_integer(stream.as_mut(), prefix, 6, name_index).await?;
                    encode_string(stream.as_mut(), 0, 1 + 7, huffman, value).await?;
                    Ok(())
                }
                EncoderInstruction::InsertWithLiteralName {
                    name_huffman,
                    name,
                    value_huffman,
                    value,
                } => {
                    let name_prefix = 0b0100_0000;
                    encode_string(stream.as_mut(), name_prefix, 1 + 5, name_huffman, name).await?;
                    encode_string(stream.as_mut(), 0, 1 + 7, value_huffman, value).await?;
                    Ok(())
                }
                EncoderInstruction::Duplicate { index } => {
                    let prefix = 0b0000_0000;
                    encode_integer(stream.as_mut(), prefix, 5, index).await?;
                    Ok(())
                }
            }
        };
        encode
            .await
            .map_err(|error: quic::StreamError| match error {
                quic::StreamError::Connection { .. } => error.into(),
                quic::StreamError::Reset { .. } => H3CriticalStreamClosed::QPackEncoder.into(),
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderInstruction {
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 |      Stream ID (7+)       |
    /// +---+---------------------------+
    /// ```
    SectionAcknowledgment { stream_id: u64 },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 |     Stream ID (6+)    |
    /// +---+---+-----------------------+
    /// ```
    StreamCancellation { stream_id: u64 },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 |     Increment (6+)    |
    /// +---+---+-----------------------+
    /// ```
    InsertCountIncrement { increment: u64 },
}

impl<S: AsyncBufRead> Decode<DecoderInstruction> for S {
    type Error = StreamError;

    async fn decode(self) -> Result<DecoderInstruction, StreamError> {
        let decode = async move {
            let mut stream = pin!(self);
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
        };
        decode.await.map_err(|error: DecodeStreamError| {
            error.map_stream_closed(|| H3CriticalStreamClosed::QPackDecoder.into())
        })
    }
}

impl<S> Encode<DecoderInstruction> for S
where
    S: AsyncWrite,
{
    type Output = ();

    type Error = StreamError;

    async fn encode(self, inst: DecoderInstruction) -> Result<Self::Output, Self::Error> {
        let encode = async move {
            let mut stream = pin!(self);
            match inst {
                DecoderInstruction::SectionAcknowledgment { stream_id } => {
                    let prefix = 0b1000_0000;
                    encode_integer(stream.as_mut(), prefix, 7, stream_id).await?;
                    Ok(())
                }
                DecoderInstruction::StreamCancellation { stream_id } => {
                    let prefix = 0b0100_0000;
                    encode_integer(stream.as_mut(), prefix, 6, stream_id).await?;
                    Ok(())
                }
                DecoderInstruction::InsertCountIncrement { increment } => {
                    let prefix = 0b0000_0000;
                    encode_integer(stream.as_mut(), prefix, 6, increment).await?;
                    Ok(())
                }
            }
        };
        encode
            .await
            .map_err(|error: quic::StreamError| match error {
                quic::StreamError::Connection { .. } => error.into(),
                quic::StreamError::Reset { .. } => H3CriticalStreamClosed::QPackEncoder.into(),
            })
    }
}
