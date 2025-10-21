use bytes::Bytes;
use futures::Sink;
use tokio::io::{AsyncBufRead, AsyncWrite};

use crate::{
    codec::error::{DecodeStreamError, EncodeStreamError},
    qpack::codec::{
        huffman::{decode_huffman, encode_huffman},
        integer::{decode_integer, encode_integer},
        literal::{decode_literal, encode_literal},
    },
};

pub async fn decode_string(
    stream: &mut (impl AsyncBufRead + Unpin),
    prefix: u8,
    n: u8,
) -> Result<(bool, Bytes), DecodeStreamError> {
    let huffman = (prefix >> (n - 1)) & 1 == 1;
    let length = decode_integer(stream, prefix, n - 1).await?;
    match huffman {
        true => Ok((huffman, decode_huffman(stream, length).await?)),
        false => Ok((huffman, decode_literal(stream, length).await?)),
    }
}

pub async fn encode_string<E>(
    stream: &mut (impl AsyncWrite + Sink<Bytes, Error = E> + Unpin),
    mut prefix: u8,
    n: u8,
    huffman: bool,
    data: Bytes,
) -> Result<(), EncodeStreamError>
where
    EncodeStreamError: From<E>,
{
    let length = data.len() as u64;
    // set H bit
    prefix |= (huffman as u8) << (n - 1);
    encode_integer(stream, prefix, n - 1, length).await?;
    match huffman {
        true => encode_huffman(stream, data).await,
        false => encode_literal(stream, data).await,
    }
}
