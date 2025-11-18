use bytes::Bytes;
use futures::{Sink, SinkExt};
use httlib_huffman::DecoderSpeed;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite};

use crate::{
    codec::{
        FixedLengthReader,
        error::{DecodeError, DecodeStreamError},
    },
    error::StreamError,
    qpack::integer::{decode_integer, encode_integer},
};

pub async fn decode_string(
    stream: impl AsyncBufRead,
    prefix: u8,
    n: u8,
) -> Result<(bool, Bytes), DecodeStreamError> {
    tokio::pin!(stream);
    let huffman = (prefix >> (n - 1)) & 1 == 1;
    let length = decode_integer(stream.as_mut(), prefix, n - 1).await?;
    let mut value = Vec::with_capacity(length as usize);
    FixedLengthReader::new(stream.as_mut(), length)
        .read_to_end(&mut value)
        .await?;
    match huffman {
        true => Ok((huffman, {
            let mut decoded_value = vec![];
            httlib_huffman::decode(&value, &mut decoded_value, DecoderSpeed::FourBits)
                .map_err(DecodeError::from)?;
            Bytes::from_owner(decoded_value)
        })),
        false => Ok((huffman, Bytes::from_owner(value))),
    }
}

pub async fn encode_string<E>(
    stream: impl AsyncWrite + Sink<Bytes, Error = E>,
    mut prefix: u8,
    n: u8,
    huffman: bool,
    data: Bytes,
) -> Result<(), StreamError>
where
    StreamError: From<E>,
{
    tokio::pin!(stream);
    // set H bit
    prefix |= (huffman as u8) << (n - 1);

    match huffman {
        true => {
            let mut encoded_data = vec![];
            httlib_huffman::encode(&data, &mut encoded_data)
                .expect("Invalid header value sequence");
            encode_integer(stream.as_mut(), prefix, n - 1, encoded_data.len() as u64).await?;
            stream.send(Bytes::from_owner(encoded_data)).await?;
            Ok(())
        }
        false => {
            encode_integer(stream.as_mut(), prefix, n - 1, data.len() as u64).await?;
            stream.send(Bytes::from_owner(data)).await?;
            Ok(())
        }
    }
}
