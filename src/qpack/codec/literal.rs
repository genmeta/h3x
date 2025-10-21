use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use crate::codec::error::{DecodeError, DecodeStreamError, EncodeStreamError};

pub async fn decode_literal(
    stream: &mut (impl AsyncBufRead + Unpin),
    length: u64,
) -> Result<Bytes, DecodeStreamError> {
    let mut buffer = BytesMut::with_capacity(length as usize);
    while (buffer.len() as u64) < length {
        let remaining = (length - buffer.len() as u64) as usize;
        let chunk = stream.fill_buf().await?;
        if chunk.is_empty() {
            return Err(DecodeError::Incomplete.into());
        }
        let read = chunk.len().min(remaining);
        buffer.extend_from_slice(&chunk[..read]);
        stream.consume(read);
    }
    Ok(buffer.freeze())
}

pub async fn encode_literal<E>(
    stream: &mut (impl Sink<Bytes, Error = E> + Unpin),
    data: Bytes,
) -> Result<(), EncodeStreamError>
where
    EncodeStreamError: From<E>,
{
    stream.send(data).await?;
    Ok(())
}
