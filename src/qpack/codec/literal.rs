use std::{
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Bytes, BytesMut};
use futures::Sink;
use tokio::io::AsyncBufRead;

use crate::codec::error::{DecodeError, DecodeStreamError, EncodeStreamError};

pub struct DecodingLiteral {
    length: u64,
    buffer: BytesMut,
}

impl DecodingLiteral {
    pub fn new(length: u64) -> Self {
        Self {
            length,
            buffer: BytesMut::new(),
        }
    }

    pub fn poll_decode(
        &mut self,
        stream: &mut (impl AsyncBufRead + Unpin),
        cx: &mut Context,
    ) -> Poll<Result<Bytes, DecodeStreamError>> {
        while self.length > self.buffer.len() as u64 {
            let remaining = (self.length - self.buffer.len() as u64) as usize;
            let chunk = ready!(Pin::new(&mut *stream).poll_fill_buf(cx))?;
            if chunk.is_empty() {
                return Poll::Ready(Err(DecodeError::Incomplete.into()));
            }
            let read = chunk.len().min(remaining);
            self.buffer.extend_from_slice(&chunk[..read]);
            Pin::new(&mut *stream).consume(read);
        }
        Poll::Ready(Ok(mem::take(&mut self.buffer).freeze()))
    }
}

pub struct LiteralEncoder {
    data: Bytes,
}

impl LiteralEncoder {
    pub const fn new(data: Bytes) -> Self {
        Self { data }
    }

    pub fn poll_encode<E>(
        &mut self,
        stream: &mut (impl Sink<Bytes, Error = E> + Unpin),
        cx: &mut Context,
    ) -> Poll<Result<(), EncodeStreamError>>
    where
        EncodeStreamError: From<E>,
    {
        if !self.data.is_empty() {
            ready!(Pin::new(&mut *stream).poll_ready(cx)?);
            Pin::new(&mut *stream).start_send(mem::take(&mut self.data))?;
        }
        Poll::Ready(Ok(()))
    }
}
