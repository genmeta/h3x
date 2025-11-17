use std::{
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Stream, TryStream};
use tokio::io::{self, AsyncBufRead, AsyncRead, ReadBuf};

use crate::{
    codec::error::{DecodeError, DecodeStreamError},
    error::StreamError,
    quic::{GetStreamId, StopSending},
    varint::VarInt,
};

pin_project_lite::pin_project! {
    /// Adapter that converts a `Stream` of `Bytes` into a `TryBufStream`
    pub struct StreamReader<S: ?Sized> {
        chunk: Bytes,
        #[pin]
        stream: S,
    }
}

impl<S> StreamReader<S>
where
    S: TryStream<Ok = Bytes> + ?Sized,
{
    pub const fn new(stream: S) -> Self
    where
        S: Sized,
    {
        Self {
            stream,
            chunk: Bytes::new(),
        }
    }

    pub fn poll_bytes<'s>(
        self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<&'s Bytes, S::Error>> {
        static EMPTY_BYTES: Bytes = Bytes::new();
        let mut project = self.project();
        while project.chunk.is_empty() {
            *project.chunk = match ready!(project.stream.as_mut().try_poll_next(cx)?) {
                Some(chunk) => chunk,
                None => return Poll::Ready(Ok(&EMPTY_BYTES)),
            };
        }
        Poll::Ready(Ok(project.chunk))
    }

    pub fn consume(self: Pin<&mut Self>, amt: usize) {
        _ = self.project().chunk.split_to(amt)
    }

    pub async fn has_remaining(mut self: Pin<&mut Self>) -> Result<bool, S::Error> {
        poll_fn(|cx| {
            self.as_mut()
                .poll_bytes(cx)
                .map_ok(|bytes| !bytes.is_empty())
        })
        .await
    }
}

impl<S: TryStream<Ok = Bytes> + ?Sized> Stream for StreamReader<S> {
    type Item = Result<Bytes, S::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().stream.try_poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}

impl<S> AsyncRead for StreamReader<S>
where
    S: TryStream<Ok = Bytes> + ?Sized,
    io::Error: From<S::Error>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let chunk = match ready!(self.as_mut().poll_bytes(cx)?) {
                chunk if chunk.is_empty() => return Poll::Ready(Ok(())),
                chunk => chunk,
            };

            let cap = buf.remaining().min(chunk.len());
            buf.put_slice(&chunk[..cap]);
            self.as_mut().consume(cap);

            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S> AsyncBufRead for StreamReader<S>
where
    S: TryStream<Ok = Bytes> + ?Sized,
    io::Error: From<S::Error>,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        self.poll_bytes(cx)
            .map_err(io::Error::from)
            .map(|res| res.map(|b| &b[..]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        Self::consume(self, amt);
    }
}

impl<S: GetStreamId + ?Sized> GetStreamId for StreamReader<S> {
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        self.project().stream.poll_stream_id(cx)
    }
}

impl<S: StopSending + ?Sized> StopSending for StreamReader<S> {
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        self.project().stream.poll_stop_sending(cx, code)
    }
}

pin_project_lite::pin_project! {
    pub struct FixedLengthReader<S: ?Sized> {
        remaining: u64,
        #[pin]
        stream: S,
    }
}

impl<P: ?Sized> FixedLengthReader<P> {
    pub const fn new(stream: P, length: u64) -> Self
    where
        P: Sized,
    {
        Self {
            stream,
            remaining: length,
        }
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    pub fn into_inner(self) -> P
    where
        P: Sized,
    {
        self.stream
    }
}

impl<R: AsyncRead + ?Sized> AsyncRead for FixedLengthReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let project = self.project();
        if *project.remaining == 0 {
            return Poll::Ready(Ok(()));
        }
        let remaining = (*project.remaining).min(buf.remaining() as u64) as usize;
        let read = {
            let mut buf = buf.take(remaining);
            ready!(project.stream.poll_read(cx, &mut buf)?);
            remaining - buf.remaining()
        };
        match read {
            0 => Poll::Ready(Err(DecodeError::Incomplete.into())),
            read => {
                unsafe {
                    buf.assume_init(read);
                }
                buf.advance(read);
                *project.remaining -= read as u64;

                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<R: AsyncBufRead + ?Sized> AsyncBufRead for FixedLengthReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        let project = self.project();
        if *project.remaining == 0 {
            return Poll::Ready(Ok(&[]));
        }
        match ready!(project.stream.poll_fill_buf(cx)?) {
            [] => Poll::Ready(Err(DecodeError::Incomplete.into())),
            bytes => {
                let len = bytes.len().min(*project.remaining as usize);
                Poll::Ready(Ok(bytes[..len].as_ref()))
            }
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let project = self.project();
        *project.remaining -= amt as u64;
        project.stream.consume(amt);
    }
}

impl<S> Stream for FixedLengthReader<StreamReader<S>>
where
    S: TryStream<Ok = Bytes> + ?Sized,
    DecodeStreamError: From<S::Error>,
{
    type Item = Result<Bytes, DecodeStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut project = self.project();
        if *project.remaining == 0 {
            return Poll::Ready(None);
        }
        match ready!(project.stream.as_mut().poll_bytes(cx)?) {
            bytes if bytes.is_empty() => Poll::Ready(Some(Err(DecodeError::Incomplete.into()))),
            bytes => {
                let len = bytes.len().min(*project.remaining as usize);
                let bytes = bytes.slice(..len);
                *project.remaining -= len as u64;
                project.stream.consume(len);
                Poll::Ready(Some(Ok(bytes)))
            }
        }
    }
}

impl<S: GetStreamId + ?Sized> GetStreamId for FixedLengthReader<S> {
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        self.project().stream.poll_stream_id(cx)
    }
}

impl<S: StopSending + ?Sized> StopSending for FixedLengthReader<S> {
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        self.project().stream.poll_stop_sending(cx, code)
    }
}
