use std::{
    future::poll_fn,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Stream, TryStream};
use tokio::io::{self, AsyncBufRead, AsyncRead, ReadBuf};

use crate::{
    codec::error::{DecodeError, DecodeStreamError},
    quic::{GetStreamId, StopSending},
};

pin_project_lite::pin_project! {
    /// Adapter that converts a `Stream` of `Bytes` into a `TryBufStream`
    pub struct BufStreamReader<S: ?Sized> {
        chunk: Bytes,
        #[pin]
        stream: S,
    }
}

impl<S> BufStreamReader<S>
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

impl<S: TryStream<Ok = Bytes> + ?Sized> Stream for BufStreamReader<S> {
    type Item = Result<Bytes, S::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().stream.try_poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}

impl<S> AsyncRead for BufStreamReader<S>
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

impl<S> AsyncBufRead for BufStreamReader<S>
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

impl<S: GetStreamId> GetStreamId for BufStreamReader<S> {
    fn stream_id(&self) -> u64 {
        self.stream.stream_id()
    }
}

impl<S: StopSending> StopSending for BufStreamReader<S> {
    fn stop_sending(self: Pin<&mut Self>, code: u64) {
        self.project().stream.stop_sending(code);
    }
}

pin_project_lite::pin_project! {
    pub struct FixedLengthReader<P> {
        remaining: u64,
        #[pin]
        stream: Pin<P>,
    }
}

impl<P> FixedLengthReader<P> {
    pub const fn new(stream: Pin<P>, length: u64) -> Self {
        Self {
            stream,
            remaining: length,
        }
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    pub fn into_inner(self) -> Pin<P> {
        self.stream
    }
}

impl<P> AsyncRead for FixedLengthReader<P>
where
    P: DerefMut<Target: AsyncRead>,
{
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

impl<P> AsyncBufRead for FixedLengthReader<P>
where
    P: DerefMut<Target: AsyncBufRead>,
{
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

impl<P, S> Stream for FixedLengthReader<P>
where
    P: DerefMut<Target = BufStreamReader<S>>,
    S: TryStream<Ok = Bytes> + ?Sized,
    DecodeStreamError: From<S::Error>,
{
    type Item = Result<Bytes, DecodeStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let project = self.project();
        if *project.remaining == 0 {
            return Poll::Ready(None);
        }
        let mut stream = project.stream.as_deref_mut();
        match ready!(stream.as_mut().poll_bytes(cx)?) {
            bytes if bytes.is_empty() => Poll::Ready(Some(Err(DecodeError::Incomplete.into()))),
            bytes => {
                let len = bytes.len().min(*project.remaining as usize);
                let bytes = bytes.slice(..len);
                *project.remaining -= len as u64;
                stream.consume(len);
                Poll::Ready(Some(Ok(bytes)))
            }
        }
    }
}

impl<P, S> GetStreamId for FixedLengthReader<P>
where
    P: DerefMut<Target = BufStreamReader<S>>,
    S: GetStreamId,
{
    fn stream_id(&self) -> u64 {
        self.stream.stream_id()
    }
}

impl<P, S> StopSending for FixedLengthReader<P>
where
    P: DerefMut<Target = BufStreamReader<S>>,
    S: StopSending,
{
    fn stop_sending(self: Pin<&mut Self>, code: u64) {
        self.project().stream.as_deref_mut().stop_sending(code);
    }
}
