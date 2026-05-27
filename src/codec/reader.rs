use std::{
    future::poll_fn,
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Stream, TryStream};
use tokio::io::{self, AsyncBufRead, AsyncRead, ReadBuf};

use crate::{
    buflist::{BufList, BuflistCursor},
    codec::error::{DecodeError, StreamDecodeError},
    quic,
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

    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> S
    where
        S: Sized,
    {
        self.stream
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

    pub fn map_stream<S1>(self, f: impl FnOnce(S) -> S1) -> StreamReader<S1>
    where
        S: Sized,
    {
        StreamReader {
            chunk: self.chunk,
            stream: f(self.stream),
        }
    }
}

impl<S: TryStream<Ok = Bytes> + ?Sized> Stream for StreamReader<S> {
    type Item = Result<Bytes, S::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.chunk.is_empty() {
            return Poll::Ready(Some(Ok(self.project().chunk.split_off(0))));
        }
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
        let chunk = ready!(self.as_mut().poll_bytes(cx)?);
        if !chunk.is_empty() {
            let cap = buf.remaining().min(chunk.len());
            buf.put_slice(&chunk[..cap]);
            self.as_mut().consume(cap);
        }

        Poll::Ready(Ok(()))
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

impl<S: quic::GetStreamId + ?Sized> quic::GetStreamId for StreamReader<S> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.project().stream.poll_stream_id(cx)
    }
}

impl<S: quic::StopStream + ?Sized> quic::StopStream for StreamReader<S> {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.project().stream.poll_stop(cx, code)
    }
}

pin_project_lite::pin_project! {
    pub struct FixedLengthReader<S: ?Sized> {
        remaining: u64,
        #[pin]
        stream: S,
    }
}

impl<S: ?Sized> FixedLengthReader<S> {
    pub const fn new(stream: S, length: u64) -> Self
    where
        S: Sized,
    {
        Self {
            stream,
            remaining: length,
        }
    }

    pub fn renew(self: Pin<&mut Self>, remaining: u64) {
        *self.project().remaining = remaining
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn project_stream_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        self.project().stream
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
                // SAFETY: `poll_read` on the inner stream initializes exactly `read`
                // bytes into the buffer. We must inform the ReadBuf that these bytes
                // are now initialized. This is the standard AsyncRead pattern and
                // ReadBuf::assume_init has no safe alternative in tokio's API.
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
    StreamDecodeError: From<S::Error>,
{
    type Item = Result<Bytes, StreamDecodeError>;

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

impl<S> Stream for FixedLengthReader<&mut StreamReader<S>>
where
    S: TryStream<Ok = Bytes> + Unpin + ?Sized,
    StreamDecodeError: From<S::Error>,
{
    type Item = Result<Bytes, StreamDecodeError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(None);
        }
        // Pin::new is safe here because StreamReader<S>: Unpin when S: Unpin
        match ready!(Pin::new(&mut *this.stream).poll_bytes(cx)?) {
            bytes if bytes.is_empty() => Poll::Ready(Some(Err(DecodeError::Incomplete.into()))),
            bytes => {
                let len = bytes.len().min(this.remaining as usize);
                let bytes = bytes.slice(..len);
                this.remaining -= len as u64;
                Pin::new(&mut *this.stream).consume(len);
                Poll::Ready(Some(Ok(bytes)))
            }
        }
    }
}

impl<S: quic::GetStreamId + ?Sized> quic::GetStreamId for FixedLengthReader<S> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.project().stream.poll_stream_id(cx)
    }
}

impl<S: quic::StopStream + ?Sized> quic::StopStream for FixedLengthReader<S> {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.project().stream.poll_stop(cx, code)
    }
}

pin_project_lite::pin_project! {
    /// A cursor-based wrapper around [`StreamReader`] that supports peek
    /// (non-destructive read), reset (rollback), and commit (consume) operations.
    ///
    /// Bytes read via [`poll_bytes`](Self::poll_bytes) are buffered internally.
    /// The `cursor` tracks how many bytes have been "peeked" (logically consumed).
    ///
    /// - [`reset`](Self::reset) — rolls `cursor` back to 0, allowing the same
    ///   bytes to be re-read.
    /// - [`commit`](Self::commit) — discards all buffered bytes up to the cursor,
    ///   making the peek permanent.
    /// - [`into_stream_reader`](Self::into_stream_reader) — converts back into a
    ///   plain `StreamReader`, preserving any unconsumed buffered data.
    pub struct PeekableStreamReader<S: ?Sized> {
        buffered: BuflistCursor,
        #[pin]
        stream: StreamReader<S>,
    }
}

impl<S: ?Sized> PeekableStreamReader<S> {
    /// Creates a new `PeekableStreamReader` wrapping the given `StreamReader`.
    pub fn new(stream: StreamReader<S>) -> Self
    where
        S: Sized,
    {
        Self {
            stream,
            buffered: BuflistCursor::new(BufList::new()),
        }
    }

    /// Resets the cursor to 0, allowing previously peeked bytes to be re-read.
    pub fn reset(self: Pin<&mut Self>) {
        self.project().buffered.reset();
    }

    /// Advances the cursor by `amt` bytes. This marks bytes as "peeked" but
    /// does not discard them — call [`commit`](Self::commit) to make the
    /// consumption permanent, or [`reset`](Self::reset) to roll back.
    pub fn consume(self: Pin<&mut Self>, amt: usize) {
        self.project().buffered.advance(amt);
    }

    /// Discards all buffered bytes up to the current cursor position,
    /// making the peek permanent. Resets the cursor to 0 afterward.
    pub fn commit(self: Pin<&mut Self>) {
        self.project().buffered.commit();
    }

    pub fn flush(self: Pin<&mut Self>) {
        let project = self.project();

        let stream_project = project.stream.project();

        project.buffered.commit();
        // After commit, self.buffered contains bytes that were pulled from
        // the stream during peek but lie beyond the old cursor. These must
        // be preserved by prepending them to the StreamReader's chunk.
        let mut stream_chunk = BytesMut::from(mem::take(stream_project.chunk));
        while project.buffered.has_remaining() {
            let chunk = project
                .buffered
                .copy_to_bytes(project.buffered.chunk().len());
            stream_chunk.put(chunk);
        }

        *stream_project.chunk = stream_chunk.freeze();
    }
}

impl<S> PeekableStreamReader<S>
where
    S: TryStream<Ok = Bytes> + Unpin,
{
    /// Polls for the next chunk of bytes at the cursor position.
    ///
    /// If there is data in the buffer beyond the cursor, returns that data
    /// immediately. Otherwise, pulls a new chunk from the underlying stream,
    /// appends it to the buffer, and returns it.
    ///
    /// The cursor is NOT advanced by this call — use [`consume`](Self::consume)
    /// to advance the cursor after inspecting the data.
    pub fn poll_bytes(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<&[u8], S::Error>> {
        let project = self.project();

        // If we have buffered data beyond the cursor, return it.
        if project.buffered.has_remaining() {
            return Poll::Ready(Ok((*project.buffered).chunk()));
        }

        // No buffered data beyond cursor — pull from underlying stream.
        let Some(chunk) = ready!(project.stream.poll_next(cx)?) else {
            return Poll::Ready(Ok(&[]));
        };

        debug_assert!(
            chunk.has_remaining(),
            "StreamReader should not yield empty chunks"
        );

        project.buffered.write(chunk.clone());
        Poll::Ready(Ok((*project.buffered).chunk()))
    }

    /// Consumes this `PeekableStreamReader` and returns the underlying
    /// `StreamReader`, preserving all buffered data.
    ///
    /// The current cursor position is first committed (bytes before cursor
    /// are discarded). Any remaining buffered bytes (beyond the cursor) are
    /// concatenated and prepended to the `StreamReader`'s internal chunk,
    /// ensuring no data is lost.
    pub fn into_stream_reader(mut self) -> StreamReader<S> {
        Pin::new(&mut self).flush();
        self.stream
    }
}

impl<S> AsyncRead for PeekableStreamReader<S>
where
    S: TryStream<Ok = Bytes> + Unpin,
    io::Error: From<S::Error>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let chunk = ready!(self.as_mut().poll_bytes(cx)?);
        if !chunk.is_empty() {
            let cap = buf.remaining().min(chunk.len());
            buf.put_slice(&chunk[..cap]);
            self.consume(cap);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncBufRead for PeekableStreamReader<S>
where
    S: TryStream<Ok = Bytes> + Unpin,
    io::Error: From<S::Error>,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        self.poll_bytes(cx).map_err(io::Error::from)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.consume(amt);
    }
}

impl<S: quic::GetStreamId + Unpin> quic::GetStreamId for PeekableStreamReader<S> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_stream_id(cx)
    }
}

impl<S: quic::StopStream + Unpin> quic::StopStream for PeekableStreamReader<S> {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_stop(cx, code)
    }
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, pin::Pin};

    use bytes::Bytes;
    use futures::{StreamExt, stream};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};

    use super::*;
    use crate::quic::{GetStreamId, StopStream, StreamError};

    fn byte_stream(
        chunks: impl IntoIterator<Item = &'static [u8]>,
    ) -> impl Stream<Item = Result<Bytes, StreamError>> {
        stream::iter(
            chunks
                .into_iter()
                .map(|chunk| Ok::<_, StreamError>(Bytes::from_static(chunk))),
        )
    }

    #[tokio::test]
    async fn stream_reader_accessors_mapping_and_io_paths() {
        let mut reader = StreamReader::new(byte_stream([&b""[..], &b"hello"[..], &b" world"[..]]));
        assert_eq!(reader.stream().size_hint(), (3, Some(3)));
        assert_eq!(reader.stream_mut().size_hint(), (3, Some(3)));

        let mut pinned = Pin::new(&mut reader);
        assert!(pinned.as_mut().has_remaining().await.unwrap());

        let mut prefix = [0; 2];
        pinned
            .as_mut()
            .read_exact(&mut prefix)
            .await
            .expect("partial async read should succeed");
        assert_eq!(&prefix, b"he");

        assert_eq!(
            pinned.as_mut().fill_buf().await.expect("fill buffered"),
            b"llo"
        );
        pinned.as_mut().consume(3);

        assert_eq!(
            pinned
                .as_mut()
                .next()
                .await
                .expect("remaining chunk should be yielded")
                .unwrap(),
            Bytes::from_static(b" world")
        );
        assert!(
            !pinned
                .as_mut()
                .has_remaining()
                .await
                .expect("eof should be clean")
        );

        let mapped = StreamReader::new(byte_stream([&b"a"[..]])).map_stream(|inner| inner);
        let mut mapped = Box::pin(mapped);
        assert_eq!(
            mapped
                .as_mut()
                .next()
                .await
                .expect("mapped stream should yield")
                .unwrap(),
            Bytes::from_static(b"a")
        );

        let inner = StreamReader::new(byte_stream([&b"inner"[..]])).into_inner();
        assert_eq!(inner.size_hint(), (1, Some(1)));
    }

    #[tokio::test]
    async fn fixed_length_reader_limits_renews_and_reports_incomplete_reads() {
        let mut reader = FixedLengthReader::new(tokio::io::empty(), 0);
        let mut empty = [0; 1];
        let read = reader
            .read(&mut empty)
            .await
            .expect("zero remaining reads eof");
        assert_eq!(read, 0);

        let mut reader = FixedLengthReader::new(tokio::io::empty(), 1);
        let err = reader
            .read_exact(&mut empty)
            .await
            .expect_err("premature eof should be incomplete");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        let mut reader = FixedLengthReader::new(tokio::io::BufReader::new(&b"abcdef"[..]), 4);
        let mut buf = [0; 8];
        let read = reader.read(&mut buf).await.expect("bounded read");
        assert_eq!(read, 4);
        assert_eq!(&buf[..read], b"abcd");
        assert_eq!(reader.read(&mut buf).await.expect("remaining exhausted"), 0);

        Pin::new(&mut reader).renew(2);
        assert_eq!(reader.fill_buf().await.expect("renewed fill buffer"), b"ef");
        reader.consume(1);
        assert_eq!(
            reader.fill_buf().await.expect("remaining after consume"),
            b"f"
        );

        let stream = reader.stream_mut();
        assert_eq!(stream.buffer().len(), 1);

        let mut pinned = Pin::new(&mut reader);
        let stream = pinned.as_mut().project_stream_mut();
        assert_eq!(stream.buffer().len(), 1);
    }

    #[tokio::test]
    async fn fixed_length_streams_slice_owned_and_borrowed_stream_readers() {
        let stream_reader = StreamReader::new(byte_stream([&b"ab"[..], &b"cdef"[..]]));
        let mut reader = Box::pin(FixedLengthReader::new(stream_reader, 5));

        assert_eq!(
            reader
                .as_mut()
                .next()
                .await
                .expect("first chunk")
                .expect("first chunk ok"),
            Bytes::from_static(b"ab")
        );
        assert_eq!(
            reader
                .as_mut()
                .next()
                .await
                .expect("second chunk")
                .expect("second chunk ok"),
            Bytes::from_static(b"cde")
        );
        assert!(reader.as_mut().next().await.is_none());

        let mut stream_reader = StreamReader::new(byte_stream([&b"12"[..], &b"345"[..]]));
        let mut borrowed = Box::pin(FixedLengthReader::new(&mut stream_reader, 4));
        assert_eq!(
            borrowed
                .as_mut()
                .next()
                .await
                .expect("borrowed first chunk")
                .expect("borrowed first chunk ok"),
            Bytes::from_static(b"12")
        );
        assert_eq!(
            borrowed
                .as_mut()
                .next()
                .await
                .expect("borrowed second chunk")
                .expect("borrowed second chunk ok"),
            Bytes::from_static(b"34")
        );
        assert!(borrowed.as_mut().next().await.is_none());

        let mut incomplete = Box::pin(FixedLengthReader::new(
            StreamReader::new(byte_stream([&b"x"[..]])),
            2,
        ));
        assert_eq!(
            incomplete
                .as_mut()
                .next()
                .await
                .expect("available byte")
                .expect("available byte ok"),
            Bytes::from_static(b"x")
        );
        assert!(
            incomplete
                .as_mut()
                .next()
                .await
                .expect("incomplete item")
                .is_err()
        );
    }

    #[tokio::test]
    async fn peekable_stream_reader_reset_commit_flush_and_traits() {
        let stream_id = VarInt::from_u32(91);
        let stop_code = VarInt::from_u32(92);
        let (mock_reader, _mock_writer) = crate::quic::test::mock_stream_pair(stream_id);
        let mut reader = Box::pin(PeekableStreamReader::new(StreamReader::new(mock_reader)));

        assert_eq!(
            poll_fn(|cx| reader.as_mut().poll_stream_id(cx))
                .await
                .expect("stream id"),
            stream_id
        );
        poll_fn(|cx| reader.as_mut().poll_stop(cx, stop_code))
            .await
            .expect("stop should delegate");

        let mut reader = Box::pin(PeekableStreamReader::new(StreamReader::new(byte_stream([
            &b"abc"[..],
            &b"def"[..],
        ]))));
        assert_eq!(reader.as_mut().fill_buf().await.unwrap(), b"abc");
        reader.as_mut().consume(2);
        reader.as_mut().reset();
        assert_eq!(reader.as_mut().fill_buf().await.unwrap(), b"abc");
        reader.as_mut().consume(2);
        reader.as_mut().commit();
        assert_eq!(reader.as_mut().fill_buf().await.unwrap(), b"c");

        let mut one = [0; 1];
        reader
            .as_mut()
            .read_exact(&mut one)
            .await
            .expect("peekable async read should consume committed byte");
        assert_eq!(&one, b"c");

        assert_eq!(reader.as_mut().fill_buf().await.unwrap(), b"def");
        reader.as_mut().consume(1);
        let mut plain = Pin::into_inner(reader).into_stream_reader();
        assert_eq!(
            Pin::new(&mut plain)
                .next()
                .await
                .expect("flushed buffered tail")
                .unwrap(),
            Bytes::from_static(b"ef")
        );
    }
}
