use std::{
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::TryStream;
use tokio::io::{self, AsyncBufRead, AsyncRead, ReadBuf};

use crate::codec::StreamReader;

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
pub struct PeekableStreamReader<S> {
    /// Chunks that have been pulled from the underlying stream and cached.
    /// Stored in arrival order as individual `Bytes` handles (zero-copy).
    buffered: Vec<Bytes>,
    /// Total number of bytes logically consumed (peeked) from `buffered`.
    /// This is a byte-level offset into the concatenation of all chunks.
    cursor: usize,
    /// The underlying stream reader.
    stream: StreamReader<S>,
}

impl<S> PeekableStreamReader<S> {
    /// Creates a new `PeekableStreamReader` wrapping the given `StreamReader`.
    pub fn new(stream: StreamReader<S>) -> Self {
        Self {
            buffered: Vec::new(),
            cursor: 0,
            stream,
        }
    }

    /// Resets the cursor to 0, allowing previously peeked bytes to be re-read.
    pub fn reset(&mut self) {
        self.cursor = 0;
    }

    /// Discards all buffered bytes up to the current cursor position,
    /// making the peek permanent. Resets the cursor to 0 afterward.
    pub fn commit(&mut self) {
        if self.cursor > 0 {
            let mut remaining = self.cursor;
            while remaining > 0 {
                let Some(front) = self.buffered.first() else {
                    break;
                };
                if front.len() <= remaining {
                    remaining -= front.len();
                    self.buffered.remove(0);
                } else {
                    // Partial consumption: slice the front chunk.
                    self.buffered[0] = self.buffered[0].slice(remaining..);
                    remaining = 0;
                }
            }
            self.cursor = 0;
        }
    }

    /// Returns the number of bytes that have been peeked (cursor position).
    #[must_use]
    pub fn peeked(&self) -> usize {
        self.cursor
    }

    /// Returns the total number of buffered bytes (regardless of cursor).
    #[must_use]
    fn buffered_len(&self) -> usize {
        self.buffered.iter().map(|b| b.len()).sum()
    }

    /// Returns the number of buffered bytes remaining after the cursor
    /// (available to read without hitting the underlying stream).
    #[must_use]
    pub fn buffered_remaining(&self) -> usize {
        self.buffered_len().saturating_sub(self.cursor)
    }

    /// Returns the chunk index and intra-chunk offset for the current cursor.
    fn cursor_position(&self) -> (usize, usize) {
        let mut remaining = self.cursor;
        for (i, chunk) in self.buffered.iter().enumerate() {
            if remaining < chunk.len() {
                return (i, remaining);
            }
            remaining -= chunk.len();
        }
        (self.buffered.len(), 0)
    }

    /// Returns a slice of the buffered data starting at the cursor position.
    /// Returns the remainder of the chunk that the cursor currently points into.
    pub fn peek_slice(&self) -> &[u8] {
        let (chunk_idx, offset) = self.cursor_position();
        if chunk_idx < self.buffered.len() {
            &self.buffered[chunk_idx][offset..]
        } else {
            &[]
        }
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
    pub fn poll_bytes(&mut self, cx: &mut Context<'_>) -> Poll<Result<&[u8], S::Error>> {
        // If we have buffered data beyond the cursor, return it.
        if self.buffered_remaining() > 0 {
            return Poll::Ready(Ok(self.peek_slice()));
        }

        // No buffered data beyond cursor — pull from underlying stream.
        let chunk = ready!(Pin::new(&mut self.stream).poll_bytes(cx)?);

        if chunk.is_empty() {
            return Poll::Ready(Ok(&[]));
        }

        // Clone the Bytes handle (zero-copy — just increments refcount).
        let bytes = chunk.clone();
        let len = bytes.len();

        // Consume from the underlying StreamReader so it advances past this chunk.
        Pin::new(&mut self.stream).consume(len);

        // Append to our buffer.
        self.buffered.push(bytes);

        // Return the freshly buffered data (cursor hasn't moved).
        Poll::Ready(Ok(self.peek_slice()))
    }

    /// Advances the cursor by `amt` bytes. This marks bytes as "peeked" but
    /// does not discard them — call [`commit`](Self::commit) to make the
    /// consumption permanent, or [`reset`](Self::reset) to roll back.
    pub fn consume(&mut self, amt: usize) {
        debug_assert!(
            self.cursor + amt <= self.buffered_len(),
            "consume beyond buffered length: cursor={}, amt={}, buffered={}",
            self.cursor,
            amt,
            self.buffered_len(),
        );
        self.cursor += amt;
    }

    /// Asynchronously ensures that data is available at the cursor position,
    /// pulling from the underlying stream if necessary. After this returns
    /// `Ok(true)`, [`peek_slice`](Self::peek_slice) is guaranteed to return
    /// a non-empty slice.
    ///
    /// Returns `Ok(false)` if the stream is exhausted.
    pub async fn fill_peek_buf(&mut self) -> Result<bool, S::Error> {
        poll_fn(|cx| self.poll_bytes(cx).map_ok(|bytes| !bytes.is_empty())).await
    }

    /// Checks whether there are more bytes available (either buffered or
    /// from the underlying stream).
    pub async fn has_remaining(&mut self) -> Result<bool, S::Error> {
        self.fill_peek_buf().await
    }

    /// Consumes this `PeekableStreamReader` and returns the underlying
    /// `StreamReader`, preserving any unconsumed buffered data.
    ///
    /// The current cursor position is first committed (bytes before cursor
    /// are discarded). Any remaining buffered bytes that were pulled from
    /// the underlying stream but not yet consumed are preserved via
    /// `map_stream`, which carries the `StreamReader`'s internal partial
    /// chunk forward.
    ///
    /// **Important**: Bytes buffered by peeking beyond the cursor are dropped
    /// because `StreamReader`'s private fields prevent re-injection. Callers
    /// should either:
    /// - `commit()` all consumed data, or
    /// - `reset()` before calling this (to avoid losing any uncommitted data
    ///   that was merely inspected but not consumed).
    pub fn into_stream_reader(mut self) -> StreamReader<S> {
        self.commit();
        // After commit, self.buffered may still contain bytes that were
        // pulled from the stream during peek but lie beyond the old cursor.
        // These are dropped here. map_stream(|s| s) preserves the
        // StreamReader's existing internal chunk (if any).
        self.stream.map_stream(|s| s)
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
        let chunk = ready!(self.as_mut().get_mut().poll_bytes(cx)?);
        if !chunk.is_empty() {
            let cap = buf.remaining().min(chunk.len());
            buf.put_slice(&chunk[..cap]);
            self.get_mut().consume(cap);
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
        self.get_mut().poll_bytes(cx).map_err(io::Error::from)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        PeekableStreamReader::consume(self.get_mut(), amt);
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::stream;

    use super::*;

    /// Helper: create a `StreamReader` from byte chunks.
    fn stream_reader_from_chunks(
        chunks: Vec<&'static [u8]>,
    ) -> StreamReader<impl TryStream<Ok = Bytes, Error = std::io::Error> + Unpin> {
        let s = stream::iter(
            chunks
                .into_iter()
                .map(|c| Ok::<Bytes, std::io::Error>(Bytes::from_static(c))),
        );
        StreamReader::new(s)
    }

    #[tokio::test]
    async fn test_new() {
        let _guard = tracing_subscriber::fmt::try_init();
        let sr = stream_reader_from_chunks(vec![b"hello"]);
        let peekable = PeekableStreamReader::new(sr);
        assert_eq!(peekable.peeked(), 0);
        assert_eq!(peekable.buffered_remaining(), 0);
    }

    #[tokio::test]
    async fn test_peek_and_reset() {
        let _guard = tracing_subscriber::fmt::try_init();
        let sr = stream_reader_from_chunks(vec![b"hello", b" world"]);
        let mut peekable = PeekableStreamReader::new(sr);

        // First peek — should get "hello"
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b"hello");

        // Consume what we peeked
        peekable.consume(5);
        assert_eq!(peekable.peeked(), 5);

        // Reset — cursor goes back to 0
        peekable.reset();
        assert_eq!(peekable.peeked(), 0);

        // Peek again — should get same "hello" from buffer (not from stream)
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b"hello");

        // Consume "hello" again, then peek next chunk
        peekable.consume(5);
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b" world");
    }

    #[tokio::test]
    async fn test_peek_and_commit() {
        let _guard = tracing_subscriber::fmt::try_init();
        let sr = stream_reader_from_chunks(vec![b"hello", b" world"]);
        let mut peekable = PeekableStreamReader::new(sr);

        // Peek and consume "hello"
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b"hello");
        peekable.consume(5);

        // Commit — discards "hello" from buffer permanently
        peekable.commit();
        assert_eq!(peekable.peeked(), 0);
        assert_eq!(peekable.buffered_remaining(), 0);

        // Reset should have no effect — committed bytes are gone
        peekable.reset();
        assert_eq!(peekable.peeked(), 0);

        // Next peek should get " world" (not "hello")
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b" world");
    }

    #[tokio::test]
    async fn test_into_stream_reader() {
        let _guard = tracing_subscriber::fmt::try_init();
        let sr = stream_reader_from_chunks(vec![b"hello", b" world"]);
        let mut peekable = PeekableStreamReader::new(sr);

        // Peek at "hello" and commit it
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b"hello");
        peekable.consume(5);
        peekable.commit();

        // Convert back to StreamReader — " world" is still in the
        // underlying stream (not yet pulled by peek).
        let mut sr = peekable.into_stream_reader();
        let has = Pin::new(&mut sr).has_remaining().await;
        assert!(has.is_ok());
        assert!(has.unwrap());
    }

    #[tokio::test]
    async fn test_peek_multiple_chunks_and_reset() {
        let _guard = tracing_subscriber::fmt::try_init();
        let sr = stream_reader_from_chunks(vec![b"ab", b"cd", b"ef"]);
        let mut peekable = PeekableStreamReader::new(sr);

        // Peek first chunk
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b"ab");
        peekable.consume(2);

        // Peek second chunk
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b"cd");
        peekable.consume(2);

        // Reset — should go back to beginning
        peekable.reset();
        assert_eq!(peekable.peeked(), 0);

        // Should get "ab" again from buffer
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b"ab");
    }

    #[tokio::test]
    async fn test_partial_consume_and_commit() {
        let _guard = tracing_subscriber::fmt::try_init();
        let sr = stream_reader_from_chunks(vec![b"hello world"]);
        let mut peekable = PeekableStreamReader::new(sr);

        // Peek the full chunk
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b"hello world");

        // Consume only "hello" (5 bytes)
        peekable.consume(5);
        peekable.commit();

        // Now should see " world" (remaining 6 bytes)
        assert!(peekable.fill_peek_buf().await.unwrap());
        assert_eq!(peekable.peek_slice(), b" world");
    }

    #[tokio::test]
    async fn test_empty_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let sr = stream_reader_from_chunks(vec![]);
        let mut peekable = PeekableStreamReader::new(sr);

        // Peek on empty stream should return false
        let has = peekable.fill_peek_buf().await.unwrap();
        assert!(!has);
        assert!(peekable.peek_slice().is_empty());

        // has_remaining should return false
        let has = peekable.has_remaining().await.unwrap();
        assert!(!has);
    }

    #[tokio::test]
    async fn test_async_buf_read_fill_and_consume() {
        use tokio::io::AsyncBufReadExt;

        let _guard = tracing_subscriber::fmt::try_init();
        let sr = stream_reader_from_chunks(vec![b"hello", b" world"]);
        let mut peekable = PeekableStreamReader::new(sr);

        // poll_fill_buf via AsyncBufRead returns peeked data
        let buf = peekable.fill_buf().await.unwrap();
        assert_eq!(buf, b"hello");

        // AsyncBufRead::consume advances cursor but doesn't commit
        AsyncBufReadExt::consume(&mut peekable, 5);
        assert_eq!(peekable.peeked(), 5);

        // Reset still works — cursor rollback
        peekable.reset();
        assert_eq!(peekable.peeked(), 0);

        // Re-read the same data after reset
        let buf = peekable.fill_buf().await.unwrap();
        assert_eq!(buf, b"hello");
    }

    #[tokio::test]
    async fn test_async_read_poll_read() {
        use tokio::io::AsyncReadExt;

        let _guard = tracing_subscriber::fmt::try_init();
        let sr = stream_reader_from_chunks(vec![b"hello", b" world"]);
        let mut peekable = PeekableStreamReader::new(sr);

        // Read via AsyncRead
        let mut buf = [0u8; 5];
        peekable.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // Cursor has advanced by 5
        assert_eq!(peekable.peeked(), 5);

        // Read next chunk
        let mut buf = [0u8; 6];
        peekable.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b" world");
    }

    #[tokio::test]
    async fn test_decode_one_varint() {
        use crate::{codec::DecodeExt, varint::VarInt};

        let _guard = tracing_subscriber::fmt::try_init();
        // 1-byte VarInt 0x02 = QPACK encoder stream type
        let sr = stream_reader_from_chunks(vec![b"\x02rest"]);
        let mut peekable = PeekableStreamReader::new(sr);

        let v: VarInt = peekable.decode_one::<VarInt>().await.unwrap();
        assert_eq!(v, VarInt::from_u32(0x02));

        // Cursor advanced past the VarInt (1 byte)
        assert_eq!(peekable.peeked(), 1);

        // Reset rolls back so we can re-read the VarInt
        peekable.reset();
        assert_eq!(peekable.peeked(), 0);

        let v2: VarInt = peekable.decode_one::<VarInt>().await.unwrap();
        assert_eq!(v2, VarInt::from_u32(0x02));
    }
}
