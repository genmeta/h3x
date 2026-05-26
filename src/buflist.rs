use std::{
    collections::{VecDeque, vec_deque},
    convert::Infallible,
    io::{self, IoSlice},
    iter,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, Stream};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default, Debug, Clone)]
pub struct BufList {
    bufs: VecDeque<Bytes>,
}

impl BufList {
    pub const fn new() -> Self {
        Self {
            bufs: VecDeque::new(),
        }
    }

    /// Copy all remaining bytes from a [`Buf`] into a new [`BufList`].
    pub fn from_buf(buf: impl Buf) -> Self {
        let mut buflist = Self::new();
        buflist.write(buf);
        buflist
    }

    pub fn write(&mut self, mut buf: impl Buf) {
        while buf.has_remaining() {
            self.bufs.push_back(buf.copy_to_bytes(buf.chunk().len()));
        }
    }
}

impl Extend<Bytes> for BufList {
    fn extend<T: IntoIterator<Item = Bytes>>(&mut self, iter: T) {
        self.bufs.extend(iter);
    }
}

impl FromIterator<Bytes> for BufList {
    fn from_iter<T: IntoIterator<Item = Bytes>>(iter: T) -> Self {
        Self {
            bufs: iter.into_iter().collect(),
        }
    }
}

impl Buf for BufList {
    fn remaining(&self) -> usize {
        self.bufs.iter().map(|b| b.len()).sum()
    }

    fn has_remaining(&self) -> bool {
        !self.bufs.is_empty()
    }

    fn chunk(&self) -> &[u8] {
        self.bufs.front().map_or(&[], |b| b.chunk())
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        let filled_len = self.bufs.len().min(dst.len());
        for (i, buf) in self.bufs.iter().take(filled_len).enumerate() {
            dst[i] = IoSlice::new(buf.chunk());
        }
        filled_len
    }

    fn advance(&mut self, cnt: usize) {
        let mut remaining = cnt;
        while remaining > 0 {
            let Some(front) = self.bufs.front_mut() else {
                panic!("advance beyond buffer length");
            };

            let front_len = front.len();
            if front_len <= remaining {
                self.bufs.pop_front();
                remaining -= front_len;
            } else {
                front.advance(remaining);
                remaining = 0;
            }
        }
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        assert!(
            self.remaining() >= len,
            "copy_to_bytes beyond buffer length"
        );

        if self.chunk().len() == len {
            return self.bufs.pop_front().expect("non-empty by prior check");
        }

        let mut bytes_mut = BytesMut::with_capacity(len);
        bytes_mut.put(self.take(len));
        bytes_mut.freeze()
    }
}

impl AsyncWrite for BufList {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        // optimize: try to write into the last bufs

        // TODO: use pop_back_if when stabilized in the next rust version
        // if let Some(bytes) = self
        //     .bufs
        //     .pop_back_if(|bytes| bytes.len() + buf.len() <= 8 * 1024)
        if let Some(bytes) = self.bufs.back()
            && bytes.len() + buf.len() <= 8 * 1024
            && let Some(bytes) = self.bufs.pop_back()
        {
            match bytes.try_into_mut() {
                Ok(mut bytes_mut) => {
                    bytes_mut.put(buf);
                    self.bufs.push_back(bytes_mut.freeze());
                    return Poll::Ready(Ok(buf.len()));
                }
                Err(bytes) => {
                    self.bufs.push_back(bytes);
                }
            }
        }

        self.write(Bytes::copy_from_slice(buf));
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Sink<Bytes> for BufList {
    type Error = Infallible;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.write(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for BufList {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = self.chunk().len().min(buf.remaining());
        buf.put(self.get_mut().take(len));
        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for BufList {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        Poll::Ready(Ok(self.get_mut().bufs.front().map_or(&[], |b| b.chunk())))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.get_mut().advance(amt);
    }
}

impl Stream for BufList {
    type Item = Bytes;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.bufs.pop_front())
    }
}

#[derive(Debug, Clone)]
pub struct BuflistCursor {
    offset: (usize, usize), // (buf index, offset in buf)
    buflist: BufList,
}

impl BuflistCursor {
    pub fn new(buflist: BufList) -> Self {
        Self {
            offset: (0, 0),
            buflist,
        }
    }

    pub const fn reset(&mut self) {
        self.offset = (0, 0);
    }

    pub fn commit(&mut self) {
        self.buflist.bufs.drain(..self.offset.0);
        if let Some(front) = self.buflist.bufs.front_mut() {
            front.advance(self.offset.1);
        }
        self.reset();
    }

    pub fn write(&mut self, buf: impl Buf) {
        self.buflist.write(buf);
    }

    pub fn iter(&self) -> BuflistCursorIter<'_> {
        self.into_iter()
    }

    pub const fn inner(&self) -> &BufList {
        &self.buflist
    }
}

impl Buf for BuflistCursor {
    fn remaining(&self) -> usize {
        self.iter().map(|b| b.len()).sum()
    }

    fn has_remaining(&self) -> bool {
        !self.chunk().is_empty()
    }

    fn chunk(&self) -> &[u8] {
        if self.offset.0 >= self.buflist.bufs.len() {
            &[]
        } else {
            &self.buflist.bufs[self.offset.0][self.offset.1..]
        }
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        let unindexed = self.buflist.bufs.iter().skip(self.offset.0 + 1);
        let unindexed = unindexed.map(Deref::deref);

        let filled_len = (unindexed.len() + 1).min(dst.len());
        for (i, buf) in iter::once(self.chunk()).chain(unindexed).enumerate() {
            dst[i] = IoSlice::new(buf);
        }
        filled_len
    }

    fn advance(&mut self, cnt: usize) {
        let mut remaining = cnt;
        while remaining > 0 {
            let front = self.chunk();
            if front.is_empty() {
                panic!("advance beyond buffer length");
            } else if front.len() <= remaining {
                remaining -= front.len();
                self.offset = (self.offset.0 + 1, 0);
            } else {
                self.offset.1 += remaining;
                remaining = 0;
            }
        }
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        if len == 0 {
            return Bytes::new();
        }
        assert!(
            self.remaining() >= len,
            "copy_to_bytes beyond buffer length"
        );

        if self.chunk().len() == len {
            let buf = self.buflist.bufs[self.offset.0].slice(self.offset.1..);
            self.offset = (self.offset.0 + 1, 0);
            return buf;
        }

        let mut bytes_mut = BytesMut::with_capacity(len);
        bytes_mut.put(self.take(len));
        bytes_mut.freeze()
    }
}

type BuflistCursorIter<'c> = iter::Chain<
    iter::Once<Bytes>,
    iter::Map<iter::Skip<vec_deque::Iter<'c, Bytes>>, for<'b> fn(&'b Bytes) -> Bytes>,
>;

impl<'c> IntoIterator for &'c BuflistCursor {
    type Item = Bytes;

    type IntoIter = BuflistCursorIter<'c>;

    fn into_iter(self) -> Self::IntoIter {
        let unindexed = self.buflist.bufs.iter().skip(self.offset.0 + 1);
        let unindexed = unindexed.map(Bytes::clone as for<'a> fn(&'a Bytes) -> Bytes);

        if self.offset.0 >= self.buflist.bufs.len() {
            iter::once(Bytes::new()).chain(unindexed)
        } else {
            let first_buf = self.buflist.bufs[self.offset.0].slice(self.offset.1..);
            iter::once(first_buf).chain(unindexed)
        }
    }
}

impl Extend<Bytes> for BuflistCursor {
    fn extend<T: IntoIterator<Item = Bytes>>(&mut self, iter: T) {
        self.buflist.extend(iter);
    }
}

#[cfg(test)]
mod tests {
    use std::io::IoSlice;

    use bytes::{Buf, Bytes, BytesMut};
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

    use super::{BufList, BuflistCursor};

    #[test]
    fn empty_buflist() {
        let bl = BufList::new();
        assert_eq!(bl.remaining(), 0);
        assert!(!bl.has_remaining());
        assert!(bl.chunk().is_empty());
    }

    #[test]
    fn write_adds_data() {
        let mut bl = BufList::new();
        bl.write(Bytes::from_static(b"hello"));
        assert_eq!(bl.remaining(), 5);
        assert!(bl.has_remaining());
        assert_eq!(bl.chunk(), b"hello");
    }

    #[test]
    fn from_buf_copies_all_remaining_data() {
        let source = Bytes::from_static(b"hello world").slice(6..);
        let bl = BufList::from_buf(source);
        assert_eq!(bl.remaining(), 5);
        assert_eq!(bl.chunk(), b"world");
    }

    #[test]
    fn multiple_writes() {
        let mut bl = BufList::new();
        bl.write(Bytes::from_static(b"hello"));
        bl.write(Bytes::from_static(b" world"));
        assert_eq!(bl.remaining(), 11);
        // chunk() returns only the first buffer segment
        assert_eq!(bl.chunk(), b"hello");
    }

    #[test]
    fn advance_within_first_chunk() {
        let mut bl = BufList::new();
        bl.write(Bytes::from_static(b"hello"));
        bl.advance(2);
        assert_eq!(bl.remaining(), 3);
        assert_eq!(bl.chunk(), b"llo");
    }

    #[test]
    fn advance_across_chunks() {
        let mut bl = BufList::new();
        bl.write(Bytes::from_static(b"abc"));
        bl.write(Bytes::from_static(b"def"));
        bl.advance(4);
        assert_eq!(bl.remaining(), 2);
        assert_eq!(bl.chunk(), b"ef");
    }

    #[test]
    fn advance_to_exact_end() {
        let mut bl = BufList::new();
        bl.write(Bytes::from_static(b"abc"));
        bl.write(Bytes::from_static(b"de"));
        bl.advance(5);
        assert_eq!(bl.remaining(), 0);
        assert!(!bl.has_remaining());
    }

    #[test]
    fn copy_to_bytes_single_chunk() {
        let mut bl = BufList::new();
        bl.write(Bytes::from_static(b"hello"));
        let b = bl.copy_to_bytes(5);
        assert_eq!(&b[..], b"hello");
        assert_eq!(bl.remaining(), 0);
    }

    #[test]
    fn copy_to_bytes_spanning_chunks() {
        let mut bl = BufList::new();
        bl.write(Bytes::from_static(b"ab"));
        bl.write(Bytes::from_static(b"cd"));
        let b = bl.copy_to_bytes(3);
        assert_eq!(&b[..], b"abc");
        assert_eq!(bl.remaining(), 1);
        assert_eq!(bl.chunk(), b"d");
    }

    #[test]
    fn from_iterator() {
        let bl: BufList = vec![Bytes::from_static(b"aaa"), Bytes::from_static(b"bb")]
            .into_iter()
            .collect();
        assert_eq!(bl.remaining(), 5);
    }

    #[test]
    fn extend_buflist() {
        let mut bl = BufList::new();
        bl.extend(vec![Bytes::from_static(b"x"), Bytes::from_static(b"yy")]);
        assert_eq!(bl.remaining(), 3);
    }

    #[test]
    fn chunks_vectored_reports_front_buffers() {
        let bl: BufList = vec![
            Bytes::from_static(b"ab"),
            Bytes::from_static(b"cd"),
            Bytes::from_static(b"ef"),
        ]
        .into_iter()
        .collect();
        let mut slices = [
            IoSlice::new(&[]),
            IoSlice::new(&[]),
            IoSlice::new(&[]),
            IoSlice::new(&[]),
        ];

        let filled = bl.chunks_vectored(&mut slices);

        assert_eq!(filled, 3);
        assert_eq!(&*slices[0], b"ab");
        assert_eq!(&*slices[1], b"cd");
        assert_eq!(&*slices[2], b"ef");
    }

    #[tokio::test]
    async fn async_write_merges_unique_tail_and_flushes() {
        let mut bl = BufList::new();
        bl.write(BytesMut::from(&b"hello"[..]).freeze());

        bl.write_all(b" world").await.unwrap();
        AsyncWriteExt::flush(&mut bl).await.unwrap();
        bl.shutdown().await.unwrap();

        assert_eq!(bl.bufs.len(), 1);
        assert_eq!(bl.copy_to_bytes(11), Bytes::from_static(b"hello world"));
    }

    #[tokio::test]
    async fn async_write_preserves_shared_tail_before_appending() {
        let mut bl = BufList::new();
        bl.write(Bytes::from_static(b"hello"));

        bl.write_all(b"!").await.unwrap();

        assert_eq!(bl.bufs.len(), 2);
        assert_eq!(bl.copy_to_bytes(6), Bytes::from_static(b"hello!"));
    }

    #[tokio::test]
    async fn sink_async_read_bufread_and_stream_delegations() {
        let mut bl = BufList::new();
        bl.send(Bytes::from_static(b"ab")).await.unwrap();
        bl.feed(Bytes::from_static(b"cd")).await.unwrap();
        SinkExt::flush(&mut bl).await.unwrap();

        let mut read = [0; 3];
        let read_len = bl.read(&mut read).await.unwrap();
        assert_eq!(read_len, 2);
        assert_eq!(&read[..read_len], b"ab");

        let filled = bl.fill_buf().await.unwrap();
        assert_eq!(filled, b"cd");
        bl.consume(1);
        assert_eq!(bl.fill_buf().await.unwrap(), b"d");
        bl.consume(1);
        assert!(bl.fill_buf().await.unwrap().is_empty());

        bl.send(Bytes::from_static(b"ef")).await.unwrap();
        assert_eq!(bl.next().await, Some(Bytes::from_static(b"ef")));
        assert_eq!(bl.next().await, None);

        bl.close().await.unwrap();
    }

    #[test]
    fn sequential_reads() {
        let mut bl = BufList::new();
        bl.write(Bytes::from_static(b"ab"));
        bl.write(Bytes::from_static(b"cd"));
        bl.write(Bytes::from_static(b"ef"));

        let c1 = bl.copy_to_bytes(2);
        assert_eq!(&c1[..], b"ab");

        let c2 = bl.copy_to_bytes(2);
        assert_eq!(&c2[..], b"cd");

        let c3 = bl.copy_to_bytes(2);
        assert_eq!(&c3[..], b"ef");

        assert_eq!(bl.remaining(), 0);
    }

    #[test]
    #[should_panic(expected = "advance beyond buffer length")]
    fn advance_beyond_panics() {
        let mut bl = BufList::new();
        bl.write(Bytes::from_static(b"ab"));
        bl.advance(3);
    }

    fn cursor_source() -> BuflistCursor {
        BuflistCursor::new(
            vec![
                Bytes::from_static(b"ab"),
                Bytes::from_static(b"cd"),
                Bytes::from_static(b"ef"),
            ]
            .into_iter()
            .collect(),
        )
    }

    #[test]
    fn cursor_reset_commit_inner_and_iteration_track_offsets() {
        let mut cursor = cursor_source();

        cursor.advance(3);
        assert_eq!(cursor.chunk(), b"d");
        assert_eq!(
            cursor.iter().collect::<Vec<_>>(),
            vec![Bytes::from_static(b"d"), Bytes::from_static(b"ef")]
        );

        cursor.reset();
        assert_eq!(cursor.chunk(), b"ab");
        assert_eq!(cursor.remaining(), 6);

        cursor.advance(3);
        cursor.commit();

        assert_eq!(cursor.inner().remaining(), 3);
        assert_eq!(cursor.chunk(), b"d");
        assert_eq!(cursor.copy_to_bytes(3), Bytes::from_static(b"def"));
    }

    #[test]
    fn cursor_write_extend_and_empty_iteration() {
        let mut cursor = BuflistCursor::new(BufList::new());

        assert!(!cursor.has_remaining());
        assert_eq!(cursor.iter().collect::<Vec<_>>(), vec![Bytes::new()]);

        cursor.write(Bytes::from_static(b"ab"));
        cursor.extend([Bytes::from_static(b"cd")]);

        assert_eq!(cursor.inner().remaining(), 4);
        assert_eq!(cursor.copy_to_bytes(4), Bytes::from_static(b"abcd"));
    }

    #[test]
    fn cursor_chunks_vectored_start_from_current_offset() {
        let mut cursor = cursor_source();
        cursor.advance(1);
        let mut slices = [
            IoSlice::new(&[]),
            IoSlice::new(&[]),
            IoSlice::new(&[]),
            IoSlice::new(&[]),
        ];

        let filled = cursor.chunks_vectored(&mut slices);

        assert_eq!(filled, 3);
        assert_eq!(&*slices[0], b"b");
        assert_eq!(&*slices[1], b"cd");
        assert_eq!(&*slices[2], b"ef");
    }

    #[test]
    fn cursor_copy_to_bytes_covers_zero_exact_and_spanning_paths() {
        let mut zero = cursor_source();
        assert_eq!(zero.copy_to_bytes(0), Bytes::new());
        assert_eq!(zero.remaining(), 6);

        let mut exact = BuflistCursor::new(
            vec![Bytes::from_static(b"abc")]
                .into_iter()
                .collect::<BufList>(),
        );
        exact.advance(1);
        assert_eq!(exact.copy_to_bytes(2), Bytes::from_static(b"bc"));
        assert_eq!(exact.remaining(), 0);

        let mut spanning = BuflistCursor::new(
            vec![Bytes::from_static(b"ab"), Bytes::from_static(b"cd")]
                .into_iter()
                .collect::<BufList>(),
        );
        spanning.advance(1);
        assert_eq!(spanning.copy_to_bytes(3), Bytes::from_static(b"bcd"));
        assert_eq!(spanning.remaining(), 0);
    }

    #[test]
    #[should_panic(expected = "advance beyond buffer length")]
    fn cursor_advance_beyond_panics() {
        let mut cursor = cursor_source();
        cursor.advance(7);
    }
}
