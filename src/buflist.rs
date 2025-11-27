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

    pub fn write(&mut self, buf: Bytes) {
        if !buf.is_empty() {
            self.bufs.push_back(buf);
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
            return self.bufs.pop_front().unwrap();
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
        if let Some(bytes) = self
            .bufs
            .pop_back_if(|bytes| bytes.len() + buf.len() <= 8 * 1024)
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
pub struct Cursor<B = BufList> {
    offset: (usize, usize), // (buf index, offset in buf)
    buflist: B,
}

impl Cursor {
    pub fn new(buflist: BufList) -> Self {
        Self {
            offset: (0, 0),
            buflist,
        }
    }

    pub fn write(&mut self, buf: Bytes) {
        self.buflist.write(buf);
    }

    pub fn iter(&self) -> CursorIter<'_> {
        self.into_iter()
    }

    pub fn inner(&self) -> &BufList {
        &self.buflist
    }
}

type CursorIter<'c> = iter::Chain<
    iter::Once<Bytes>,
    iter::Map<iter::Skip<vec_deque::Iter<'c, Bytes>>, for<'b> fn(&'b Bytes) -> Bytes>,
>;

impl<'c> IntoIterator for &'c Cursor {
    type Item = Bytes;

    type IntoIter = CursorIter<'c>;

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

impl Extend<Bytes> for Cursor {
    fn extend<T: IntoIterator<Item = Bytes>>(&mut self, iter: T) {
        self.buflist.extend(iter);
    }
}

impl Buf for Cursor {
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
