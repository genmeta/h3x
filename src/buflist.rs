use std::{
    collections::VecDeque,
    convert::Infallible,
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::Sink;
use tokio::io::AsyncWrite;

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
        self.bufs.push_back(buf);
    }
}

impl Buf for BufList {
    fn remaining(&self) -> usize {
        self.bufs.iter().map(|b| b.len()).sum()
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

        if self.bufs[0].len() == len {
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
