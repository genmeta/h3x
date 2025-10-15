use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::io::{AsyncBufRead, AsyncWrite};

use crate::codec::error::{DecodeStreamError, EncodeError, EncodeStreamError};

pub fn poll_write_u8(
    writer: &mut (impl AsyncWrite + Unpin),
    cx: &mut Context<'_>,
    byte: u8,
) -> Poll<Result<(), EncodeStreamError>> {
    match ready!(Pin::new(writer).poll_write(cx, &[byte]))? {
        0 => Poll::Ready(Err(EncodeError::WriteZero.into())),
        1 => Poll::Ready(Ok(())),
        _ => unreachable!("poll_write should write at most 1 byte"),
    }
}

pub fn poll_buffer(
    reader: &mut (impl AsyncBufRead + Unpin),
    cx: &mut Context<'_>,
) -> Poll<Result<impl bytes::Buf, DecodeStreamError>> {
    #[ouroboros::self_referencing]
    struct OuroborosBuffer<'r, R> {
        reader: &'r mut R,
        #[borrows(mut reader)]
        #[covariant]
        buffer: Poll<&'this [u8]>,
        read: usize,
    }

    struct Buffer<'r, R>
    where
        R: AsyncBufRead + Unpin,
    {
        inner: Option<OuroborosBuffer<'r, R>>,
    }

    impl<R> bytes::Buf for OuroborosBuffer<'_, R> {
        fn remaining(&self) -> usize {
            self.chunk().len()
        }

        fn chunk(&self) -> &[u8] {
            match self.borrow_buffer() {
                Poll::Ready(buffer) => &buffer[*self.borrow_read()..],
                Poll::Pending => unreachable!(),
            }
        }

        fn advance(&mut self, cnt: usize) {
            assert!(
                cnt <= self.remaining(),
                "advance {} exceeds remaining {}",
                cnt,
                self.remaining()
            );
            self.with_read_mut(|read| *read += cnt);
        }
    }

    impl<'r, R> Buffer<'r, R>
    where
        R: AsyncBufRead + Unpin,
    {
        fn poll_new(
            reader: &'r mut R,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self, DecodeStreamError>> {
            let buffer = OuroborosBufferTryBuilder::try_build(OuroborosBufferTryBuilder {
                reader,
                buffer_builder: |reader| match Pin::new(&mut *reader).poll_fill_buf(cx) {
                    Poll::Ready(Ok(buf)) => Ok(Poll::Ready(buf)),
                    Poll::Pending => Ok(Poll::Pending),
                    Poll::Ready(Err(error)) => Err(error),
                },
                read: 0,
            })?;
            if buffer.borrow_buffer().is_pending() {
                return Poll::Pending;
            }
            Poll::Ready(Ok(Self {
                inner: Some(buffer),
            }))
        }
    }

    impl<'r, R> bytes::Buf for Buffer<'r, R>
    where
        R: AsyncBufRead + Unpin,
    {
        fn remaining(&self) -> usize {
            self.inner.as_ref().unwrap().remaining()
        }

        fn chunk(&self) -> &[u8] {
            self.inner.as_ref().unwrap().chunk()
        }

        fn advance(&mut self, cnt: usize) {
            self.inner.as_mut().unwrap().advance(cnt);
        }
    }

    impl<R> Drop for Buffer<'_, R>
    where
        R: AsyncBufRead + Unpin,
    {
        fn drop(&mut self) {
            let heads = self
                .inner
                .take()
                .expect("Buffer dropped twice")
                .into_heads();
            Pin::new(heads.reader).consume(heads.read);
        }
    }

    Buffer::poll_new(reader, cx)
}
