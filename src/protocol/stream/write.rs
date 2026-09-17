use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use qrecovery::send::CancelStream;
use tokio::io::AsyncWrite;

use super::{Goaway, H3Stream};
use crate::ErrorCode;

/// Application-owned write direction, observed weakly by the connection.
pub struct H3WriteStream<W: CancelStream> {
    id: u64,
    pub(super) state: Arc<Mutex<Result<H3Stream<W>, Goaway>>>,
}

impl<W: CancelStream> H3WriteStream<W> {
    pub fn new(stream_id: u64, stream: W) -> Self {
        Self {
            id: stream_id,
            state: Arc::new(Mutex::new(Ok(H3Stream::new(stream)))),
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<W: CancelStream> CancelStream for &H3WriteStream<W> {
    fn cancel(&mut self, error_code: u64) {
        let mut state = self.state.lock().unwrap();
        let waker = super::terminate(&mut state, |io| io.cancel(error_code));
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> H3WriteStream<W> {
    fn poll_io<O>(
        &mut self,
        cx: &mut Context<'_>,
        finish: bool,
        poll: impl FnOnce(Pin<&mut W>, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>> {
        let mut inner = self.state.lock().unwrap();
        let result = super::poll_io(&mut *inner, cx, poll);
        if finish && matches!(result, Poll::Ready(Ok(_))) {
            super::finish(&mut *inner);
        }
        drop(inner);
        result
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> AsyncWrite for H3WriteStream<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_io(cx, false, |send, cx| send.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, false, |send, cx| send.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, true, |send, cx| send.poll_shutdown(cx))
    }
}

impl<W: CancelStream> Drop for H3WriteStream<W> {
    fn drop(&mut self) {
        (&*self).cancel(ErrorCode::H3_REQUEST_CANCELLED.as_u64());
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Wake, Waker},
    };

    use qrecovery::recv::StopSending;

    use super::*;
    use crate::ErrorCode;
    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn goaway_wakes_pending_read_and_errors_all_write_operations() {
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let (recv, _peer) = tokio::io::duplex(1);
        let mut recv = crate::test_support::read_stream(4, recv);
        let mut bytes = [0];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);
        use tokio::io::AsyncRead;
        assert!(
            Pin::new(&mut recv)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
        let wakers = super::super::goaway(&mut *recv.state.lock().unwrap(), |io| {
            io.stop(ErrorCode::H3_REQUEST_REJECTED.as_u64())
        });
        if let Some(waker) = wakers {
            waker.wake();
        }
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        let Poll::Ready(Err(error)) = Pin::new(&mut recv).poll_read(&mut cx, &mut buf) else {
            panic!("closed receive stream must fail");
        };
        assert_eq!(ErrorCode::from(error), ErrorCode::H3_REQUEST_REJECTED);
        let mut send = crate::test_support::write_stream(4, tokio::io::sink());
        let wakers = super::super::goaway(&mut *send.state.lock().unwrap(), |io| {
            io.cancel(ErrorCode::H3_REQUEST_REJECTED.as_u64())
        });
        if let Some(waker) = wakers {
            waker.wake();
        }
        for result in [
            Pin::new(&mut send).poll_write(&mut cx, b"x").map_ok(|_| ()),
            Pin::new(&mut send).poll_flush(&mut cx),
            Pin::new(&mut send).poll_shutdown(&mut cx),
        ] {
            let Poll::Ready(Err(error)) = result else {
                panic!("closed send stream must fail");
            };
            assert_eq!(ErrorCode::from(error), ErrorCode::H3_REQUEST_REJECTED);
        }
    }

    struct PendingWriter;

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[test]
    fn pending_write_flush_and_shutdown_wake_the_latest_waiter() {
        for operation in 0..3 {
            let old = Arc::new(Wakes::default());
            let latest = Arc::new(Wakes::default());
            let mut send = crate::test_support::write_stream(4, PendingWriter);
            let poll =
                |send: &mut H3WriteStream<crate::test_support::TestStream<PendingWriter>>,
                 cx: &mut Context<'_>| match operation {
                    0 => Pin::new(send).poll_write(cx, b"x").map_ok(|_| ()),
                    1 => Pin::new(send).poll_flush(cx),
                    _ => Pin::new(send).poll_shutdown(cx),
                };
            for wakes in [&old, &latest] {
                assert!(
                    poll(
                        &mut send,
                        &mut Context::from_waker(&Waker::from(wakes.clone()))
                    )
                    .is_pending()
                );
            }
            let wakers = super::super::goaway(&mut *send.state.lock().unwrap(), |io| {
                io.cancel(ErrorCode::H3_REQUEST_REJECTED.as_u64())
            });
            if let Some(waker) = wakers {
                waker.wake();
            }
            assert_eq!(old.0.load(Ordering::SeqCst), 0);
            assert_eq!(latest.0.load(Ordering::SeqCst), 1);
            let Poll::Ready(Err(error)) = poll(&mut send, &mut Context::from_waker(Waker::noop()))
            else {
                panic!()
            };
            assert_eq!(ErrorCode::from(error), ErrorCode::H3_REQUEST_REJECTED);
        }
    }

    #[tokio::test]
    async fn ready_io_clears_waiter_and_completion_survives_later_goaway() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut recv = crate::test_support::read_stream(4, std::io::Cursor::new(vec![7]));
        *recv.state.lock().unwrap() = Ok(H3Stream::Polling(
            crate::test_support::TestStream::new(std::io::Cursor::new(vec![7])),
            Waker::noop().clone(),
        ));
        let mut bytes = [0];
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, [7]);
        assert!(matches!(*recv.state.lock().unwrap(), Ok(H3Stream::Idle(_))));
        assert!(
            !recv
                .state
                .lock()
                .unwrap()
                .as_ref()
                .map_or(true, |s| matches!(s, super::H3Stream::Finished(_)))
        );
        assert_eq!(recv.stream_id(), 4);
        let mut send = crate::test_support::write_stream(4, Vec::new());
        *send.state.lock().unwrap() = Ok(H3Stream::Polling(
            crate::test_support::TestStream::new(Vec::new()),
            Waker::noop().clone(),
        ));
        send.write_all(b"x").await.unwrap();
        assert!(matches!(*send.state.lock().unwrap(), Ok(H3Stream::Idle(_))));
        send.flush().await.unwrap();
        send.shutdown().await.unwrap();
        assert!(
            send.state
                .lock()
                .unwrap()
                .as_ref()
                .map_or(true, |s| matches!(s, super::H3Stream::Finished(_)))
        );
        super::super::goaway(&mut *send.state.lock().unwrap(), |_| {
            panic!("finished stream must not be reset")
        });
        assert!(send.state.lock().unwrap().is_ok());
        assert_eq!(send.stream_id(), 4);
    }
}
