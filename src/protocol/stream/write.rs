use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::AsyncWrite;

use super::{StreamState, bi::BiStream};
use crate::{Error, protocol::frame::Goaway};

/// Write handle for a stream owned by the connection.
/// `R` is the paired transport reader; standalone writers use `()`.
pub struct H3WriteStream<W, R = ()> {
    pub(super) stream: Arc<BiStream<R, W>>,
}

impl<W> H3WriteStream<W> {
    pub fn new(stream_id: u64, stream: W) -> Self {
        Self {
            stream: Arc::new(BiStream::new(
                stream_id,
                StreamState::Closed(Error::H3_NO_ERROR),
                StreamState::Idle(stream),
            )),
        }
    }
}

impl<W, R> H3WriteStream<W, R> {
    pub fn stream_id(&self) -> u64 {
        self.stream.id
    }

    pub fn on_recv(&mut self, goaway: Goaway) {
        self.stream.terminate_write(StreamState::Goaway(goaway));
    }
}

impl<W: AsyncWrite + Unpin, R> H3WriteStream<W, R> {
    fn poll_io<O>(
        &mut self,
        cx: &mut Context<'_>,
        finish: bool,
        poll: impl FnOnce(Pin<&mut W>, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>> {
        let mut state = self.stream.send.lock().unwrap();
        let result = state.poll_io(cx, poll);
        if finish && matches!(result, Poll::Ready(Ok(_))) {
            state.terminate(StreamState::Finished);
        }
        result
    }
}

impl<W: AsyncWrite + Unpin, R> AsyncWrite for H3WriteStream<W, R> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_io(cx, false, |send, cx| send.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(*self.stream.send.lock().unwrap(), StreamState::Finished) {
            return Poll::Ready(Ok(()));
        }
        self.get_mut()
            .poll_io(cx, false, |send, cx| send.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(*self.stream.send.lock().unwrap(), StreamState::Finished) {
            return Poll::Ready(Ok(()));
        }
        self.get_mut()
            .poll_io(cx, true, |send, cx| send.poll_shutdown(cx))
    }
}

impl<W, R> Drop for H3WriteStream<W, R> {
    fn drop(&mut self) {
        self.stream
            .terminate_write(StreamState::Closed(Error::H3_REQUEST_CANCELLED));
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

    use qbase::varint::VarInt;

    use super::*;
    use crate::{Error, protocol::stream::H3ReadStream};
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
        let mut recv = H3ReadStream::new(4, recv);
        let mut bytes = [0];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);
        use tokio::io::AsyncRead;
        assert!(
            Pin::new(&mut recv)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
        recv.recv_goaway(Goaway {
            id: VarInt::from_u32(0),
        });
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(
            matches!(Pin::new(&mut recv).poll_read(&mut cx,&mut buf),Poll::Ready(Err(e)) if e.get_ref().and_then(|e|e.downcast_ref::<Error>())==Some(&Error::H3_REQUEST_REJECTED))
        );
        let mut send = H3WriteStream::new(4, tokio::io::sink());
        send.on_recv(Goaway {
            id: VarInt::from_u32(0),
        });
        for result in [
            Pin::new(&mut send).poll_write(&mut cx, b"x").map_ok(|_| ()),
            Pin::new(&mut send).poll_flush(&mut cx),
            Pin::new(&mut send).poll_shutdown(&mut cx),
        ] {
            assert!(
                matches!(result,Poll::Ready(Err(e)) if e.get_ref().and_then(|e|e.downcast_ref::<Error>())==Some(&Error::H3_REQUEST_REJECTED))
            );
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
            let mut send = H3WriteStream::new(4, PendingWriter);
            let poll =
                |send: &mut H3WriteStream<PendingWriter>, cx: &mut Context<'_>| match operation {
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
            send.on_recv(Goaway {
                id: VarInt::from_u32(4),
            });
            assert_eq!(old.0.load(Ordering::SeqCst), 0);
            assert_eq!(latest.0.load(Ordering::SeqCst), 1);
            let Poll::Ready(Err(error)) = poll(&mut send, &mut Context::from_waker(Waker::noop()))
            else {
                panic!()
            };
            assert_eq!(Error::from(error), Error::H3_REQUEST_REJECTED);
        }
    }

    #[tokio::test]
    async fn stream_state_returns_to_idle_after_ready_io() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut recv = H3ReadStream::new(4, std::io::Cursor::new(vec![7]));
        *recv.stream.recv.lock().unwrap() =
            StreamState::Polling(std::io::Cursor::new(vec![7]), Waker::noop().clone());
        let mut bytes = [0];
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, [7]);
        assert!(matches!(
            *recv.stream.recv.lock().unwrap(),
            StreamState::Idle(_)
        ));
        recv.recv_goaway(Goaway {
            id: VarInt::from_u32(4),
        });
        assert!(matches!(
            *recv.stream.recv.lock().unwrap(),
            StreamState::Goaway(_)
        ));
        assert_eq!(recv.stream_id(), 4);
        let mut send = H3WriteStream::new(4, Vec::new());
        *send.stream.send.lock().unwrap() = StreamState::Polling(Vec::new(), Waker::noop().clone());
        send.write_all(b"x").await.unwrap();
        assert!(matches!(
            *send.stream.send.lock().unwrap(),
            StreamState::Idle(_)
        ));
        send.flush().await.unwrap();
        send.shutdown().await.unwrap();
        assert!(matches!(
            *send.stream.send.lock().unwrap(),
            StreamState::Finished
        ));
        send.on_recv(Goaway {
            id: VarInt::from_u32(4),
        });
        assert!(matches!(
            *send.stream.send.lock().unwrap(),
            StreamState::Finished
        ));
        assert_eq!(send.stream_id(), 4);
    }
}
