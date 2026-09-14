use std::{
    io, mem,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use tokio::io::AsyncWrite;

use crate::protocol::frame::Goaway;

pub enum H3WriteStream<WS> {
    Idle(u64, WS),
    Polling(u64, WS, Waker),
    Goaway(u64, Goaway),
    Transition,
}

impl<WS> H3WriteStream<WS> {
    pub fn new(stream_id: u64, stream: WS) -> Self {
        Self::Idle(stream_id, stream)
    }
    pub fn stream_id(&self) -> u64 {
        match self {
            Self::Idle(id, _) | Self::Polling(id, _, _) | Self::Goaway(id, _) => *id,
            Self::Transition => unreachable!(),
        }
    }
    pub fn on_recv(&mut self, goaway: Goaway) {
        let id = self.stream_id();
        if let Self::Polling(_, _, waker) = mem::replace(self, Self::Goaway(id, goaway)) {
            waker.wake();
        }
    }
}

impl<WS: AsyncWrite + Unpin> H3WriteStream<WS> {
    fn poll_io<T>(
        &mut self,
        cx: &mut Context<'_>,
        poll: impl FnOnce(Pin<&mut WS>, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        match mem::replace(self, Self::Transition) {
            Self::Idle(id, mut ws) | Self::Polling(id, mut ws, _) => {
                match poll(Pin::new(&mut ws), cx) {
                    Poll::Pending => {
                        *self = Self::Polling(id, ws, cx.waker().clone());
                        Poll::Pending
                    }
                    Poll::Ready(result) => {
                        *self = Self::Idle(id, ws);
                        Poll::Ready(result)
                    }
                }
            }
            Self::Goaway(id, goaway) => {
                *self = Self::Goaway(id, goaway);
                Poll::Ready(Err(crate::Error::H3_REQUEST_REJECTED.into()))
            }
            Self::Transition => unreachable!(),
        }
    }
}

impl<WS: AsyncWrite + Unpin> AsyncWrite for H3WriteStream<WS> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_io(cx, |ws, cx| ws.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_io(cx, |ws, cx| ws.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_io(cx, |ws, cx| ws.poll_shutdown(cx))
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
        recv.on_recv(Goaway {
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
    async fn original_variants_return_to_idle_after_ready_io() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut recv =
            H3ReadStream::Polling(4, std::io::Cursor::new(vec![7]), Waker::noop().clone());
        let mut bytes = [0];
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, [7]);
        assert!(matches!(recv, H3ReadStream::Idle(4, _)));
        recv.on_recv(Goaway {
            id: VarInt::from_u32(4),
        });
        assert!(matches!(recv, H3ReadStream::Goaway(4, _)));
        assert_eq!(recv.stream_id(), 4);
        let mut send = H3WriteStream::Polling(4, Vec::new(), Waker::noop().clone());
        send.write_all(b"x").await.unwrap();
        assert!(matches!(send, H3WriteStream::Idle(4, _)));
        send.flush().await.unwrap();
        send.shutdown().await.unwrap();
        assert!(matches!(send, H3WriteStream::Idle(4, _)));
        send.on_recv(Goaway {
            id: VarInt::from_u32(4),
        });
        assert!(matches!(send, H3WriteStream::Goaway(4, _)));
        assert_eq!(send.stream_id(), 4);
    }
}
