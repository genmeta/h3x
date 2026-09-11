use std::{
    io, mem,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use tokio::io::AsyncWrite;

use crate::protocol::{frame::Goaway, stream::write::H3WriteStream::Idle};

pub enum H3WriteStream<WS> {
    Idle(WS),
    #[allow(dead_code, reason = "GOAWAY dispatch is not wired up yet")]
    Polling(WS, Waker),
    Goaway(Goaway),
    Transition,
}

impl<WS> H3WriteStream<WS> {
    #[allow(dead_code, reason = "GOAWAY dispatch is not wired up yet")]
    pub fn on_recv(&mut self, goaway: Goaway) {
        if let Self::Polling(_, waker) = mem::replace(self, Self::Goaway(goaway)) {
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
            Self::Idle(mut ws) | Self::Polling(mut ws, _) => match poll(Pin::new(&mut ws), cx) {
                Poll::Pending => {
                    *self = Self::Polling(ws, cx.waker().clone());
                    Poll::Pending
                }
                Poll::Ready(result) => {
                    *self = Self::Idle(ws);
                    Poll::Ready(result)
                }
            },
            Self::Goaway(goaway) => {
                *self = Self::Goaway(goaway);
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "received GOAWAY",
                )))
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

impl<WS: AsyncWrite> From<WS> for H3WriteStream<WS> {
    fn from(value: WS) -> Self {
        Idle(value)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };

    use super::*;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Writer(bool);

    impl AsyncWrite for Writer {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.0 {
                Poll::Ready(Ok(buf.len()))
            } else {
                Poll::Pending
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    #[test]
    fn pending_operations_wake_on_goaway() {
        for operation in 0..3 {
            let old = Arc::new(WakeCount::default());
            let latest = Arc::new(WakeCount::default());
            let mut stream = H3WriteStream::Idle(Writer(false));
            let poll = |stream: &mut H3WriteStream<Writer>, cx: &mut Context<'_>| match operation {
                0 => Pin::new(stream).poll_write(cx, b"data").map_ok(|_| ()),
                1 => Pin::new(stream).poll_flush(cx),
                _ => Pin::new(stream).poll_shutdown(cx),
            };
            assert!(
                poll(
                    &mut stream,
                    &mut Context::from_waker(&Waker::from(old.clone()))
                )
                .is_pending()
            );
            assert!(
                poll(
                    &mut stream,
                    &mut Context::from_waker(&Waker::from(latest.clone()))
                )
                .is_pending()
            );
            stream.on_recv(Goaway {
                id: qbase::varint::VarInt::from_u32(4),
            });
            assert_eq!(old.0.load(Ordering::SeqCst), 0);
            assert_eq!(latest.0.load(Ordering::SeqCst), 1);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(
                matches!(poll(&mut stream, &mut cx), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionAborted)
            );
            stream.on_recv(Goaway {
                id: qbase::varint::VarInt::from_u32(0),
            });
            assert_eq!(latest.0.load(Ordering::SeqCst), 1);

            let mut stream = H3WriteStream::Polling(Writer(true), Waker::from(latest.clone()));
            assert!(matches!(poll(&mut stream, &mut cx), Poll::Ready(Ok(()))));
            assert!(matches!(stream, H3WriteStream::Idle(_)));
            stream.on_recv(Goaway {
                id: qbase::varint::VarInt::from_u32(0),
            });
            assert_eq!(latest.0.load(Ordering::SeqCst), 1);
        }
    }
}
