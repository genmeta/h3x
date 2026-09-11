use std::{
    io, mem,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, ReadBuf};

use crate::protocol::{frame::Goaway, stream::read::H3ReadStream::Idle};

pub enum H3ReadStream<RS> {
    Idle(RS),
    #[allow(dead_code, reason = "GOAWAY dispatch is not wired up yet")]
    Polling(RS, Waker),
    Goaway(Goaway),
    Transition,
}

impl<RS> H3ReadStream<RS> {
    #[allow(dead_code, reason = "GOAWAY dispatch is not wired up yet")]
    pub fn on_recv(&mut self, goaway: Goaway) {
        if let Self::Polling(_, waker) = mem::replace(self, Self::Goaway(goaway)) {
            waker.wake();
        }
    }
}

impl<RS: AsyncRead + Unpin> AsyncRead for H3ReadStream<RS> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match mem::replace(this, Self::Transition) {
            Self::Idle(mut rs) | Self::Polling(mut rs, _) => {
                match Pin::new(&mut rs).poll_read(cx, buf) {
                    Poll::Pending => {
                        *this = Self::Polling(rs, cx.waker().clone());
                        Poll::Pending
                    }
                    Poll::Ready(result) => {
                        *this = Self::Idle(rs);
                        Poll::Ready(result)
                    }
                }
            }
            Self::Goaway(goaway) => {
                *this = Self::Goaway(goaway);
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "received GOAWAY",
                )))
            }
            Self::Transition => unreachable!(),
        }
    }
}

impl<RS: AsyncRead> From<RS> for H3ReadStream<RS> {
    fn from(value: RS) -> Self {
        Idle(value)
    }
}
