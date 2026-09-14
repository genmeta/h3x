use std::{
    io, mem,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, ReadBuf};

use crate::protocol::frame::Goaway;

pub enum H3ReadStream<RS> {
    Idle(u64, RS),
    Polling(u64, RS, Waker),
    Goaway(u64, Goaway),
    Transition,
}

impl<RS> H3ReadStream<RS> {
    pub fn new(stream_id: u64, stream: RS) -> Self {
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

impl<RS: AsyncRead + Unpin> AsyncRead for H3ReadStream<RS> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match mem::replace(this, Self::Transition) {
            Self::Idle(id, mut rs) | Self::Polling(id, mut rs, _) => {
                match Pin::new(&mut rs).poll_read(cx, buf) {
                    Poll::Pending => {
                        *this = Self::Polling(id, rs, cx.waker().clone());
                        Poll::Pending
                    }
                    Poll::Ready(result) => {
                        *this = Self::Idle(id, rs);
                        Poll::Ready(result)
                    }
                }
            }
            Self::Goaway(id, goaway) => {
                *this = Self::Goaway(id, goaway);
                Poll::Ready(Err(crate::Error::H3_REQUEST_REJECTED.into()))
            }
            Self::Transition => unreachable!(),
        }
    }
}
