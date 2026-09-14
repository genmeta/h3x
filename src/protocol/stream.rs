pub(crate) mod bi;
pub(crate) mod control;
pub(crate) mod read;
pub(crate) mod uni;
pub(crate) mod write;

use std::{
    io, mem,
    pin::Pin,
    task::{Context, Poll, Waker},
};

pub(crate) use read::H3ReadStream;
pub(crate) use uni::UniStreams;
pub(crate) use write::H3WriteStream;

use crate::{Error, protocol::frame::Goaway};

/// State of one transport half, independent of its application handle.
pub(crate) enum StreamState<T> {
    Idle(T),
    Polling(T, Waker),
    Goaway(Goaway),
    Closed(Error),
    Finished,
    Transition,
}

impl<T> StreamState<T> {
    pub(super) fn is_terminal(&self) -> bool {
        matches!(self, Self::Goaway(_) | Self::Closed(_) | Self::Finished)
    }

    pub(crate) fn terminate(&mut self, terminal: Self) -> Option<Waker> {
        if self.is_terminal() {
            return None;
        }
        match mem::replace(self, terminal) {
            Self::Polling(_, waker) => Some(waker),
            _ => None,
        }
    }
}

impl<T: Unpin> StreamState<T> {
    fn poll_io<O>(
        &mut self,
        cx: &mut Context<'_>,
        poll: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>> {
        match mem::replace(self, Self::Transition) {
            Self::Idle(mut io) | Self::Polling(mut io, _) => {
                let result = poll(Pin::new(&mut io), cx);
                *self = match &result {
                    Poll::Pending => Self::Polling(io, cx.waker().clone()),
                    Poll::Ready(Err(error))
                        if !matches!(
                            error.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                        ) =>
                    {
                        Self::Closed(
                            error
                                .get_ref()
                                .and_then(|source| source.downcast_ref::<Error>())
                                .copied()
                                .unwrap_or_else(|| Error::from(io::Error::from(error.kind()))),
                        )
                    }
                    _ => Self::Idle(io),
                };
                result
            }
            Self::Goaway(goaway) => {
                *self = Self::Goaway(goaway);
                Poll::Ready(Err(Error::H3_REQUEST_REJECTED.into()))
            }
            Self::Closed(error) => {
                *self = Self::Closed(error);
                Poll::Ready(Err(error.into()))
            }
            Self::Finished => {
                *self = Self::Finished;
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
            Self::Transition => unreachable!(),
        }
    }
}
