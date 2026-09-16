pub(crate) mod bi;
pub(crate) mod read;
pub(crate) mod write;

use std::{
    io, mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

pub(crate) use read::H3ReadStream;
pub(crate) use write::H3WriteStream;

use crate::Error;

/// State of one transport half, independent of its application handle.
enum StreamStatus<T> {
    Idle(T),
    Polling(T, Waker),
    Closed(Arc<io::Error>),
    Finished,
    Transition,
}

/// I/O state and completion waiter, protected by the owning direction's mutex.
pub(crate) struct StreamState<T> {
    status: StreamStatus<T>,
    finished_waker: Option<Waker>,
}

impl<T> StreamState<T> {
    fn new(io: T) -> Self {
        Self {
            status: StreamStatus::Idle(io),
            finished_waker: None,
        }
    }

    fn is_finished(&self) -> bool {
        matches!(
            self.status,
            StreamStatus::Closed(_) | StreamStatus::Finished
        )
    }

    fn poll_finished(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.is_finished() {
            Poll::Ready(())
        } else {
            self.finished_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    // Return wakers so the caller can wake after releasing the state lock.
    fn close(&mut self, error: Error, terminate: impl FnOnce(&mut T)) -> [Option<Waker>; 2] {
        let io_waker = if self.is_finished() {
            None
        } else {
            if let StreamStatus::Idle(io) | StreamStatus::Polling(io, _) = &mut self.status {
                terminate(io);
            }
            match mem::replace(
                &mut self.status,
                StreamStatus::Closed(Arc::new(error.into())),
            ) {
                StreamStatus::Polling(_, waker) => Some(waker),
                _ => None,
            }
        };
        [io_waker, self.finished_waker.take()]
    }
}

impl<T: Unpin> StreamState<T> {
    fn poll_io<O>(
        &mut self,
        cx: &mut Context<'_>,
        poll: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>> {
        match mem::replace(&mut self.status, StreamStatus::Transition) {
            StreamStatus::Idle(mut io) | StreamStatus::Polling(mut io, _) => {
                match poll(Pin::new(&mut io), cx) {
                    Poll::Pending => {
                        self.status = StreamStatus::Polling(io, cx.waker().clone());
                        Poll::Pending
                    }
                    Poll::Ready(Err(error))
                        if !matches!(
                            error.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                        ) =>
                    {
                        let error = Arc::new(error);
                        self.status = StreamStatus::Closed(error.clone());
                        Poll::Ready(Err(io::Error::new(error.kind(), error)))
                    }
                    result => {
                        self.status = StreamStatus::Idle(io);
                        result
                    }
                }
            }
            StreamStatus::Closed(error) => {
                self.status = StreamStatus::Closed(error.clone());
                Poll::Ready(Err(io::Error::new(error.kind(), error)))
            }
            StreamStatus::Finished => {
                self.status = StreamStatus::Finished;
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
            StreamStatus::Transition => unreachable!(),
        }
    }
}

#[cfg(test)]
mod termination_tests;
