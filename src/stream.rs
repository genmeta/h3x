pub(crate) mod bi;
pub(crate) mod read;
pub(crate) mod view;
pub(crate) mod write;

use std::{
    io, mem,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

pub(crate) use read::H3ReadStream;
pub(crate) use write::H3WriteStream;

use crate::ErrorCode;

/// A GOAWAY boundary rejected this request; other errors come from transport I/O.
#[derive(Debug)]
pub(crate) struct Goaway;

/// State of one transport half, independent of its application handle.
pub(crate) enum H3Stream<T> {
    Idle(T),
    Polling(T, Waker),
    Finished(T),
    Terminated,
    Transition,
}

impl<T> H3Stream<T> {
    fn is_finished(&self) -> bool {
        matches!(self, Self::Finished(_) | Self::Terminated)
    }

    fn terminate(&mut self, f: impl FnOnce(&mut T)) -> Option<Waker> {
        match mem::replace(self, Self::Transition) {
            Self::Idle(mut io) => {
                f(&mut io);
                *self = Self::Terminated;
                None
            }
            Self::Polling(mut io, waker) => {
                f(&mut io);
                *self = Self::Terminated;
                Some(waker)
            }
            finished @ Self::Finished(_) => {
                *self = finished;
                None
            }
            Self::Terminated => {
                *self = Self::Terminated;
                None
            }
            Self::Transition => unreachable!(),
        }
    }

    fn finish(&mut self) {
        *self = match mem::replace(self, Self::Transition) {
            Self::Idle(io) | Self::Polling(io, _) | Self::Finished(io) => Self::Finished(io),
            Self::Terminated => Self::Terminated,
            Self::Transition => unreachable!(),
        };
    }

    fn poll_io<O>(
        &mut self,
        cx: &mut Context<'_>,
        f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>>
    where
        T: Unpin,
    {
        let (mut io, finished) = match mem::replace(self, Self::Transition) {
            Self::Idle(io) | Self::Polling(io, _) => (io, false),
            Self::Finished(io) => (io, true),
            Self::Terminated => {
                *self = Self::Terminated;
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            Self::Transition => unreachable!(),
        };
        let result = f(Pin::new(&mut io), cx);
        *self = if finished {
            Self::Finished(io)
        } else if result.is_pending() {
            Self::Polling(io, cx.waker().clone())
        } else {
            Self::Idle(io)
        };
        result
    }
}

pub(crate) struct ArcH3Stream<T>(Arc<Mutex<Result<H3Stream<T>, Goaway>>>);

impl<T> Clone for ArcH3Stream<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> ArcH3Stream<T> {
    pub(crate) fn new(io: T) -> Self {
        Self(Arc::new(Mutex::new(Ok(H3Stream::Idle(io)))))
    }

    pub(crate) fn terminate(&self, f: impl FnOnce(&mut T)) -> bool {
        let mut state = self.0.lock().unwrap();
        let waker = match state.as_mut() {
            Ok(stream) if !stream.is_finished() => stream.terminate(f),
            _ => return false,
        };
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }

    pub(crate) fn goaway(&self, f: impl FnOnce(&mut T)) -> bool {
        let mut state = self.0.lock().unwrap();
        let waker = match state.as_mut() {
            Ok(stream) if !stream.is_finished() => stream.terminate(f),
            _ => return false,
        };
        *state = Err(Goaway);
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }

    pub(crate) fn finish(&self) -> bool {
        let mut state = self.0.lock().unwrap();
        if let Ok(stream) = state.as_mut()
            && !stream.is_finished()
        {
            stream.finish();
            return true;
        }
        false
    }

    pub(crate) fn poll_io<O>(
        &self,
        cx: &mut Context<'_>,
        f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>>
    where
        T: Unpin,
    {
        let mut state = self.0.lock().unwrap();
        match state.as_mut() {
            Ok(stream) => stream.poll_io(cx, f),
            Err(Goaway) => Poll::Ready(Err(ErrorCode::RequestRejected
                .reason("request rejected by GOAWAY")
                .into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Waker};

    use super::*;

    #[test]
    fn stream_state_transitions_cover_idle_polling_finished_and_goaway() {
        let idle = ArcH3Stream::new(1);
        idle.terminate(|io| *io += 1);
        idle.terminate(|_| panic!("finished I/O is untouched"));

        let rejected = ArcH3Stream::new(2);
        assert!(rejected.goaway(|io| *io += 1));
        rejected.terminate(|_| {});
        assert!(!rejected.goaway(|_| {}));

        let waker = Waker::noop().clone();
        let polling = ArcH3Stream(Arc::new(Mutex::new(Ok(H3Stream::Polling(3, waker)))));
        polling.terminate(|io| *io += 1);

        let idle = ArcH3Stream::new(7);
        idle.finish();
        idle.finish();
    }

    #[test]
    fn poll_io_retains_retryable_states_and_finishes_terminal_states() {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let state = ArcH3Stream::new(1);
        assert!(
            state
                .poll_io(&mut cx, |_, _| Poll::<io::Result<()>>::Pending)
                .is_pending()
        );
        assert!(matches!(
            *state.0.lock().unwrap(),
            Ok(H3Stream::Polling(_, _))
        ));
        assert!(
            state
                .poll_io(&mut cx, |_, _| Poll::Ready(Ok(())))
                .is_ready()
        );
        assert!(matches!(*state.0.lock().unwrap(), Ok(H3Stream::Idle(_))));

        assert!(
            state
                .poll_io(&mut cx, |_, _| {
                    Poll::<io::Result<()>>::Ready(Err(io::Error::from(io::ErrorKind::Interrupted)))
                })
                .is_ready()
        );
        assert!(matches!(*state.0.lock().unwrap(), Ok(H3Stream::Idle(_))));

        assert!(
            state
                .poll_io(&mut cx, |_, _| {
                    Poll::<io::Result<()>>::Ready(Err(io::Error::other("fatal")))
                })
                .is_ready()
        );
        assert!(matches!(*state.0.lock().unwrap(), Ok(H3Stream::Idle(_))));
        state.finish();
        assert!(
            state
                .poll_io(&mut cx, |_, _| Poll::Ready(Ok(())))
                .is_ready()
        );
        assert!(matches!(
            *state.0.lock().unwrap(),
            Ok(H3Stream::Finished(_))
        ));

        let rejected = ArcH3Stream::new(2);
        rejected.goaway(|_| {});
        let Poll::Ready(Err(error)) =
            rejected.poll_io(&mut cx, |_, _| Poll::<io::Result<()>>::Pending)
        else {
            panic!("GOAWAY must reject I/O")
        };
        assert_eq!(crate::Error::from(error).code, ErrorCode::RequestRejected);
    }
}
