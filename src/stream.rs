pub(crate) mod bi;
pub(crate) mod read;
pub(crate) mod view;
pub(crate) mod write;

use std::{
    mem,
    sync::{Arc, Mutex},
    task::Waker,
};

pub(crate) use read::H3ReadStream;
pub(crate) use write::H3WriteStream;

use crate::Error;

/// Completion of one transport direction: `Ok` for a normal finish and
/// `Err` for an H3 failure that still needs to be propagated.
pub(crate) type StreamEvent = crate::Result<()>;
pub(crate) type StreamEventHandler = Arc<dyn Fn(StreamEvent) + Send + Sync>;

/// Normal state of one transport half. Failures live in the surrounding
/// `Result<H3Stream<T>, Error>` so every abnormal terminal state retains its
/// complete H3 error.
#[derive(Debug)]
pub(crate) enum H3Stream<T> {
    Idle(T),
    Polling(T, Waker),
    Finished,
    Transition,
}

impl<T> H3Stream<T> {
    fn is_finished(&self) -> bool {
        matches!(self, Self::Finished)
    }
}

pub(crate) struct ArcH3Stream<T>(Arc<Mutex<crate::Result<H3Stream<T>>>>);

impl<T> Clone for ArcH3Stream<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> ArcH3Stream<T> {
    pub(crate) fn new(io: T) -> Self {
        Self(Arc::new(Mutex::new(Ok(H3Stream::Idle(io)))))
    }

    /// Retain the first H3 failure, terminate active transport I/O, and wake a
    /// task that was pending on that I/O. A normal finish may be upgraded to a
    /// failure when message validation discovers an error after FIN.
    pub(crate) fn fail(&self, error: Error, terminate: impl FnOnce(&mut T)) -> bool {
        let mut state = self.0.lock().unwrap();
        let waker = match state.as_mut() {
            Err(_) => return false,
            Ok(stream) => match mem::replace(stream, H3Stream::Transition) {
                H3Stream::Idle(mut io) => {
                    terminate(&mut io);
                    None
                }
                H3Stream::Polling(mut io, waker) => {
                    terminate(&mut io);
                    Some(waker)
                }
                H3Stream::Finished => None,
                H3Stream::Transition => unreachable!(),
            },
        };
        *state = Err(error);
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }

    /// Complete this direction normally and release its transport I/O.
    pub(crate) fn finish(&self) -> bool {
        let mut state = self.0.lock().unwrap();
        let Ok(stream) = state.as_mut() else {
            return false;
        };
        match mem::replace(stream, H3Stream::Transition) {
            H3Stream::Idle(io) | H3Stream::Polling(io, _) => {
                drop(io);
                *stream = H3Stream::Finished;
                true
            }
            H3Stream::Finished => {
                *stream = H3Stream::Finished;
                false
            }
            H3Stream::Transition => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    #[test]
    fn stream_state_retains_normal_and_failed_terminal_states() {
        let failed = ArcH3Stream::new(1);
        let error = ErrorCode::RequestCancelled.stream("cancelled");
        assert!(failed.fail(error.clone(), |io| *io += 1));
        assert!(
            !failed.fail(ErrorCode::InternalError.stream("later"), |_| panic!(
                "failed I/O is untouched"
            ))
        );
        assert_eq!(failed.0.lock().unwrap().as_ref().unwrap_err(), &error);

        let waker = Waker::noop().clone();
        let polling = ArcH3Stream(Arc::new(Mutex::new(Ok(H3Stream::Polling(3, waker)))));
        assert!(polling.fail(error.clone(), |io| *io += 1));

        let finished = ArcH3Stream::new(7);
        assert!(finished.finish());
        assert!(!finished.finish());
        assert!(matches!(
            *finished.0.lock().unwrap(),
            Ok(H3Stream::Finished)
        ));
        assert!(finished.fail(error.clone(), |_| {
            panic!("finished I/O has already been released")
        }));
        assert_eq!(finished.0.lock().unwrap().as_ref().unwrap_err(), &error);
    }
}
