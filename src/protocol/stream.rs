pub(crate) mod bi;
pub(crate) mod read;
pub(crate) mod view;
pub(crate) mod write;

use std::{
    io, mem,
    pin::Pin,
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
    Transition,
}

impl<T> H3Stream<T> {
    fn new(io: T) -> Self {
        Self::Idle(io)
    }
}

pub(crate) fn is_finished<T>(s: &Result<H3Stream<T>, Goaway>) -> bool {
    matches!(s, Err(Goaway) | Ok(H3Stream::Finished(_)))
}

pub(crate) fn terminate<T>(
    s: &mut Result<H3Stream<T>, Goaway>,
    f: impl FnOnce(&mut T),
) -> Option<Waker> {
    let Ok(stream) = s else { return None };
    match mem::replace(stream, H3Stream::Transition) {
        H3Stream::Idle(mut io) => {
            f(&mut io);
            *stream = H3Stream::Finished(io);
            None
        }
        H3Stream::Polling(mut io, w) => {
            f(&mut io);
            *stream = H3Stream::Finished(io);
            Some(w)
        }
        x @ H3Stream::Finished(_) => {
            *stream = x;
            None
        }
        H3Stream::Transition => unreachable!(),
    }
}
pub(crate) fn goaway<T>(
    s: &mut Result<H3Stream<T>, Goaway>,
    f: impl FnOnce(&mut T),
) -> Option<Waker> {
    if is_finished(s) {
        None
    } else {
        let w = terminate(s, f);
        *s = Err(Goaway);
        w
    }
}

pub(crate) fn finish<T>(s: &mut Result<H3Stream<T>, Goaway>) {
    if let Ok(stream) = s {
        *stream = match mem::replace(stream, H3Stream::Transition) {
            H3Stream::Idle(io) | H3Stream::Polling(io, _) | H3Stream::Finished(io) => {
                H3Stream::Finished(io)
            }
            H3Stream::Transition => unreachable!(),
        };
    }
}

pub(crate) fn poll_io<T: Unpin, O>(
    s: &mut Result<H3Stream<T>, Goaway>,
    cx: &mut Context<'_>,
    f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<O>>,
) -> Poll<io::Result<O>> {
    let stream = match s {
        Ok(x) => x,
        Err(Goaway) => {
            return Poll::Ready(Err(ErrorCode::H3_REQUEST_REJECTED
                .reason("request rejected by GOAWAY")
                .into()));
        }
    };
    let (mut io, finished) = match mem::replace(stream, H3Stream::Transition) {
        H3Stream::Idle(io) | H3Stream::Polling(io, _) => (io, false),
        H3Stream::Finished(io) => (io, true),
        H3Stream::Transition => unreachable!(),
    };
    let r = f(Pin::new(&mut io), cx);
    let failed = matches!(&r,Poll::Ready(Err(e)) if !matches!(e.kind(),io::ErrorKind::Interrupted|io::ErrorKind::WouldBlock));
    *stream = if finished || failed {
        H3Stream::Finished(io)
    } else if r.is_pending() {
        H3Stream::Polling(io, cx.waker().clone())
    } else {
        H3Stream::Idle(io)
    };
    r
}
