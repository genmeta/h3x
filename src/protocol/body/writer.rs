use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use http::HeaderMap;
use tokio::{
    io::{AsyncWrite, ReadHalf, SimplexStream, WriteHalf},
    sync::{mpsc, oneshot},
};

use crate::Error;

pub(crate) enum Control {
    Flush {
        through: u64,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Finish {
        through: u64,
        trailers: Option<HeaderMap>,
    },
}

impl Control {
    pub(crate) fn through(&self) -> u64 {
        match self {
            Self::Flush { through, .. } | Self::Finish { through, .. } => *through,
        }
    }
}

/// An exclusive, bounded byte producer for one HTTP request direction.
///
/// A successful write accepts bytes locally. Flush and shutdown wait for the
/// transport; dropping an unfinished writer aborts only the upload.
pub struct BodyWriter {
    pipe: WriteHalf<SimplexStream>,
    control: mpsc::Sender<Control>,
    done: oneshot::Receiver<Result<(), Error>>,
    flush: Option<oneshot::Receiver<Result<(), Error>>>,
    written: u64,
    ending: bool,
    result: Option<Result<(), Error>>,
}

impl std::fmt::Debug for BodyWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyWriter")
            .field("ending", &self.ending)
            .finish_non_exhaustive()
    }
}

/// Created before scheduling so destroying an unpolled owner wakes the writer.
pub(crate) struct Upload {
    pub(crate) pipe: ReadHalf<SimplexStream>,
    pub(crate) control: mpsc::Receiver<Control>,
    done: Option<oneshot::Sender<Result<(), Error>>>,
}

impl Upload {
    pub(crate) fn complete(&mut self, result: Result<(), Error>) {
        if let Some(done) = self.done.take() {
            let _ = done.send(result);
        }
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        self.complete(Err(Error::OwnerStopped));
    }
}

impl BodyWriter {
    pub(crate) fn channel() -> (Self, Upload) {
        let (reader, pipe) = tokio::io::simplex(64 * 1024);
        let (control, commands) = mpsc::channel(1);
        let (done, result) = oneshot::channel();
        (
            Self {
                pipe,
                control,
                done: result,
                flush: None,
                written: 0,
                ending: false,
                result: None,
            },
            Upload {
                pipe: reader,
                control: commands,
                done: Some(done),
            },
        )
    }

    fn poll_result(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if let Some(result) = &self.result {
            return Poll::Ready(result.clone());
        }
        let result = ready!(Pin::new(&mut self.done).poll(cx)).unwrap_or(Err(Error::OwnerStopped));
        self.result = Some(result.clone());
        Poll::Ready(result)
    }

    fn poll_pending_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if let Some(flush) = &mut self.flush {
            // An owner failure must wake even if it never polled the flush command.
            if let Poll::Ready(result) = Pin::new(flush).poll(cx) {
                self.flush = None;
                return match result {
                    Ok(result) => Poll::Ready(result),
                    Err(_) => self.poll_result(cx),
                };
            }
            if let Poll::Ready(result) = self.poll_result(cx) {
                self.flush = None;
                return Poll::Ready(result);
            }
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_finish(
        &mut self,
        cx: &mut Context<'_>,
        trailers: &mut Option<HeaderMap>,
    ) -> Poll<Result<(), Error>> {
        if !self.ending {
            ready!(self.poll_pending_flush(cx))?;
            if let Poll::Ready(result) = self.poll_result(cx) {
                return Poll::Ready(result);
            }
            let command = Control::Finish {
                through: self.written,
                trailers: trailers.take(),
            };
            if self.control.try_send(command).is_err() {
                return self.poll_result(cx);
            }
            self.ending = true;
            // The end intention is in the control queue before the pipe can report EOF.
            ready!(Pin::new(&mut self.pipe).poll_shutdown(cx)).map_err(|_| Error::OwnerStopped)?;
        }
        self.poll_result(cx)
    }

    /// Submits FIN and waits for the final transport result of the upload.
    pub async fn finish(mut self) -> Result<(), Error> {
        poll_fn(|cx| self.poll_finish(cx, &mut None)).await
    }

    /// Sends one trailing field section after all accepted bytes, then FIN.
    pub async fn trailers(mut self, trailers: HeaderMap) -> Result<(), Error> {
        let mut trailers = Some(trailers);
        poll_fn(|cx| self.poll_finish(cx, &mut trailers)).await
    }
}

fn io_error(error: Error) -> io::Error {
    io::Error::other(error)
}

impl AsyncWrite for BodyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.ending {
            return Poll::Ready(Err(io_error(Error::invalid_state("write"))));
        }
        ready!(self.poll_pending_flush(cx)).map_err(io_error)?;
        if let Poll::Ready(result) = self.poll_result(cx) {
            return Poll::Ready(Err(io_error(
                result.err().unwrap_or(Error::invalid_state("write")),
            )));
        }
        let count = match ready!(Pin::new(&mut self.pipe).poll_write(cx, buf)) {
            Ok(count) => count,
            Err(_) => {
                return self
                    .poll_result(cx)
                    .map(|result| Err(io_error(result.err().unwrap_or(Error::OwnerStopped))));
            }
        };
        self.written += count as u64;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.ending {
            return self.poll_result(cx).map_err(io_error);
        }
        if self.flush.is_none() {
            if let Poll::Ready(result) = self.poll_result(cx) {
                return Poll::Ready(result.map_err(io_error));
            }
            let (reply, receive) = oneshot::channel();
            if self
                .control
                .try_send(Control::Flush {
                    through: self.written,
                    reply,
                })
                .is_err()
            {
                return self.poll_result(cx).map_err(io_error);
            }
            self.flush = Some(receive);
        }
        self.poll_pending_flush(cx).map_err(io_error)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_finish(cx, &mut None).map_err(io_error)
    }
}
