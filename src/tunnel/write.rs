//! Bounded DATA buffering and send-side shutdown.
use std::{
    io, mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use qrecovery::send::CancelStream;
use tokio::io::AsyncWrite;

use crate::{
    Error, H3WriteStream,
    protocol::frame::{Data, Frame, Write as _},
};

const MAX_PAYLOAD: usize = 16 * 1024;

pub(super) struct DataWriter<W: CancelStream> {
    stream: H3WriteStream<W>,
    state: WriteState,
}

enum WriteState {
    Open,
    Sending(PendingData),
    Closing(Option<PendingData>),
    Finished,
    Failed(Error),
}

/// Owned frame bytes; advancing the slice preserves partial writes across cancellation.
struct PendingData(Bytes);

impl PendingData {
    fn new(payload: &[u8]) -> io::Result<Self> {
        let mut frame = Vec::with_capacity(payload.len() + 9);
        frame.put_frame(&Frame::new(Data(payload.len())).map_err(io::Error::from)?);
        frame.extend_from_slice(payload);
        Ok(Self(frame.into()))
    }

    fn poll_send<W: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.0.has_remaining() {
            let n = ready!(Pin::new(&mut *stream).poll_write(cx, &self.0))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "tunnel write returned zero",
                )));
            }
            self.0.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<W: CancelStream> DataWriter<W> {
    pub(super) fn new(stream: H3WriteStream<W>) -> Self {
        Self {
            stream,
            state: WriteState::Open,
        }
    }
    pub(super) fn stream_id(&self) -> u64 {
        self.stream.stream_id()
    }
    pub(super) fn abort(&mut self, error: Error) {
        self.stream.cancel_with_error(error.clone());
        if !matches!(self.state, WriteState::Failed(_)) {
            self.state = WriteState::Failed(error);
        }
    }
    fn fail(&mut self, error: io::Error) -> io::Error {
        let error = Error::from(error);
        self.abort(error.clone());
        error.into()
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> DataWriter<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            WriteState::Failed(error) => return Poll::Ready(Err(error.clone().into())),
            WriteState::Sending(pending) | WriteState::Closing(Some(pending)) => {
                if let Err(error) = ready!(pending.poll_send(&mut self.stream, cx)) {
                    return Poll::Ready(Err(self.fail(error)));
                }
            }
            _ => return Poll::Ready(Ok(())),
        }
        self.state = match self.state {
            WriteState::Sending(_) => WriteState::Open,
            _ => WriteState::Closing(None),
        };
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> AsyncWrite for DataWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if !matches!(this.state, WriteState::Open) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tunnel send direction is closed",
            )));
        }
        let n = input.len().min(MAX_PAYLOAD);
        if n > 0 {
            this.state = WriteState::Sending(PendingData::new(&input[..n])?);
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        match ready!(Pin::new(&mut this.stream).poll_flush(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(this.fail(error))),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state = match mem::replace(&mut this.state, WriteState::Closing(None)) {
            WriteState::Open => WriteState::Closing(None),
            WriteState::Sending(pending) => WriteState::Closing(Some(pending)),
            state => state,
        };
        ready!(this.poll_drain(cx))?;
        if matches!(this.state, WriteState::Finished) {
            return Poll::Ready(Ok(()));
        }
        if let Err(error) = ready!(Pin::new(&mut this.stream).poll_shutdown(cx)) {
            return Poll::Ready(Err(this.fail(error)));
        }
        this.state = WriteState::Finished;
        Poll::Ready(Ok(()))
    }
}
