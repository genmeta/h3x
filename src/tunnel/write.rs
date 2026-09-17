//! Bounded DATA buffering and send-side shutdown.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use qrecovery::send::CancelStream;
use tokio::io::AsyncWrite;

use crate::{
    Error, H3WriteStream,
    common::wnd_buf::WndBuf,
    protocol::frame::{Data, Frame, Write as _},
};

const MAX_PAYLOAD: usize = 16 * 1024;
// One-byte DATA type and up to four bytes for a length bounded by MAX_PAYLOAD.
const MAX_HEADER: usize = 5;

pub(super) struct DataWriter<W: CancelStream> {
    stream: H3WriteStream<W>,
    state: WriteState,
    buffer: WndBuf,
}

enum WriteState {
    Open,
    Closing,
    Finished,
    Failed(Error),
}

impl<W: CancelStream> DataWriter<W> {
    pub(super) fn new(stream: H3WriteStream<W>) -> Self {
        Self {
            stream,
            state: WriteState::Open,
            buffer: WndBuf::new(MAX_PAYLOAD + MAX_HEADER),
        }
    }

    pub(super) fn stream_id(&self) -> u64 {
        self.stream.stream_id()
    }

    pub(super) fn abort(&mut self, error: Error) {
        (&self.stream).cancel(error.code.as_u64());
        if !matches!(self.state, WriteState::Failed(_)) {
            self.state = WriteState::Failed(error);
            while !self.buffer.chunk().is_empty() {
                self.buffer.consume(self.buffer.chunk().len());
            }
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
        if let WriteState::Failed(error) = &self.state {
            return Poll::Ready(Err(error.clone().into()));
        }
        while !self.buffer.chunk().is_empty() {
            match ready!(Pin::new(&mut self.stream).poll_write(cx, self.buffer.chunk())) {
                Ok(0) => {
                    return Poll::Ready(Err(self.fail(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tunnel write returned zero",
                    ))));
                }
                Ok(n) => self.buffer.consume(n),
                Err(error) => return Poll::Ready(Err(self.fail(error))),
            }
        }
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
        if let WriteState::Failed(error) = &this.state {
            return Poll::Ready(Err(error.clone().into()));
        }
        if !matches!(this.state, WriteState::Open) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tunnel send direction is closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // A blocked transport may still leave room to accept another complete frame.
        if let Poll::Ready(result) = this.poll_drain(cx) {
            result?;
        }
        let n = input
            .len()
            .min(MAX_PAYLOAD)
            .min(this.buffer.remaining_capacity().saturating_sub(MAX_HEADER));
        if n == 0 {
            return Poll::Pending;
        }
        let mut header = [0; MAX_HEADER];
        let mut remaining = &mut header[..];
        remaining.put_frame(&Frame::new(Data(n)).map_err(io::Error::from)?);
        let header_len = MAX_HEADER - remaining.len();
        // Space for both writes was reserved above, so neither can be partial or pending.
        ready!(Pin::new(&mut this.buffer).poll_write(cx, &header[..header_len]))?;
        ready!(Pin::new(&mut this.buffer).poll_write(cx, &input[..n]))?;
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
        if matches!(this.state, WriteState::Open) {
            this.state = WriteState::Closing;
        }
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

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn window_accepts_until_full_and_drains_wrapped_frames() {
        let (stream, mut peer) = tokio::io::duplex(1);
        let mut writer = DataWriter::new(crate::test_support::write_stream(0, stream));
        let payload = vec![7; MAX_PAYLOAD * 2];
        let mut expected = Vec::new();
        for _ in 0..3 {
            assert_eq!(writer.write(b"abc").await.unwrap(), 3);
            expected.put_frame(&Frame::new(Data(3)).unwrap());
            expected.extend_from_slice(b"abc");
            // The first frame is blocked after one byte, but the window still accepts data.
            let n = writer.write(&payload).await.unwrap();
            assert!(n > 0 && n <= MAX_PAYLOAD);
            expected.put_frame(&Frame::new(Data(n)).unwrap());
            expected.extend_from_slice(&payload[..n]);
            assert!(
                Pin::new(&mut writer)
                    .poll_write(&mut Context::from_waker(std::task::Waker::noop()), b"x")
                    .is_pending()
            );
            let mut wire = vec![0; expected.len()];
            let (flushed, read) = tokio::join!(writer.flush(), peer.read_exact(&mut wire));
            flushed.unwrap();
            read.unwrap();
            assert_eq!(wire, expected);
            expected.clear();
        }
    }
}
