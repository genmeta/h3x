//! Directly driven CONNECT DATA streams. No WebSocket message decoding or tasks.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{ArcQpack, ErrorCode, H3ReadStream, H3WriteStream, Result};

mod read;
mod write;
use read::DataReader;
use write::DataWriter;

/// A bidirectional byte stream over HTTP/3 DATA frames.
/// Writes accept at most 16 KiB into owned storage. Flush drives accepted bytes;
/// shutdown sends FIN only in the write direction. Dropping cancels unfinished I/O.
pub struct Tunnel<R: StopSending, W: CancelStream> {
    recv: DataReader<R>,
    send: DataWriter<W>,
}

impl<R: AsyncRead + StopSending + Unpin, W: CancelStream> Tunnel<R, W> {
    pub(crate) fn new(recv: H3ReadStream<R>, send: H3WriteStream<W>, qpack: ArcQpack) -> Self {
        Self {
            recv: DataReader::new(recv, qpack),
            send: DataWriter::new(send),
        }
    }

    /// Discard buffered bytes and cancel both directions. Idempotent.
    pub fn abort(&mut self) {
        let error = ErrorCode::H3_REQUEST_CANCELLED.with_reason("tunnel aborted");
        self.recv.abort(error.clone());
        self.send.abort(error);
    }
}

impl<R: StopSending, W: CancelStream> Tunnel<R, W> {
    pub fn stream_id(&self) -> u64 {
        self.send.stream_id()
    }
}

impl<R: StopSending, W: AsyncWrite + CancelStream + Unpin> Tunnel<R, W> {
    pub async fn finish(&mut self) -> Result<()> {
        self.shutdown().await.map_err(Into::into)
    }
}

impl<R: AsyncRead + StopSending + Unpin, W: CancelStream> AsyncRead for Tunnel<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, output)
    }
}

impl<R: StopSending, W: AsyncWrite + CancelStream + Unpin> AsyncWrite for Tunnel<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
