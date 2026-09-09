use std::{
    fmt,
    future::poll_fn,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use http::HeaderMap;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};
use tokio::io::AsyncWrite;

use crate::Error;

/// Complete in-memory request content.
#[derive(Debug, Default)]
pub struct Fixed {
    body: http_body_util::Full<Bytes>,
}

impl From<Bytes> for Fixed {
    fn from(data: Bytes) -> Self {
        Self {
            body: http_body_util::Full::new(data),
        }
    }
}

impl HttpBody for Fixed {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// Construction marker for a streaming request. No pipe exists until execution.
#[derive(Debug)]
pub struct Chunk;

/// An HTTP body that reads the receive stream only when polled.
/// Each DATA item is a bounded chunk, not necessarily a complete HTTP/3 DATA frame.
pub struct ChunkBody {
    inner: Option<UnsyncBoxBody<Bytes, Error>>,
}

impl fmt::Debug for ChunkBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkBody")
            .field("ended", &self.inner.is_none())
            .finish_non_exhaustive()
    }
}

impl ChunkBody {
    pub(crate) fn new(body: impl HttpBody<Data = Bytes, Error = Error> + Send + 'static) -> Self {
        Self {
            inner: Some(body.boxed_unsync()),
        }
    }
}

impl HttpBody for ChunkBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let Some(body) = self.inner.as_mut() else {
            return Poll::Ready(None);
        };
        let frame = std::task::ready!(Pin::new(body).poll_frame(cx));
        if !matches!(frame, Some(Ok(_))) {
            // Release the reader immediately; its cleanup reports the end of reading.
            self.inner.take();
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        if self.inner.is_none() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::default()
        }
    }
}

/// Owns the send direction of a streaming request.
/// DATA writes are submitted as complete, bounded frames. Flush waits only for
/// submission, while shutdown waits for FIN completion. Drop cancels this direction.
pub struct BodyWriter {
    writer: Option<dquic::prelude::StreamWriter>,
    pub(super) writing: Option<super::connection::drain::Guard>,
    qpack: Arc<crate::qpack::Qpack>,
    stream_id: crate::StreamId,
    message_body: super::message::MessageBody,
    finishing: Option<futures::future::BoxFuture<'static, Result<(), Error>>>,
    result: Option<Result<(), Error>>,
    upload_failed: Option<tokio::sync::oneshot::Sender<Error>>,
}

impl fmt::Debug for BodyWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyWriter")
            .field("stream_id", &self.stream_id)
            .field(
                "ending",
                &(self.finishing.is_some() || self.result.is_some()),
            )
            .finish_non_exhaustive()
    }
}

impl BodyWriter {
    pub(super) fn new(
        writer: dquic::prelude::StreamWriter,
        qpack: Arc<crate::qpack::Qpack>,
        stream_id: crate::StreamId,
        message_body: super::message::MessageBody,
    ) -> Self {
        Self {
            writer: Some(writer),
            writing: None,
            qpack,
            stream_id,
            message_body,
            finishing: None,
            result: None,
            upload_failed: None,
        }
    }

    pub(super) fn stream(&mut self) -> &mut dquic::prelude::StreamWriter {
        self.writer.as_mut().expect("send direction finished")
    }

    pub(super) fn reset(&mut self, code: crate::Code) {
        if let Some(mut writer) = self.writer.take() {
            dquic::prelude::CancelStream::cancel(&mut writer, code.as_u64());
        }
        self.writing.take();
    }

    pub(super) async fn finish_send(&mut self) -> Result<(), dquic::prelude::StreamError> {
        futures::SinkExt::close(self.stream()).await?;
        self.writer.take();
        self.writing.take();
        Ok(())
    }

    pub(super) fn report_upload_failure(&mut self, sender: tokio::sync::oneshot::Sender<Error>) {
        self.upload_failed = Some(sender);
    }

    fn fail(&mut self, error: Error) -> Error {
        self.reset(error.code().unwrap_or(crate::Code::H3_REQUEST_CANCELLED));
        self.finishing.take();
        let _ = self
            .qpack
            .terminate_on_connection_error::<()>(Err(error.clone()));
        if let Some(upload_failed) = self.upload_failed.take() {
            let _ = upload_failed.send(error.clone());
        }
        self.result = Some(Err(error.clone()));
        error
    }

    fn check_connection(&mut self) -> Result<(), Error> {
        if let Some(result) = &self.result {
            return result.clone();
        }
        match self.qpack.failure() {
            Some(error) => Err(self.fail(error)),
            None => Ok(()),
        }
    }

    fn poll_finish(
        &mut self,
        cx: &mut Context<'_>,
        trailers: &mut Option<HeaderMap>,
    ) -> Poll<Result<(), Error>> {
        self.check_connection()?;
        if let Some(result) = &self.result {
            return Poll::Ready(result.clone());
        }
        if self.finishing.is_none() {
            if let Err(error) = self.message_body.finish() {
                return Poll::Ready(Err(self.fail(error)));
            }
            let mut writer = Self::new(
                self.writer.take().unwrap(),
                self.qpack.clone(),
                self.stream_id,
                self.message_body,
            );
            writer.writing = self.writing.take();
            let qpack = self.qpack.clone();
            let stream_id = self.stream_id;
            let message_body = self.message_body;
            let trailers = trailers.take();
            self.finishing = Some(Box::pin(async move {
                let result = tokio::select! {
                    biased;
                    error = qpack.stopped() => Err(error),
                    result = async {
                        if let Some(trailers) = trailers {
                            super::message::send_trailers(&mut writer, trailers, &message_body, &qpack, stream_id).await?;
                        }
                        writer.finish_send().await.map_err(crate::wire::map_stream_error)
                    } => result,
                };
                if let Err(error) = &result {
                    writer.reset(error.code().unwrap_or(crate::Code::H3_REQUEST_CANCELLED));
                }
                result
            }));
        }
        let result = ready!(self.finishing.as_mut().unwrap().as_mut().poll(cx));
        self.finishing.take();
        if let Err(error) = result {
            return Poll::Ready(Err(self.fail(error)));
        }
        self.upload_failed.take();
        self.result = Some(Ok(()));
        Poll::Ready(Ok(()))
    }

    /// Submits FIN and waits for the final transport result of the upload.
    pub async fn finish(mut self) -> Result<(), Error> {
        poll_fn(|cx| self.poll_finish(cx, &mut None)).await
    }

    /// Sends one trailing field section after all submitted DATA, then FIN.
    pub async fn trailers(mut self, trailers: HeaderMap) -> Result<(), Error> {
        let mut trailers = Some(trailers);
        poll_fn(|cx| self.poll_finish(cx, &mut trailers)).await
    }
}

impl Drop for BodyWriter {
    fn drop(&mut self) {
        self.reset(crate::Code::H3_REQUEST_CANCELLED);
        self.finishing.take();
        if let Some(upload_failed) = self.upload_failed.take() {
            let _ = upload_failed.send(Error::Cancelled);
        }
    }
}

impl AsyncWrite for BodyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check_connection().map_err(io::Error::other)?;
        if self.finishing.is_some() || self.result.is_some() {
            return Poll::Ready(Err(io::Error::other(Error::invalid_state("write"))));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = buf.len().min(crate::wire::MAX_DATA_CHUNK);
        let mut message_body = self.message_body;
        if let Err(error) = message_body.data(count as u64) {
            return Poll::Ready(Err(io::Error::other(self.fail(error))));
        }
        if let Err(error) = ready!(self.stream().poll_ready(cx)) {
            return Poll::Ready(Err(io::Error::other(
                self.fail(crate::wire::map_stream_error(error)),
            )));
        }
        // Sink accepts one Bytes atomically. Keeping header and payload together
        // avoids leaving a half-submitted frame when a pending write is cancelled.
        let mut frame = Vec::with_capacity(count + 16);
        if let Err(error) = crate::wire::WriteFrame::put_frame(
            &mut frame,
            &crate::wire::FrameHeader {
                frame_type: crate::wire::FrameType::Data,
                length: count as u64,
            },
        ) {
            return Poll::Ready(Err(io::Error::other(self.fail(error))));
        }
        frame.extend_from_slice(&buf[..count]);
        if let Err(error) = futures::Sink::start_send(Pin::new(self.stream()), Bytes::from(frame)) {
            return Poll::Ready(Err(io::Error::other(
                self.fail(crate::wire::map_stream_error(error)),
            )));
        }
        self.message_body = message_body;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.finishing.is_some() {
            return self.poll_finish(cx, &mut None).map_err(io::Error::other);
        }
        // Each successful write already submitted a complete DATA frame. Native
        // StreamWriter::poll_flush waits for ACKs, which is not this API's barrier.
        Poll::Ready(self.check_connection().map_err(io::Error::other))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_finish(cx, &mut None).map_err(io::Error::other)
    }
}
