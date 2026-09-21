use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

use super::ArcH3Stream;
use crate::{
    ArcQpack, Error, ErrorCode, TransportError,
    common::{
        request::{ReadRequest, Request},
        response::{ReadResponse, Response},
    },
    frame::{self, Frame, H3Frame},
};

/// Application-owned read direction, sharing state with the connection registry.
pub struct H3ReadStream<R: StopSending> {
    pub(super) state: ArcH3Stream<R>,
    pub(super) finish_cb: Arc<dyn Fn() + Send + Sync>,
    cancel_cb: Arc<dyn Fn(u64) + Send + Sync>,
    id: u64,
}

impl<R: StopSending> H3ReadStream<R> {
    pub fn new(stream_id: u64, stream: R) -> Self {
        Self {
            id: stream_id,
            state: ArcH3Stream::new(stream),
            finish_cb: Arc::new(|| {}),
            cancel_cb: Arc::new(|_| {}),
        }
    }

    pub(super) fn on_finish(&mut self, callback: impl Fn() + Send + Sync + 'static) {
        self.finish_cb = Arc::new(callback);
    }

    pub(super) fn on_cancel(&mut self, callback: impl Fn(u64) + Send + Sync + 'static) {
        self.cancel_cb = Arc::new(callback);
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<R: StopSending> StopSending for &H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        if self.state.terminate(|io| io.stop(error_code)) {
            (self.finish_cb)();
            (self.cancel_cb)(error_code);
        }
    }
}

impl<R: StopSending> StopSending for H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        qrecovery::recv::StopSending::stop(&mut &*self, error_code);
    }
}

impl<R: AsyncRead + StopSending + Unpin> AsyncRead for H3ReadStream<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // A zero-capacity read is not evidence of EOF.
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = self.state.poll_io(cx, |recv, cx| recv.poll_read(cx, buf));
        let eof = matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() == before;
        let failed = matches!(&result, Poll::Ready(Err(error)) if !matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock));
        if eof || failed {
            if self.state.finish() {
                (self.finish_cb)();
            }
        }
        result
    }
}

impl<R: StopSending> Drop for H3ReadStream<R> {
    fn drop(&mut self) {
        if self.state.finish() {
            (self.finish_cb)();
        }
    }
}

pub(crate) enum NextFrame {
    Data(Frame<frame::Data>),
    Trailer(Frame<frame::Headers>),
}

impl<R: AsyncRead + StopSending + TransportError + Unpin> H3ReadStream<R> {
    async fn read_frame(&mut self) -> crate::Result<Option<H3Frame>> {
        let Some(ty) = frame::be_frame_type(self).await.map_err(R::map_error)? else {
            return Ok(None);
        };
        let length = frame::be_frame_length(self).await.map_err(R::map_error)?;
        frame::be_frame_payload(self, ty, length)
            .await
            .map(Some)
            .map_err(R::map_error)
    }

    pub(crate) async fn read_headers_frame(
        &mut self,
    ) -> crate::Result<Option<Frame<frame::Headers>>> {
        loop {
            match self.read_frame().await? {
                Some(H3Frame::Headers(frame)) => return Ok(Some(frame)),
                Some(H3Frame::Unknown { length, .. }) => {
                    frame::skip_payload(self, length.into_u64())
                        .await
                        .map_err(R::map_error)?;
                }
                Some(_) => {
                    return Err(ErrorCode::FrameUnexpected
                        .reason("expected HEADERS before message body")
                        .connection());
                }
                None => return Ok(None),
            }
        }
    }

    pub(crate) async fn read_next_frame(
        &mut self,
        trailers: bool,
    ) -> crate::Result<Option<NextFrame>> {
        if trailers {
            return match frame::be_frame_type(self).await.map_err(R::map_error)? {
                Some(_) => Err(ErrorCode::FrameUnexpected
                    .reason("frame received after trailers")
                    .connection()),
                None => Ok(None),
            };
        }
        loop {
            match self.read_frame().await? {
                Some(H3Frame::Headers(frame)) => return Ok(Some(NextFrame::Trailer(frame))),
                Some(H3Frame::Data(frame)) => return Ok(Some(NextFrame::Data(frame))),
                Some(H3Frame::Unknown { length, .. }) => {
                    frame::skip_payload(self, length.into_u64())
                        .await
                        .map_err(R::map_error)?;
                }
                Some(_) => {
                    return Err(ErrorCode::FrameUnexpected
                        .reason("frame is not allowed on a request stream")
                        .connection());
                }
                None => return Ok(None),
            }
        }
    }
}

impl<R> ReadRequest for H3ReadStream<R>
where
    R: AsyncRead + StopSending + TransportError + Unpin + Send + 'static,
{
    async fn read_request(mut self, qpack: ArcQpack) -> crate::Result<Request<crate::R>> {
        let mut body = crate::ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        body.on_error_callback({
            let state = self.state.clone();
            let finish = self.finish_cb.clone();
            let cancel = self.cancel_cb.clone();
            move |error| {
                if state.terminate(|io| io.stop(error.code.as_u64())) {
                    finish();
                    cancel(error.code.as_u64());
                }
            }
        });
        let consumer = body.clone();
        let request = async {
            let frame = self.read_headers_frame().await?.ok_or_else(|| {
                ErrorCode::RequestIncomplete
                    .reason("stream ended before request HEADERS")
                    .stream()
            })?;
            let fields = qpack
                .decode(self.stream_id(), frame.payload.field_section)
                .await?;
            Request::from_fields(fields, consumer).map_err(Error::stream)
        }
        .await
        .map_err(|failure| {
            let failure = if failure.is_connection() {
                qpack.on_connection_error(failure)
            } else {
                failure.stream()
            };
            self.stop(failure.code.as_u64());
            qpack.error().unwrap_or(failure)
        })?;
        let message_trailers = request.trailers.clone();

        tokio::spawn(async move {
            let result: crate::Result<()> = async {
                let mut trailers = false;
                while let Some(frame) = self.read_next_frame(trailers).await? {
                    match frame {
                        NextFrame::Data(frame) => {
                            let mut payload = (&mut self).take(frame.length.into_u64());
                            tokio::io::copy(&mut payload, &mut body)
                                .await
                                .map_err(R::map_error)?;
                            if payload.limit() != 0 {
                                return Err(ErrorCode::FrameError
                                    .reason("DATA payload ended before the declared frame length")
                                    .connection());
                            }
                        }
                        NextFrame::Trailer(frame) => {
                            let fields = qpack
                                .decode(self.stream_id(), frame.payload.field_section)
                                .await?;
                            message_trailers
                                .extend_fields(fields)
                                .map_err(Error::stream)?;
                            trailers = true;
                        }
                    }
                }
                body.shutdown()
                    .await
                    .map_err(Error::from)
                    .map_err(Error::stream)?;
                Ok(())
            }
            .await;
            if let Err(failure) = result {
                let failure = if failure.is_connection() {
                    qpack.on_connection_error(failure)
                } else {
                    failure.stream()
                };
                body.on_error(failure);
            }
        });
        Ok(request)
    }
}

impl<R> ReadResponse for H3ReadStream<R>
where
    R: AsyncRead + StopSending + TransportError + Unpin + Send + 'static,
{
    async fn read_response(
        mut self,
        request_method: http::Method,
        qpack: ArcQpack,
    ) -> crate::Result<Response<crate::R>> {
        let mut body = crate::ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        body.on_error_callback({
            let state = self.state.clone();
            let finish = self.finish_cb.clone();
            let cancel = self.cancel_cb.clone();
            move |error| {
                if state.terminate(|io| io.stop(error.code.as_u64())) {
                    finish();
                    cancel(error.code.as_u64());
                }
            }
        });
        let consumer = body.clone();
        let response = async {
            loop {
                let frame = self.read_headers_frame().await?.ok_or_else(|| {
                    ErrorCode::RequestIncomplete
                        .reason("stream ended before final response HEADERS")
                        .stream()
                })?;
                let fields = qpack
                    .decode(self.stream_id(), frame.payload.field_section)
                    .await?;
                let response =
                    Response::from_fields(fields, consumer.clone()).map_err(Error::stream)?;
                if response.status().is_informational() {
                    tokio::task::yield_now().await;
                    continue;
                }
                return Ok::<_, Error>(response);
            }
        }
        .await
        .map_err(|failure| {
            let failure = if failure.is_connection() {
                qpack.on_connection_error(failure)
            } else {
                failure.stream()
            };
            self.stop(failure.code.as_u64());
            qpack.error().unwrap_or(failure)
        })?;

        let body_allowed = request_method != http::Method::HEAD
            && response.status() != http::StatusCode::NO_CONTENT
            && response.status() != http::StatusCode::NOT_MODIFIED;
        let message_trailers = response.trailers.clone();
        tokio::spawn(async move {
            let result: crate::Result<()> = async {
                let mut trailers = false;
                while let Some(frame) = self.read_next_frame(trailers).await? {
                    match frame {
                        NextFrame::Data(frame) => {
                            if !body_allowed {
                                return Err(ErrorCode::MessageError
                                    .reason("DATA is not allowed for this response")
                                    .stream());
                            }
                            let mut payload = (&mut self).take(frame.length.into_u64());
                            tokio::io::copy(&mut payload, &mut body)
                                .await
                                .map_err(R::map_error)?;
                            if payload.limit() != 0 {
                                return Err(ErrorCode::FrameError
                                    .reason("DATA payload ended before the declared frame length")
                                    .connection());
                            }
                        }
                        NextFrame::Trailer(frame) => {
                            let fields = qpack
                                .decode(self.stream_id(), frame.payload.field_section)
                                .await?;
                            message_trailers
                                .extend_fields(fields)
                                .map_err(Error::stream)?;
                            trailers = true;
                        }
                    }
                }
                body.shutdown()
                    .await
                    .map_err(Error::from)
                    .map_err(Error::stream)?;
                Ok(())
            }
            .await;
            if let Err(failure) = result {
                let failure = if failure.is_connection() {
                    qpack.on_connection_error(failure)
                } else {
                    failure.stream()
                };
                body.on_error(failure);
            }
        });
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use qbase::varint::{VarInt, WriteVarInt};
    use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

    use super::*;
    use crate::frame::Write as _;

    #[derive(Default)]
    struct Io {
        bytes: Vec<u8>,
        offset: usize,
        stops: Vec<u64>,
    }

    impl Io {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                ..Self::default()
            }
        }
    }

    impl AsyncRead for Io {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let count = (self.bytes.len() - self.offset).min(buf.remaining());
            buf.put_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Poll::Ready(Ok(()))
        }
    }

    impl StopSending for Io {
        fn stop(&mut self, code: u64) {
            self.stops.push(code);
        }
    }

    impl TransportError for Io {
        fn map_error(error: io::Error) -> Error {
            Error::from_stream_io(error)
        }
    }

    fn headers(bytes: &'static [u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.put_frame(
            &Frame::new(frame::Headers {
                field_section: Bytes::from_static(bytes),
            })
            .unwrap(),
        );
        wire
    }

    #[tokio::test]
    async fn header_and_next_frame_readers_skip_extensions_and_enforce_placement() {
        let mut wire = Vec::new();
        wire.put_varint(&VarInt::from_u32(42));
        wire.put_varint(&VarInt::from_u32(2));
        wire.extend_from_slice(b"xx");
        wire.extend_from_slice(&headers(b"head"));
        let mut stream = H3ReadStream::new(4, Io::new(wire));
        assert_eq!(stream.stream_id(), 4);
        assert_eq!(
            stream
                .read_headers_frame()
                .await
                .unwrap()
                .unwrap()
                .payload
                .field_section,
            Bytes::from_static(b"head")
        );
        assert!(stream.read_headers_frame().await.unwrap().is_none());

        let mut stream = H3ReadStream::new(8, Io::new(vec![0, 1, b'x']));
        let Some(NextFrame::Data(frame)) = stream.read_next_frame(false).await.unwrap() else {
            panic!("expected DATA")
        };
        assert_eq!(frame.length.into_u64(), 1);
        let mut payload = [0];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, [b'x']);
        assert!(stream.read_next_frame(false).await.unwrap().is_none());

        let mut stream = H3ReadStream::new(12, Io::new(headers(b"trailers")));
        assert!(matches!(
            stream.read_next_frame(false).await.unwrap(),
            Some(NextFrame::Trailer(_))
        ));
        assert!(stream.read_next_frame(true).await.unwrap().is_none());

        let mut stream = H3ReadStream::new(16, Io::new(vec![0, 0]));
        assert_eq!(
            stream.read_headers_frame().await.unwrap_err().code,
            ErrorCode::FrameUnexpected
        );
        let mut stream = H3ReadStream::new(20, Io::new(vec![7, 1, 0]));
        assert_eq!(
            stream.read_next_frame(false).await.err().unwrap().code,
            ErrorCode::FrameUnexpected
        );
        let mut stream = H3ReadStream::new(24, Io::new(vec![0]));
        assert_eq!(
            stream.read_next_frame(true).await.err().unwrap().code,
            ErrorCode::FrameUnexpected
        );
    }

    #[tokio::test]
    async fn read_completion_notifies_finish_once() {
        fn reject<R: StopSending>(stream: &H3ReadStream<R>) -> bool {
            stream
                .state
                .goaway(|io| io.stop(ErrorCode::RequestRejected.as_u64()))
        }

        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut stream = H3ReadStream::new(0, Io::new(b"abc".to_vec()));
        stream.on_finish(move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        let _registered = stream.state.clone();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"abc");
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        stream.stop(ErrorCode::InternalError.as_u64());
        assert!(!reject(&stream));
        stream.stop(9);
        assert_eq!(completed.load(Ordering::SeqCst), 1);

        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut rejected = H3ReadStream::new(4, Io::default());
        rejected.on_finish(move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        assert!(reject(&rejected));
        assert_eq!(completed.load(Ordering::SeqCst), 0);
        let mut byte = [0];
        let error = rejected.read(&mut byte).await.unwrap_err();
        assert_eq!(crate::Error::from(error).code, ErrorCode::RequestRejected);
    }

    #[tokio::test]
    async fn read_request_rejects_a_stream_without_initial_headers() {
        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut stream = H3ReadStream::new(0, Io::default());
        stream.on_finish(move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        let result: crate::Result<crate::Request<crate::R>> =
            stream.read_request(crate::qpack::tests::qpack()).await;
        let Err(error) = result else {
            panic!("a message without HEADERS must fail")
        };
        assert_eq!(error.code, ErrorCode::RequestIncomplete);
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }
}
