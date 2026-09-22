use std::{
    future::{Future, poll_fn},
    io, mem,
    pin::Pin,
    task::{Context, Poll},
};

use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

use super::{ArcH3Stream, H3Stream, StreamEventHandler};
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
    handler: StreamEventHandler,
    id: u64,
}

impl<R: StopSending> H3ReadStream<R> {
    pub(crate) fn new(stream_id: u64, stream: R, handler: StreamEventHandler) -> Self {
        Self {
            id: stream_id,
            state: ArcH3Stream::new(stream),
            handler,
        }
    }

    fn finish(&self) {
        if self.state.finish() {
            (self.handler)(Ok(()));
        }
    }

    fn fail(&self, error: Error) {
        let code = error.code.as_u64();
        if self.state.fail(error.clone(), |io| io.stop(code)) {
            (self.handler)(Err(error));
        }
    }

    fn error_handler(&self) -> impl FnOnce(Error) + Send + 'static
    where
        R: Send + 'static,
    {
        let state = self.state.clone();
        let events = self.handler.clone();
        move |error| {
            let code = error.code.as_u64();
            if state.fail(error.clone(), |io| io.stop(code)) {
                events(Err(error));
            }
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<R: StopSending> StopSending for &H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        let error = ErrorCode::try_from(error_code)
            .unwrap_or(ErrorCode::InternalError)
            .stream(format!("read stream stopped with code 0x{error_code:x}"));
        self.fail(error);
    }
}

impl<R: StopSending> StopSending for H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        qrecovery::recv::StopSending::stop(&mut &*self, error_code);
    }
}

impl<R: AsyncRead + StopSending + TransportError + Unpin> AsyncRead for H3ReadStream<R> {
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
        let mut state = self.state.0.lock().unwrap();
        let stream = match state.as_mut() {
            Err(error) => return Poll::Ready(Err(error.clone().into())),
            Ok(H3Stream::Finished) => return Poll::Ready(Ok(())),
            Ok(stream) => stream,
        };
        let mut io = match mem::replace(stream, H3Stream::Transition) {
            H3Stream::Idle(io) | H3Stream::Polling(io, _) => io,
            H3Stream::Finished | H3Stream::Transition => unreachable!(),
        };
        match Pin::new(&mut io).poll_read(cx, buf) {
            Poll::Pending => {
                *stream = H3Stream::Polling(io, cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(value)) => {
                if buf.filled().len() == before {
                    *stream = H3Stream::Finished;
                    drop(io);
                    drop(state);
                    (self.handler)(Ok(()));
                } else {
                    *stream = H3Stream::Idle(io);
                }
                Poll::Ready(Ok(value))
            }
            Poll::Ready(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                *stream = H3Stream::Idle(io);
                Poll::Ready(Err(error))
            }
            Poll::Ready(Err(error)) => {
                let error = R::map_error(error);
                *state = Err(error.clone());
                drop(io);
                drop(state);
                (self.handler)(Err(error.clone()));
                Poll::Ready(Err(error.into()))
            }
        }
    }
}

impl<R: StopSending> Drop for H3ReadStream<R> {
    fn drop(&mut self) {
        self.finish();
    }
}

pub(crate) enum NextFrame {
    Data(Frame<frame::Data>),
    Trailer(Frame<frame::Headers>),
}

impl<R: AsyncRead + StopSending + TransportError + Unpin> H3ReadStream<R> {
    async fn decode(
        &self,
        qpack: &ArcQpack,
        payload: bytes::Bytes,
    ) -> crate::Result<Vec<crate::qpack::Field>> {
        let decoding = qpack.decode(self.stream_id(), payload);
        tokio::pin!(decoding);

        poll_fn(|cx| {
            let state = self.state.0.lock().unwrap();
            match state.as_ref() {
                Ok(stream) if !stream.is_finished() => decoding.as_mut().poll(cx),
                Ok(_) => Poll::Ready(Err(
                    ErrorCode::RequestCancelled.stream("stream is terminated")
                )),
                Err(error) => Poll::Ready(Err(error.clone())),
            }
        })
        .await
    }

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
                        .connection("expected HEADERS before message body"));
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
            loop {
                match frame::be_frame_type(self).await.map_err(R::map_error)? {
                    Some(frame::FrameType::Unknown(_)) => {
                        let length = frame::be_frame_length(self).await.map_err(R::map_error)?;
                        frame::skip_payload(self, length.into_u64())
                            .await
                            .map_err(R::map_error)?;
                    }
                    Some(_) => {
                        return Err(
                            ErrorCode::FrameUnexpected.connection("frame received after trailers")
                        );
                    }
                    None => return Ok(None),
                }
            }
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
                        .connection("frame is not allowed on a request stream"));
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
        body.on_error(self.error_handler());
        let consumer = body.clone();
        let request = async {
            let frame = self.read_headers_frame().await?.ok_or_else(|| {
                ErrorCode::RequestIncomplete.stream("stream ended before request HEADERS")
            })?;
            let fields = self.decode(&qpack, frame.payload.field_section).await?;
            Request::from_fields(fields, consumer).map_err(Error::stream)
        }
        .await
        .map_err(|failure| {
            let failure = if failure.is_connection() {
                qpack.on_connection_error(failure)
            } else {
                failure.stream()
            };
            self.fail(failure.clone());
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
                                return Err(ErrorCode::FrameError.connection(
                                    "DATA payload ended before the declared frame length",
                                ));
                            }
                        }
                        NextFrame::Trailer(frame) => {
                            let fields = self.decode(&qpack, frame.payload.field_section).await?;
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
                body.error(failure);
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
        body.on_error(self.error_handler());
        let consumer = body.clone();
        let response = async {
            loop {
                let frame = self.read_headers_frame().await?.ok_or_else(|| {
                    ErrorCode::RequestIncomplete
                        .stream("stream ended before final response HEADERS")
                })?;
                let fields = self.decode(&qpack, frame.payload.field_section).await?;
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
            self.fail(failure.clone());
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
                                    .stream("DATA is not allowed for this response"));
                            }
                            let mut payload = (&mut self).take(frame.length.into_u64());
                            tokio::io::copy(&mut payload, &mut body)
                                .await
                                .map_err(R::map_error)?;
                            if payload.limit() != 0 {
                                return Err(ErrorCode::FrameError.connection(
                                    "DATA payload ended before the declared frame length",
                                ));
                            }
                        }
                        NextFrame::Trailer(frame) => {
                            if !body_allowed {
                                return Err(ErrorCode::MessageError
                                    .stream("trailers are not allowed for this response"));
                            }
                            let fields = self.decode(&qpack, frame.payload.field_section).await?;
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
                body.error(failure);
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
            Arc, Barrier, Mutex,
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

    struct PendingIo {
        bytes: Vec<u8>,
        offset: usize,
        stops: Arc<Mutex<Vec<u64>>>,
    }

    impl AsyncRead for PendingIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset == self.bytes.len() {
                return Poll::Pending;
            }
            let count = (self.bytes.len() - self.offset).min(buf.remaining());
            buf.put_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Poll::Ready(Ok(()))
        }
    }

    impl StopSending for PendingIo {
        fn stop(&mut self, code: u64) {
            self.stops.lock().unwrap().push(code);
        }
    }

    impl TransportError for PendingIo {
        fn map_error(error: io::Error) -> Error {
            Error::from_stream_io(error)
        }
    }

    #[test]
    fn read_poll_preserves_transient_errors_and_reports_terminal_error_once() {
        struct ScriptedIo(usize);

        impl AsyncRead for ScriptedIo {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                self.0 += 1;
                match self.0 {
                    1 => Poll::Pending,
                    2 => Poll::Ready(Err(io::ErrorKind::Interrupted.into())),
                    3 => Poll::Ready(Err(io::ErrorKind::WouldBlock.into())),
                    4 => {
                        buf.put_slice(b"x");
                        Poll::Ready(Ok(()))
                    }
                    5 => Poll::Ready(Err(ErrorCode::InternalError.connection("fatal").into())),
                    _ => panic!("failed I/O must not be polled again"),
                }
            }
        }

        impl StopSending for ScriptedIo {
            fn stop(&mut self, _: u64) {}
        }

        impl TransportError for ScriptedIo {
            fn map_error(error: io::Error) -> Error {
                Error::from_stream_io(error)
            }
        }

        let reported = Arc::new(Mutex::new(Vec::new()));
        let captured = reported.clone();
        let mut stream = H3ReadStream::new(4, ScriptedIo(0), events());
        let shared = stream.state.clone();
        stream.handler = Arc::new(move |event| {
            assert!(shared.0.try_lock().is_ok(), "notify outside the state lock");
            captured.lock().unwrap().push(event);
        });
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut bytes = [0; 8];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
        assert!(matches!(
            *stream.state.0.lock().unwrap(),
            Ok(H3Stream::Polling(_, _))
        ));
        for kind in [io::ErrorKind::Interrupted, io::ErrorKind::WouldBlock] {
            let Poll::Ready(Err(error)) = Pin::new(&mut stream).poll_read(&mut cx, &mut buf) else {
                panic!("transient error must be returned");
            };
            assert_eq!(error.kind(), kind);
        }
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"x");
        assert!(reported.lock().unwrap().is_empty());
        let expected = ErrorCode::InternalError.connection("fatal");
        for _ in 0..2 {
            let Poll::Ready(Err(error)) = Pin::new(&mut stream).poll_read(&mut cx, &mut buf) else {
                panic!("terminal error must be retained");
            };
            assert_eq!(Error::from_stream_io(error), expected);
        }
        drop(stream);
        assert_eq!(reported.lock().unwrap().as_slice(), [Err(expected)]);
    }

    fn events() -> StreamEventHandler {
        Arc::new(|_| {})
    }

    #[test]
    fn stop_before_decode_registration_prevents_a_new_qpack_wait() {
        let qpack = crate::qpack::tests::qpack();
        qpack
            .with_state(|state| {
                state.decoder.on_instruction(|_| Ok(()));
                Ok(())
            })
            .unwrap();

        let event_qpack = qpack.clone();
        let stream = Arc::new(H3ReadStream::new(
            4,
            Io::default(),
            Arc::new(move |event| {
                if event.is_err() {
                    event_qpack.cancel_decode(vec![4]).unwrap();
                }
            }),
        ));
        let headers_read = Arc::new(Barrier::new(2));
        let resume_decode = Arc::new(Barrier::new(2));

        std::thread::scope(|scope| {
            let receiving = stream.clone();
            let receiving_qpack = qpack.clone();
            let receiving_headers_read = headers_read.clone();
            let receiving_resume_decode = resume_decode.clone();
            let receive = scope.spawn(move || {
                // RIC=1, Base=0, post-Base index 0: this would wait for an insert.
                let payload = Bytes::from_static(&[0x02, 0x80, 0x10]);
                let mut decoding = Box::pin(receiving.decode(&receiving_qpack, payload));
                receiving_headers_read.wait();
                receiving_resume_decode.wait();
                let mut cx = Context::from_waker(futures::task::noop_waker_ref());
                decoding.as_mut().poll(&mut cx)
            });

            headers_read.wait();
            let mut application = &*stream;
            application.stop(ErrorCode::RequestCancelled.as_u64());
            resume_decode.wait();

            let Poll::Ready(Err(error)) = receive.join().unwrap() else {
                panic!("a stopped stream must not start another QPACK wait")
            };
            assert_eq!(error.code, ErrorCode::RequestCancelled);
        });
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
        let mut stream = H3ReadStream::new(4, Io::new(wire), events());
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

        let mut stream = H3ReadStream::new(8, Io::new(vec![0, 1, b'x']), events());
        let Some(NextFrame::Data(frame)) = stream.read_next_frame(false).await.unwrap() else {
            panic!("expected DATA")
        };
        assert_eq!(frame.length.into_u64(), 1);
        let mut payload = [0];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, [b'x']);
        assert!(stream.read_next_frame(false).await.unwrap().is_none());

        let mut stream = H3ReadStream::new(12, Io::new(headers(b"trailers")), events());
        assert!(matches!(
            stream.read_next_frame(false).await.unwrap(),
            Some(NextFrame::Trailer(_))
        ));
        assert!(stream.read_next_frame(true).await.unwrap().is_none());

        let mut stream = H3ReadStream::new(14, Io::new(vec![0x21, 2, b'x', b'y']), events());
        assert!(stream.read_next_frame(true).await.unwrap().is_none());

        let mut stream = H3ReadStream::new(16, Io::new(vec![0, 0]), events());
        assert_eq!(
            stream.read_headers_frame().await.unwrap_err().code,
            ErrorCode::FrameUnexpected
        );
        let mut stream = H3ReadStream::new(20, Io::new(vec![7, 1, 0]), events());
        assert_eq!(
            stream.read_next_frame(false).await.err().unwrap().code,
            ErrorCode::FrameUnexpected
        );
        let mut stream = H3ReadStream::new(24, Io::new(vec![0]), events());
        assert_eq!(
            stream.read_next_frame(true).await.err().unwrap().code,
            ErrorCode::FrameUnexpected
        );

        let mut stream = H3ReadStream::new(28, Io::new(vec![0x21, 2, b'x']), events());
        assert_eq!(
            stream.read_next_frame(true).await.err().unwrap().code,
            ErrorCode::FrameError
        );
    }

    #[tokio::test]
    async fn read_completion_notifies_finish_once() {
        fn reject<R: StopSending>(stream: &H3ReadStream<R>) -> bool {
            let error = ErrorCode::RequestRejected.stream("request rejected by GOAWAY");
            stream
                .state
                .fail(error.clone(), |io| io.stop(error.code.as_u64()))
        }

        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut stream = H3ReadStream::new(
            0,
            Io::new(b"abc".to_vec()),
            Arc::new(move |event| {
                if event.is_ok() {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            }),
        );
        let _registered = stream.state.clone();
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
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
        let mut rejected = H3ReadStream::new(
            4,
            Io::default(),
            Arc::new(move |event| {
                if event.is_ok() {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            }),
        );
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
        let stream = H3ReadStream::new(
            0,
            Io::default(),
            Arc::new(move |event| {
                if event.is_ok() {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            }),
        );
        let result: crate::Result<crate::Request<crate::R>> =
            stream.read_request(crate::qpack::tests::qpack()).await;
        let Err(error) = result else {
            panic!("a message without HEADERS must fail")
        };
        assert_eq!(error.code, ErrorCode::RequestIncomplete);
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelling_request_body_stops_the_pending_transport_read() {
        let qpack = crate::qpack::tests::qpack();
        let field = |name: &'static [u8], value: &'static [u8]| crate::qpack::Field {
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
            never_index: false,
        };
        let fields = vec![
            field(b":method", b"GET"),
            field(b":scheme", b"https"),
            field(b":authority", b"example.com"),
            field(b":path", b"/"),
        ];
        let field_section = qpack.encode(0, fields).unwrap();
        let mut wire = Vec::new();
        wire.put_frame(
            &Frame::new(frame::Headers { field_section })
                .expect("small literal headers fit in one frame"),
        );
        let stops = Arc::new(Mutex::new(Vec::new()));
        let stream = H3ReadStream::new(
            0,
            PendingIo {
                bytes: wire,
                offset: 0,
                stops: stops.clone(),
            },
            events(),
        );
        let mut request = stream.read_request(qpack).await.unwrap();
        request.stop(ErrorCode::RequestCancelled.as_u64());
        assert_eq!(
            &*stops.lock().unwrap(),
            &[ErrorCode::RequestCancelled.as_u64()]
        );
        assert_eq!(
            Error::from(request.read(&mut [0]).await.unwrap_err()).code,
            ErrorCode::RequestCancelled
        );
    }
}
