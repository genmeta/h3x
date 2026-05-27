use std::{convert::Infallible, pin::pin};

use http_body::Body;
use http_body_util::BodyExt;
use snafu::{ResultExt, Snafu};

use super::{MessageStreamError, WriteStream};
use crate::{
    error::H3StreamError,
    qpack::field::{
        MalformedHeaderSection,
        hyper::{
            header_map_to_field_lines, hyper_response_parts_to_field_lines,
            validated_hyper_request_parts_to_field_lines,
        },
    },
    quic::CancelStreamExt,
};

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum SendMessageError<E: std::error::Error + 'static> {
    #[snafu(display("failed to send message on stream"))]
    Stream { source: MessageStreamError },
    #[snafu(display("request pseudo-header section is malformed"))]
    MalformedHeader { source: MalformedHeaderSection },
    #[snafu(display("failed to read body frame"))]
    Body { source: E },
}

impl<E: std::error::Error + 'static> SendMessageError<E> {
    pub fn map_body_error<E1: std::error::Error + 'static>(
        self,
        f: impl FnOnce(E) -> E1,
    ) -> SendMessageError<E1> {
        match self {
            SendMessageError::Stream { source } => SendMessageError::Stream { source },
            SendMessageError::MalformedHeader { source } => {
                SendMessageError::MalformedHeader { source }
            }
            SendMessageError::Body { source } => SendMessageError::Body { source: f(source) },
        }
    }
}

impl WriteStream {
    pub(crate) async fn send_hyper_body<B: Body>(
        &mut self,
        body: B,
    ) -> Result<(), SendMessageError<B::Error>>
    where
        B::Data: Send,
        B::Error: std::error::Error + 'static,
    {
        let mut body = pin!(body);
        while let Some(frame) = body.frame().await {
            let frame = frame.context(send_message_error::BodySnafu)?;
            let frame = match frame.into_data() {
                Ok(data) => {
                    self.write_data(data)
                        .await
                        .context(send_message_error::StreamSnafu)?;
                    continue;
                }
                Err(frame) => frame,
            };
            let frame = match frame.into_trailers() {
                Ok(trailers) => {
                    self.write_header(header_map_to_field_lines(trailers))
                        .await
                        .context(send_message_error::StreamSnafu)?;
                    break;
                }
                Err(frame) => frame,
            };

            tracing::warn!("ignore unknown http body frame");
            _ = frame;
        }
        Ok(())
    }

    pub async fn send_hyper_request_parts(
        &mut self,
        parts: http::request::Parts,
    ) -> Result<(), SendMessageError<Infallible>> {
        let fields = match validated_hyper_request_parts_to_field_lines(parts) {
            Ok(fields) => fields,
            Err(source) => {
                _ = self.stream.cancel(source.code().into_inner()).await;
                return Err(SendMessageError::MalformedHeader { source });
            }
        };
        self.write_header(fields)
            .await
            .context(send_message_error::StreamSnafu)
    }

    pub async fn send_hyper_request<B: Body>(
        &mut self,
        request: http::Request<B>,
    ) -> Result<(), SendMessageError<B::Error>>
    where
        B::Data: Send,
        B::Error: std::error::Error + 'static,
    {
        let (parts, body) = request.into_parts();
        let fields = match validated_hyper_request_parts_to_field_lines(parts) {
            Ok(fields) => fields,
            Err(source) => {
                _ = self.stream.cancel(source.code().into_inner()).await;
                return Err(SendMessageError::MalformedHeader { source });
            }
        };
        self.write_header(fields)
            .await
            .context(send_message_error::StreamSnafu)?;
        self.send_hyper_body(body).await
    }

    pub async fn send_hyper_response_parts(
        &mut self,
        parts: http::response::Parts,
    ) -> Result<(), MessageStreamError> {
        self.write_header(hyper_response_parts_to_field_lines(parts))
            .await
    }

    pub async fn send_hyper_response<B: Body>(
        &mut self,
        response: http::Response<B>,
    ) -> Result<(), SendMessageError<B::Error>>
    where
        B::Data: Send,
        B::Error: std::error::Error + 'static,
    {
        let (parts, body) = response.into_parts();
        self.write_header(hyper_response_parts_to_field_lines(parts))
            .await
            .context(send_message_error::StreamSnafu)?;
        self.send_hyper_body(body).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        fmt,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream, stream};
    use http_body::Frame;
    use http_body_util::{Empty, Full, StreamBody};

    use super::*;
    use crate::{
        codec::SinkWriter,
        message::{stream::guard, test::write_stream_for_test},
        qpack::protocol::QPackEncoder,
        quic,
        varint::VarInt,
    };

    #[derive(Debug)]
    struct TestBodyError;

    impl fmt::Display for TestBodyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("test body error")
        }
    }

    impl std::error::Error for TestBodyError {}

    #[derive(Debug)]
    struct MappedBodyError;

    impl fmt::Display for MappedBodyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("mapped body error")
        }
    }

    impl std::error::Error for MappedBodyError {}

    fn request_parts(uri: &'static str) -> http::request::Parts {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(http::Uri::try_from(uri).expect("uri"))
            .header("x-test", "present")
            .body(())
            .expect("request");
        request.into_parts().0
    }

    fn cancel_observing_write_stream(stream_id: VarInt) -> (WriteStream, Arc<Mutex<Vec<VarInt>>>) {
        struct TestWriter {
            stream_id: VarInt,
            cancelled: Arc<Mutex<Vec<VarInt>>>,
        }
        impl quic::GetStreamId for TestWriter {
            fn poll_stream_id(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<VarInt, quic::StreamError>> {
                Poll::Ready(Ok(self.get_mut().stream_id))
            }
        }
        impl quic::CancelStream for TestWriter {
            fn poll_cancel(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                code: VarInt,
            ) -> Poll<Result<(), quic::StreamError>> {
                self.cancelled.lock().expect("cancel lock").push(code);
                Poll::Ready(Ok(()))
            }
        }
        impl Sink<Bytes> for TestWriter {
            type Error = quic::StreamError;

            fn poll_ready(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
                Ok(())
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn poll_close(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
        }

        fn enc_sink() -> Pin<
            Box<
                dyn Sink<
                        crate::qpack::encoder::EncoderInstruction,
                        Error = crate::connection::StreamError,
                    > + Send,
            >,
        > {
            Box::pin(
                futures::sink::drain::<crate::qpack::encoder::EncoderInstruction>()
                    .sink_map_err(|never| match never {}),
            )
        }
        fn enc_stream() -> Pin<
            Box<
                dyn Stream<
                        Item = Result<
                            crate::qpack::decoder::DecoderInstruction,
                            crate::connection::StreamError,
                        >,
                    > + Send,
            >,
        > {
            Box::pin(futures::stream::empty::<
                Result<crate::qpack::decoder::DecoderInstruction, crate::connection::StreamError>,
            >())
        }

        let mock = Arc::new(crate::connection::tests::MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = mock;

        let mut protocols = crate::protocol::Protocols::new();
        protocols.insert(crate::dhttp::protocol::DHttpProtocol::new_for_test(
            erased.clone(),
        ));
        let state = crate::connection::ConnectionState::new_for_test(erased, Arc::new(protocols));

        let cancelled = Arc::new(Mutex::new(Vec::new()));
        let writer = SinkWriter::new(guard::GuardedQuicWriter::new(Box::pin(TestWriter {
            stream_id,
            cancelled: cancelled.clone(),
        })
            as crate::codec::BoxWriteStream));

        let stream = WriteStream::new(
            writer,
            Arc::new(QPackEncoder::new(
                Arc::new(crate::dhttp::settings::Settings::default()),
                enc_sink(),
                enc_stream(),
            )),
            state,
        );

        (stream, cancelled)
    }

    #[tokio::test]
    async fn send_hyper_request_parts_accepts_valid_parts() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));

        stream
            .send_hyper_request_parts(request_parts("https://example.test/path"))
            .await
            .expect("request parts sent");
    }

    #[tokio::test]
    async fn send_hyper_request_parts_rejects_malformed_parts() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));

        let error = stream
            .send_hyper_request_parts(request_parts("example.test"))
            .await
            .expect_err("authority-only GET is malformed");

        assert!(matches!(error, SendMessageError::MalformedHeader { .. }));
    }

    #[tokio::test]
    async fn send_hyper_request_writes_header_and_body() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(http::Uri::from_static("https://example.test/upload"))
            .body(Full::new(Bytes::from_static(b"payload")))
            .expect("request");

        stream
            .send_hyper_request(request)
            .await
            .expect("request sent");
    }

    #[tokio::test]
    async fn send_hyper_body_writes_data_and_trailers() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trailer", http::HeaderValue::from_static("done"));
        let body = StreamBody::new(stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"data"))),
            Ok(Frame::trailers(trailers)),
        ]));

        stream.send_hyper_body(body).await.expect("body sent");
    }

    #[tokio::test]
    async fn send_hyper_body_stops_after_trailers() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trailer", http::HeaderValue::from_static("done"));
        let body = StreamBody::new(stream::iter([
            Ok::<_, TestBodyError>(Frame::<Bytes>::trailers(trailers)),
            Err(TestBodyError),
        ]));

        stream
            .send_hyper_body(body)
            .await
            .expect("body stops after trailers");
    }

    #[tokio::test]
    async fn send_hyper_body_maps_body_errors() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));
        let body = StreamBody::new(stream::iter([Err::<Frame<Bytes>, _>(TestBodyError)]));

        let error = stream
            .send_hyper_body(body)
            .await
            .expect_err("body error should be returned");

        assert!(matches!(error, SendMessageError::Body { .. }));
    }

    #[tokio::test]
    async fn send_hyper_request_accepts_empty_body() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(http::Uri::from_static("https://example.test/"))
            .body(Empty::<Bytes>::new())
            .expect("request");

        stream
            .send_hyper_request(request)
            .await
            .expect("empty request sent");
    }

    #[tokio::test]
    async fn send_hyper_response_parts_and_response_succeed() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));
        let response = http::Response::builder()
            .status(http::StatusCode::CREATED)
            .header("x-test", "present")
            .body(())
            .expect("response");
        let (parts, ()) = response.into_parts();

        stream
            .send_hyper_response_parts(parts)
            .await
            .expect("response parts sent");

        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Full::new(Bytes::from_static(b"response")))
            .expect("response");

        stream
            .send_hyper_response(response)
            .await
            .expect("response sent");
    }

    #[tokio::test]
    async fn send_hyper_response_accepts_empty_body() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));
        let response = http::Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .body(Empty::<Bytes>::new())
            .expect("response");

        stream
            .send_hyper_response(response)
            .await
            .expect("empty response sent");
    }

    #[tokio::test]
    async fn send_hyper_response_maps_body_errors() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));
        let body = StreamBody::new(stream::iter([Err::<Frame<Bytes>, _>(TestBodyError)]));
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(body)
            .expect("response");

        let error = stream
            .send_hyper_response(response)
            .await
            .expect_err("response body error should be returned");

        assert!(matches!(
            error,
            SendMessageError::Body {
                source: TestBodyError
            }
        ));
    }

    #[tokio::test]
    async fn send_hyper_request_parts_cancels_stream_on_malformed_parts() {
        let (mut stream, cancelled) = cancel_observing_write_stream(VarInt::from_u32(0));
        let expected_code =
            validated_hyper_request_parts_to_field_lines(request_parts("example.test"))
                .expect_err("authority-only GET is malformed")
                .code()
                .into_inner();

        let error = stream
            .send_hyper_request_parts(request_parts("example.test"))
            .await
            .expect_err("authority-only GET is malformed");

        assert!(matches!(error, SendMessageError::MalformedHeader { .. }));
        assert_eq!(*cancelled.lock().expect("cancel lock"), vec![expected_code]);
    }

    #[test]
    fn map_body_error_preserves_non_body_variants() {
        let stream_error = SendMessageError::<TestBodyError>::Stream {
            source: MessageStreamError::MalformedOutgoingMessage,
        }
        .map_body_error(|_| MappedBodyError);
        assert!(matches!(stream_error, SendMessageError::Stream { .. }));

        let malformed = SendMessageError::<Infallible>::MalformedHeader {
            source: validated_hyper_request_parts_to_field_lines(request_parts("example.test"))
                .expect_err("authority-only GET is malformed"),
        }
        .map_body_error(|never| match never {});
        assert!(matches!(
            malformed,
            SendMessageError::MalformedHeader { .. }
        ));
    }

    #[test]
    fn map_body_error_maps_body_variant() {
        let error = SendMessageError::Body {
            source: TestBodyError,
        }
        .map_body_error(|_| MappedBodyError);

        assert!(matches!(error, SendMessageError::Body { .. }));
    }
}
