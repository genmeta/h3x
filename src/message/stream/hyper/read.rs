use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{StreamExt, stream};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Empty, StreamBody};

use super::{
    MessageStreamError, ReadStream,
    upgrade::{RemainStream, TakeoverSlot},
};
use crate::error::H3MessageError;

pin_project_lite::pin_project! {
    #[project = EitherProj]
    pub enum Either<L, R> {
        Left { #[pin] body: L },
        Right { #[pin] body: R }
    }
}

impl<L, R> Either<L, R> {
    pub fn left(body: L) -> Self {
        Self::Left { body }
    }

    pub fn right(body: R) -> Self {
        Self::Right { body }
    }
}

impl<L: Body, R: Body<Data = L::Data, Error = L::Error>> Body for Either<L, R> {
    type Data = L::Data;
    type Error = L::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            EitherProj::Left { body } => body.poll_frame(cx),
            EitherProj::Right { body } => body.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Either::Left { body } => body.is_end_stream(),
            Either::Right { body } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Either::Left { body } => body.size_hint(),
            Either::Right { body } => body.size_hint(),
        }
    }
}

impl ReadStream {
    pub async fn read_hyper_request_parts(
        &mut self,
    ) -> Result<http::request::Parts, MessageStreamError> {
        let Some(field_section) = self.read_header().await? else {
            let error = self
                .handle_stream_error(H3MessageError::MissingHeaderSection.into())
                .await;
            return Err(error.into());
        };
        match http::request::Parts::try_from(field_section) {
            Ok(parts) => Ok(parts),
            Err(error) => {
                let error = self.handle_stream_error(error.into()).await;
                Err(error.into())
            }
        }
    }

    pub async fn read_hyper_response_parts(
        &mut self,
    ) -> Result<http::response::Parts, MessageStreamError> {
        let Some(field_section) = self.read_header().await? else {
            let error = self
                .handle_stream_error(H3MessageError::MissingHeaderSection.into())
                .await;
            return Err(error.into());
        };
        match http::response::Parts::try_from(field_section) {
            Ok(parts) => Ok(parts),
            Err(error) => {
                let error = self.handle_stream_error(error.into()).await;
                Err(error.into())
            }
        }
    }

    pub async fn read_hyper_frame(&mut self) -> Result<Option<Frame<Bytes>>, MessageStreamError> {
        if let Some(data) = self.read_data_chunk().await? {
            return Ok(Some(Frame::data(data)));
        }

        let Some(field_section) = self.read_header().await? else {
            return Ok(None);
        };

        if !field_section.is_trailer() {
            let error = self
                .handle_stream_error(H3MessageError::UnexpectedHeadersInBody.into())
                .await;
            return Err(error.into());
        }

        Ok(Some(Frame::trailers(field_section.into_header_map())))
    }

    pub fn as_hyper_body(&mut self) -> impl Body<Data = Bytes, Error = MessageStreamError> + Send {
        StreamBody::new(
            stream::unfold(self, async |stream| {
                let frame = stream.read_hyper_frame().await.transpose()?;
                Some((frame, stream))
            })
            .fuse(),
        )
    }

    pub fn into_hyper_body(self) -> impl Body<Data = Bytes, Error = MessageStreamError> + Send {
        StreamBody::new(
            stream::unfold(self, async |mut stream| {
                let frame = stream.read_hyper_frame().await.transpose()?;
                Some((frame, stream))
            })
            .fuse(),
        )
    }

    pub async fn into_hyper_request(
        mut self,
    ) -> Result<
        http::Request<impl Body<Data = Bytes, Error = MessageStreamError> + Send>,
        MessageStreamError,
    > {
        let mut parts = self.read_hyper_request_parts().await?;
        if parts.method == http::Method::CONNECT {
            parts
                .extensions
                .insert(TakeoverSlot::new(RemainStream::immediately(self)));
            let body = Either::right(Empty::new().map_err(|n| match n {}));
            Ok(http::Request::from_parts(parts, body))
        } else {
            let body = Either::left(self.into_hyper_body());
            Ok(http::Request::from_parts(parts, body))
        }
    }

    pub async fn into_hyper_response(
        mut self,
    ) -> Result<
        http::Response<impl Body<Data = Bytes, Error = MessageStreamError> + Send>,
        MessageStreamError,
    > {
        let mut parts = self.read_hyper_response_parts().await?;
        match parts.status.is_informational() {
            true => {
                parts.extensions.insert(RemainStream::immediately(self));
                let body = Either::right(Empty::new().map_err(|n| match n {}));
                Ok(http::Response::from_parts(parts, body))
            }
            false => {
                // no remain
                let body = self.into_hyper_body();
                Ok(http::Response::from_parts(parts, Either::left(body)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, pin::Pin, sync::Arc};

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream};
    use http_body::Body;
    use http_body_util::{BodyExt, Empty, Full, StreamBody};

    use super::*;
    use crate::{
        codec::{SinkWriter, StreamReader},
        connection::{ConnectionState, StreamError, tests::MockConnection},
        dhttp::{protocol::DHttpProtocol, settings::Settings},
        message::{
            stream::{WriteStream, guard},
            test::read_stream_for_test,
        },
        protocol::Protocols,
        qpack::{
            decoder::DecoderInstruction,
            encoder::EncoderInstruction,
            field::hyper::header_map_to_field_lines,
            protocol::{QPackDecoder, QPackEncoder},
        },
        quic,
        varint::VarInt,
    };

    fn qpack_decoder_sink() -> Pin<Box<dyn Sink<DecoderInstruction, Error = StreamError> + Send>> {
        Box::pin(futures::sink::drain::<DecoderInstruction>().sink_map_err(|never| match never {}))
    }

    fn qpack_decoder_stream()
    -> Pin<Box<dyn Stream<Item = Result<EncoderInstruction, StreamError>> + Send>> {
        Box::pin(futures::stream::empty::<
            Result<EncoderInstruction, StreamError>,
        >())
    }

    fn qpack_encoder_sink() -> Pin<Box<dyn Sink<EncoderInstruction, Error = StreamError> + Send>> {
        Box::pin(futures::sink::drain::<EncoderInstruction>().sink_map_err(|never| match never {}))
    }

    fn qpack_encoder_stream()
    -> Pin<Box<dyn Stream<Item = Result<DecoderInstruction, StreamError>> + Send>> {
        Box::pin(futures::stream::empty::<
            Result<DecoderInstruction, StreamError>,
        >())
    }

    fn stream_pair(stream_id: VarInt) -> (ReadStream, WriteStream) {
        let erased: Arc<dyn quic::DynConnection> = Arc::new(MockConnection::new());

        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased.clone()));
        let state = ConnectionState::new_for_test(erased, Arc::new(protocols));

        let (reader, writer) = quic::test::mock_stream_pair_with_capacity(stream_id, 64);
        let reader = StreamReader::new(guard::GuardedQuicReader::new(
            Box::pin(reader) as crate::codec::BoxReadStream
        ));
        let writer = SinkWriter::new(guard::GuardedQuicWriter::new(
            Box::pin(writer) as crate::codec::BoxWriteStream
        ));

        (
            ReadStream::new(
                reader,
                Arc::new(QPackDecoder::new(
                    Arc::new(Settings::default()),
                    qpack_decoder_sink(),
                    qpack_decoder_stream(),
                )),
                state.clone(),
            ),
            WriteStream::new(
                writer,
                Arc::new(QPackEncoder::new(
                    Arc::new(Settings::default()),
                    qpack_encoder_sink(),
                    qpack_encoder_stream(),
                )),
                state,
            ),
        )
    }

    async fn next_body_frame<B: Body>(
        mut body: Pin<&mut B>,
    ) -> Option<Result<Frame<B::Data>, B::Error>> {
        futures::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await
    }

    fn request_parts(method: http::Method, uri: &'static str) -> http::request::Parts {
        let request = http::Request::builder()
            .method(method)
            .uri(uri)
            .header("x-test", "present")
            .body(())
            .expect("request");
        request.into_parts().0
    }

    fn response_parts(status: http::StatusCode) -> http::response::Parts {
        let response = http::Response::builder()
            .status(status)
            .header("x-test", "present")
            .body(())
            .expect("response");
        response.into_parts().0
    }

    #[tokio::test]
    async fn either_left_and_right_delegate_body_methods() {
        let mut left =
            Either::<Full<Bytes>, Empty<Bytes>>::left(Full::new(Bytes::from_static(b"left")));
        assert!(!left.is_end_stream());
        assert_eq!(left.size_hint().lower(), 4);
        let frame = left.frame().await.expect("frame").expect("ok frame");
        assert_eq!(
            frame.into_data().expect("data"),
            Bytes::from_static(b"left")
        );
        assert!(left.is_end_stream());

        let mut right =
            Either::<Empty<Bytes>, Full<Bytes>>::right(Full::new(Bytes::from_static(b"right")));
        assert!(!right.is_end_stream());
        assert_eq!(right.size_hint().lower(), 5);
        let frame = right.frame().await.expect("frame").expect("ok frame");
        assert_eq!(
            frame.into_data().expect("data"),
            Bytes::from_static(b"right")
        );
        assert!(right.is_end_stream());
    }

    #[tokio::test]
    async fn read_hyper_request_parts_errors_when_header_missing() {
        let mut stream = read_stream_for_test(VarInt::from_u32(0));

        let error = stream
            .read_hyper_request_parts()
            .await
            .expect_err("missing header should be rejected");

        assert!(matches!(error, MessageStreamError::Quic { .. }));
    }

    #[tokio::test]
    async fn read_hyper_response_parts_errors_when_header_missing() {
        let mut stream = read_stream_for_test(VarInt::from_u32(0));

        let error = stream
            .read_hyper_response_parts()
            .await
            .expect_err("missing header should be rejected");

        assert!(matches!(error, MessageStreamError::Quic { .. }));
    }

    #[tokio::test]
    async fn read_hyper_request_parts_rejects_response_pseudo_headers() {
        let (mut reader, mut writer) = stream_pair(VarInt::from_u32(0));
        writer
            .send_hyper_response_parts(response_parts(http::StatusCode::OK))
            .await
            .expect("response header should be written");

        let error = reader
            .read_hyper_request_parts()
            .await
            .expect_err("response pseudo headers are malformed for requests");

        assert!(matches!(error, MessageStreamError::Quic { .. }));
    }

    #[tokio::test]
    async fn read_hyper_response_parts_rejects_request_pseudo_headers() {
        let (mut reader, mut writer) = stream_pair(VarInt::from_u32(0));
        writer
            .send_hyper_request_parts(request_parts(http::Method::GET, "https://example.test/"))
            .await
            .expect("request header should be written");

        let error = reader
            .read_hyper_response_parts()
            .await
            .expect_err("request pseudo headers are malformed for responses");

        assert!(matches!(error, MessageStreamError::Quic { .. }));
    }

    #[tokio::test]
    async fn read_hyper_frame_returns_none_on_empty_stream() {
        let mut stream = read_stream_for_test(VarInt::from_u32(0));

        let frame = stream.read_hyper_frame().await.expect("empty stream");

        assert!(frame.is_none());
    }

    #[tokio::test]
    async fn as_hyper_body_and_into_hyper_body_end_on_empty_stream() {
        let mut borrowed = read_stream_for_test(VarInt::from_u32(0));
        let body = borrowed.as_hyper_body();
        let mut body = std::pin::pin!(body);
        assert!(next_body_frame(body.as_mut()).await.is_none());

        let owned = read_stream_for_test(VarInt::from_u32(0));
        let body = owned.into_hyper_body();
        let mut body = std::pin::pin!(body);
        assert!(next_body_frame(body.as_mut()).await.is_none());
    }

    #[tokio::test]
    async fn as_hyper_body_yields_data_frames() {
        let (mut reader, mut writer) = stream_pair(VarInt::from_u32(0));
        writer
            .send_data(Bytes::from_static(b"borrowed-body"))
            .await
            .expect("data should be written");
        writer.close().await.expect("stream should close cleanly");

        let body = reader.as_hyper_body();
        let mut body = std::pin::pin!(body);
        let frame = next_body_frame(body.as_mut())
            .await
            .expect("body frame")
            .expect("data frame should decode");
        assert_eq!(
            frame.into_data().expect("data"),
            Bytes::from_static(b"borrowed-body")
        );
        assert!(next_body_frame(body.as_mut()).await.is_none());
    }

    #[tokio::test]
    async fn into_hyper_body_yields_data_frames() {
        let (reader, mut writer) = stream_pair(VarInt::from_u32(0));
        writer
            .send_data(Bytes::from_static(b"owned-body"))
            .await
            .expect("data should be written");
        writer.close().await.expect("stream should close cleanly");

        let body = reader.into_hyper_body();
        let mut body = std::pin::pin!(body);
        let frame = next_body_frame(body.as_mut())
            .await
            .expect("body frame")
            .expect("data frame should decode");
        assert_eq!(
            frame.into_data().expect("data"),
            Bytes::from_static(b"owned-body")
        );
        assert!(next_body_frame(body.as_mut()).await.is_none());
    }

    #[tokio::test]
    async fn read_hyper_request_and_body_from_written_request() {
        let (reader, mut writer) = stream_pair(VarInt::from_u32(0));
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.test/upload")
            .header("x-test", "present")
            .body(Full::new(Bytes::from_static(b"payload")))
            .expect("request");

        writer
            .send_hyper_request(request)
            .await
            .expect("request sent");
        drop(writer);

        let request = reader.into_hyper_request().await.expect("request decoded");
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri(), "https://example.test/upload");
        assert_eq!(request.headers()["x-test"], "present");

        let (_parts, body) = request.into_parts();
        let mut body = std::pin::pin!(body);
        let frame = next_body_frame(body.as_mut())
            .await
            .expect("body frame")
            .expect("ok frame");
        assert_eq!(
            frame.into_data().expect("data"),
            Bytes::from_static(b"payload")
        );
    }

    #[tokio::test]
    async fn read_hyper_response_and_body_from_written_response() {
        let (reader, mut writer) = stream_pair(VarInt::from_u32(0));
        let response = http::Response::builder()
            .status(http::StatusCode::CREATED)
            .header("x-test", "present")
            .body(Full::new(Bytes::from_static(b"response")))
            .expect("response");

        writer
            .send_hyper_response(response)
            .await
            .expect("response sent");
        drop(writer);

        let response = reader
            .into_hyper_response()
            .await
            .expect("response decoded");
        assert_eq!(response.status(), http::StatusCode::CREATED);
        assert_eq!(response.headers()["x-test"], "present");

        let (_parts, body) = response.into_parts();
        let mut body = std::pin::pin!(body);
        let frame = next_body_frame(body.as_mut())
            .await
            .expect("body frame")
            .expect("ok frame");
        assert_eq!(
            frame.into_data().expect("data"),
            Bytes::from_static(b"response")
        );
    }

    #[tokio::test]
    async fn read_hyper_body_reads_data_and_trailers() {
        let (mut reader, mut writer) = stream_pair(VarInt::from_u32(0));
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trailer", http::HeaderValue::from_static("done"));
        let body = StreamBody::new(futures::stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"data"))),
            Ok(Frame::trailers(trailers)),
        ]));

        writer.send_hyper_body(body).await.expect("body sent");

        let frame = reader
            .read_hyper_frame()
            .await
            .expect("data frame")
            .expect("data frame present");
        assert_eq!(
            frame.into_data().expect("data"),
            Bytes::from_static(b"data")
        );

        let frame = reader
            .read_hyper_frame()
            .await
            .expect("trailer frame")
            .expect("trailer frame present");
        let trailers = frame.into_trailers().expect("trailers");
        assert_eq!(trailers["x-trailer"], "done");
    }

    #[tokio::test]
    async fn read_hyper_frame_rejects_non_trailer_headers_in_body() {
        let (mut reader, mut writer) = stream_pair(VarInt::from_u32(0));

        writer
            .send_hyper_response_parts(response_parts(http::StatusCode::OK))
            .await
            .expect("response header sent");

        let error = reader
            .read_hyper_frame()
            .await
            .expect_err("header in body should be rejected");

        assert!(matches!(error, MessageStreamError::Quic { .. }));
    }

    #[tokio::test]
    async fn into_hyper_request_connect_stores_takeover_slot() {
        let (reader, mut writer) = stream_pair(VarInt::from_u32(0));

        writer
            .send_hyper_request_parts(request_parts(http::Method::CONNECT, "example.test:443"))
            .await
            .expect("connect header sent");

        let request = reader
            .into_hyper_request()
            .await
            .expect("connect request decoded");

        assert_eq!(request.method(), http::Method::CONNECT);
        assert!(
            request
                .extensions()
                .get::<TakeoverSlot<ReadStream>>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn into_hyper_response_informational_stores_remain_stream() {
        let (reader, mut writer) = stream_pair(VarInt::from_u32(0));

        writer
            .send_hyper_response_parts(response_parts(http::StatusCode::EARLY_HINTS))
            .await
            .expect("informational response sent");

        let response = reader
            .into_hyper_response()
            .await
            .expect("informational response decoded");

        assert_eq!(response.status(), http::StatusCode::EARLY_HINTS);
        assert!(
            response
                .extensions()
                .get::<RemainStream<ReadStream>>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn read_hyper_frame_reads_trailer_header_without_data() {
        let (mut reader, mut writer) = stream_pair(VarInt::from_u32(0));
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trailer", http::HeaderValue::from_static("only"));

        writer
            .write_header(header_map_to_field_lines(trailers))
            .await
            .expect("trailer header sent");

        let frame = reader
            .read_hyper_frame()
            .await
            .expect("trailer frame")
            .expect("trailer frame present");
        let trailers = frame.into_trailers().expect("trailers");
        assert_eq!(trailers["x-trailer"], "only");
    }
}
