use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{SinkExt, StreamExt, TryStream, sink};

use crate::{
    codec::{DecodeExt, FixedLengthReader, StreamDecodeError, StreamReader},
    connection::StreamError,
    dhttp::frame::Frame,
    error::H3FrameDecodeError,
    quic::{self, GetStreamId, StopStream},
    varint::VarInt,
};

pin_project_lite::pin_project! {
    pub struct FrameStream<S: ?Sized> {
        // frame: Option<Result<Frame<FixedLengthReader<&'this mut StreamReader<S>>>, Error>>,
        frame: Option<Result<Frame<()>, StreamError>>,
        #[pin]
        stream: FixedLengthReader<StreamReader<S>>,
    }
}

pub type ReadableFrame<'s, S> = Frame<Pin<&'s mut FixedLengthReader<StreamReader<S>>>>;

impl<S: ?Sized + Send> FrameStream<S>
where
    S: TryStream<Ok = Bytes, Error = quic::StreamError>,
{
    pub const fn new(stream: StreamReader<S>) -> Self
    where
        S: Sized,
    {
        Self {
            stream: FixedLengthReader::new(stream, 0),
            frame: None,
        }
    }

    fn project_stream_mut(self: Pin<&mut Self>) -> Pin<&mut StreamReader<S>> {
        self.project().stream.project_stream_mut()
    }

    pub(crate) fn inner_mut(&mut self) -> &mut S
    where
        S: Sized,
    {
        self.stream.stream_mut().stream_mut()
    }

    pub fn frame<'s>(self: Pin<&'s mut Self>) -> Option<Result<ReadableFrame<'s, S>, StreamError>> {
        match self.frame.as_ref()? {
            Ok(frame) => Some(Ok(Frame {
                r#type: frame.r#type,
                length: frame.length,
                payload: self.project().stream,
            })),
            Err(error) => Some(Err(error.clone())),
        }
    }

    pub async fn consume_current_frame(mut self: Pin<&mut Self>) -> Result<(), StreamError> {
        let map_decode_stream_error = |error: StreamDecodeError| {
            error.into_stream_error(|decode_error| {
                H3FrameDecodeError {
                    source: decode_error,
                }
                .into()
            })
        };

        match self.as_mut().frame() {
            Some(Ok(mut frame)) => {
                let mut drain = sink::drain().sink_map_err(|never| match never {});
                let result = (&mut frame).forward(&mut drain).await;
                if let Err(error) = result.map_err(map_decode_stream_error) {
                    *self.project().frame = Some(Err(error.clone()));
                    return Err(error);
                }
                *self.project().frame = None;
                Ok(())
            }
            Some(Err(error)) => Err(error.clone()),
            None => Ok(()),
        }
    }

    pub async fn decode_next_frame(mut self: Pin<&mut Self>) {
        let try_decode_next_frame = async {
            self.as_mut().consume_current_frame().await?;
            let mut stream = self.as_mut().project_stream_mut();
            if !stream.as_mut().has_remaining().await? {
                return Ok(None);
            }

            let convert_decode_varint_error = |error: io::Error| {
                StreamDecodeError::from(error).into_stream_error(|decode_error| {
                    H3FrameDecodeError {
                        source: decode_error,
                    }
                    .into()
                })
            };
            let r#type =
                (stream.decode_one::<VarInt>().await).map_err(convert_decode_varint_error)?;
            let length =
                (stream.decode_one::<VarInt>().await).map_err(convert_decode_varint_error)?;
            Ok(Some(Frame {
                r#type,
                length,
                payload: (),
            }))
        };

        match try_decode_next_frame.await {
            Ok(Some(frame)) => {
                let project = self.project();
                project.stream.renew(frame.length.into_inner());
                *project.frame = Some(Ok(frame));
            }
            Ok(None) => *self.project().frame = None,
            Err(error) => *self.project().frame = Some(Err(error)),
        }
    }

    pub async fn next_frame(
        mut self: Pin<&mut Self>,
    ) -> Option<Result<ReadableFrame<'_, S>, StreamError>> {
        self.as_mut().decode_next_frame().await;
        self.frame()
    }

    pub async fn decode_next_unreserved_frame(mut self: Pin<&mut Self>) {
        loop {
            match self.as_mut().next_frame().await {
                Some(Ok(frame)) if frame.is_reserved_frame() => continue,
                _decoded => break,
            }
        }
    }

    pub async fn next_unreserved_frame(
        mut self: Pin<&mut Self>,
    ) -> Option<Result<ReadableFrame<'_, S>, StreamError>> {
        self.as_mut().decode_next_unreserved_frame().await;
        self.frame()
    }
}

impl<S: GetStreamId + ?Sized> GetStreamId for FrameStream<S> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.project().stream.poll_stream_id(cx)
    }
}

impl<S: StopStream + ?Sized> StopStream for FrameStream<S> {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.project().stream.poll_stop(cx, code)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{SinkExt, Stream, StreamExt, future::poll_fn, stream};
    use tokio::io::AsyncReadExt;

    use super::FrameStream;
    use crate::{
        codec::{EncodeExt, StreamReader},
        connection::{self, StreamError},
        dhttp::frame::Frame,
        error::Code,
        quic,
        quic::{GetStreamId, StopStream},
        varint::VarInt,
    };

    #[derive(Debug)]
    struct MockStream {
        stream_id: VarInt,
        stop_code: Arc<Mutex<Option<VarInt>>>,
        items: std::vec::IntoIter<Result<Bytes, quic::StreamError>>,
    }

    impl MockStream {
        fn from_iter(stream_id: VarInt, items: Vec<Result<Bytes, quic::StreamError>>) -> Self {
            Self {
                stream_id,
                stop_code: Arc::new(Mutex::new(None)),
                items: items.into_iter(),
            }
        }
    }

    impl futures::Stream for MockStream {
        type Item = std::result::Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.get_mut().items.next())
        }
    }

    impl quic::GetStreamId for MockStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::StopStream for MockStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            *self.stop_code.lock().expect("stop_code lock poisoned") = Some(code);
            Poll::Ready(Ok(()))
        }
    }

    fn to_pre_byte_stream(
        data: impl IntoIterator<Item = u8>,
    ) -> impl Stream<Item = Result<Bytes, quic::StreamError>> {
        stream::iter(data.into_iter().map(|byte| Ok(Bytes::from(vec![byte]))))
    }

    fn expect_h3_frame_decode_error(error: StreamError) {
        match error {
            StreamError::Connection {
                source: connection::ConnectionError::H3 { source, .. },
            } => {
                assert_eq!(source.code(), Code::H3_FRAME_ERROR);
            }
            other => panic!("expected h3 frame decode error, got {other:?}"),
        }
    }

    fn channel() -> (
        impl futures::Sink<Bytes, Error = quic::StreamError>,
        impl Stream<Item = Result<Bytes, quic::StreamError>>,
    ) {
        let (sink, stream) = futures::channel::mpsc::channel(8);
        (sink.sink_map_err(|_e| unreachable!()), stream.map(Ok))
    }

    #[tokio::test]
    async fn frame_reads_next_frame_payload_and_advances() {
        let stream = StreamReader::new(to_pre_byte_stream([
            0x00, 0x05, // DATA, len 5
            b'H', b'e', b'l', b'l', b'o', 0x00, 0x05, // DATA, len 5
            b'W', b'o', b'r', b'l', b'd',
        ]));

        let mut stream = std::pin::pin!(FrameStream::new(stream));

        let mut frame1 = stream.as_mut().next_frame().await.unwrap().unwrap();
        assert_eq!(frame1.r#type().into_inner(), 0);
        assert_eq!(frame1.length().into_inner(), 5);

        let mut payload = Vec::new();
        frame1.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload[..], b"Hello");

        let mut frame2 = stream.next_frame().await.unwrap().unwrap();
        let mut payload = Vec::new();
        frame2.read_to_end(&mut payload).await.unwrap();
        assert_eq!(&payload[..], b"World");
    }

    #[tokio::test]
    async fn empty_input_produces_no_frame() {
        let mut stream =
            std::pin::pin!(FrameStream::new(StreamReader::new(to_pre_byte_stream([]))));

        assert!(stream.as_mut().frame().is_none());
        assert!(stream.as_mut().next_frame().await.is_none());
        assert!(stream.as_mut().frame().is_none());
    }

    #[tokio::test]
    async fn next_unreserved_frame_skips_reserved_frames() {
        let stream = StreamReader::new(to_pre_byte_stream([
            0x21, 0x02, // RESERVED frame type, len 2
            b'p', b'a', 0x00, 0x03, // DATA frame, len 3
            b'o', b'n', b'e',
        ]));

        let mut stream = std::pin::pin!(FrameStream::new(stream));
        let mut frame = stream
            .as_mut()
            .next_unreserved_frame()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.r#type(), Frame::DATA_FRAME_TYPE);

        let mut payload = Vec::new();
        frame.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload.as_slice(), b"one");
    }

    #[tokio::test]
    async fn next_unreserved_frame_returns_none_after_only_reserved_frames() {
        let stream = StreamReader::new(to_pre_byte_stream([
            0x21, 0x02, // RESERVED frame type, len 2
            b'p', b'a',
        ]));

        let mut stream = std::pin::pin!(FrameStream::new(stream));

        assert!(stream.as_mut().next_unreserved_frame().await.is_none());
        assert!(stream.as_mut().frame().is_none());
    }

    #[tokio::test]
    async fn next_frame_consumes_previous_frame_before_decoding_next() {
        let stream = StreamReader::new(to_pre_byte_stream([
            0x00, 0x04, // DATA, len 4
            b'P', b'u', b't', b's', 0x01, 0x00, // HEADERS, len 0
        ]));

        let mut stream = std::pin::pin!(FrameStream::new(stream));
        let mut first = stream.as_mut().next_frame().await.unwrap().unwrap();

        let mut prefix = [0u8; 2];
        first.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"Pu");

        let second = stream.as_mut().next_frame().await.unwrap().unwrap();
        assert_eq!(second.r#type(), Frame::HEADERS_FRAME_TYPE);
        assert_eq!(second.length().into_inner(), 0);
    }

    #[tokio::test]
    async fn consume_current_frame_drains_payload_and_clears_current_frame() {
        let stream = StreamReader::new(to_pre_byte_stream([
            0x00, 0x03, // DATA, len 3
            b'a', b'b', b'c', 0x01, 0x00, // HEADERS, len 0
        ]));

        let mut stream = std::pin::pin!(FrameStream::new(stream));
        {
            let first = stream.as_mut().next_frame().await.unwrap().unwrap();
            assert_eq!(first.r#type(), Frame::DATA_FRAME_TYPE);
            assert_eq!(first.length().into_inner(), 3);
        }

        stream
            .as_mut()
            .consume_current_frame()
            .await
            .expect("current frame is drained");
        assert!(stream.as_mut().frame().is_none());

        let second = stream.as_mut().next_frame().await.unwrap().unwrap();
        assert_eq!(second.r#type(), Frame::HEADERS_FRAME_TYPE);
        assert_eq!(second.length().into_inner(), 0);
    }

    #[tokio::test]
    async fn incomplete_length_converts_to_frame_decode_error() {
        let mut stream = std::pin::pin!(FrameStream::new(StreamReader::new(to_pre_byte_stream([
            0x00, // frame type present but length missing
        ]))));

        let error = match stream.as_mut().next_frame().await {
            Some(Err(error)) => error,
            Some(Ok(_)) => panic!("expected frame decode error"),
            None => panic!("expected frame decode error"),
        };
        expect_h3_frame_decode_error(error);

        let error = match stream.as_mut().frame() {
            Some(Err(error)) => error,
            Some(Ok(_)) => panic!("expected frame decode error"),
            None => panic!("expected frame decode error"),
        };
        expect_h3_frame_decode_error(error);
    }

    #[tokio::test]
    async fn incomplete_type_varint_converts_to_frame_decode_error() {
        let mut stream = std::pin::pin!(FrameStream::new(StreamReader::new(to_pre_byte_stream([
            0x40, // two-byte varint prefix without the second byte
        ]))));

        let error = match stream.as_mut().next_frame().await {
            Some(Err(error)) => error,
            Some(Ok(_)) => panic!("expected frame decode error"),
            None => panic!("expected frame decode error"),
        };
        expect_h3_frame_decode_error(error);
    }

    #[tokio::test]
    async fn consume_current_frame_returns_stored_decode_error() {
        let mut stream = std::pin::pin!(FrameStream::new(StreamReader::new(to_pre_byte_stream([
            0x00, // frame type present but length missing
        ]))));

        let error = match stream.as_mut().next_frame().await {
            Some(Err(error)) => error,
            Some(Ok(_)) => panic!("expected frame decode error"),
            None => panic!("expected frame decode error"),
        };
        expect_h3_frame_decode_error(error);

        let error = stream
            .as_mut()
            .consume_current_frame()
            .await
            .expect_err("stored decode error should be returned");
        expect_h3_frame_decode_error(error);
    }

    #[tokio::test]
    async fn incomplete_payload_error_propagates_on_consume() {
        let mut stream = std::pin::pin!(FrameStream::new(StreamReader::new(to_pre_byte_stream([
            0x00, 0x05, // DATA len 5
            b'H', b'e', b'l', b'l', // payload incomplete
        ]))));

        assert!(stream.as_mut().next_frame().await.unwrap().is_ok());

        let error = match stream.as_mut().next_frame().await {
            Some(Err(error)) => error,
            Some(Ok(_)) => panic!("expected frame decode error"),
            None => panic!("expected frame decode error"),
        };
        expect_h3_frame_decode_error(error);
    }

    #[tokio::test]
    async fn stream_reset_error_is_forwarded() {
        let stream = StreamReader::new(stream::iter([Err(quic::StreamError::Reset {
            code: VarInt::from_u32(0x22),
        })]));
        let mut stream = std::pin::pin!(FrameStream::new(stream));

        let error = match stream.as_mut().next_frame().await {
            Some(Err(error)) => error,
            Some(Ok(_)) => panic!("expected stream reset"),
            None => panic!("expected stream reset"),
        };
        assert!(matches!(error, StreamError::Reset { code } if code.into_inner() == 0x22));
    }

    #[tokio::test]
    async fn control_traits_delegate_to_inner() {
        let stream_id = VarInt::from_u32(7);
        let stop_code = VarInt::from_u32(9);
        let mock = MockStream::from_iter(stream_id, vec![Ok(Bytes::from_static(b"\x00\x00"))]);
        let stop_code_ref = mock.stop_code.clone();
        let mut stream = FrameStream::new(StreamReader::new(mock));

        assert_eq!(
            poll_fn(|cx| Pin::new(&mut stream).poll_stream_id(cx))
                .await
                .expect("stream id"),
            stream_id
        );
        poll_fn(|cx| Pin::new(&mut stream).poll_stop(cx, stop_code))
            .await
            .expect("stream stop");
        assert_eq!(
            *stop_code_ref.lock().expect("stop_code lock poisoned"),
            Some(stop_code)
        );
    }

    #[tokio::test]
    async fn mock_stream_payload_decodes_frame() {
        let mock = MockStream::from_iter(
            VarInt::from_u32(11),
            vec![Ok(Bytes::from_static(b"\x00\x02ok"))],
        );
        let mut stream = std::pin::pin!(FrameStream::new(StreamReader::new(mock)));

        let mut frame = stream.as_mut().next_frame().await.unwrap().unwrap();
        assert_eq!(frame.r#type(), Frame::DATA_FRAME_TYPE);
        assert_eq!(frame.length().into_inner(), 2);

        let mut payload = Vec::new();
        frame.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"ok");
    }

    #[tokio::test]
    async fn encode_and_decode_frames() {
        use crate::codec::SinkWriter;

        let (sink, stream) = channel();

        let decode = async move {
            let stream = StreamReader::new(stream);
            let mut stream = std::pin::pin!(FrameStream::new(stream));

            let mut frame1 = stream.as_mut().next_frame().await.unwrap().unwrap();
            assert_eq!(frame1.r#type().into_inner(), 0);
            let mut payload = Vec::new();
            frame1.read_to_end(&mut payload).await.unwrap();
            assert_eq!(&payload[..], b"ok");

            let mut frame2 = stream.as_mut().next_frame().await.unwrap().unwrap();
            assert_eq!(frame2.r#type().into_inner(), 0);
            let mut payload = Vec::new();
            frame2.read_to_end(&mut payload).await.unwrap();
            assert_eq!(&payload[..], b"go");
            Ok::<(), ()>(())
        };

        let encode = async move {
            let mut sink = SinkWriter::new(sink);

            let frame1 =
                Frame::new(VarInt::from_u32(0), Bytes::from_static(b"ok")).expect("frame1");
            let frame2 =
                Frame::new(VarInt::from_u32(0), Bytes::from_static(b"go")).expect("frame2");

            sink.encode_one(frame1).await.unwrap();
            sink.encode_one(frame2).await.unwrap();
            futures::SinkExt::flush(&mut sink).await.unwrap();
            Ok::<(), ()>(())
        };

        tokio::try_join!(decode, encode).unwrap();
    }
}
