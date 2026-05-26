use std::convert::Infallible;

use bytes::Buf;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use crate::{
    buflist::BufList,
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto, StreamDecodeError},
    connection::StreamError,
    dhttp::frame::Frame,
    error::{H3CriticalStreamClosed, H3FrameDecodeError, H3GeneralProtocolError},
    varint::VarInt,
};

/// GOAWAY Frame {
///   Type (i) = 0x07,
///   Length (i),
///   Stream ID/Push ID (i),
/// }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Goaway {
    stream_id: VarInt,
}

impl Goaway {
    pub const fn new(stream_id: VarInt) -> Self {
        Self { stream_id }
    }

    pub const fn stream_id(&self) -> VarInt {
        self.stream_id
    }
}

impl<S> DecodeFrom<&mut Frame<S>> for Goaway
where
    for<'f> &'f mut Frame<S>: AsyncBufRead,
    S: Send,
{
    type Error = StreamError;

    async fn decode_from(mut stream: &mut Frame<S>) -> Result<Self, Self::Error> {
        assert!(stream.r#type() == Frame::GOAWAY_FRAME_TYPE);
        let stream_id = stream.decode_one::<VarInt>().await.map_err(|error| {
            StreamDecodeError::from(error)
                .escalate_critical_close(|| H3CriticalStreamClosed::Control.into())
                .into_stream_error(|decode_error| {
                    H3FrameDecodeError {
                        source: decode_error,
                    }
                    .into()
                })
        })?;

        // ensure frame is exhausted
        if !stream.fill_buf().await?.is_empty() {
            // FIXME: which error kind?
            return Err(H3GeneralProtocolError::TrailingPayload.into());
        };

        Ok(Goaway { stream_id })
    }
}

impl EncodeInto<BufList> for Goaway {
    type Output = Frame<BufList>;

    type Error = Infallible;

    async fn encode_into(self, stream: BufList) -> Result<Self::Output, Self::Error> {
        assert!(
            !stream.has_remaining(),
            "Only empty buflist can be used to encode frame"
        );

        let mut frame =
            Frame::new(Frame::GOAWAY_FRAME_TYPE, stream).expect("empty BufList fits in VarInt");
        frame
            .encode_one(self.stream_id)
            .await
            .expect("size of varint never exceeded 2^62-1");
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{
        codec::{DecodeFrom, EncodeExt},
        connection::ConnectionError,
        error::Code,
    };

    #[test]
    fn new_stores_stream_id() {
        let stream_id = VarInt::from_u32(11);

        assert_eq!(Goaway::new(stream_id).stream_id(), stream_id);
    }

    #[tokio::test]
    async fn encode_decode_round_trips() {
        let stream_id = VarInt::from_u32(1337);
        let mut frame = BufList::new()
            .encode(Goaway::new(stream_id))
            .await
            .expect("goaway encoding is infallible");

        assert_eq!(frame.r#type(), Frame::GOAWAY_FRAME_TYPE);

        let decoded = Goaway::decode_from(&mut frame).await.expect("goaway frame");

        assert_eq!(decoded.stream_id(), stream_id);
    }

    #[tokio::test]
    async fn encode_decode_round_trips_with_boundary_stream_ids() {
        for stream_id in [VarInt::from_u32(0), VarInt::MAX] {
            let mut frame = BufList::new()
                .encode(Goaway::new(stream_id))
                .await
                .expect("goaway encoding is infallible");

            let decoded = Goaway::decode_from(&mut frame).await.expect("goaway frame");

            assert_eq!(decoded.stream_id(), stream_id);
        }
    }

    #[tokio::test]
    async fn decode_rejects_trailing_payload() {
        let mut payload = BufList::new();
        payload
            .encode_one(VarInt::from_u32(7))
            .await
            .expect("varint encoding into buflist is infallible");
        payload.write(Bytes::from_static(b"trailing"));
        let mut frame =
            Frame::new(Frame::GOAWAY_FRAME_TYPE, payload).expect("payload length fits varint");

        let error = Goaway::decode_from(&mut frame)
            .await
            .expect_err("trailing payload is malformed");

        let StreamError::Connection {
            source: ConnectionError::H3 { source },
        } = error
        else {
            panic!("trailing payload should produce a connection-scoped H3 error");
        };
        assert_eq!(source.code(), Code::H3_GENERAL_PROTOCOL_ERROR);
    }

    #[tokio::test]
    async fn decode_rejects_empty_payload_as_closed_critical_stream() {
        let mut frame = Frame::new(Frame::GOAWAY_FRAME_TYPE, BufList::new())
            .expect("payload length fits varint");

        let error = Goaway::decode_from(&mut frame)
            .await
            .expect_err("missing stream id is malformed");

        let StreamError::Connection {
            source: ConnectionError::H3 { source },
        } = error
        else {
            panic!("empty payload should produce a connection-scoped H3 error");
        };
        assert_eq!(source.code(), Code::H3_CLOSED_CRITICAL_STREAM);
    }

    #[tokio::test]
    async fn encode_rejects_non_empty_output_buffer() {
        let mut prefilled = BufList::new();
        prefilled.write(Bytes::from_static(b"already-filled"));

        let join = tokio::spawn(async move {
            prefilled
                .encode(Goaway::new(VarInt::from_u32(1)))
                .await
                .expect("goaway encoding should panic before this")
        });

        let err = join
            .await
            .expect_err("encoding with non-empty buffer should panic");
        assert!(err.is_panic());
    }

    #[tokio::test]
    async fn decode_panics_on_wrong_frame_type() {
        let mut payload = BufList::new();
        payload
            .encode_one(VarInt::from_u32(7))
            .await
            .expect("varint encoding into buflist is infallible");
        let frame =
            Frame::new(Frame::SETTINGS_FRAME_TYPE, payload).expect("payload length fits varint");

        let join = tokio::spawn(async move {
            let mut frame = frame;
            let _ = Goaway::decode_from(&mut frame).await;
        });

        let err = join
            .await
            .expect_err("decoding a mismatched frame type should panic");
        assert!(err.is_panic());
    }

    #[test]
    fn debug_renders_stream_id() {
        let goaway = Goaway::new(VarInt::from_u32(123));
        let rendered = format!("{goaway:?}");
        assert!(rendered.contains("Goaway"));
        assert!(rendered.contains("123"));
    }
}
