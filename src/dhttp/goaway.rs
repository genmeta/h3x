use std::convert::Infallible;

use bytes::Buf;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use crate::{
    buflist::BufList,
    codec::{DecodeExt, DecodeFrom, DecodeStreamError, EncodeExt, EncodeInto},
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
            DecodeStreamError::from(error).map_stream_closed(
                |_reset_code| H3CriticalStreamClosed::Control.into(),
                |decode_error| {
                    H3FrameDecodeError {
                        source: decode_error,
                    }
                    .into()
                },
            )
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

        let mut frame = Frame::new(Frame::GOAWAY_FRAME_TYPE, stream).expect("empty BufList fits in VarInt");
        frame
            .encode_one(self.stream_id)
            .await
            .expect("size of varint never exceeded 2^62-1");
        Ok(frame)
    }
}
