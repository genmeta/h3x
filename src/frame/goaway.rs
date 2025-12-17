use std::convert::Infallible;

use bytes::Buf;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use crate::{
    buflist::BufList,
    codec::{Decode, DecodeExt, DecodeStreamError, Encode, EncodeExt},
    connection::StreamError,
    error::{Code, H3CriticalStreamClosed},
    frame::Frame,
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

impl<S> Decode<Goaway> for &mut Frame<S>
where
    for<'f> &'f mut Frame<S>: AsyncBufRead,
{
    type Error = StreamError;

    async fn decode(mut self) -> Result<Goaway, Self::Error> {
        assert!(self.r#type() == Frame::GOAWAY_FRAME_TYPE);
        let stream_id = self.decode_one::<VarInt>().await.map_err(|error| {
            DecodeStreamError::from(error).map_stream_closed(
                |_reset_code| H3CriticalStreamClosed::Control.into(),
                |decode_error| Code::H3_FRAME_ERROR.with(decode_error).into(),
            )
        })?;

        // ensure frame is exhausted
        if !self.fill_buf().await?.is_empty() {
            // FIXME: which error kind?
            return Err(Code::H3_GENERAL_PROTOCOL_ERROR.into());
        };

        Ok(Goaway { stream_id })
    }
}

impl Encode<Goaway> for BufList {
    type Output = Frame<BufList>;

    type Error = Infallible;

    async fn encode(self, goaway: Goaway) -> Result<Self::Output, Self::Error> {
        assert!(
            !self.has_remaining(),
            "Only empty buflist can be used to encode frame"
        );

        let mut frame = Frame::new(Frame::GOAWAY_FRAME_TYPE, self).unwrap();
        frame
            .encode_one(goaway.stream_id)
            .await
            .expect("size of varint never exceeded 2^62-1");
        Ok(frame)
    }
}
