use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite};

use crate::{
    buflist::BufList,
    codec::util::{DecodeFrom, EncodeInto},
    error::{Code, Error, H3CriticalStreamClosed},
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

    pub async fn encode(&self) -> Frame<BufList> {
        let mut frame = Frame::new(Frame::GOAWAY_FRAME_TYPE, BufList::new()).unwrap();
        self.encode_into(&mut frame).await.unwrap();
        frame
    }
}

impl<S: AsyncBufRead> DecodeFrom<S> for Goaway {
    type Error = Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        tokio::pin!(stream);
        let stream_id = VarInt::decode_from(stream.as_mut())
            .await
            .map_err(|error| error.map_stream_closed(|| H3CriticalStreamClosed::Control.into()))?;
        // ensure frame is exhausted
        if !stream.fill_buf().await?.is_empty() {
            // TODO: error kind
            return Err(Code::H3_GENERAL_PROTOCOL_ERROR.into());
        };

        Ok(Self { stream_id })
    }
}

impl<S: AsyncWrite> EncodeInto<S> for Goaway {
    type Error = Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        match self.stream_id.encode_into(stream).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_reset() => Err(H3CriticalStreamClosed::Control.into()),
            Err(error) => Err(error.into()),
        }
    }
}
