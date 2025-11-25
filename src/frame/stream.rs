use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{SinkExt, StreamExt, TryStream, sink};

use crate::{
    codec::{DecodeExt, DecodeStreamError, FixedLengthReader, StreamReader},
    connection::StreamError,
    error::Code,
    frame::Frame,
    quic::{self, GetStreamId, StopSending},
    varint::VarInt,
};

pin_project_lite::pin_project! {
    pub struct FrameStream<S: ?Sized> {
        // TODO: this is actually a flatten self reference state
        // frame: Option<Result<Frame<FixedLengthReader<&'this mut StreamReader<S>>>, Error>>,
        frame: Option<Result<Frame<()>, StreamError>>,
        #[pin]
        stream: FixedLengthReader<StreamReader<S>>,
    }
}

impl<S: ?Sized> FrameStream<S>
where
    S: TryStream<Ok = Bytes, Error = quic::StreamError>,
    StreamReader<S>: Unpin,
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

    fn stream(&mut self) -> &mut StreamReader<S> {
        self.stream.stream_mut()
    }

    pub fn frame<'s: 'f, 'f>(
        &'s mut self,
    ) -> Option<Result<Frame<&'f mut FixedLengthReader<StreamReader<S>>>, StreamError>> {
        match self.frame.as_ref()? {
            Ok(frame) => Some(Ok(Frame {
                r#type: frame.r#type,
                length: frame.length,
                payload: &mut self.stream,
            })),
            Err(error) => Some(Err(error.clone())),
        }
    }

    pub async fn decode_next_frame(&mut self)
    where
        S: Unpin,
    {
        let map_decode_stream_error = |error: DecodeStreamError| {
            error.map_decode_error(|decode_error| Code::H3_FRAME_ERROR.with(decode_error).into())
        };

        match self.frame() {
            Some(Ok(mut frame)) => {
                let mut drain = sink::drain().sink_map_err(|never| match never {});
                let result = (&mut frame).forward(&mut drain).await;
                if let Err(error) = result {
                    self.frame = Some(Err(map_decode_stream_error(error)));
                    return;
                }
            }
            Some(Err(..)) => return,
            None => {}
        }

        match Pin::new(self.stream()).has_remaining().await {
            Ok(has_remaining) => {
                if !has_remaining {
                    self.frame = None;
                    return;
                }
            }
            Err(error) => {
                self.frame = Some(Err(error.into()));
                return;
            }
        }

        let r#type = match self.stream().decode_one::<VarInt>().await {
            Ok(r#type) => r#type,
            Err(error) => {
                let error = map_decode_stream_error(DecodeStreamError::from(error));
                self.frame = Some(Err(error));
                return;
            }
        };
        let length = match self.stream().decode_one::<VarInt>().await {
            Ok(length) => length,
            Err(error) => {
                let error = map_decode_stream_error(DecodeStreamError::from(error));
                self.frame = Some(Err(error));
                return;
            }
        };
        self.frame = Some(Ok(Frame {
            r#type,
            length,
            payload: (),
        }));
        self.stream.renew(length.into_inner());
    }

    pub async fn next_frame(
        &mut self,
    ) -> Option<Result<Frame<&mut FixedLengthReader<StreamReader<S>>>, StreamError>>
    where
        S: Unpin,
    {
        self.decode_next_frame().await;
        self.frame()
    }

    pub async fn decode_next_unreserved_frame(&mut self)
    where
        S: Unpin,
    {
        loop {
            self.decode_next_frame().await;
            match self.frame() {
                Some(Ok(frame)) if frame.is_reversed_frame() => continue,
                _decoded => break,
            }
        }
    }

    pub async fn next_unreserved_frame(
        &mut self,
    ) -> Option<Result<Frame<&mut FixedLengthReader<StreamReader<S>>>, StreamError>>
    where
        S: Unpin,
    {
        self.decode_next_unreserved_frame().await;
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

impl<S: StopSending + ?Sized> StopSending for FrameStream<S> {
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.project().stream.poll_stop_sending(cx, code)
    }
}
