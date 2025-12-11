use std::{
    io,
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
    quic::{self, GetStreamId, StopStream},
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

    pub fn stream(&self) -> &StreamReader<S> {
        self.stream.stream()
    }

    fn stream_mut(&mut self) -> &mut StreamReader<S> {
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

    pub async fn consume_current_frame(&mut self) -> Result<(), StreamError> {
        let map_decode_stream_error = |error: DecodeStreamError| {
            error.map_decode_error(|decode_error| Code::H3_FRAME_ERROR.with(decode_error).into())
        };

        match self.frame() {
            Some(Ok(mut frame)) => {
                let mut drain = sink::drain().sink_map_err(|never| match never {});
                let result = (&mut frame).forward(&mut drain).await;
                if let Err(error) = result.map_err(map_decode_stream_error) {
                    self.frame = Some(Err(error.clone()));
                    return Err(error);
                }
                self.frame = None;
                Ok(())
            }
            Some(Err(error)) => Err(error.clone()),
            None => Ok(()),
        }
    }

    pub async fn decode_next_frame(&mut self)
    where
        S: Unpin,
    {
        let try_decode_next_frame = async {
            self.consume_current_frame().await?;
            if !Pin::new(self.stream_mut()).has_remaining().await? {
                return Ok(None);
            }

            let convert_decode_varint_error = |error: io::Error| {
                DecodeStreamError::from(error)
                    .map_decode_error(|decode_error| Code::H3_FRAME_ERROR.with(decode_error).into())
            };
            let r#type = (self.stream_mut().decode_one::<VarInt>().await)
                .map_err(convert_decode_varint_error)?;
            let length = (self.stream_mut().decode_one::<VarInt>().await)
                .map_err(convert_decode_varint_error)?;
            Ok(Some(Frame {
                r#type,
                length,
                payload: (),
            }))
        };

        match try_decode_next_frame.await {
            Ok(Some(frame)) => {
                self.stream.renew(frame.length.into_inner());
                self.frame = Some(Ok(frame));
            }
            Ok(None) => {
                self.frame = None;
            }
            Err(error) => {
                self.frame = Some(Err(error));
            }
        }
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
            match self.next_frame().await {
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

impl<S: StopStream + ?Sized> StopStream for FrameStream<S> {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.project().stream.poll_stop(cx, code)
    }
}
