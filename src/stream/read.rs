use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

use super::{Goaway, H3Stream};
use crate::{
    ArcQpack, Error, ErrorCode,
    common::message::{Headers, Message, PesudoHeaders, ReadMeesage},
    frame::{self, Frame, H3Frame},
};

/// Application-owned read direction, sharing state with its registered handle.
pub struct H3ReadStream<R: StopSending> {
    finish_cb: Box<dyn Fn() + Send + Sync>,
    pub(super) state: Arc<Mutex<std::result::Result<H3Stream<R>, Goaway>>>,
    id: u64,
}

impl<R: StopSending> H3ReadStream<R> {
    pub fn new(stream_id: u64, stream: R) -> Self {
        Self {
            id: stream_id,
            state: Arc::new(Mutex::new(Ok(H3Stream::new(stream)))),
            finish_cb: Box::new(|| {}),
        }
    }

    /// Registry handle: completion is reported by the application handle only.
    pub(super) fn registered(&self) -> Self {
        Self {
            id: self.id,
            state: self.state.clone(),
            finish_cb: Box::new(|| {}),
        }
    }

    pub(super) fn on_finish(&mut self, callback: impl Fn() + Send + Sync + 'static) {
        self.finish_cb = Box::new(callback);
    }

    pub(crate) fn shutdown(&self) {
        (self.finish_cb)();
    }

    pub(crate) fn close(&self, error: Error) {
        let code = error.code.as_u64();
        let mut state = self.state.lock().unwrap();
        let was_finished = super::is_finished(&state);
        let waker = super::terminate(&mut state, |io| io.stop(code));
        let finished = !was_finished && super::is_finished(&state);
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        if finished {
            self.shutdown();
        }
    }

    pub(super) fn reject(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        let changed = !super::is_finished(&state);
        let waker = super::goaway(&mut state, |io| {
            io.stop(ErrorCode::H3_REQUEST_REJECTED.as_u64())
        });
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        changed
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<R: StopSending> StopSending for &H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        let mut state = self.state.lock().unwrap();
        let was_finished = super::is_finished(&state);
        let waker = super::terminate(&mut state, |io| io.stop(error_code));
        let finished = !was_finished && super::is_finished(&state);
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        if finished {
            self.shutdown();
        }
    }
}

impl<R: StopSending> StopSending for H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        qrecovery::recv::StopSending::stop(&mut &*self, error_code);
    }
}

impl<R: AsyncRead + StopSending + Unpin> AsyncRead for H3ReadStream<R> {
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
        let mut inner = self.state.lock().unwrap();
        let was_finished = super::is_finished(&inner);
        let result = super::poll_io(&mut *inner, cx, |recv, cx| recv.poll_read(cx, buf));
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() == before {
            super::finish(&mut *inner);
        }
        let finished = !was_finished && super::is_finished(&inner);
        drop(inner);
        if finished {
            self.shutdown();
        }
        result
    }
}

impl<R: StopSending> Drop for H3ReadStream<R> {
    fn drop(&mut self) {
        self.close(ErrorCode::H3_REQUEST_CANCELLED.reason("request cancelled"));
    }
}

pub(crate) enum NextFrame {
    Data(Frame<frame::Data>),
    Trailer(Frame<frame::Headers>),
}

impl<R: AsyncRead + StopSending + Unpin> H3ReadStream<R> {
    async fn read_frame(&mut self) -> crate::Result<Option<H3Frame>> {
        let Some(ty) = frame::be_frame_type(self).await? else {
            return Ok(None);
        };
        let length = frame::be_frame_length(self).await?;
        frame::be_frame_payload(self, ty, length).await.map(Some)
    }

    pub(crate) async fn read_headers_frame(
        &mut self,
    ) -> crate::Result<Option<Frame<frame::Headers>>> {
        loop {
            match self.read_frame().await? {
                Some(H3Frame::Headers(frame)) => return Ok(Some(frame)),
                Some(H3Frame::Unknown { length, .. }) => {
                    frame::skip_payload(self, length.into_u64()).await?;
                }
                Some(_) => {
                    return Err(ErrorCode::H3_FRAME_UNEXPECTED
                        .reason("expected HEADERS before message body"));
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
            return match frame::be_frame_type(self).await? {
                Some(_) => {
                    Err(ErrorCode::H3_FRAME_UNEXPECTED.reason("frame received after trailers"))
                }
                None => Ok(None),
            };
        }
        loop {
            match self.read_frame().await? {
                Some(H3Frame::Headers(frame)) => return Ok(Some(NextFrame::Trailer(frame))),
                Some(H3Frame::Data(frame)) => return Ok(Some(NextFrame::Data(frame))),
                Some(H3Frame::Unknown { length, .. }) => {
                    frame::skip_payload(self, length.into_u64()).await?;
                }
                Some(_) => {
                    return Err(ErrorCode::H3_FRAME_UNEXPECTED
                        .reason("frame is not allowed on a request stream"));
                }
                None => return Ok(None),
            }
        }
    }
}

impl<R, P> ReadMeesage<P> for H3ReadStream<R>
where
    R: AsyncRead + StopSending + Unpin + Send + 'static,
    P: PesudoHeaders + From<Message>,
{
    async fn read_message(mut self, qpack: ArcQpack) -> crate::Result<P> {
        let head = async {
            loop {
                let frame = self.read_headers_frame().await?.ok_or_else(|| {
                    ErrorCode::H3_REQUEST_INCOMPLETE.reason("stream ended before final HEADERS")
                })?;
                let head = Headers::decode_headers(self.stream_id(), frame, &qpack).await?;
                if P::pesudo_headers().contains(&":status")
                    && head.response_status()?.is_informational()
                {
                    tokio::task::yield_now().await;
                    continue;
                }
                return Ok::<_, Error>(head);
            }
        }
        .await
        .map_err(|error| {
            self.close(error.clone());
            self.shutdown();
            qpack.on_error(self.stream_id(), error)
        })?;

        let mut body = crate::ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        let consumer = body.clone();
        tokio::spawn(async move {
            let result: crate::Result<()> = async {
                let mut trailers = false;
                while let Some(frame) = self.read_next_frame(trailers).await? {
                    match frame {
                        NextFrame::Data(frame) => {
                            let mut payload = (&mut self).take(frame.length.into_u64());
                            tokio::io::copy(&mut payload, &mut body).await?;
                            if payload.limit() != 0 {
                                return Err(ErrorCode::H3_FRAME_ERROR.reason(
                                    "DATA payload ended before the declared frame length",
                                ));
                            }
                        }
                        NextFrame::Trailer(frame) => {
                            qpack
                                .decode(self.stream_id(), frame.payload.field_section)
                                .await?;
                            trailers = true;
                        }
                    }
                }
                body.shutdown().await?;
                Ok(())
            }
            .await;
            if let Err(error) = result {
                self.close(error.clone());
                body.on_error(qpack.on_error(self.stream_id(), error));
            }
            self.shutdown();
        });
        Ok(Message::from_parts(head, consumer).into())
    }
}
