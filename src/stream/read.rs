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

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use qbase::varint::{VarInt, WriteVarInt};
    use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

    use super::*;
    use crate::frame::Write as _;

    #[derive(Default)]
    struct Io {
        bytes: Vec<u8>,
        offset: usize,
        stops: Vec<u64>,
    }

    impl Io {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                ..Self::default()
            }
        }
    }

    impl AsyncRead for Io {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let count = (self.bytes.len() - self.offset).min(buf.remaining());
            buf.put_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Poll::Ready(Ok(()))
        }
    }

    impl StopSending for Io {
        fn stop(&mut self, code: u64) {
            self.stops.push(code);
        }
    }

    fn headers(bytes: &'static [u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.put_frame(
            &Frame::new(frame::Headers {
                field_section: Bytes::from_static(bytes),
            })
            .unwrap(),
        );
        wire
    }

    #[tokio::test]
    async fn header_and_next_frame_readers_skip_extensions_and_enforce_placement() {
        let mut wire = Vec::new();
        wire.put_varint(&VarInt::from_u32(42));
        wire.put_varint(&VarInt::from_u32(2));
        wire.extend_from_slice(b"xx");
        wire.extend_from_slice(&headers(b"head"));
        let mut stream = H3ReadStream::new(4, Io::new(wire));
        assert_eq!(stream.stream_id(), 4);
        assert_eq!(
            stream
                .read_headers_frame()
                .await
                .unwrap()
                .unwrap()
                .payload
                .field_section,
            Bytes::from_static(b"head")
        );
        assert!(stream.read_headers_frame().await.unwrap().is_none());

        let mut stream = H3ReadStream::new(8, Io::new(vec![0, 1, b'x']));
        let Some(NextFrame::Data(frame)) = stream.read_next_frame(false).await.unwrap() else {
            panic!("expected DATA")
        };
        assert_eq!(frame.length.into_u64(), 1);
        let mut payload = [0];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, [b'x']);
        assert!(stream.read_next_frame(false).await.unwrap().is_none());

        let mut stream = H3ReadStream::new(12, Io::new(headers(b"trailers")));
        assert!(matches!(
            stream.read_next_frame(false).await.unwrap(),
            Some(NextFrame::Trailer(_))
        ));
        assert!(stream.read_next_frame(true).await.unwrap().is_none());

        let mut stream = H3ReadStream::new(16, Io::new(vec![0, 0]));
        assert_eq!(
            stream.read_headers_frame().await.unwrap_err().code,
            ErrorCode::H3_FRAME_UNEXPECTED
        );
        let mut stream = H3ReadStream::new(20, Io::new(vec![7, 1, 0]));
        assert_eq!(
            stream.read_next_frame(false).await.err().unwrap().code,
            ErrorCode::H3_FRAME_UNEXPECTED
        );
        let mut stream = H3ReadStream::new(24, Io::new(vec![0]));
        assert_eq!(
            stream.read_next_frame(true).await.err().unwrap().code,
            ErrorCode::H3_FRAME_UNEXPECTED
        );
    }

    #[tokio::test]
    async fn read_completion_close_reject_and_stop_fire_finish_once() {
        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut stream = H3ReadStream::new(0, Io::new(b"abc".to_vec()));
        stream.on_finish(move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        let _registered = stream.registered();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"abc");
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        stream.close(ErrorCode::H3_INTERNAL_ERROR.reason("late"));
        assert!(!stream.reject());
        stream.stop(9);
        assert_eq!(completed.load(Ordering::SeqCst), 1);

        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut rejected = H3ReadStream::new(4, Io::default());
        rejected.on_finish(move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        assert!(rejected.reject());
        assert_eq!(completed.load(Ordering::SeqCst), 0);
        let mut byte = [0];
        let error = rejected.read(&mut byte).await.unwrap_err();
        assert_eq!(
            crate::Error::from(error).code,
            ErrorCode::H3_REQUEST_REJECTED
        );
    }

    #[tokio::test]
    async fn read_message_rejects_a_stream_without_initial_headers() {
        let stream = H3ReadStream::new(0, Io::default());
        let result: crate::Result<crate::Request<crate::R>> =
            stream.read_message(crate::qpack::tests::qpack()).await;
        let Err(error) = result else {
            panic!("a message without HEADERS must fail")
        };
        // The isolated QPACK fixture has no decoder-instruction callback, so
        // cancelling this request is promoted to a connection-scoped error.
        assert_eq!(error.code, ErrorCode::H3_INTERNAL_ERROR);
    }
}
