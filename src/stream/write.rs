use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use qrecovery::send::CancelStream;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ArcH3Stream;
use crate::{
    ArcQpack, Error, ErrorCode,
    common::{
        request::{Request, WriteRequest},
        response::{Response, WriteResponse},
    },
    frame::{self, Data, Frame, Write as _},
    qpack::Field,
};

/// Application-owned write direction, sharing state with the connection registry.
pub struct H3WriteStream<W: CancelStream> {
    pub(super) state: ArcH3Stream<W>,
    finish_cb: Box<dyn Fn() + Send + Sync>,
    id: u64,
}

impl<W: CancelStream> H3WriteStream<W> {
    pub fn new(stream_id: u64, stream: W) -> Self {
        Self {
            state: ArcH3Stream::new(stream),
            id: stream_id,
            finish_cb: Box::new(|| {}),
        }
    }

    pub(super) fn on_finish(&mut self, callback: impl Fn() + Send + Sync + 'static) {
        self.finish_cb = Box::new(callback);
    }

    pub(crate) fn shutdown(&self) {
        (self.finish_cb)();
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<W: CancelStream> CancelStream for &H3WriteStream<W> {
    fn cancel(&mut self, error_code: u64) {
        if self.state.terminate(|io| io.cancel(error_code)) {
            H3WriteStream::shutdown(self);
        }
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> H3WriteStream<W> {
    fn poll_io<O>(
        &mut self,
        cx: &mut Context<'_>,
        finish: bool,
        poll: impl FnOnce(Pin<&mut W>, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>> {
        let result = self.state.poll_io(cx, poll);
        let completed = finish && matches!(result, Poll::Ready(Ok(_)));
        let failed = matches!(&result, Poll::Ready(Err(error)) if !matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock));
        if (completed || failed) && self.state.finish() {
            H3WriteStream::shutdown(self);
        }
        result
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> AsyncWrite for H3WriteStream<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_io(cx, false, |send, cx| send.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, false, |send, cx| send.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, true, |send, cx| send.poll_shutdown(cx))
    }
}

impl<W: CancelStream> Drop for H3WriteStream<W> {
    fn drop(&mut self) {
        (&*self).cancel(ErrorCode::H3_REQUEST_CANCELLED.as_u64());
    }
}

impl<W> WriteRequest for H3WriteStream<W>
where
    W: AsyncWrite + CancelStream + Unpin + Send,
{
    async fn write_request(
        mut self,
        request: Request<crate::W>,
        qpack: ArcQpack,
    ) -> crate::Result<()> {
        let mut fields = Vec::with_capacity(request.head.headers.len() + 5);
        for (name, value) in request.pseudo_headers() {
            if let Some(value) = value {
                fields.push(Field {
                    name: Bytes::from_static(name),
                    value: Bytes::copy_from_slice(value.as_bytes()),
                    never_index: false,
                });
            }
        }
        fields.extend(request.head.headers.iter().map(|(name, value)| Field {
            name: Bytes::copy_from_slice(name.as_str().as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            never_index: value.is_sensitive(),
        }));
        let mut body = request.body;
        let producer = body.clone();
        let sending = async {
            let headers = Frame::new(frame::Headers {
                field_section: qpack.encode(self.stream_id(), fields)?,
            })?;
            let mut bytes = Vec::new();
            bytes.put_frame(&headers);
            self.write_all(&bytes).await?;

            let mut buf = vec![0; frame::MAX_DATA_CHUNK];
            loop {
                let count = body.read(&mut buf).await?;
                if count == 0 {
                    break;
                }
                bytes.clear();
                bytes.put_frame(&Frame::new(Data(count))?);
                self.write_all(&bytes).await?;
                self.write_all(&buf[..count]).await?;
            }
            AsyncWriteExt::shutdown(&mut self).await?;
            Ok::<_, Error>(())
        };
        let result = sending.await.inspect_err(|error| {
            (&self).cancel(error.code.as_u64());
            producer.on_error(error.clone());
            qpack.on_error(self.stream_id(), error.clone());
        });
        self.shutdown();
        result
    }
}

impl<W> WriteResponse for H3WriteStream<W>
where
    W: AsyncWrite + CancelStream + Unpin + Send,
{
    async fn write_response(
        mut self,
        response: Response<crate::W>,
        request_method: http::Method,
        qpack: ArcQpack,
    ) -> crate::Result<()> {
        let send_body = request_method != http::Method::HEAD
            && response.head.status != http::StatusCode::NO_CONTENT
            && response.head.status != http::StatusCode::NOT_MODIFIED;
        let mut fields = Vec::with_capacity(response.head.headers.len() + 1);
        for (name, value) in response.pseudo_headers() {
            if let Some(value) = value {
                fields.push(Field {
                    name: Bytes::from_static(name),
                    value: Bytes::copy_from_slice(value.as_bytes()),
                    never_index: false,
                });
            }
        }
        fields.extend(response.head.headers.iter().map(|(name, value)| Field {
            name: Bytes::copy_from_slice(name.as_str().as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            never_index: value.is_sensitive(),
        }));
        let mut body = response.body;
        let producer = body.clone();
        let sending = async {
            let headers = Frame::new(frame::Headers {
                field_section: qpack.encode(self.stream_id(), fields)?,
            })?;
            let mut bytes = Vec::new();
            bytes.put_frame(&headers);
            self.write_all(&bytes).await?;

            if send_body {
                let mut buf = vec![0; frame::MAX_DATA_CHUNK];
                loop {
                    let count = body.read(&mut buf).await?;
                    if count == 0 {
                        break;
                    }
                    bytes.clear();
                    bytes.put_frame(&Frame::new(Data(count))?);
                    self.write_all(&bytes).await?;
                    self.write_all(&buf[..count]).await?;
                }
            }
            AsyncWriteExt::shutdown(&mut self).await?;
            Ok::<_, Error>(())
        };
        let result = sending.await.inspect_err(|error| {
            (&self).cancel(error.code.as_u64());
            producer.on_error(error.clone());
            qpack.on_error(self.stream_id(), error.clone());
        });
        H3WriteStream::shutdown(&self);
        result
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use super::*;

    #[derive(Clone, Default)]
    struct Io {
        bytes: Arc<Mutex<Vec<u8>>>,
        cancels: Arc<Mutex<Vec<u64>>>,
    }

    impl AsyncWrite for Io {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl CancelStream for Io {
        fn cancel(&mut self, code: u64) {
            self.cancels.lock().unwrap().push(code);
        }
    }

    #[tokio::test]
    async fn write_flush_shutdown_and_cancel_transition_once() {
        let io = Io::default();
        let bytes = io.bytes.clone();
        let cancels = io.cancels.clone();
        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut stream = H3WriteStream::new(4, io);
        stream.on_finish(move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        let _registered = stream.state.clone();
        assert_eq!(stream.stream_id(), 4);
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        AsyncWriteExt::shutdown(&mut stream).await.unwrap();
        assert_eq!(&*bytes.lock().unwrap(), b"hello");
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        (&stream).cancel(7);
        assert!(cancels.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reject_and_explicit_cancel_report_expected_codes() {
        fn reject<W: CancelStream>(stream: &H3WriteStream<W>) -> bool {
            stream
                .state
                .goaway(|io| io.cancel(ErrorCode::H3_REQUEST_REJECTED.as_u64()))
        }

        let io = Io::default();
        let cancels = io.cancels.clone();
        let mut stream = H3WriteStream::new(8, io);
        assert!(reject(&stream));
        assert!(!reject(&stream));
        assert_eq!(
            &*cancels.lock().unwrap(),
            &[ErrorCode::H3_REQUEST_REJECTED.as_u64()]
        );
        assert_eq!(
            stream.write_all(b"x").await.unwrap_err().kind(),
            io::ErrorKind::Other
        );

        let io = Io::default();
        let cancels = io.cancels.clone();
        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut stream = H3WriteStream::new(12, io);
        stream.on_finish(move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        (&stream).cancel(9);
        assert_eq!(&*cancels.lock().unwrap(), &[9]);
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        (&stream).cancel(10);
        assert_eq!(&*cancels.lock().unwrap(), &[9]);
    }
}
