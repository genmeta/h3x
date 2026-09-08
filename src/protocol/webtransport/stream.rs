use std::{
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream};

use super::{SessionState, application_error_code, map_application_error};
use crate::{
    Code, Error, StreamId,
    platform::{MaybeSend, MaybeSync},
    transport, wire,
};

pub(crate) trait Writer:
    Sink<Bytes, Error = transport::StreamError> + MaybeSend + Unpin + 'static
{
    fn id(&self) -> StreamId;
    fn reset_at(&mut self, code: Code, reliable_size: u64) -> Result<(), transport::StreamError>;
}

pub(crate) type BoxWriter = Box<dyn Writer>;

struct AdaptedWriter<T: transport::webtransport::Connection> {
    id: StreamId,
    transport: Arc<T>,
    stream: T::SendStream,
}

impl<T: transport::webtransport::Connection> Sink<Bytes> for AdaptedWriter<T> {
    type Error = transport::StreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        transport::SendStream::poll_ready(&mut self.stream, cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        transport::SendStream::start_send(&mut self.stream, item)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        transport::SendStream::poll_close(&mut self.stream, cx)
    }
}

impl<T: transport::webtransport::Connection> Writer for AdaptedWriter<T> {
    fn id(&self) -> StreamId {
        self.id
    }

    fn reset_at(&mut self, code: Code, reliable_size: u64) -> Result<(), transport::StreamError> {
        self.transport
            .reset_stream_at(&mut self.stream, code, reliable_size)
    }
}

pub(crate) fn adapt_writer<T>(transport: Arc<T>, id: StreamId, stream: T::SendStream) -> BoxWriter
where
    T: transport::webtransport::Connection,
{
    Box::new(AdaptedWriter { id, transport, stream })
}

pub(crate) trait AbortStream: MaybeSend + MaybeSync {
    fn abort(&self, code: Code);
    fn finished(&self) -> bool;
}

struct RecvCore {
    reader: Mutex<wire::ChunkReader>,
    finished: AtomicBool,
    error: Mutex<Option<Error>>,
}

impl AbortStream for RecvCore {
    fn abort(&self, code: Code) {
        let mut error = self
            .error
            .lock()
            .expect("WebTransport receive error lock poisoned");
        if self
            .finished
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            *error = Some(Error::stream(
                Some(code),
                "WebTransport receive stream was aborted",
            ));
            drop(error);
            let _ = self
                .reader
                .lock()
                .expect("WebTransport receive stream lock poisoned")
                .stop(code);
        }
    }

    fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
}

/// Receive direction of a WebTransport data stream.
pub struct RecvStream {
    id: StreamId,
    core: Arc<RecvCore>,
    session: Weak<SessionState>,
}

impl std::fmt::Debug for RecvStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvStream").field("id", &self.id).finish()
    }
}

impl RecvStream {
    pub(crate) fn new(reader: wire::ChunkReader, session: &Arc<SessionState>) -> Self {
        let id = reader.stream_id();
        let core = Arc::new(RecvCore {
            reader: Mutex::new(reader),
            finished: AtomicBool::new(false),
            error: Mutex::new(None),
        });
        session.register_stream(Arc::clone(&core) as Arc<dyn AbortStream>);
        Self {
            id,
            core,
            session: Arc::downgrade(session),
        }
    }

    pub const fn id(&self) -> StreamId {
        self.id
    }

    pub fn stop(&mut self, error_code: u32) -> Result<(), Error> {
        self.stop_with_code(map_application_error(error_code))
    }

    pub(crate) fn stop_with_code(&mut self, code: Code) -> Result<(), Error> {
        if self.core.finished.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.core
            .reader
            .lock()
            .expect("WebTransport receive stream lock poisoned")
            .stop(code)
    }

    fn finish(&self) {
        self.core.finished.store(true, Ordering::Release);
        if let Some(session) = self.session.upgrade() {
            session.prune_streams();
        }
    }
}

impl Stream for RecvStream {
    type Item = Result<Bytes, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.core.finished.load(Ordering::Acquire) {
            return Poll::Ready(
                self.core
                    .error
                    .lock()
                    .expect("WebTransport receive error lock poisoned")
                    .take()
                    .map(Err),
            );
        }
        let polled = {
            let mut reader = self
                .core
                .reader
                .lock()
                .expect("WebTransport receive stream lock poisoned");
            Pin::new(&mut *reader).poll_next(cx)
        };
        match polled {
            Poll::Ready(None) => {
                self.finish();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                self.finish();
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        if !self.core.finished.load(Ordering::Acquire) {
            let _ = self.stop(0);
        }
        if let Some(session) = self.session.upgrade() {
            session.prune_streams();
        }
    }
}

struct SendCore {
    writer: Mutex<BoxWriter>,
    reliable_size: u64,
    finished: AtomicBool,
}

impl AbortStream for SendCore {
    fn abort(&self, code: Code) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            let _ = self
                .writer
                .lock()
                .expect("WebTransport send stream lock poisoned")
                .reset_at(code, self.reliable_size);
        }
    }

    fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
}

/// Send direction of a WebTransport data stream.
pub struct SendStream {
    id: StreamId,
    core: Arc<SendCore>,
    session: Weak<SessionState>,
}

impl std::fmt::Debug for SendStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendStream").field("id", &self.id).finish()
    }
}

impl SendStream {
    pub(crate) fn new(writer: BoxWriter, reliable_size: u64, session: &Arc<SessionState>) -> Self {
        let id = writer.id();
        let core = Arc::new(SendCore {
            writer: Mutex::new(writer),
            reliable_size,
            finished: AtomicBool::new(false),
        });
        session.register_stream(Arc::clone(&core) as Arc<dyn AbortStream>);
        Self {
            id,
            core,
            session: Arc::downgrade(session),
        }
    }

    pub const fn id(&self) -> StreamId {
        self.id
    }

    pub fn reset(&mut self, error_code: u32) -> Result<(), Error> {
        self.reset_with_code(map_application_error(error_code))
    }

    pub(crate) fn reset_with_code(&mut self, code: Code) -> Result<(), Error> {
        if self.core.finished.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.core
            .writer
            .lock()
            .expect("WebTransport send stream lock poisoned")
            .reset_at(code, self.core.reliable_size)
            .map_err(map_stream_error)
    }

    fn finish(&self) {
        self.core.finished.store(true, Ordering::Release);
        if let Some(session) = self.session.upgrade() {
            session.prune_streams();
        }
    }
}

impl Sink<Bytes> for SendStream {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.core.finished.load(Ordering::Acquire) {
            return Poll::Ready(Err(Error::stream(
                Some(Code::WT_SESSION_GONE),
                "WebTransport send stream is closed",
            )));
        }
        let polled = {
            let mut writer = self
                .core
                .writer
                .lock()
                .expect("WebTransport send stream lock poisoned");
            Pin::new(&mut **writer).poll_ready(cx)
        };
        polled.map_err(map_stream_error)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        if self.core.finished.load(Ordering::Acquire) {
            return Err(Error::stream(
                Some(Code::WT_SESSION_GONE),
                "WebTransport send stream is closed",
            ));
        }
        let mut writer = self
            .core
            .writer
            .lock()
            .expect("WebTransport send stream lock poisoned");
        Pin::new(&mut **writer)
            .start_send(item)
            .map_err(map_stream_error)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let polled = {
            let mut writer = self
                .core
                .writer
                .lock()
                .expect("WebTransport send stream lock poisoned");
            Pin::new(&mut **writer).poll_flush(cx)
        };
        polled.map_err(map_stream_error)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.core.finished.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        let polled = {
            let mut writer = self
                .core
                .writer
                .lock()
                .expect("WebTransport send stream lock poisoned");
            Pin::new(&mut **writer).poll_close(cx)
        };
        match polled {
            Poll::Ready(Ok(())) => {
                self.finish();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.finish();
                Poll::Ready(Err(map_stream_error(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        if !self.core.finished.load(Ordering::Acquire) {
            let _ = self.reset(0);
        }
        if let Some(session) = self.session.upgrade() {
            session.prune_streams();
        }
    }
}

fn map_stream_error(error: transport::StreamError) -> Error {
    let code = error.code();
    if error.is_connection() {
        Error::connection(
            code,
            "QUIC connection failed while using a WebTransport stream",
            error,
        )
    } else {
        let application = code.and_then(application_error_code);
        let message = match application {
            Some(_) => "WebTransport stream was reset by the peer",
            None => "WebTransport stream was reset with a protocol error",
        };
        Error::stream_with_source(code, message, error)
    }
}
