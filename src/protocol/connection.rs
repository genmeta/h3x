//! Connection supervision and request admission. Message processing lives in protocol::message.

use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::Bytes;
use dquic::prelude::{StreamReader, StreamWriter};
use futures::{
    FutureExt, SinkExt,
    future::{AbortHandle, AbortRegistration, Abortable, Shared, poll_fn},
};
use qbase::varint::{VarInt, WriteVarInt};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot, watch},
    task::JoinSet,
};

use crate::{
    BodyWriter, ChunkBody, Code, Error, Settings, StreamId,
    protocol::{
        headers,
        message::{self, MessageBody, MessageReader},
        request::ResponseFuture,
    },
    qpack,
    transport::{self, CloseOnDrop, ResetOnDrop},
    wire::{self, ChunkReader, FrameReader, FrameType, write_frame},
};
mod client;
mod server;
mod state;
#[cfg(test)]
mod tests;
pub use server::ResponseSender;
use state::*;

struct QueuedRequest {
    stream_id: StreamId,
    request_head: http::request::Parts,
    reader: MessageReader,
    message_body: MessageBody,
    writer: ResetOnDrop,
}
type ResponseReply = oneshot::Sender<Result<http::Response<ChunkBody>, Error>>;

const REQUEST_QUEUE_SIZE: usize = 256;
const MAX_CLASSIFYING: usize = 32;

/// HTTP/3 connection: request sending, serialized acceptance and graceful shutdown.
/// Share with Arc when needed; dropping the connection closes its transport.
pub struct Connection<T: transport::Connection> {
    inner: Arc<H3Connection<T>>,
    accepting: tokio::sync::Mutex<()>,
    control: Mutex<Option<StreamWriter>>,
}

struct H3Connection<T: transport::Connection> {
    transport: Arc<T>,
    qpack: Arc<qpack::Qpack>,
    tasks: ConnectionTasks,
    closed_rx: Shared<oneshot::Receiver<Result<(), Error>>>,
    // Boundary checks and request registration share one atomic update.
    state: Mutex<ConnectionState>,
    terminal: watch::Sender<Option<Error>>,
    state_changed: Notify,
    request_ready: Notify,
}

/// Adopts a transport and returns the HTTP/3 connection.
/// Protocol work runs in the background; Connection owns connection shutdown.
pub fn new<T: transport::Connection>(
    transport: T,
    mut settings: Settings,
) -> impl std::future::Future<Output = Result<Connection<T>, Error>> + crate::platform::MaybeSend {
    let transport = Arc::new(transport);
    let close_guard = CloseOnDrop(Some(transport.clone()), Code::H3_INTERNAL_ERROR);
    async move {
        if settings.max_field_section_size().is_none() {
            settings.set_max_field_section_size(Some(32 * 1024));
        }
        let mut settings_frame = Vec::new();
        wire::WriteFrame::put_frame(
            &mut settings_frame,
            &wire::frame::SettingsFrame {
                settings: settings.clone(),
            },
        )?;
        let (id, control) = transport.open_uni().await.map_err(map_connection_error)?;
        let mut control = prepare_critical(id, control, wire::StreamType::Control).await?;
        control
            .feed(Bytes::from(settings_frame))
            .await
            .map_err(wire::map_stream_error)?;
        let (id, encoder) = transport.open_uni().await.map_err(map_connection_error)?;
        let encoder = prepare_critical(id, encoder, wire::StreamType::QpackEncoder).await?;
        let (id, decoder) = transport.open_uni().await.map_err(map_connection_error)?;
        let decoder = prepare_critical(id, decoder, wire::StreamType::QpackDecoder).await?;
        let (inner, decoder, closed) =
            H3Connection::shared_state(transport, &settings, encoder, decoder);
        let root = inner.clone();
        tokio::spawn(async move {
            let _close = close_guard;
            root.run(decoder, closed).await;
        });
        Ok(Connection {
            inner,
            accepting: tokio::sync::Mutex::new(()),
            control: Mutex::new(Some(control)),
        })
    }
}

impl<T: transport::Connection> Connection<T> {
    /// The underlying QUIC connection, including its transport termination signal.
    /// HTTP requests use request()/request_streaming() to retain protocol checks.
    pub fn transport(&self) -> &T {
        &self.inner.transport
    }

    pub fn is_draining(&self) -> bool {
        self.inner.is_draining()
    }

    pub fn close(&self, code: Code, reason: &[u8]) {
        self.inner.close(code, reason);
    }

    pub async fn closed(&self) -> Result<(), Error> {
        self.inner
            .closed_rx
            .clone()
            .await
            .unwrap_or(Err(Error::OwnerStopped))
    }

    /// Starts graceful shutdown once. Later calls return InvalidState.
    /// Dropping this waiter does not cancel the shutdown; use closed() to wait again.
    pub async fn shutdown(&self) -> Result<(), Error> {
        let payload = self.inner.begin_shutdown()?;
        let control = self
            .control
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| Error::invalid_state("shutdown"))?;
        self.inner.tasks.spawn(
            self.inner.clone(),
            self.inner.clone().drain(control, payload),
        );
        self.closed().await
    }
}
impl<T: transport::Connection> Drop for Connection<T> {
    fn drop(&mut self) {
        self.close(Code::H3_NO_ERROR, b"connection dropped");
    }
}

impl<T: transport::Connection> H3Connection<T> {
    async fn drain(
        self: Arc<Self>,
        mut control: StreamWriter,
        payload: Bytes,
    ) -> Result<(), Error> {
        let sent = self
            .until_stopped(write_frame(&mut control, wire::FrameType::Goaway, payload))
            .await;
        if let Err(error) = sent {
            self.terminate(error.clone());
            return Err(error);
        }
        tokio::select! {
            _ = self.drained() => {},
            _ = stopped(&self.terminal) => {},
        }
        self.close(Code::H3_NO_ERROR, b"HTTP/3 drained");
        // The control stream must outlive the GOAWAY write and the drain wait.
        drop(control);
        Ok(())
    }

    async fn accept_uni_loop(self: &Arc<Self>) -> Result<(), Error> {
        let classifying = Arc::new(Semaphore::new(MAX_CLASSIFYING));
        let seen = Arc::new(std::array::from_fn(|_| AtomicBool::new(false)));
        loop {
            tokio::task::consume_budget().await;
            let (id, mut recv) = self
                .transport
                .accept_uni()
                .await
                .map_err(map_connection_error)?;
            let permit = classify_uni(&classifying, &mut recv)?;
            let inner = self.clone();
            let seen = seen.clone();
            self.tasks.spawn(self.clone(), async move {
                inner
                    .until_stopped(inner.handle_uni_stream(id, recv, permit, &seen))
                    .await
            });
        }
    }

    async fn handle_uni_stream(
        &self,
        id: StreamId,
        recv: StreamReader,
        classification: OwnedSemaphorePermit,
        peer_critical_seen: &[AtomicBool; 3],
    ) -> Result<(), Error> {
        let role = self.transport.role().map_err(map_connection_error)?;
        if u64::from(id) & 3 != ((!role) as u64 | 2) {
            return Err(Error::connection_protocol(
                Code::H3_STREAM_CREATION_ERROR,
                "invalid peer unidirectional stream ID",
            ));
        }
        let mut reader = ChunkReader::new(id, recv);
        let kind = reader.read_varint().await?.ok_or_else(|| {
            Error::connection_protocol(Code::H3_FRAME_ERROR, "missing unidirectional stream type")
        })?;
        let kind = wire::StreamType::from(kind);
        drop(classification);
        if register_critical(kind, peer_critical_seen)? {
            let result = match kind {
                wire::StreamType::Control => self.read_control_stream(reader).await,
                wire::StreamType::QpackEncoder => self.qpack.handle_encoder_stream(reader).await,
                wire::StreamType::QpackDecoder => self.qpack.handle_decoder_stream(reader).await,
                _ => unreachable!(),
            };
            return critical_result(result);
        }
        if kind == wire::StreamType::Push {
            return Err(Error::connection_protocol(
                if role == transport::Role::Server {
                    Code::H3_STREAM_CREATION_ERROR
                } else {
                    Code::H3_ID_ERROR
                },
                "server push not enabled",
            ));
        }
        // Unknown streams cannot hold an unbounded population of drain tasks.
        reader.stop(Code::H3_NO_ERROR)
    }

    async fn read_control_stream(&self, reader: ChunkReader) -> Result<(), Error> {
        let mut reader = FrameReader::new(reader);
        let first = reader.next_header().await?.ok_or_else(|| {
            Error::connection_protocol(Code::H3_CLOSED_CRITICAL_STREAM, "control stream closed")
        })?;
        if first.frame_type != FrameType::Settings {
            return Err(Error::connection_protocol(
                Code::H3_MISSING_SETTINGS,
                "first control frame must be SETTINGS",
            ));
        }
        let wire::Frame::Settings(frame) = reader
            .read(|input| crate::wire::frame::be_frame(input, first))
            .await?
        else {
            unreachable!()
        };
        let settings = frame.settings;
        self.qpack.apply_peer_settings(&settings).await?;
        let mut max_push = None;
        while let Some(header) = reader.next_header().await? {
            match header.frame_type {
                FrameType::Goaway => {
                    let wire::Frame::Goaway(frame) = reader
                        .read(|input| crate::wire::frame::be_frame(input, header))
                        .await?
                    else {
                        unreachable!()
                    };
                    self.on_peer_goaway(frame.id.into_u64())?;
                }
                FrameType::MaxPushId
                    if self.transport.role().map_err(map_connection_error)?
                        == transport::Role::Server =>
                {
                    let wire::Frame::MaxPushId(frame) = reader
                        .read(|input| crate::wire::frame::be_frame(input, header))
                        .await?
                    else {
                        unreachable!()
                    };
                    let value = frame.push_id.into_u64();
                    if max_push.is_some_and(|previous| value < previous) {
                        return Err(Error::connection_protocol(
                            Code::H3_ID_ERROR,
                            "MAX_PUSH_ID decreased",
                        ));
                    }
                    max_push = Some(value);
                }
                FrameType::CancelPush => {
                    reader
                        .read(|input| crate::wire::frame::be_frame(input, header))
                        .await?;
                    return Err(Error::connection_protocol(
                        Code::H3_ID_ERROR,
                        "no push was promised",
                    ));
                }
                FrameType::Unknown(_) => reader.discard_payload().await?,
                _ => {
                    return Err(Error::connection_protocol(
                        Code::H3_FRAME_UNEXPECTED,
                        "frame forbidden on control stream",
                    ));
                }
            }
        }
        Err(Error::connection_protocol(
            Code::H3_CLOSED_CRITICAL_STREAM,
            "control stream ended",
        ))
    }
}

impl<T: transport::Connection> H3Connection<T> {
    /// Body owns the reader; EOF, error or drop releases it and reports reading finished.
    pub(super) fn wrap_body(&self, reader: MessageReader, message_body: MessageBody) -> ChunkBody {
        let frames = futures::stream::unfold(
            (reader, message_body, self.terminal.clone()),
            |(mut reader, mut message_body, terminal)| async move {
                let result = tokio::select! {
                    biased;
                    error = stopped(&terminal) => Err(error),
                    result = reader.next_frame(&mut message_body) => result,
                };
                let frame = match result {
                    Ok(Some(frame)) => Ok(frame),
                    Ok(None) => return None,
                    Err(error) => Err(reader.fail(error)),
                };
                Some((frame, (reader, message_body, terminal)))
            },
        );
        ChunkBody::new(http_body_util::StreamBody::new(frames))
    }

    pub(super) fn shared_state(
        transport: Arc<T>,
        settings: &Settings,
        encoder: StreamWriter,
        decoder: StreamWriter,
    ) -> (
        Arc<Self>,
        qpack::DecoderWriter,
        oneshot::Sender<Result<(), Error>>,
    ) {
        let (closed, closed_rx) = oneshot::channel();
        let mut decoder_writer = None;
        let inner = Arc::new_cyclic(|weak: &std::sync::Weak<Self>| {
            let weak = weak.clone();
            let (qpack, writer) = qpack::Qpack::new(
                settings,
                encoder,
                decoder,
                Box::new(move |error| {
                    if let Some(connection) = weak.upgrade() {
                        connection.terminate(error);
                    }
                }),
            );
            decoder_writer = Some(writer);
            Self {
                transport,
                qpack,
                tasks: ConnectionTasks::default(),
                closed_rx: closed_rx.shared(),
                state: Mutex::new(ConnectionState::default()),
                terminal: watch::channel(None).0,
                state_changed: Notify::new(),
                request_ready: Notify::new(),
            }
        });
        (
            inner,
            decoder_writer.expect("QPACK writer initialized with connection"),
            closed,
        )
    }

    async fn run(
        self: Arc<Self>,
        decoder: qpack::DecoderWriter,
        closed: oneshot::Sender<Result<(), Error>>,
    ) {
        if std::panic::AssertUnwindSafe(async {
            let inner = self.clone();
            self.tasks.spawn(self.clone(), async move {
                inner.until_stopped(decoder.run()).await
            });
            let result = tokio::select! {
                error = stopped(&self.terminal) => Err(error),
                error = self.transport.closed() => Err(map_connection_error(error)),
                result = self.accept_requests() => result,
                result = self.accept_uni_loop() => result,
                _ = self.tasks.reap(&self) => unreachable!(),
            };
            if let Err(error) = result {
                self.terminate(error);
            }
        })
        .catch_unwind()
        .await
        .is_err()
        {
            self.terminate(Error::OwnerStopped);
        }
        let error = self.failure();
        self.transport.close(
            error.code().unwrap_or(Code::H3_INTERNAL_ERROR),
            error.to_string().as_bytes(),
        );
        self.qpack.fail(error);
        self.tasks.join(&self).await;
        let error = self.failure();
        let _ = closed.send(if error.code() == Some(Code::H3_NO_ERROR) {
            Ok(())
        } else {
            Err(error)
        });
    }
}

// The accept loop polls completions; after it exits, the root joins the remainder.
#[derive(Default)]
struct ConnectionTasks {
    pub(super) running: Mutex<JoinSet<()>>,
    pub(super) added: Notify,
}

impl ConnectionTasks {
    pub(super) fn spawn<T: transport::Connection, F>(
        &self,
        connection: Arc<H3Connection<T>>,
        work: F,
    ) where
        F: Future<Output = Result<(), Error>> + Send + 'static,
    {
        self.running.lock().unwrap().spawn(async move {
            if let Err(error) = work.await
                && error.is_connection()
            {
                connection.terminate(error);
            }
        });
        self.added.notify_one();
    }

    pub(super) async fn reap<T: transport::Connection>(&self, connection: &H3Connection<T>) {
        loop {
            tokio::select! {
                result = poll_fn(|cx| {
                    let mut running = self.running.lock().unwrap();
                    if running.is_empty() {
                        std::task::Poll::Pending
                    } else {
                        running.poll_join_next(cx)
                    }
                }) => {
                    if let Some(Err(_)) = result {
                        connection.terminate(Error::OwnerStopped);
                    }
                },
                _ = self.added.notified() => {},
            }
        }
    }

    pub(super) async fn join<T: transport::Connection>(&self, connection: &H3Connection<T>) {
        loop {
            let result = poll_fn(|cx| self.running.lock().unwrap().poll_join_next(cx)).await;
            match result {
                None => break,
                Some(Err(_)) => connection.terminate(Error::OwnerStopped),
                _ => {}
            }
        }
    }
}

pub(super) fn map_connection_error(error: transport::ConnectionError) -> Error {
    Error::connection(error.code(), "QUIC connection failed", error)
}

pub(super) async fn prepare_critical(
    id: StreamId,
    mut stream: StreamWriter,
    kind: wire::StreamType,
) -> Result<StreamWriter, Error> {
    if u64::from(id) & 2 == 0 {
        return Err(Error::connection_protocol(
            Code::H3_STREAM_CREATION_ERROR,
            "open_uni returned a bidirectional stream",
        ));
    }
    let mut header = Vec::new();
    header.put_varint(&VarInt::try_from(u64::from(kind)).expect("known critical stream type"));
    stream
        .feed(Bytes::from(header))
        .await
        .map_err(wire::map_stream_error)?;
    Ok(stream)
}

pub(super) fn classify_uni(
    classifying: &Arc<Semaphore>,
    recv: &mut StreamReader,
) -> Result<OwnedSemaphorePermit, Error> {
    classifying.clone().try_acquire_owned().map_err(|_| {
        dquic::prelude::StopSending::stop(recv, Code::H3_EXCESSIVE_LOAD.as_u64());
        Error::connection_protocol(
            Code::H3_EXCESSIVE_LOAD,
            "too many unclassified unidirectional streams",
        )
    })
}

pub(super) fn register_critical(
    kind: wire::StreamType,
    seen: &[AtomicBool; 3],
) -> Result<bool, Error> {
    let index = match kind {
        wire::StreamType::Control => 0,
        wire::StreamType::QpackEncoder => 1,
        wire::StreamType::QpackDecoder => 2,
        _ => return Ok(false),
    };
    if seen[index].swap(true, Ordering::Relaxed) {
        return Err(Error::connection_protocol(
            Code::H3_STREAM_CREATION_ERROR,
            "duplicate critical stream",
        ));
    }
    Ok(true)
}

pub(super) fn critical_result(result: Result<(), Error>) -> Result<(), Error> {
    match result {
        Err(error) if error.is_stream() => Err(Error::connection(
            Some(Code::H3_CLOSED_CRITICAL_STREAM),
            "critical stream reset",
            error,
        )),
        Ok(()) => Err(Error::connection_protocol(
            Code::H3_CLOSED_CRITICAL_STREAM,
            "critical stream ended",
        )),
        other => other,
    }
}

impl<T: transport::Connection> H3Connection<T> {
    pub(super) fn close(&self, code: Code, reason: &[u8]) {
        self.transport.close(code, reason);
        self.terminate(Error::connection(
            code.into(),
            "local connection close",
            transport::ConnectionError::application(code, Bytes::copy_from_slice(reason)),
        ));
    }

    pub(super) async fn until_stopped<V>(
        &self,
        work: impl Future<Output = Result<V, Error>>,
    ) -> Result<V, Error> {
        let result = tokio::select! {
            error = stopped(&self.terminal) => Err(error),
            result = work => result,
        };
        self.check(result)
    }
}

pub(super) async fn cancel_on_abort<V>(
    work: impl Future<Output = Result<V, Error>>,
    registration: futures::future::AbortRegistration,
) -> Result<V, Error> {
    Abortable::new(work, registration)
        .await
        .unwrap_or(Err(Error::Cancelled))
}
