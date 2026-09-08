//! Connection supervision and stream admission. Frame/message loops live in stream.

use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::Bytes;
use futures::{
    FutureExt, SinkExt,
    future::{AbortHandle, Abortable, Shared, poll_fn},
};
use http_body::Body;
use http_body_util::BodyExt;
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
};

use crate::{
    BodyWriter, ChunkBody, Code, Error, Settings, StreamId,
    platform::{BoxFuture, MaybeSend},
    protocol::{headers, request::ResponseFuture},
    qpack,
    transport::{self, PendingTransport, RecvStream, SendStream},
    wire::{self, ChunkReader, FrameReader, FrameType},
};
mod stream;
pub use stream::ResponseSender;
use stream::{MessageReader, Outgoing, ResetOnDrop, write_frame};

type Completion = Shared<BoxFuture<'static, Result<(), Error>>>;
type IncomingRequest = (
    http::Request<ChunkBody>,
    ResponseSender,
    oneshot::Sender<()>,
);
type ResponseReply = oneshot::Sender<Result<http::Response<ChunkBody>, Error>>;
type BoxSend = Box<dyn transport::SendStream>;
const MAX_REQUESTS: usize = 256;
const MAX_CLASSIFYING: usize = 32;

#[derive(Default)]
struct Goaway {
    local_boundary: Option<u64>,
    peer_boundary: Option<StreamId>,
    max_delivered: Option<StreamId>,
}
impl Goaway {
    fn delivered(&mut self, id: StreamId) {
        self.max_delivered = Some(self.max_delivered.map_or(id, |previous| previous.max(id)));
    }

    fn begin_shutdown(&mut self) -> Result<u64, Error> {
        if self.local_boundary.is_some() {
            return Err(Error::invalid_state("shutdown"));
        }
        let boundary = self
            .max_delivered
            .map_or(Some(0), |id| u64::from(id).checked_add(4))
            .filter(|v| *v <= crate::stream_id::MAX_VARINT)
            .ok_or_else(|| {
                Error::connection_protocol(Code::H3_ID_ERROR, "GOAWAY boundary overflow")
            })?;
        self.local_boundary = Some(boundary);
        Ok(boundary)
    }

    fn received(&mut self, boundary: StreamId) -> Result<(), Error> {
        if self
            .peer_boundary
            .is_some_and(|previous| boundary > previous)
        {
            return Err(Error::connection_protocol(
                Code::H3_ID_ERROR,
                "GOAWAY boundary increased",
            ));
        }
        self.peer_boundary = Some(boundary);
        Ok(())
    }
}

#[derive(Default)]
struct Requests {
    incoming: HashMap<StreamId, AbortHandle>,
    responses: HashMap<StreamId, (ResponseReply, AbortHandle)>,
}
impl Requests {
    fn cancel_incoming(&mut self) {
        for (_, stop) in self.incoming.drain() {
            stop.abort();
        }
    }

    fn fail(&mut self, error: &Error) {
        self.cancel_incoming();
        for (_, (reply, stop)) in self.responses.drain() {
            let _ = reply.send(Err(error.clone()));
            stop.abort();
        }
    }

    fn reject_from(&mut self, boundary: StreamId) {
        let covered: Vec<_> = self
            .responses
            .keys()
            .copied()
            .filter(|id| *id >= boundary)
            .collect();
        for id in covered {
            if let Some((reply, stop)) = self.responses.remove(&id) {
                let _ = reply.send(Err(Error::Goaway { boundary }));
                stop.abort();
            }
        }
    }
}

/// Cloneable capability for initiating requests on a symmetric HTTP/3 connection.
/// Dropping a sender does not close the connection; Connection owns its lifetime.
pub struct Sender<T: transport::Connection> {
    inner: Arc<Inner<T>>,
}
impl<T: transport::Connection> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// HTTP/3 connection owner with exclusive request acceptance and graceful shutdown.
/// Keep this owner alive while using Sender; dropping it closes the connection.
pub struct Connection<T: transport::Connection> {
    inner: Arc<Inner<T>>,
    incoming: mpsc::Receiver<IncomingRequest>,
    control: Option<BoxSend>,
}

struct Inner<T: transport::Connection> {
    transport: Arc<T>,
    role: u64,
    qpack: Arc<qpack::Qpack>,
    state: Arc<ConnectionState>,
    tasks: ConnectionTasks,
    completion: Completion,
}

// Connection shutdown state and terminal notification share one close transition.
pub(crate) struct ConnectionState {
    // Boundary checks and request registration share one atomic update.
    active: Mutex<Option<(Goaway, Requests)>>,
    terminal: watch::Sender<Option<Error>>,
    requests: Arc<Semaphore>,
}
impl ConnectionState {
    pub(crate) fn new() -> Self {
        Self {
            active: Mutex::new(Some((Goaway::default(), Requests::default()))),
            terminal: watch::channel(None).0,
            requests: Arc::new(Semaphore::new(MAX_REQUESTS)),
        }
    }

    fn failure(&self) -> Error {
        self.terminal
            .borrow()
            .clone()
            .unwrap_or(Error::OwnerStopped)
    }

    fn is_draining(&self) -> bool {
        self.active
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|(goaway, _)| {
                goaway.local_boundary.is_some() || goaway.peer_boundary.is_some()
            })
    }

    // Record the first terminal error and wake the driver to close the transport.
    pub(crate) fn terminate(&self, error: Error) {
        let mut active = self.active.lock().unwrap();
        let Some((_, mut requests)) = active.take() else {
            return;
        };
        requests.fail(&error);
        self.terminal.send_replace(Some(error));
    }

    async fn drained(&self) {
        tokio::select! {
            _ = self.requests.acquire_many(MAX_REQUESTS as u32) => {},
            _ = stopped(&self.terminal) => {},
        }
    }
}

// The accept loop polls completions; after it exits, the root joins the remainder.
#[derive(Default)]
struct ConnectionTasks {
    running: Mutex<JoinSet<()>>,
    added: Notify,
}
impl ConnectionTasks {
    fn spawn(
        &self,
        state: Arc<ConnectionState>,
        work: impl Future<Output = Result<(), Error>> + Send + 'static,
    ) {
        self.running.lock().unwrap().spawn(async move {
            if let Err(error) = work.await
                && error.is_connection()
            {
                state.terminate(error);
            }
        });
        self.added.notify_one();
    }

    async fn reap(&self, state: &ConnectionState) {
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
                    state.terminate(Error::OwnerStopped);
                }
            },
            _ = self.added.notified() => {},
        }
    }

    async fn join(&self, state: &ConnectionState) {
        loop {
            let result = poll_fn(|cx| self.running.lock().unwrap().poll_join_next(cx)).await;
            match result {
                None => break,
                Some(Err(_)) => state.terminate(Error::OwnerStopped),
                _ => {}
            }
        }
    }
}

// Created before the first await, and moved into the root future before spawning.
struct CloseOnDrop<T: transport::Connection>(Arc<T>);
impl<T: transport::Connection> Drop for CloseOnDrop<T> {
    fn drop(&mut self) {
        self.0
            .close(Code::H3_INTERNAL_ERROR, b"protocol owner stopped");
    }
}

/// Adopts a transport and returns its sending and receiving capabilities.
/// Protocol work runs in the background; Connection owns connection shutdown.
pub async fn new<T: transport::Connection>(
    mut pending: PendingTransport<T>,
    mut settings: Settings,
) -> Result<(Sender<T>, Connection<T>), Error> {
    let transport = Arc::new(pending.transport.take().expect("unadopted transport"));
    let close_guard = CloseOnDrop(transport.clone());
    let role = match transport.role().map_err(map_connection_error)? {
        transport::Role::Client => 0,
        transport::Role::Server => 1,
    };
    if settings.max_field_section_size().is_none() {
        settings.set_max_field_section_size(Some(32 * 1024));
    }
    let settings_frame = wire::encode_settings_frame(&settings)?;
    let mut control = open_critical(&*transport, wire::CONTROL_STREAM_TYPE).await?;
    control
        .send(settings_frame)
        .await
        .map_err(wire::map_stream_error)?;
    let encoder = open_critical(&*transport, wire::QPACK_ENCODER_STREAM_TYPE).await?;
    let decoder = open_critical(&*transport, wire::QPACK_DECODER_STREAM_TYPE).await?;
    let connection_state = Arc::new(ConnectionState::new());
    let (qpack, decoder) = qpack::Qpack::new(&settings, encoder, decoder, connection_state.clone());
    let (finished, completion) = oneshot::channel();
    let inner = Arc::new(Inner {
        transport,
        role,
        qpack,
        state: connection_state,
        tasks: ConnectionTasks::default(),
        completion: async move { completion.await.unwrap_or(Err(Error::OwnerStopped)) }
            .boxed()
            .shared(),
    });
    let (incoming, requests) = mpsc::channel(MAX_REQUESTS);
    let root = inner.clone();
    tokio::spawn(async move {
        let _close = close_guard;
        let result = std::panic::AssertUnwindSafe(root.clone().accept_streams(incoming, decoder))
            .catch_unwind()
            .await;
        if result.is_err() {
            root.state.terminate(Error::OwnerStopped);
        }
        let error = root.state.failure();
        root.transport.close(
            error.code().unwrap_or(Code::H3_INTERNAL_ERROR),
            error.to_string().as_bytes(),
        );
        root.qpack.fail(error);
        root.tasks.join(&root.state).await;
        let error = root.state.failure();
        let _ = finished.send(if error.code() == Some(Code::H3_NO_ERROR) {
            Ok(())
        } else {
            Err(error)
        });
    });
    Ok((
        Sender {
            inner: inner.clone(),
        },
        Connection {
            inner,
            incoming: requests,
            control: Some(control),
        },
    ))
}

impl<T: transport::Connection> Sender<T> {
    pub async fn request<B>(
        &self,
        request: http::Request<B>,
    ) -> Result<http::Response<ChunkBody>, Error>
    where
        B: Body<Data = Bytes> + MaybeSend + 'static,
        B::Error: Into<crate::BoxError>,
    {
        let (parts, body) = request.into_parts();
        headers::validate_request(&parts).map_err(Error::into_invalid_message)?;
        let message_body = stream::request_body(&parts)?;
        message_body.validate_size(body.size_hint())?;
        let (response, upload_stop) = self
            .inner
            .start_request(
                parts,
                Outgoing::Body(
                    body.map_err(|e| Error::Body {
                        source: Arc::from(e.into()),
                    })
                    .boxed_unsync(),
                ),
            )
            .await?;
        let mut cancellation = AbortOnDrop(Some(upload_stop));
        let result = response.await;
        if result.is_ok() {
            cancellation.0.take();
        } // Final delivery leaves upload independently owned.
        result
    }

    pub async fn request_streaming(
        &self,
        parts: http::request::Parts,
    ) -> Result<(BodyWriter, ResponseFuture), Error> {
        headers::validate_request(&parts).map_err(Error::into_invalid_message)?;
        let (writer, upload) = BodyWriter::channel();
        let (response, _) = self
            .inner
            .start_request(parts, Outgoing::Upload(upload))
            .await?;
        Ok((writer, response))
    }

    pub fn is_draining(&self) -> bool {
        self.inner.state.is_draining()
    }

    pub fn close(&self, code: Code, reason: &[u8]) {
        self.inner.close(code, reason);
    }

    pub async fn closed(&self) -> Result<(), Error> {
        self.inner.completion.clone().await
    }
}

impl<T: transport::Connection> Connection<T> {
    pub async fn accept(
        &mut self,
    ) -> Result<Option<(http::Request<ChunkBody>, ResponseSender)>, Error> {
        loop {
            let next = tokio::select! {
                biased;
                error = stopped(&self.inner.state.terminal) => {
                    return if error.code() == Some(Code::H3_NO_ERROR) {
                        Ok(None)
                    } else {
                        Err(error)
                    };
                },
                next = self.incoming.recv() => next,
            };
            let Some((request, response, delivered)) = next else {
                return Ok(None);
            };
            let mut lock = self.inner.state.active.lock().unwrap();
            let Some((goaway, requests)) = lock.as_mut() else {
                return Err(self.inner.state.failure());
            };
            let id = response.stream_id;
            if goaway
                .local_boundary
                .is_some_and(|boundary| u64::from(id) >= boundary)
            {
                continue;
            }
            if delivered.send(()).is_err() {
                continue;
            }
            requests.incoming.remove(&id);
            goaway.delivered(id);
            return Ok(Some((request, response)));
        }
    }

    pub fn is_draining(&self) -> bool {
        self.inner.state.is_draining()
    }

    pub fn close(&self, code: Code, reason: &[u8]) {
        self.inner.close(code, reason);
    }

    pub async fn closed(&self) -> Result<(), Error> {
        self.inner.completion.clone().await
    }

    /// Starts graceful shutdown once. Later calls return InvalidState.
    /// Dropping this waiter does not cancel the shutdown; use closed() to wait again.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        {
            let mut lock = self.inner.state.active.lock().unwrap();
            let (goaway, requests) = lock
                .as_mut()
                .ok_or_else(|| Error::invalid_state("shutdown"))?;
            let value = goaway.begin_shutdown()?;
            requests.cancel_incoming();
            let mut payload = Vec::new();
            wire::encode_varint(value, &mut payload)?;
            let mut control = self
                .control
                .take()
                .ok_or_else(|| Error::invalid_state("shutdown"))?;
            let inner = self.inner.clone();
            self.inner.tasks.spawn(self.inner.state.clone(), async move {
                let result = tokio::select! {
                    error = stopped(&inner.state.terminal) => Err(error),
                    result = write_frame(&mut control, wire::GOAWAY_FRAME_TYPE, Bytes::from(payload)) => result,
                };
                if let Err(error) = result {
                    inner.state.terminate(error);
                    return Ok(());
                }
                inner.state.drained().await;
                inner.close(Code::H3_NO_ERROR, b"HTTP/3 drained");
                // Keep the critical stream alive until the connection is closed.
                drop(control);
                Ok(())
            });
        }
        self.closed().await
    }
}
impl<T: transport::Connection> Drop for Connection<T> {
    fn drop(&mut self) {
        self.close(Code::H3_NO_ERROR, b"connection dropped");
    }
}

struct AbortOnDrop(Option<AbortHandle>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(stop) = self.0.take() {
            stop.abort();
        }
    }
}

impl<T: transport::Connection> Inner<T> {
    fn close(&self, code: Code, reason: &[u8]) {
        self.transport.close(code, reason);
        self.state.terminate(Error::connection(
            code.into(),
            "local connection close",
            transport::ConnectionError::application(code, Bytes::copy_from_slice(reason)),
        ));
    }

    fn check<V>(&self, result: Result<V, Error>) -> Result<V, Error> {
        if let Err(error) = &result
            && error.is_connection()
        {
            self.state.terminate(error.clone());
        }
        result
    }

    async fn start_request(
        self: &Arc<Self>,
        parts: http::request::Parts,
        outgoing: Outgoing,
    ) -> Result<(ResponseFuture, AbortHandle), Error> {
        let message_body = stream::request_body(&parts).map_err(Error::into_invalid_message)?;
        let method = parts.method.clone();
        let fields = headers::request_fields(parts).map_err(Error::into_invalid_message)?;
        let permit = {
            let lock = self.state.active.lock().unwrap();
            let (goaway, _) = lock.as_ref().ok_or_else(|| self.state.failure())?;
            if let Some(boundary) = goaway.peer_boundary {
                return Err(Error::Goaway { boundary });
            }
            if goaway.local_boundary.is_some() {
                return Err(Error::Draining);
            }
            self.state
                .requests
                .clone()
                .try_acquire_owned()
                .map(Arc::new)
                .map_err(|_| Error::Capacity)?
        };
        let (stream_id, (mut recv, mut send)) = tokio::select! {
            error = stopped(&self.state.terminal) => return Err(error),
            pair = self.transport.open_bi() => self.check(pair.map_err(map_connection_error))?,
        };
        self.check(validate_pair(stream_id, &mut recv, &mut send, self.role))?;
        let reader = MessageReader::new(
            ChunkReader::new(stream_id, recv),
            self.qpack.clone(),
            stream_id,
            self.state.clone(),
        );
        let mut writer = ResetOnDrop::new(Box::new(send));
        let (reply, receive) = oneshot::channel();
        let (recv_stop, recv_registration) = AbortHandle::new_pair();
        let mut cancel_receive = AbortOnDrop(Some(recv_stop.clone()));
        {
            let mut lock = self.state.active.lock().unwrap();
            let (goaway, requests) = lock.as_mut().ok_or_else(|| self.state.failure())?;
            if goaway.local_boundary.is_some() {
                return Err(Error::Draining);
            }
            if let Some(boundary) = goaway.peer_boundary
                && stream_id >= boundary
            {
                return Err(Error::Goaway { boundary });
            }
            requests
                .responses
                .insert(stream_id, (reply, recv_stop.clone()));
        }
        let pending = PendingResponse {
            connection_state: self.state.clone(),
            stream_id,
        };
        tokio::select! {
            error = stopped(&self.state.terminal) => return Err(error),
            result = stream::send_request_headers(&mut writer, &self.qpack, stream_id, fields) => self.check(result)?,
        }
        // A GOAWAY received during the initial write must win before pair delivery.
        // Keep connection state locked through registration of both direction tasks.
        let connection_state = self.state.active.lock().unwrap();
        let (goaway, requests) = connection_state
            .as_ref()
            .ok_or_else(|| self.state.failure())?;
        if !requests.responses.contains_key(&stream_id) {
            return Err(goaway
                .peer_boundary
                .map_or(Error::Draining, |boundary| Error::Goaway { boundary }));
        }
        let (upload_stop, upload_registration) = AbortHandle::new_pair();
        let inner = self.clone();
        let upload_permit = permit.clone();
        self.tasks.spawn(self.state.clone(), async move {
            let _permit = upload_permit;
            let result = match outgoing {
                Outgoing::Body(body) => {
                    let work =
                        stream::send_body(&mut writer, body, message_body, &inner.qpack, stream_id);
                    tokio::select! {
                        error = stopped(&inner.state.terminal) => Err(error),
                        result = Abortable::new(work, upload_registration) => {
                            result.unwrap_or(Err(Error::Cancelled))
                        }
                    }
                }
                Outgoing::Upload(mut upload) => {
                    let work = stream::send_upload(
                        &mut writer,
                        &mut upload,
                        message_body,
                        &inner.qpack,
                        stream_id,
                    );
                    let result = tokio::select! {
                        error = stopped(&inner.state.terminal) => Err(error),
                        result = Abortable::new(work, upload_registration) => {
                            result.unwrap_or(Err(Error::Cancelled))
                        }
                    };
                    upload.complete(result.clone());
                    result
                }
            };
            if let Err(error) = &result {
                writer.reset(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
                let mut lock = inner.state.active.lock().unwrap();
                if let Some((_, requests)) = lock.as_mut()
                    && let Some((reply, stop)) = requests.responses.remove(&stream_id)
                {
                    let _ = reply.send(Err(error.clone()));
                    stop.abort();
                }
            }
            result
        });
        let inner = self.clone();
        self.tasks.spawn(self.state.clone(), async move {
            let _pending = pending;
            let work = async {
                let mut reader = reader;
                let head = tokio::select! {
                    error = stopped(&inner.state.terminal) => Err(error),
                    head = reader.response(&method) => head,
                };
                let (parts, message_body) = match head {
                    Ok(value) => value,
                    Err(error) => {
                        if let Some((_, requests)) = inner.state.active.lock().unwrap().as_mut()
                            && let Some((reply, _)) = requests.responses.remove(&stream_id)
                        {
                            let _ = reply.send(Err(error.clone()));
                        }
                        return Err(error);
                    }
                };
                let body = reader.into_body(message_body, inner.state.terminal.clone(), permit);
                let mut response = http::Response::from_parts(parts, body);
                response.extensions_mut().insert(stream_id);
                let delivery = {
                    let mut lock = inner.state.active.lock().unwrap();
                    let (_, requests) = lock.as_mut().ok_or_else(|| inner.state.failure())?;
                    let Some((reply, _)) = requests.responses.remove(&stream_id) else {
                        return Ok(());
                    };
                    reply.send(Ok(response))
                };
                // Dropping an undelivered Body can report QPACK errors; release the connection state lock first.
                drop(delivery);
                Ok(())
            };
            Abortable::new(work, recv_registration)
                .await
                .unwrap_or(Ok(()))
        });
        drop(connection_state);
        cancel_receive.0.take();
        Ok((
            ResponseFuture {
                reply: receive,
                stop: Some(recv_stop),
            },
            upload_stop,
        ))
    }

    async fn accept_streams(
        self: Arc<Self>,
        incoming: mpsc::Sender<IncomingRequest>,
        decoder: qpack::DecoderWriter,
    ) {
        let bidi = Arc::new(Semaphore::new(MAX_CLASSIFYING));
        let uni = Arc::new(Semaphore::new(MAX_CLASSIFYING));
        // Peer control, QPACK encoder, QPACK decoder; registration never resets.
        let peer_critical_seen = Arc::new(std::array::from_fn(|_| AtomicBool::new(false)));
        let inner = self.clone();
        self.tasks.spawn(self.state.clone(), async move {
            tokio::select! {
                _ = stopped(&inner.state.terminal) => Ok(()),
                result = decoder.run() => result,
            }
        });
        loop {
            tokio::select! {
                _ = stopped(&self.state.terminal) => break,
                error = self.transport.closed() => {
                    self.state.terminate(map_connection_error(error));
                    break;
                },
                _ = self.tasks.reap(&self.state) => {},
                pair = self.transport.accept_bi() => match pair {
                    Ok((id, (mut recv, mut send))) => {
                        let permit = bidi.clone().try_acquire_owned();
                        match permit {
                            Ok(permit) => {
                                let inner = self.clone();
                                let incoming = incoming.clone();
                                self.tasks.spawn(self.state.clone(), async move {
                                    inner.handle_bidi_stream(id, recv, send, incoming, permit).await
                                });
                            },
                            Err(_) => {
                                let _ = recv.stop(Code::H3_REQUEST_REJECTED);
                                let _ = send.reset(Code::H3_REQUEST_REJECTED);
                            }
                        }
                    },
                    Err(error) => self.state.terminate(map_connection_error(error)),
                },
                stream = self.transport.accept_uni() => match stream {
                    Ok((id, mut recv)) => match uni.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let inner = self.clone();
                            let peer_critical_seen = peer_critical_seen.clone();
                            self.tasks.spawn(self.state.clone(), async move {
                                tokio::select! {
                                    _ = stopped(&inner.state.terminal) => Ok(()),
                                    result = inner.handle_uni_stream(id, recv, permit, &peer_critical_seen) => result,
                                }
                            });
                        },
                        Err(_) => {
                            let _ = recv.stop(Code::H3_EXCESSIVE_LOAD);
                            self.state.terminate(Error::connection_protocol(
                                Code::H3_EXCESSIVE_LOAD,
                                "too many unclassified unidirectional streams",
                            ));
                        }
                    },
                    Err(error) => self.state.terminate(map_connection_error(error)),
                },
            }
        }
    }

    async fn handle_bidi_stream(
        self: Arc<Self>,
        id: StreamId,
        mut recv: T::RecvStream,
        mut send: T::SendStream,
        incoming: mpsc::Sender<IncomingRequest>,
        classification: OwnedSemaphorePermit,
    ) -> Result<(), Error> {
        validate_pair(id, &mut recv, &mut send, self.role ^ 1)?;
        let mut reader = ChunkReader::new(id, recv);
        let mut writer = ResetOnDrop::new(Box::new(send));
        let first = tokio::select! {
            _ = stopped(&self.state.terminal) => return Ok(()),
            result = reader.read_varint_opt() => result?,
        };
        let Some(first) = first else {
            return Ok(());
        };
        #[cfg(feature = "webtransport")]
        if first == wire::WEBTRANSPORT_BIDI_SIGNAL {
            let _session = tokio::select! {
                _ = stopped(&self.state.terminal) => return Ok(()),
                id = reader.read_varint() => id?,
            };
            // No WT transport hooks are attached to a plain HTTP connection.
            reader.stop(Code::WT_BUFFERED_STREAM_REJECTED)?;
            writer.reset(Code::WT_BUFFERED_STREAM_REJECTED);
            return Ok(());
        }
        let permit = match self
            .state
            .requests
            .clone()
            .try_acquire_owned()
            .map(Arc::new)
            .map_err(|_| Error::Capacity)
        {
            Ok(permit) => permit,
            Err(_) => {
                reader.stop(Code::H3_REQUEST_REJECTED)?;
                writer.reset(Code::H3_REQUEST_REJECTED);
                return Ok(());
            }
        };
        drop(classification);
        let (stop, registration) = AbortHandle::new_pair();
        {
            let mut lock = self.state.active.lock().unwrap();
            let (goaway, requests) = lock.as_mut().ok_or_else(|| self.state.failure())?;
            if goaway.local_boundary.is_some() {
                writer.reset(Code::H3_REQUEST_REJECTED);
                reader.stop(Code::H3_REQUEST_REJECTED)?;
                return Ok(());
            }
            requests.incoming.insert(id, stop);
        }
        let _pending = PendingIncoming {
            connection_state: self.state.clone(),
            stream_id: id,
        };
        Abortable::new(
            self.resolve_request(reader, writer, id, first, incoming, permit),
            registration,
        )
        .await
        .unwrap_or(Ok(()))
    }

    async fn resolve_request(
        self: &Arc<Self>,
        reader: ChunkReader,
        writer: ResetOnDrop,
        id: StreamId,
        first: u64,
        incoming: mpsc::Sender<IncomingRequest>,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Result<(), Error> {
        let mut reader = MessageReader::new(reader, self.qpack.clone(), id, self.state.clone());
        let (parts, message_body) = tokio::select! {
            _ = stopped(&self.state.terminal) => return Ok(()),
            result = reader.request(first) => result?,
        };
        let method = parts.method.clone();
        let body = reader.into_body(message_body, self.state.terminal.clone(), permit.clone());
        let mut request = http::Request::from_parts(parts, body);
        request.extensions_mut().insert(id);
        let (respond, response) = oneshot::channel();
        let (sent, receipt) = oneshot::channel();
        let (send_stop, send_registration) = AbortHandle::new_pair();
        let sender = ResponseSender {
            stream_id: id,
            method: method.clone(),
            response: Some(respond),
            sent: receipt,
            stop: Some(send_stop),
        };
        let (delivered, accepted) = oneshot::channel();
        {
            let lock = self.state.active.lock().unwrap();
            let (goaway, _) = lock.as_ref().ok_or_else(|| self.state.failure())?;
            if goaway
                .local_boundary
                .is_some_and(|boundary| u64::from(id) >= boundary)
            {
                return Ok(());
            }
        }
        tokio::select! {
            _ = stopped(&self.state.terminal) => return Ok(()),
            result = incoming.send((request, sender, delivered)) => {
                if result.is_err() {
                    return Ok(());
                }
            }
        }
        tokio::select! {
            _ = stopped(&self.state.terminal) => return Ok(()),
            result = accepted => if result.is_err() {
                return Ok(());
            }
        }
        let _permit = permit;
        let work = async {
            let mut writer = writer;
            let result = tokio::select! {
                error = stopped(&self.state.terminal) => Err(error),
                result = async {
                    let response = response.await.map_err(|_| Error::Cancelled)?;
                    stream::send_response(&mut writer, response, &method, &self.qpack, id).await
                } => result,
            };
            if let Err(error) = &result
                && error.is_connection()
            {
                self.state.terminate(error.clone());
            }
            let _ = sent.send(result.clone());
            result
        };
        Abortable::new(work, send_registration)
            .await
            .unwrap_or(Ok(()))
    }

    async fn handle_uni_stream(
        &self,
        id: StreamId,
        recv: T::RecvStream,
        classification: OwnedSemaphorePermit,
        peer_critical_seen: &[AtomicBool; 3],
    ) -> Result<(), Error> {
        if u64::from(id) & 3 != (self.role ^ 1) | 2 {
            return Err(Error::connection_protocol(
                Code::H3_STREAM_CREATION_ERROR,
                "invalid peer unidirectional stream ID",
            ));
        }
        let mut reader = ChunkReader::new(id, recv);
        let kind = reader.read_varint().await?;
        drop(classification);
        let critical = match kind {
            wire::CONTROL_STREAM_TYPE => Some(0),
            wire::QPACK_ENCODER_STREAM_TYPE => Some(1),
            wire::QPACK_DECODER_STREAM_TYPE => Some(2),
            _ => None,
        };
        if let Some(index) = critical {
            if peer_critical_seen[index].swap(true, Ordering::Relaxed) {
                return Err(Error::connection_protocol(
                    Code::H3_STREAM_CREATION_ERROR,
                    "duplicate critical stream",
                ));
            }
            let result = match index {
                0 => self.read_control_stream(reader).await,
                1 => self.qpack.handle_encoder_stream(reader).await,
                _ => self.qpack.handle_decoder_stream(reader).await,
            };
            return match result {
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
            };
        }
        if kind == wire::PUSH_STREAM_TYPE {
            return Err(Error::connection_protocol(
                if self.role == 1 {
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
        let settings = wire::decode_settings_payload(
            &reader
                .read_payload(wire::MAX_BUFFERED_FRAME_PAYLOAD)
                .await?,
        )?;
        self.qpack.apply_peer_settings(&settings).await?;
        let mut max_push = None;
        while let Some(header) = reader.next_header().await? {
            match header.frame_type {
                FrameType::Goaway => {
                    let value = reader.read_id_payload().await?;
                    if value != 0 && value & 3 != self.role {
                        return Err(Error::connection_protocol(
                            Code::H3_ID_ERROR,
                            "GOAWAY has the wrong stream role",
                        ));
                    }
                    let boundary = crate::stream_id::try_from_u64(value)?;
                    let mut lock = self.state.active.lock().unwrap();
                    if let Some((goaway, requests)) = lock.as_mut() {
                        goaway.received(boundary)?;
                        requests.reject_from(boundary);
                    }
                }
                FrameType::MaxPushId if self.role == 1 => {
                    let value = reader.read_id_payload().await?;
                    if max_push.is_some_and(|previous| value < previous) {
                        return Err(Error::connection_protocol(
                            Code::H3_ID_ERROR,
                            "MAX_PUSH_ID decreased",
                        ));
                    }
                    max_push = Some(value);
                }
                FrameType::CancelPush => {
                    reader.read_id_payload().await?;
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

struct PendingIncoming {
    connection_state: Arc<ConnectionState>,
    stream_id: StreamId,
}
impl Drop for PendingIncoming {
    fn drop(&mut self) {
        if let Some((_, requests)) = self.connection_state.active.lock().unwrap().as_mut() {
            requests.incoming.remove(&self.stream_id);
        }
    }
}
struct PendingResponse {
    connection_state: Arc<ConnectionState>,
    stream_id: StreamId,
}
impl Drop for PendingResponse {
    fn drop(&mut self) {
        if let Some((_, requests)) = self.connection_state.active.lock().unwrap().as_mut() {
            requests.responses.remove(&self.stream_id);
        }
    }
}

async fn stopped(terminal: &watch::Sender<Option<Error>>) -> Error {
    let mut receiver = terminal.subscribe();
    receiver
        .wait_for(|value| value.is_some())
        .await
        .expect("ConnectionState owns terminal sender")
        .clone()
        .unwrap()
}

fn map_connection_error(error: transport::ConnectionError) -> Error {
    Error::connection(error.code(), "QUIC connection failed", error)
}

fn validate_pair<R: RecvStream, S: SendStream>(
    id: StreamId,
    recv: &mut R,
    send: &mut S,
    role: u64,
) -> Result<(), Error> {
    if u64::from(id) & 3 != role {
        let _ = recv.stop(Code::H3_STREAM_CREATION_ERROR);
        let _ = send.reset(Code::H3_STREAM_CREATION_ERROR);
        return Err(Error::connection_protocol(
            Code::H3_STREAM_CREATION_ERROR,
            "invalid bidirectional stream pair",
        ));
    }
    Ok(())
}

async fn open_critical<T: transport::Connection>(
    transport: &T,
    kind: u64,
) -> Result<BoxSend, Error> {
    let (id, stream) = transport.open_uni().await.map_err(map_connection_error)?;
    let mut stream: BoxSend = Box::new(stream);
    if u64::from(id) & 2 == 0 {
        return Err(Error::connection_protocol(
            Code::H3_STREAM_CREATION_ERROR,
            "open_uni returned a bidirectional stream",
        ));
    }
    stream
        .send(wire::encode_stream_type(kind)?)
        .await
        .map_err(wire::map_stream_error)?;
    Ok(stream)
}
