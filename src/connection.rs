use std::{
    collections::BTreeSet,
    error::Error as StdError,
    fmt,
    pin::{Pin, pin},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::{Buf, Bytes};
use futures::SinkExt;
use http::{HeaderMap, Request as HttpRequest, Response as HttpResponse, header::CONTENT_LENGTH};
use http_body::{Body as HttpBody, Frame as HttpFrame};
use http_body_util::{BodyExt, StreamBody};
use tokio::{
    sync::{Mutex as AsyncMutex, Notify, mpsc, watch},
    task::{JoinHandle, JoinSet},
};

use crate::{
    Body, Code, Error, Settings, StreamId, qpack,
    stream_id::{MAX_VARINT, StreamIdExt as _},
    transport::{self, RecvStream as _, SendStream as _},
    wire::{
        self, CONTROL_STREAM_TYPE, ChunkReader, FrameHeader, FrameReader, FrameType,
        GOAWAY_FRAME_TYPE, PUSH_STREAM_TYPE, PayloadBudget, QPACK_DECODER_STREAM_TYPE,
        QPACK_ENCODER_STREAM_TYPE,
    },
};

type BoxSendStream = Box<dyn transport::SendStream>;
type FailConnection = Arc<dyn Fn(Error) + Send + Sync>;
const PENDING_REQUEST_LIMIT: usize = 256;

struct OptionalWebTransport<S> {
    #[cfg(feature = "webtransport")]
    hooks: Option<crate::webtransport::Hooks<S>>,
    #[cfg(not(feature = "webtransport"))]
    marker: std::marker::PhantomData<fn(S)>,
}

impl<S> Default for OptionalWebTransport<S> {
    fn default() -> Self {
        Self {
            #[cfg(feature = "webtransport")]
            hooks: None,
            #[cfg(not(feature = "webtransport"))]
            marker: std::marker::PhantomData,
        }
    }
}

impl<S> Clone for OptionalWebTransport<S> {
    fn clone(&self) -> Self {
        Self {
            #[cfg(feature = "webtransport")]
            hooks: self.hooks.clone(),
            #[cfg(not(feature = "webtransport"))]
            marker: std::marker::PhantomData,
        }
    }
}

#[cfg(feature = "webtransport")]
impl<S> OptionalWebTransport<S> {
    fn new(hooks: crate::webtransport::Hooks<S>) -> Self {
        Self { hooks: Some(hooks) }
    }

    fn runtime(&self) -> Option<Arc<crate::webtransport::Runtime>> {
        self.hooks.as_ref().map(|hooks| Arc::clone(hooks.runtime()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Running,
    Draining,
    Closed,
}

#[derive(Debug)]
struct State {
    phase: Phase,
    max_received_stream_id: Option<StreamId>,
    local_goaway_boundary: Option<StreamId>,
    peer_goaway_boundary: Option<StreamId>,
    outgoing_streams: BTreeSet<StreamId>,
    active_incoming: usize,
    terminal: Option<Error>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            phase: Phase::Running,
            max_received_stream_id: None,
            local_goaway_boundary: None,
            peer_goaway_boundary: None,
            outgoing_streams: BTreeSet::new(),
            active_incoming: 0,
            terminal: None,
        }
    }
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    local_role_bit: u64,
    closed: Notify,
    goaway: Notify,
    exchanges_finished: Notify,
    payload_budget: PayloadBudget,
}

impl Shared {
    fn terminal(&self) -> Option<Error> {
        self.state
            .lock()
            .expect("connection state lock poisoned")
            .terminal
            .clone()
    }

    fn check_send(&self) -> Result<(), Error> {
        let state = self.state.lock().expect("connection state lock poisoned");
        match state.phase {
            Phase::Closed => Err(Error::closed("HTTP/3 connection is closed")),
            Phase::Draining => Err(Error::draining("HTTP/3 connection is draining")),
            Phase::Running if state.peer_goaway_boundary.is_some() => Err(Error::Goaway {
                boundary: state.peer_goaway_boundary.expect("checked above"),
            }),
            Phase::Running => Ok(()),
        }
    }

    fn register_incoming(&self, _stream_id: StreamId) -> bool {
        let state = self.state.lock().expect("connection state lock poisoned");
        if state.phase != Phase::Running {
            return false;
        }
        true
    }

    fn register_outgoing(&self, stream_id: StreamId) -> Result<(), Error> {
        let mut state = self.state.lock().expect("connection state lock poisoned");
        match state.phase {
            Phase::Closed => return Err(Error::closed("HTTP/3 connection is closed")),
            Phase::Draining => return Err(Error::draining("HTTP/3 connection is draining")),
            Phase::Running => {}
        }
        if let Some(boundary) = state.peer_goaway_boundary {
            return Err(Error::Goaway { boundary });
        }
        state.outgoing_streams.insert(stream_id);
        Ok(())
    }

    fn unregister_outgoing(&self, stream_id: StreamId) {
        let removed = self
            .state
            .lock()
            .expect("connection state lock poisoned")
            .outgoing_streams
            .remove(&stream_id);
        if removed {
            self.exchanges_finished.notify_waiters();
        }
    }

    fn register_incoming_delivery(&self, stream_id: StreamId) -> Result<(), Error> {
        let mut state = self.state.lock().expect("connection state lock poisoned");
        if state.phase != Phase::Running {
            return Err(Error::request_rejected(
                "request was not delivered because the connection is draining",
            ));
        }
        state.max_received_stream_id = Some(
            state
                .max_received_stream_id
                .map_or(stream_id, |current| current.max(stream_id)),
        );
        state.active_incoming += 1;
        Ok(())
    }

    fn finish_incoming(&self) {
        let mut state = self.state.lock().expect("connection state lock poisoned");
        debug_assert!(state.active_incoming > 0);
        state.active_incoming = state.active_incoming.saturating_sub(1);
        drop(state);
        self.exchanges_finished.notify_waiters();
    }

    fn begin_shutdown(&self) -> Option<StreamId> {
        let mut state = self.state.lock().expect("connection state lock poisoned");
        if state.phase != Phase::Running {
            return state.local_goaway_boundary;
        }

        let boundary = match state.max_received_stream_id {
            None => Some(crate::stream_id::from_u64_unchecked(0)),
            Some(stream_id) => stream_id
                .as_u64()
                .checked_add(4)
                .filter(|value| *value <= MAX_VARINT)
                .map(crate::stream_id::from_u64_unchecked),
        };
        state.phase = Phase::Draining;
        state.local_goaway_boundary = boundary;
        boundary
    }

    fn apply_peer_goaway(&self, boundary: StreamId) -> Result<(), Error> {
        let mut state = self.state.lock().expect("connection state lock poisoned");
        let raw = boundary.as_u64();
        if raw != 0 && (raw & 0x02 != 0 || raw & 0x01 != self.local_role_bit) {
            return Err(Error::connection_protocol(
                Code::H3_ID_ERROR,
                "GOAWAY boundary is not a locally initiated bidirectional stream ID",
            ));
        }
        if let Some(previous) = state.peer_goaway_boundary
            && boundary > previous
        {
            return Err(Error::connection_protocol(
                Code::H3_ID_ERROR,
                format!(
                    "GOAWAY boundary increased from {} to {}",
                    previous.as_u64(),
                    boundary.as_u64()
                ),
            ));
        }
        state.peer_goaway_boundary = Some(boundary);
        drop(state);
        self.goaway.notify_waiters();
        Ok(())
    }

    fn is_accepting(&self) -> bool {
        self.state
            .lock()
            .expect("connection state lock poisoned")
            .phase
            == Phase::Running
    }

    fn is_draining(&self) -> bool {
        let state = self.state.lock().expect("connection state lock poisoned");
        state.phase != Phase::Running || state.peer_goaway_boundary.is_some()
    }

    fn fail(&self, error: Error) {
        let mut state = self.state.lock().expect("connection state lock poisoned");
        if state.terminal.is_none() {
            state.phase = Phase::Closed;
            state.terminal = Some(error);
            drop(state);
            self.closed.notify_waiters();
        }
    }

    async fn wait_closed(&self) -> Error {
        loop {
            let notified = self.closed.notified();
            if let Some(error) = self.terminal() {
                return error;
            }
            notified.await;
        }
    }

    async fn wait_peer_goaway_covering(&self, stream_id: StreamId) -> StreamId {
        loop {
            let notified = self.goaway.notified();
            if let Some(boundary) = self
                .state
                .lock()
                .expect("connection state lock poisoned")
                .peer_goaway_boundary
                .filter(|boundary| stream_id >= *boundary)
            {
                return boundary;
            }
            notified.await;
        }
    }

    async fn wait_for_exchanges(&self) {
        loop {
            let notified = self.exchanges_finished.notified();
            let finished = {
                let state = self.state.lock().expect("connection state lock poisoned");
                state.outgoing_streams.is_empty() && state.active_incoming == 0
            };
            if finished {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Debug, Default)]
struct PeerCriticalStreams {
    control: AtomicBool,
    qpack_encoder: AtomicBool,
    qpack_decoder: AtomicBool,
}

impl PeerCriticalStreams {
    fn claim(flag: &AtomicBool, name: &'static str) -> Result<(), Error> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| {
                Error::connection_protocol(
                    Code::H3_STREAM_CREATION_ERROR,
                    format!("duplicate peer {name} stream"),
                )
            })
    }
}

struct LocalCriticalStreams {
    control: AsyncMutex<BoxSendStream>,
}

type AcceptedRequest = (HttpRequest<Body>, Response);

struct Inner<T: transport::Connection> {
    transport: Arc<T>,
    shared: Arc<Shared>,
    requests: AsyncMutex<mpsc::Receiver<AcceptedRequest>>,
    stop_accepting: watch::Sender<bool>,
    cancel: watch::Sender<bool>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    critical: LocalCriticalStreams,
    qpack: Arc<qpack::Qpack>,
    fail_connection: FailConnection,
    #[cfg_attr(not(feature = "webtransport"), allow(dead_code))]
    webtransport: OptionalWebTransport<T::SendStream>,
}

impl<T: transport::Connection> Drop for Inner<T> {
    fn drop(&mut self) {
        let _ = self.stop_accepting.send(true);
        let _ = self.cancel.send(true);
        self.transport
            .close(Code::H3_NO_ERROR, b"last h3x connection handle dropped");
        #[cfg(feature = "webtransport")]
        if let Some(runtime) = self.webtransport.runtime() {
            runtime.fail(Error::closed("HTTP/3 connection handle was dropped"));
        }
        for task in self.tasks.lock().expect("task lock poisoned").drain(..) {
            task.abort();
        }
    }
}

impl<T: transport::Connection> Inner<T> {
    async fn join_tasks(&self) -> Result<(), Error> {
        let tasks: Vec<_> = self
            .tasks
            .lock()
            .expect("task lock poisoned")
            .drain(..)
            .collect();
        for task in tasks {
            match task.await {
                Ok(()) => {}
                Err(error) if error.is_cancelled() => {}
                Err(error) => {
                    return Err(Error::connection(
                        Some(Code::H3_INTERNAL_ERROR),
                        "HTTP/3 supervisor task failed",
                        error,
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Symmetric HTTP/3 protocol running over an established QUIC connection.
pub struct Connection<T: transport::Connection> {
    inner: Arc<Inner<T>>,
}

impl<T: transport::Connection> Clone for Connection<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: transport::Connection> fmt::Debug for Connection<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("draining", &self.is_draining())
            .finish_non_exhaustive()
    }
}

impl<T: transport::Connection> Connection<T> {
    pub async fn new(transport: T, settings: Settings) -> Result<Self, Error> {
        let transport = Arc::new(transport);
        let tasks = Arc::new(Mutex::new(Vec::new()));
        Self::new_inner(transport, settings, tasks, OptionalWebTransport::default()).await
    }

    async fn new_inner(
        transport: Arc<T>,
        settings: Settings,
        tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
        webtransport: OptionalWebTransport<T::SendStream>,
    ) -> Result<Self, Error> {
        validate_settings(&settings)?;

        let mut control = open_critical_stream(&*transport, CONTROL_STREAM_TYPE)
            .await
            .inspect_err(|error| close_after_init_failure(&*transport, error))?;
        send_bytes(&mut control, wire::encode_settings_frame(&settings)?)
            .await
            .inspect_err(|error| close_after_init_failure(&*transport, error))?;

        let qpack_encoder = open_critical_stream(&*transport, QPACK_ENCODER_STREAM_TYPE)
            .await
            .inspect_err(|error| close_after_init_failure(&*transport, error))?;
        let qpack_decoder = open_critical_stream(&*transport, QPACK_DECODER_STREAM_TYPE)
            .await
            .inspect_err(|error| close_after_init_failure(&*transport, error))?;

        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            local_role_bit: control.id().as_u64() & 0x01,
            closed: Notify::new(),
            goaway: Notify::new(),
            exchanges_finished: Notify::new(),
            payload_budget: PayloadBudget::default(),
        });
        let fail_connection = {
            let transport = Arc::clone(&transport);
            let shared = Arc::clone(&shared);
            Arc::new(move |error| fail_protocol(&*transport, &shared, error))
                as Arc<dyn Fn(Error) + Send + Sync>
        };
        let (qpack, qpack_decoder_writer) = qpack::Qpack::new(
            &settings,
            qpack_encoder,
            qpack_decoder,
            Arc::clone(&fail_connection),
        );

        let peer_critical = Arc::new(PeerCriticalStreams::default());
        let (requests_tx, requests_rx) = mpsc::channel(PENDING_REQUEST_LIMIT);
        let (stop_accepting, stop_accepting_rx) = watch::channel(false);
        let (cancel, cancel_rx) = watch::channel(false);
        #[cfg(feature = "webtransport")]
        let webtransport_runtime = webtransport.runtime();

        let inner = Arc::new(Inner {
            transport: Arc::clone(&transport),
            shared: Arc::clone(&shared),
            requests: AsyncMutex::new(requests_rx),
            stop_accepting,
            cancel,
            tasks,
            critical: LocalCriticalStreams {
                control: AsyncMutex::new(control),
            },
            qpack: Arc::clone(&qpack),
            fail_connection: Arc::clone(&fail_connection),
            webtransport: webtransport.clone(),
        });

        let closed_task = tokio::spawn(watch_transport_closed(
            Arc::clone(&transport),
            Arc::clone(&shared),
        ));
        let request_dispatch = RequestDispatch {
            shared: Arc::clone(&shared),
            requests: requests_tx,
            qpack: Arc::clone(&qpack),
            fail_connection: Arc::clone(&fail_connection),
            shutdown: stop_accepting_rx,
            #[cfg(feature = "webtransport")]
            connection: Some(Arc::clone(&inner) as Arc<dyn Send + Sync>),
        };
        let bi_task = tokio::spawn(accept_bidi_streams(
            Arc::clone(&transport),
            request_dispatch,
            webtransport.clone(),
        ));
        let uni_task = tokio::spawn(accept_uni_streams(
            Arc::clone(&transport),
            Arc::clone(&shared),
            peer_critical,
            Arc::clone(&qpack),
            Arc::clone(&fail_connection),
            cancel_rx,
            webtransport,
        ));
        let qpack_writer_task = tokio::spawn(supervise_qpack_decoder_writer(
            Arc::clone(&transport),
            Arc::clone(&shared),
            qpack_decoder_writer,
            inner.cancel.subscribe(),
        ));
        let qpack_lifecycle_task = tokio::spawn(supervise_qpack_lifecycle(
            Arc::clone(&shared),
            Arc::clone(&qpack),
        ));
        inner.tasks.lock().expect("task lock poisoned").extend([
            closed_task,
            bi_task,
            uni_task,
            qpack_writer_task,
            qpack_lifecycle_task,
        ]);

        #[cfg(feature = "webtransport")]
        if let Some(runtime) = webtransport_runtime {
            let datagram_task = tokio::spawn(supervise_webtransport_datagrams(
                Arc::clone(&transport),
                Arc::clone(&shared),
                Arc::clone(&runtime),
                inner.cancel.subscribe(),
            ));
            let lifecycle_task = tokio::spawn(supervise_webtransport_lifecycle(
                Arc::clone(&shared),
                runtime,
            ));
            inner
                .tasks
                .lock()
                .expect("task lock poisoned")
                .extend([datagram_task, lifecycle_task]);
        }

        Ok(Self { inner })
    }

    /// Opens a request stream and sends its HEADERS.
    ///
    /// Request DATA, trailers, FIN, and the response are driven explicitly by
    /// the returned stream; no body pump is started in the background.
    pub async fn request(&self, parts: http::request::Parts) -> Result<RequestStream, Error> {
        self.inner.shared.check_send()?;
        let remaining = content_length(&parts.headers).map_err(Error::into_invalid_message)?;
        let (mut reader, mut writer) = fail_on_connection(
            self.inner
                .transport
                .open_bi()
                .await
                .map_err(map_connection_error),
            &self.inner.fail_connection,
        )?;
        let stream_id = reader.id();
        if stream_id != writer.id() || stream_id.as_u64() & 0x02 != 0 {
            let error = Error::connection_protocol(
                Code::H3_ID_ERROR,
                "transport returned an invalid bidirectional stream pair",
            );
            let _ = reader.stop(Code::H3_ID_ERROR);
            let _ = writer.reset(Code::H3_ID_ERROR);
            fail_protocol(&*self.inner.transport, &self.inner.shared, error.clone());
            return Err(error);
        }
        if let Err(error) = self.inner.shared.register_outgoing(stream_id) {
            let _ = reader.stop(Code::H3_REQUEST_REJECTED);
            let _ = writer.reset(Code::H3_REQUEST_REJECTED);
            return Err(error);
        }

        let exchange = OutgoingExchange {
            shared: Arc::clone(&self.inner.shared),
            stream_id,
        };
        let headers = match self.inner.qpack.encode_request(stream_id, parts).await {
            Ok(headers) => headers,
            Err(error) => {
                let _ = reader.stop(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
                let _ = writer.reset(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
                return Err(error);
            }
        };
        let mut writer: BoxSendStream = Box::new(writer);
        if let Err(error) = fail_on_connection(
            write_h3_frame(&mut writer, wire::HEADERS_FRAME_TYPE, &headers).await,
            &self.inner.fail_connection,
        ) {
            let _ = writer.reset(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
            return Err(error);
        }

        Ok(RequestStream {
            stream_id,
            send: AsyncMutex::new(RequestSendState {
                writer: Some(writer),
                remaining,
                phase: RequestSendPhase::Open,
            }),
            response: AsyncMutex::new(RequestResponseState {
                reader: Some(FrameReader::new(
                    ChunkReader::new(reader),
                    self.inner.shared.payload_budget.clone(),
                )),
                phase: RequestResponsePhase::Waiting,
            }),
            response_waiting: AtomicBool::new(false),
            exchange: Mutex::new(Some(exchange)),
            shared: Arc::clone(&self.inner.shared),
            qpack: Arc::clone(&self.inner.qpack),
            fail_connection: Arc::clone(&self.inner.fail_connection),
            #[cfg(feature = "webtransport")]
            webtransport: self.inner.webtransport.runtime(),
        })
    }

    pub async fn accept(&self) -> Result<Option<AcceptedRequest>, Error> {
        if !self.inner.shared.is_accepting() {
            return Ok(None);
        }

        let mut requests = self.inner.requests.lock().await;
        tokio::select! {
            request = requests.recv() => match request {
                Some(request) => Ok(Some(request)),
                None => self.inner.shared.terminal().map_or(Ok(None), Err),
            },
            error = self.inner.shared.wait_closed() => Err(error),
        }
    }

    pub fn is_draining(&self) -> bool {
        self.inner.shared.is_draining()
    }

    pub async fn shutdown(&self) -> Result<(), Error> {
        if let Some(error) = self.inner.shared.terminal() {
            return if error.code() == Some(Code::H3_NO_ERROR) {
                Ok(())
            } else {
                Err(error)
            };
        }

        if let Some(boundary) = self.inner.shared.begin_shutdown() {
            let mut payload = Vec::with_capacity(8);
            wire::encode_varint(boundary.as_u64(), &mut payload)?;
            let goaway = wire::encode_frame(GOAWAY_FRAME_TYPE, &payload)?;
            let mut control = self.inner.critical.control.lock().await;
            send_bytes(&mut control, goaway).await?;
        }

        let _ = self.inner.stop_accepting.send(true);
        let mut requests = self.inner.requests.lock().await;
        while let Ok(request) = requests.try_recv() {
            drop(request);
        }
        drop(requests);

        self.inner.shared.wait_for_exchanges().await;

        self.inner
            .transport
            .close(Code::H3_NO_ERROR, b"graceful HTTP/3 shutdown");
        let result = self.closed().await;
        let _ = self.inner.cancel.send(true);
        let tasks = self.inner.join_tasks().await;
        result.and(tasks)
    }

    pub fn close(&self, code: Code, reason: &[u8]) {
        self.inner.shared.begin_shutdown();
        let _ = self.inner.stop_accepting.send(true);
        let _ = self.inner.cancel.send(true);
        self.inner.transport.close(code, reason);
    }

    pub async fn closed(&self) -> Result<(), Error> {
        let error = self.inner.shared.wait_closed().await;
        if error.code() == Some(Code::H3_NO_ERROR) {
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[cfg(feature = "webtransport")]
impl<T: transport::webtransport::Connection> Connection<T> {
    pub async fn new_webtransport(transport: T, mut settings: Settings) -> Result<Self, Error> {
        settings.enable_webtransport();
        let transport = Arc::new(transport);
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let hooks = match crate::webtransport::configure(
            Arc::clone(&transport),
            crate::webtransport::Config::default(),
            Arc::clone(&tasks),
        ) {
            Ok(hooks) => hooks,
            Err(error) => {
                close_after_init_failure(&*transport, &error);
                return Err(error);
            }
        };
        Self::new_inner(transport, settings, tasks, OptionalWebTransport::new(hooks)).await
    }

    pub async fn webtransport(
        &self,
        mut request: HttpRequest<()>,
    ) -> Result<crate::webtransport::ConnectResponse, Error> {
        self.inner.shared.check_send()?;
        if self.inner.shared.local_role_bit != 0 {
            return Err(Error::invalid_state("webtransport"));
        }
        if request.method() != http::Method::CONNECT {
            return Err(Error::stream(None, "WebTransport requires CONNECT"));
        }
        if !request
            .uri()
            .scheme()
            .is_some_and(|scheme| scheme.as_str().eq_ignore_ascii_case("https"))
        {
            return Err(Error::stream(None, "WebTransport requires an https URI"));
        }
        if content_length(request.headers())
            .map_err(Error::into_invalid_message)?
            .is_some()
        {
            return Err(Error::stream(
                None,
                "WebTransport CONNECT request cannot declare Content-Length",
            ));
        }
        let runtime = self
            .inner
            .webtransport
            .runtime()
            .ok_or_else(|| Error::invalid_state("webtransport"))?;
        runtime.wait_server_support().await?;

        request
            .extensions_mut()
            .insert(crate::webtransport::ProtocolMarker);
        let (parts, ()) = request.into_parts();
        let (mut reader, mut writer) = fail_on_connection(
            self.inner
                .transport
                .open_bi()
                .await
                .map_err(map_connection_error),
            &self.inner.fail_connection,
        )?;
        let stream_id = reader.id();
        if stream_id != writer.id() || stream_id.as_u64() & 0x03 != 0 {
            let error = Error::connection_protocol(
                Code::H3_ID_ERROR,
                "WebTransport CONNECT must use a client-initiated bidirectional stream",
            );
            let _ = reader.stop(Code::H3_ID_ERROR);
            let _ = writer.reset(Code::H3_ID_ERROR);
            fail_protocol(&*self.inner.transport, &self.inner.shared, error.clone());
            return Err(error);
        }
        if let Err(error) = self.inner.shared.register_outgoing(stream_id) {
            let _ = reader.stop(Code::H3_REQUEST_REJECTED);
            let _ = writer.reset(Code::H3_REQUEST_REJECTED);
            return Err(error);
        }

        let exchange = OutgoingExchange {
            shared: Arc::clone(&self.inner.shared),
            stream_id,
        };
        let mut writer = ResetOnDrop::new(Box::new(writer), Code::H3_REQUEST_CANCELLED);
        let pending =
            match runtime.prepare(stream_id, Arc::clone(&self.inner) as Arc<dyn Send + Sync>) {
                Ok(pending) => pending,
                Err(error) => {
                    let code = error.code().unwrap_or(Code::H3_REQUEST_CANCELLED);
                    let _ = reader.stop(code);
                    let _ = writer.writer().reset(code);
                    writer.disarm();
                    return Err(error);
                }
            };
        let mut qpack_cancellation =
            QpackCancelOnDrop::new(Arc::clone(&self.inner.qpack), stream_id);
        let headers = self.inner.qpack.encode_request(stream_id, parts).await?;
        fail_on_connection(
            write_h3_frame(writer.writer(), wire::HEADERS_FRAME_TYPE, &headers).await,
            &self.inner.fail_connection,
        )?;
        let mut reader = FrameReader::new(
            ChunkReader::new(reader),
            self.inner.shared.payload_budget.clone(),
        );

        tokio::select! {
            result = async { loop {
                let frame = read_h3_frame(&mut reader, &self.inner.fail_connection, Some(&runtime))
                    .await.map_err(map_outgoing_request_error)?;
            let Some(frame) = frame else {
                return Err(Error::stream(
                    Some(Code::H3_REQUEST_INCOMPLETE),
                    "WebTransport CONNECT ended before final response headers",
                ));
            };
            match frame.frame_type {
                FrameType::Headers => {
                    let payload = read_h3_payload(&mut reader, &self.inner.fail_connection).await?;
                    let mut parts = self
                        .inner
                        .qpack
                        .decode_response(stream_id, &payload)
                        .await
                        .map_err(map_outgoing_request_error)?;
                    if parts.status.is_informational() {
                        continue;
                    }
                    let accepted = parts.status.is_success();
                    if accepted && content_length(&parts.headers)?.is_some() {
                        return Err(Error::stream(
                            Some(Code::H3_MESSAGE_ERROR),
                            "successful WebTransport response cannot declare Content-Length",
                        ));
                    }
                    parts.extensions.insert(stream_id);
                    let body = ReceivedBody {
                        reader,
                        is_response: true,
                        qpack: Arc::clone(&self.inner.qpack),
                        fail_connection: Arc::clone(&self.inner.fail_connection),
                        stream_id,
                        remaining: None,
                        trailers_received: false,
                        finished: false,
                        stop_code: Code::WT_SESSION_GONE,
                        _exchange: Some(BodyExchange::outgoing(exchange)),
                        webtransport: Some(Arc::clone(&runtime)),
                    }
                    .into_body();
                    qpack_cancellation.disarm();
                    if accepted {
                        let response = HttpResponse::from_parts(parts, ());
                        let session = pending.start(body, writer.take());
                        return Ok(crate::webtransport::ConnectResponse::Accepted {
                            response,
                            session,
                        });
                    }

                    fail_on_connection(
                        writer
                            .writer()
                            .close()
                            .await
                            .map_err(wire::map_stream_error),
                        &self.inner.fail_connection,
                    )?;
                    writer.disarm();
                    return Ok(crate::webtransport::ConnectResponse::Rejected(
                        HttpResponse::from_parts(parts, body),
                    ));
                }
                FrameType::Data => {
                    return Err(unexpected_frame(&self.inner.fail_connection));
                }
                FrameType::PushPromise => {
                    return Err(
                        reject_push_promise(&mut reader, &self.inner.fail_connection).await,
                    );
                }
                FrameType::Unknown(_) => {
                    discard_h3_payload(&mut reader, &self.inner.fail_connection).await?
                }
                _ => return Err(unexpected_frame(&self.inner.fail_connection)),
            }
            } } => result,
            boundary = self.inner.shared.wait_peer_goaway_covering(stream_id) => Err(Error::Goaway { boundary }),
        }
    }
}

#[derive(Clone)]
enum RequestSendPhase {
    Open,
    Finished,
    Failed(Error),
}

struct RequestSendState {
    writer: Option<BoxSendStream>,
    remaining: Option<u64>,
    phase: RequestSendPhase,
}

#[derive(Clone)]
enum RequestResponsePhase {
    Waiting,
    Delivered,
    Failed(Error),
}

struct RequestResponseState {
    reader: Option<FrameReader>,
    phase: RequestResponsePhase,
}

/// One outbound HTTP/3 request stream.
pub struct RequestStream {
    stream_id: StreamId,
    send: AsyncMutex<RequestSendState>,
    response: AsyncMutex<RequestResponseState>,
    response_waiting: AtomicBool,
    exchange: Mutex<Option<OutgoingExchange>>,
    shared: Arc<Shared>,
    qpack: Arc<qpack::Qpack>,
    fail_connection: FailConnection,
    #[cfg(feature = "webtransport")]
    webtransport: Option<Arc<crate::webtransport::Runtime>>,
}

impl fmt::Debug for RequestStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestStream")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

impl RequestStream {
    pub const fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub async fn write(&self, data: Bytes) -> Result<(), Error> {
        let mut state = self.send.lock().await;
        match &state.phase {
            RequestSendPhase::Open => {}
            RequestSendPhase::Finished => {
                return Err(Error::invalid_state("write"));
            }
            RequestSendPhase::Failed(error) => return Err(error.clone()),
        }

        let remaining = match state.remaining {
            Some(remaining) => Some(remaining.checked_sub(data.len() as u64).ok_or_else(|| {
                Error::stream(
                    Some(Code::H3_MESSAGE_ERROR),
                    "outgoing body exceeds Content-Length",
                )
            })?),
            None => None,
        };
        let frame = wire::encode_frame(wire::DATA_FRAME_TYPE, &data)?;
        let mut commit = RequestSendCommit::new(&mut state);
        if let Err(error) = send_bytes(commit.writer(), frame).await {
            commit.fail(error.clone());
            return fail_on_connection(Err(error), &self.fail_connection);
        }
        commit.disarm();
        drop(commit);
        state.remaining = remaining;
        Ok(())
    }

    pub async fn trailers(&self, trailers: HeaderMap) -> Result<(), Error> {
        let mut state = self.send.lock().await;
        match &state.phase {
            RequestSendPhase::Open => {}
            RequestSendPhase::Finished => {
                return Err(Error::invalid_state("trailers"));
            }
            RequestSendPhase::Failed(error) => return Err(error.clone()),
        }
        if state.remaining.is_some_and(|remaining| remaining != 0) {
            return Err(Error::stream(
                Some(Code::H3_MESSAGE_ERROR),
                "outgoing body length does not match Content-Length",
            ));
        }

        let trailers = self.qpack.encode_trailers(self.stream_id, trailers).await?;
        let mut commit = RequestSendCommit::new(&mut state);
        let result = async {
            write_h3_frame(commit.writer(), wire::HEADERS_FRAME_TYPE, &trailers).await?;
            commit
                .writer()
                .close()
                .await
                .map_err(wire::map_stream_error)
        }
        .await;
        if let Err(error) = result {
            commit.fail(error.clone());
            return fail_on_connection(Err(error), &self.fail_connection);
        }
        commit.finish();
        Ok(())
    }

    pub async fn finish(&self) -> Result<(), Error> {
        let mut state = self.send.lock().await;
        match &state.phase {
            RequestSendPhase::Finished => return Ok(()),
            RequestSendPhase::Failed(error) => return Err(error.clone()),
            RequestSendPhase::Open => {}
        }
        if state.remaining.is_some_and(|remaining| remaining != 0) {
            return Err(Error::stream(
                Some(Code::H3_MESSAGE_ERROR),
                "outgoing body length does not match Content-Length",
            ));
        }

        let mut commit = RequestSendCommit::new(&mut state);
        if let Err(error) = commit
            .writer()
            .close()
            .await
            .map_err(wire::map_stream_error)
        {
            commit.fail(error.clone());
            return fail_on_connection(Err(error), &self.fail_connection);
        }
        commit.finish();
        Ok(())
    }

    /// Waits for the final response headers.
    ///
    /// Dropping this future once reading begins stops the response direction;
    /// it cannot be retried after a partial frame. Uploading remains independent.
    pub async fn response(&self) -> Result<HttpResponse<Body>, Error> {
        if self
            .response_waiting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::invalid_state("response"));
        }
        let _waiting = ResponseWaitGuard(&self.response_waiting);
        let mut state = self.response.lock().await;
        match &state.phase {
            RequestResponsePhase::Waiting => {}
            RequestResponsePhase::Delivered => {
                return Err(Error::invalid_state("response"));
            }
            RequestResponsePhase::Failed(error) => return Err(error.clone()),
        }

        let cancellation = ResponseReadGuard {
            state: &mut state,
            qpack: &self.qpack,
            stream_id: self.stream_id,
        };
        let state = &mut *cancellation.state;
        let result = tokio::select! {
            result = async {
            loop {
                let frame = read_h3_frame(
                    state.reader.as_mut().expect("response reader is present"),
                    &self.fail_connection,
                    #[cfg(feature = "webtransport")]
                    self.webtransport.as_ref(),
                ).await.map_err(map_outgoing_request_error);
                let frame = frame?;
                let Some(frame) = frame else {
                    return Err(Error::stream(
                        Some(Code::H3_REQUEST_INCOMPLETE),
                        "response stream ended before final response headers",
                    ));
                };
                match frame.frame_type {
                    FrameType::Headers => {
                        let payload = read_h3_payload(
                            state.reader.as_mut().expect("response reader is present"),
                            &self.fail_connection,
                        )
                        .await?;
                        let mut parts = self
                            .qpack
                            .decode_response(self.stream_id, &payload)
                            .await
                            .map_err(map_outgoing_request_error)?;
                        if parts.status.is_informational() {
                            continue;
                        }
                        parts.extensions.insert(self.stream_id);
                        let remaining = content_length(&parts.headers)?;
                        let body = ReceivedBody {
                            reader: state.reader.take().expect("response reader is present"),
                            is_response: true,
                            qpack: Arc::clone(&self.qpack),
                            fail_connection: Arc::clone(&self.fail_connection),
                            stream_id: self.stream_id,
                            remaining,
                            trailers_received: false,
                            finished: false,
                            stop_code: Code::H3_REQUEST_CANCELLED,
                            _exchange: self
                                .exchange
                                .lock()
                                .expect("request exchange lock poisoned")
                                .take()
                                .map(BodyExchange::outgoing),
                            #[cfg(feature = "webtransport")]
                            webtransport: self.webtransport.clone(),
                        }
                        .into_body();
                        state.phase = RequestResponsePhase::Delivered;
                        return Ok(HttpResponse::from_parts(parts, body));
                    }
                    FrameType::Data => return Err(unexpected_frame(&self.fail_connection)),
                    FrameType::PushPromise => {
                        return Err(reject_push_promise(
                            state.reader.as_mut().expect("response reader is present"),
                            &self.fail_connection,
                        )
                        .await);
                    }
                    FrameType::Unknown(_) => {
                        discard_h3_payload(
                            state.reader.as_mut().expect("response reader is present"),
                            &self.fail_connection,
                        )
                        .await?
                    }
                    _ => return Err(unexpected_frame(&self.fail_connection)),
                }
            }
            } => result,
            boundary = self.shared.wait_peer_goaway_covering(self.stream_id) => Err(Error::Goaway { boundary }),
        };
        if let Err(error) = &result {
            state.phase = RequestResponsePhase::Failed(error.clone());
        }
        result
    }
}

impl Drop for RequestStream {
    fn drop(&mut self) {
        let send = self.send.get_mut();
        if matches!(send.phase, RequestSendPhase::Open)
            && let Some(writer) = &mut send.writer
        {
            let _ = writer.reset(Code::H3_REQUEST_CANCELLED);
        }
        let response = self.response.get_mut();
        if matches!(response.phase, RequestResponsePhase::Waiting) {
            self.qpack.cancel_stream(self.stream_id);
            if let Some(reader) = &mut response.reader {
                let _ = reader.stop(Code::H3_REQUEST_CANCELLED);
            }
        }
    }
}

struct RequestSendCommit<'a> {
    state: &'a mut RequestSendState,
    armed: bool,
}

impl<'a> RequestSendCommit<'a> {
    fn new(state: &'a mut RequestSendState) -> Self {
        Self { state, armed: true }
    }

    fn writer(&mut self) -> &mut BoxSendStream {
        self.state.writer.as_mut().expect("request writer is open")
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn finish(mut self) {
        self.armed = false;
        self.state.writer.take();
        self.state.phase = RequestSendPhase::Finished;
    }

    fn fail(&mut self, error: Error) {
        if let Some(writer) = &mut self.state.writer {
            let _ = writer.reset(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
        }
        self.state.writer.take();
        self.state.phase = RequestSendPhase::Failed(error);
        self.armed = false;
    }
}

impl Drop for RequestSendCommit<'_> {
    fn drop(&mut self) {
        if self.armed {
            let error = Error::stream(
                Some(Code::H3_REQUEST_CANCELLED),
                "request send was cancelled after frame submission began",
            );
            if let Some(writer) = &mut self.state.writer {
                let _ = writer.reset(Code::H3_REQUEST_CANCELLED);
            }
            self.state.writer.take();
            self.state.phase = RequestSendPhase::Failed(error);
        }
    }
}

// A cancelled response read cannot restart after consuming part of an envelope or QPACK section.
struct ResponseReadGuard<'a> {
    state: &'a mut RequestResponseState,
    qpack: &'a qpack::Qpack,
    stream_id: StreamId,
}

impl Drop for ResponseReadGuard<'_> {
    fn drop(&mut self) {
        if matches!(self.state.phase, RequestResponsePhase::Delivered) {
            return;
        }
        if matches!(self.state.phase, RequestResponsePhase::Waiting) {
            self.state.phase = RequestResponsePhase::Failed(Error::stream(
                Some(Code::H3_REQUEST_CANCELLED),
                "response read was cancelled",
            ));
        }
        if let Some(mut reader) = self.state.reader.take() {
            let code = match &self.state.phase {
                RequestResponsePhase::Failed(error) => {
                    error.code().unwrap_or(Code::H3_REQUEST_CANCELLED)
                }
                _ => Code::H3_REQUEST_CANCELLED,
            };
            let _ = reader.stop(code);
        }
        self.qpack.cancel_stream(self.stream_id);
    }
}

struct ResponseWaitGuard<'a>(&'a AtomicBool);

impl Drop for ResponseWaitGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Accepted request stream whose QPACK header resolution is caller-scheduled.
struct RequestResolver {
    first: Option<FrameHeader>,
    stream_id: StreamId,
    shared: Arc<Shared>,
    reader: Option<FrameReader>,
    writer: Option<BoxSendStream>,
    qpack: Arc<qpack::Qpack>,
    fail_connection: FailConnection,
    qpack_cancellation_armed: bool,
    #[cfg(feature = "webtransport")]
    webtransport: Option<Arc<crate::webtransport::Runtime>>,
    #[cfg(feature = "webtransport")]
    connection: Option<Arc<dyn Send + Sync>>,
}

impl fmt::Debug for RequestResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestResolver")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

impl RequestResolver {
    async fn resolve(mut self) -> Result<(HttpRequest<Body>, Response), Error> {
        let reader = self.reader.take().expect("resolver reader is present");
        let writer = self.writer.take().expect("resolver writer is present");
        let mut streams = RejectOnDrop::new(reader, writer);

        loop {
            let frame = match if let Some(first) = self.first.take() {
                Ok(Some(first))
            } else {
                read_h3_frame(
                    streams.reader(),
                    &self.fail_connection,
                    #[cfg(feature = "webtransport")]
                    self.webtransport.as_ref(),
                )
                .await
            } {
                Ok(frame) => frame,
                Err(error) => {
                    streams.code = error.code().unwrap_or(Code::H3_REQUEST_INCOMPLETE);
                    return Err(error);
                }
            };
            let Some(frame) = frame else {
                streams.code = Code::H3_REQUEST_INCOMPLETE;
                return Err(Error::stream(
                    Some(Code::H3_REQUEST_INCOMPLETE),
                    "request stream ended before HEADERS",
                ));
            };
            match frame.frame_type {
                FrameType::Headers => {
                    let payload = read_h3_payload(streams.reader(), &self.fail_connection).await?;
                    let mut parts = match self.qpack.decode_request(self.stream_id, &payload).await
                    {
                        Ok(parts) => parts,
                        Err(error) => {
                            streams.code = error.code().unwrap_or(Code::H3_MESSAGE_ERROR);
                            return Err(error);
                        }
                    };
                    #[cfg(feature = "webtransport")]
                    if parts
                        .extensions
                        .get::<crate::webtransport::ProtocolMarker>()
                        .is_some()
                        && let Some(webtransport) = &self.webtransport
                        && let Err(error) = webtransport.wait_client_support().await
                    {
                        streams.code = error.code().unwrap_or(Code::H3_MESSAGE_ERROR);
                        return Err(error);
                    }
                    parts.extensions.insert(self.stream_id);
                    let remaining = match content_length(&parts.headers) {
                        Ok(remaining) => remaining,
                        Err(error) => {
                            streams.code = error.code().unwrap_or(Code::H3_MESSAGE_ERROR);
                            return Err(error);
                        }
                    };
                    let (reader, writer) = streams.take();
                    if let Err(error) = self.shared.register_incoming_delivery(self.stream_id) {
                        let mut streams = RejectOnDrop::new(reader, writer);
                        streams.code = Code::H3_REQUEST_REJECTED;
                        return Err(error);
                    }
                    let exchange = Arc::new(IncomingExchange {
                        shared: Arc::clone(&self.shared),
                    });
                    #[cfg(feature = "webtransport")]
                    let body_stop_code = if parts
                        .extensions
                        .get::<crate::webtransport::ProtocolMarker>()
                        .is_some()
                    {
                        Code::WT_SESSION_GONE
                    } else {
                        Code::H3_REQUEST_CANCELLED
                    };
                    #[cfg(not(feature = "webtransport"))]
                    let body_stop_code = Code::H3_REQUEST_CANCELLED;
                    let body = ReceivedBody {
                        reader,
                        is_response: false,
                        qpack: Arc::clone(&self.qpack),
                        fail_connection: Arc::clone(&self.fail_connection),
                        stream_id: self.stream_id,
                        remaining,
                        trailers_received: false,
                        finished: false,
                        stop_code: body_stop_code,
                        _exchange: Some(BodyExchange::incoming(Arc::clone(&exchange))),
                        #[cfg(feature = "webtransport")]
                        webtransport: self.webtransport.clone(),
                    }
                    .into_body();
                    self.qpack_cancellation_armed = false;
                    let request = HttpRequest::from_parts(parts, body);
                    let response_sender = Response {
                        stream_id: self.stream_id,
                        writer: Some(writer),
                        _exchange: Some(exchange),
                        qpack: Arc::clone(&self.qpack),
                        fail_connection: Arc::clone(&self.fail_connection),
                        #[cfg(feature = "webtransport")]
                        webtransport: self.webtransport.clone(),
                        #[cfg(feature = "webtransport")]
                        connection: self.connection.take(),
                    };
                    return Ok((request, response_sender));
                }
                FrameType::Data => {
                    streams.code = Code::H3_FRAME_UNEXPECTED;
                    return Err(unexpected_frame(&self.fail_connection));
                }
                FrameType::Unknown(_) => {
                    discard_h3_payload(streams.reader(), &self.fail_connection).await?
                }
                _ => return Err(unexpected_frame(&self.fail_connection)),
            }
        }
    }
}

impl Drop for RequestResolver {
    fn drop(&mut self) {
        if self.qpack_cancellation_armed {
            self.qpack.cancel_stream(self.stream_id);
        }
        if let Some(reader) = &mut self.reader {
            let _ = reader.stop(Code::H3_REQUEST_REJECTED);
        }
        if let Some(writer) = &mut self.writer {
            let _ = writer.reset(Code::H3_REQUEST_REJECTED);
        }
    }
}

/// Single-use response direction paired with an accepted request stream.
pub struct Response {
    stream_id: StreamId,
    writer: Option<BoxSendStream>,
    _exchange: Option<Arc<IncomingExchange>>,
    qpack: Arc<qpack::Qpack>,
    fail_connection: FailConnection,
    #[cfg(feature = "webtransport")]
    webtransport: Option<Arc<crate::webtransport::Runtime>>,
    #[cfg(feature = "webtransport")]
    connection: Option<Arc<dyn Send + Sync>>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

impl Response {
    pub const fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub async fn send<B>(mut self, response: HttpResponse<B>) -> Result<(), Error>
    where
        B: HttpBody + Send,
        B::Data: Buf + Send,
        B::Error: StdError + Send + Sync + 'static,
    {
        if response.status().is_informational() {
            return Err(Error::stream(
                Some(Code::H3_MESSAGE_ERROR),
                "Response requires one final response",
            ));
        }
        let (parts, body) = response.into_parts();
        let content_length = content_length(&parts.headers).map_err(Error::into_invalid_message)?;
        let headers = self.qpack.encode_response(self.stream_id, parts).await?;
        let writer = self.writer.take().expect("response writer is present");
        let result = send_message(
            writer,
            headers,
            body,
            content_length,
            Arc::clone(&self.qpack),
            self.stream_id,
        )
        .await;
        fail_on_connection(result, &self.fail_connection)
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn webtransport_runtime(&self) -> Option<Arc<crate::webtransport::Runtime>> {
        self.webtransport.clone()
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn webtransport_keepalive(&self) -> Arc<dyn Send + Sync> {
        self.connection
            .as_ref()
            .cloned()
            .expect("an accepted response sender retains its connection")
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn reject(mut self, code: Code) {
        if let Some(writer) = &mut self.writer {
            let _ = writer.reset(code);
        }
        self.writer.take();
    }

    #[cfg(feature = "webtransport")]
    pub(crate) async fn start_webtransport_response(
        mut self,
        response: HttpResponse<()>,
    ) -> Result<BoxSendStream, Error> {
        if content_length(response.headers())
            .map_err(Error::into_invalid_message)?
            .is_some()
        {
            return Err(Error::stream(
                Some(Code::H3_MESSAGE_ERROR),
                "WebTransport CONNECT response cannot declare Content-Length",
            ));
        }
        let (parts, ()) = response.into_parts();
        let headers = self.qpack.encode_response(self.stream_id, parts).await?;
        let writer = self.writer.take().expect("response writer is present");
        let mut writer = ResetOnDrop::new(writer, Code::H3_REQUEST_CANCELLED);
        fail_on_connection(
            write_h3_frame(writer.writer(), wire::HEADERS_FRAME_TYPE, &headers).await,
            &self.fail_connection,
        )?;
        Ok(writer.take())
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        if let Some(writer) = &mut self.writer {
            let _ = writer.reset(Code::H3_REQUEST_CANCELLED);
        }
    }
}

struct RejectOnDrop {
    reader: Option<FrameReader>,
    writer: Option<BoxSendStream>,
    code: Code,
}

impl RejectOnDrop {
    fn new(reader: FrameReader, writer: BoxSendStream) -> Self {
        Self {
            reader: Some(reader),
            writer: Some(writer),
            code: Code::H3_REQUEST_REJECTED,
        }
    }

    fn reader(&mut self) -> &mut FrameReader {
        self.reader.as_mut().expect("request reader is present")
    }

    fn take(&mut self) -> (FrameReader, BoxSendStream) {
        (
            self.reader.take().expect("request reader is present"),
            self.writer.take().expect("response writer is present"),
        )
    }
}

impl Drop for RejectOnDrop {
    fn drop(&mut self) {
        if let Some(reader) = &mut self.reader {
            let _ = reader.stop(self.code);
        }
        if let Some(writer) = &mut self.writer {
            let _ = writer.reset(self.code);
        }
    }
}

struct ResetOnDrop {
    writer: Option<BoxSendStream>,
    code: Code,
}

#[cfg(feature = "webtransport")]
struct QpackCancelOnDrop {
    qpack: Arc<qpack::Qpack>,
    stream_id: StreamId,
    armed: bool,
}

#[cfg(feature = "webtransport")]
impl QpackCancelOnDrop {
    fn new(qpack: Arc<qpack::Qpack>, stream_id: StreamId) -> Self {
        Self {
            qpack,
            stream_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(feature = "webtransport")]
impl Drop for QpackCancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.qpack.cancel_stream(self.stream_id);
        }
    }
}

impl ResetOnDrop {
    fn new(writer: BoxSendStream, code: Code) -> Self {
        Self {
            writer: Some(writer),
            code,
        }
    }

    fn writer(&mut self) -> &mut BoxSendStream {
        self.writer.as_mut().expect("writer guard is armed")
    }

    #[cfg(feature = "webtransport")]
    fn take(mut self) -> BoxSendStream {
        self.writer.take().expect("writer guard is armed")
    }

    fn disarm(mut self) {
        self.writer.take();
    }
}

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        if let Some(writer) = &mut self.writer {
            let _ = writer.reset(self.code);
        }
    }
}

async fn send_message<B>(
    writer: BoxSendStream,
    headers: Bytes,
    body: B,
    content_length: Option<u64>,
    qpack: Arc<qpack::Qpack>,
    stream_id: StreamId,
) -> Result<(), Error>
where
    B: HttpBody + Send,
    B::Data: Buf + Send,
    B::Error: StdError + Send + Sync + 'static,
{
    let mut writer = ResetOnDrop::new(writer, Code::H3_REQUEST_CANCELLED);
    write_h3_frame(writer.writer(), wire::HEADERS_FRAME_TYPE, &headers).await?;
    send_body(writer.writer(), body, content_length, &qpack, stream_id).await?;
    writer
        .writer()
        .close()
        .await
        .map_err(wire::map_stream_error)?;
    writer.disarm();
    Ok(())
}

async fn send_body<B>(
    writer: &mut BoxSendStream,
    body: B,
    mut content_length: Option<u64>,
    qpack: &qpack::Qpack,
    stream_id: StreamId,
) -> Result<(), Error>
where
    B: HttpBody + Send,
    B::Data: Buf + Send,
    B::Error: StdError + Send + Sync + 'static,
{
    let mut body = pin!(body);
    let mut trailers_sent = false;

    loop {
        wait_writer_ready(writer).await?;
        let Some(frame) = body.as_mut().frame().await else {
            return if content_length.is_some_and(|remaining| remaining != 0) {
                Err(Error::stream(
                    Some(Code::H3_MESSAGE_ERROR),
                    "outgoing body length does not match Content-Length",
                ))
            } else {
                Ok(())
            };
        };
        let frame = frame.map_err(Error::send_body)?;

        let frame = match frame.into_data() {
            Ok(mut data) => {
                if trailers_sent {
                    return Err(Error::stream(
                        Some(Code::H3_MESSAGE_ERROR),
                        "outgoing body produced DATA after trailers",
                    ));
                }
                let remaining = data.remaining();
                if let Some(expected) = &mut content_length {
                    *expected = expected.checked_sub(remaining as u64).ok_or_else(|| {
                        Error::stream(
                            Some(Code::H3_MESSAGE_ERROR),
                            "outgoing body exceeds Content-Length",
                        )
                    })?;
                }
                wire::encode_frame(wire::DATA_FRAME_TYPE, &data.copy_to_bytes(remaining))?
            }
            Err(frame) => match frame.into_trailers() {
                Ok(trailers) => {
                    if trailers_sent {
                        return Err(Error::stream(
                            Some(Code::H3_MESSAGE_ERROR),
                            "outgoing body produced more than one trailer section",
                        ));
                    }
                    trailers_sent = true;
                    let trailers = qpack.encode_trailers(stream_id, trailers).await?;
                    wire::encode_frame(wire::HEADERS_FRAME_TYPE, &trailers)?
                }
                Err(_unknown) => continue,
            },
        };

        Pin::new(&mut **writer)
            .start_send(frame)
            .map_err(wire::map_stream_error)?;
        writer.flush().await.map_err(wire::map_stream_error)?;
    }
}

async fn wait_writer_ready(writer: &mut BoxSendStream) -> Result<(), Error> {
    futures::future::poll_fn(|cx| Pin::new(&mut **writer).poll_ready(cx))
        .await
        .map_err(wire::map_stream_error)
}

async fn write_h3_frame(
    writer: &mut BoxSendStream,
    frame_type: u64,
    payload: &[u8],
) -> Result<(), Error> {
    send_bytes(writer, wire::encode_frame(frame_type, payload)?).await
}

fn fail_on_connection<T>(
    result: Result<T, Error>,
    fail_connection: &FailConnection,
) -> Result<T, Error> {
    if let Err(error) = &result
        && error.is_connection()
    {
        fail_connection(error.clone());
    }
    result
}

async fn read_h3_frame(
    reader: &mut FrameReader,
    fail_connection: &FailConnection,
    #[cfg(feature = "webtransport")] webtransport: Option<&Arc<crate::webtransport::Runtime>>,
) -> Result<Option<FrameHeader>, Error> {
    let result = async {
        #[cfg(feature = "webtransport")]
        if webtransport.is_some() {
            let Some(frame_type) = reader.next_type().await? else {
                return Ok(None);
            };
            if frame_type == wire::WEBTRANSPORT_BIDI_SIGNAL {
                return Err(Error::connection_protocol(
                    Code::H3_FRAME_ERROR,
                    "WT_STREAM is only valid at the beginning of a WebTransport stream",
                ));
            }
            return reader.header_after_type(frame_type).await.map(Some);
        }
        reader.next_header().await
    }
    .await;
    fail_on_connection(result, fail_connection)
}

async fn read_h3_payload(
    reader: &mut FrameReader,
    fail_connection: &FailConnection,
) -> Result<wire::BufferedPayload, Error> {
    fail_on_connection(
        reader.read_payload(wire::MAX_BUFFERED_FRAME_PAYLOAD).await,
        fail_connection,
    )
}

async fn discard_h3_payload(
    reader: &mut FrameReader,
    fail_connection: &FailConnection,
) -> Result<(), Error> {
    fail_on_connection(reader.discard_payload().await, fail_connection)
}

async fn reject_push_promise(reader: &mut FrameReader, fail_connection: &FailConnection) -> Error {
    // Neither endpoint advertises push IDs; parse only the ID, never the QPACK payload.
    let error = match reader.read_payload_varint().await {
        Err(error) => error,
        Ok(_) => {
            Error::connection_protocol(Code::H3_ID_ERROR, "peer promised an unauthorized push ID")
        }
    };
    if error.is_connection() {
        fail_connection(error.clone());
    }
    error
}

fn unexpected_frame(fail_connection: &FailConnection) -> Error {
    let error = Error::connection_protocol(
        Code::H3_FRAME_UNEXPECTED,
        "frame is forbidden in this HTTP stream phase",
    );
    fail_connection(error.clone());
    error
}

struct OutgoingExchange {
    shared: Arc<Shared>,
    stream_id: StreamId,
}

impl Drop for OutgoingExchange {
    fn drop(&mut self) {
        self.shared.unregister_outgoing(self.stream_id);
    }
}

struct IncomingExchange {
    shared: Arc<Shared>,
}

impl Drop for IncomingExchange {
    fn drop(&mut self) {
        self.shared.finish_incoming();
    }
}

struct BodyExchange {
    _outgoing: Option<OutgoingExchange>,
    _incoming: Option<Arc<IncomingExchange>>,
}

impl BodyExchange {
    fn outgoing(exchange: OutgoingExchange) -> Self {
        Self {
            _outgoing: Some(exchange),
            _incoming: None,
        }
    }

    fn incoming(exchange: Arc<IncomingExchange>) -> Self {
        Self {
            _outgoing: None,
            _incoming: Some(exchange),
        }
    }
}

struct ReceivedBody {
    reader: FrameReader,
    is_response: bool,
    qpack: Arc<qpack::Qpack>,
    fail_connection: FailConnection,
    stream_id: StreamId,
    remaining: Option<u64>,
    trailers_received: bool,
    finished: bool,
    stop_code: Code,
    _exchange: Option<BodyExchange>,
    #[cfg(feature = "webtransport")]
    webtransport: Option<Arc<crate::webtransport::Runtime>>,
}

impl ReceivedBody {
    fn into_body(self) -> Body {
        let frames = futures::stream::try_unfold(self, |mut state| async move {
            state
                .next_frame()
                .await
                .map(|frame| frame.map(|frame| (frame, state)))
        });
        Body::new(StreamBody::new(frames))
    }

    async fn next_frame(&mut self) -> Result<Option<HttpFrame<Bytes>>, Error> {
        let result = self.next_frame_inner().await;
        fail_on_connection(result, &self.fail_connection)
    }

    async fn next_frame_inner(&mut self) -> Result<Option<HttpFrame<Bytes>>, Error> {
        loop {
            // Only DATA can survive a successful iteration with payload left unread.
            if self.reader.remaining() != 0 {
                let bytes = self
                    .reader
                    .read_payload_chunk(wire::MAX_DATA_CHUNK)
                    .await?
                    .expect("DATA has remaining payload");
                return Ok(Some(HttpFrame::data(bytes)));
            }
            let Some(frame) = read_h3_frame(
                &mut self.reader,
                &self.fail_connection,
                #[cfg(feature = "webtransport")]
                self.webtransport.as_ref(),
            )
            .await?
            else {
                self.finished = true;
                if self.remaining.is_some_and(|remaining| remaining != 0) {
                    return Err(Error::stream(
                        Some(Code::H3_MESSAGE_ERROR),
                        "Content-Length does not match received DATA length",
                    ));
                }
                return Ok(None);
            };

            match frame.frame_type {
                FrameType::Data => {
                    if self.trailers_received {
                        return Err(unexpected_frame(&self.fail_connection));
                    }
                    if let Some(remaining) = &mut self.remaining {
                        *remaining = remaining.checked_sub(frame.length).ok_or_else(|| {
                            Error::stream(
                                Some(Code::H3_MESSAGE_ERROR),
                                "received more DATA than Content-Length",
                            )
                        })?;
                    }
                    // Zero-length DATA is not EOF; the next iteration reads another header.
                }
                FrameType::Headers => {
                    if self.trailers_received {
                        return Err(unexpected_frame(&self.fail_connection));
                    }
                    if self.remaining.is_some_and(|remaining| remaining != 0) {
                        return Err(Error::stream(
                            Some(Code::H3_MESSAGE_ERROR),
                            "trailers received before Content-Length was satisfied",
                        ));
                    }
                    let payload = read_h3_payload(&mut self.reader, &self.fail_connection).await?;
                    let trailers = self.qpack.decode_trailers(self.stream_id, &payload).await?;
                    self.trailers_received = true;
                    return Ok(Some(HttpFrame::trailers(trailers)));
                }
                FrameType::PushPromise if self.is_response => {
                    return Err(reject_push_promise(&mut self.reader, &self.fail_connection).await);
                }
                FrameType::Unknown(_) => self.reader.discard_payload().await?,
                _ => return Err(unexpected_frame(&self.fail_connection)),
            }
        }
    }
}

impl Drop for ReceivedBody {
    fn drop(&mut self) {
        if !self.finished {
            self.qpack.cancel_stream(self.stream_id);
            let _ = self.reader.stop(self.stop_code);
        }
    }
}

fn content_length(headers: &HeaderMap) -> Result<Option<u64>, Error> {
    let mut parsed = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        let value = value.to_str().map_err(|source| {
            Error::stream_with_source(
                Some(Code::H3_MESSAGE_ERROR),
                "Content-Length is not ASCII",
                source,
            )
        })?;
        for value in value.split(',') {
            let value = value.trim().parse::<u64>().map_err(|source| {
                Error::stream_with_source(
                    Some(Code::H3_MESSAGE_ERROR),
                    "Content-Length is not a non-negative integer",
                    source,
                )
            })?;
            if parsed.is_some_and(|previous| previous != value) {
                return Err(Error::stream(
                    Some(Code::H3_MESSAGE_ERROR),
                    "conflicting Content-Length values",
                ));
            }
            parsed = Some(value);
        }
    }
    Ok(parsed)
}

async fn open_critical_stream<T: transport::Connection>(
    transport: &T,
    stream_type: u64,
) -> Result<BoxSendStream, Error> {
    let mut stream: BoxSendStream =
        Box::new(transport.open_uni().await.map_err(map_connection_error)?);
    if stream.id().as_u64() & 0x02 == 0 {
        return Err(Error::connection_protocol(
            Code::H3_STREAM_CREATION_ERROR,
            format!(
                "transport returned bidirectional stream {} from open_uni",
                stream.id()
            ),
        ));
    }
    send_bytes(&mut stream, wire::encode_stream_type(stream_type)?).await?;
    Ok(stream)
}

async fn send_bytes(stream: &mut BoxSendStream, bytes: Bytes) -> Result<(), Error> {
    stream.send(bytes).await.map_err(wire::map_stream_error)
}

fn validate_settings(settings: &Settings) -> Result<(), Error> {
    for (name, value) in [
        ("max_field_section_size", settings.max_field_section_size()),
        (
            "qpack_max_table_capacity",
            Some(settings.qpack_max_table_capacity()),
        ),
        (
            "qpack_blocked_streams",
            Some(settings.qpack_blocked_streams()),
        ),
    ] {
        if value.is_some_and(|value| value > MAX_VARINT) {
            return Err(Error::invalid_settings(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{name} exceeds the QUIC variable-length integer range"),
            )));
        }
    }
    Ok(())
}

fn map_connection_error(error: transport::ConnectionError) -> Error {
    Error::connection(error.code(), "QUIC connection failed", error)
}

fn map_outgoing_request_error(error: Error) -> Error {
    if error.code() == Some(Code::H3_REQUEST_REJECTED) {
        Error::request_rejected_with_source("peer rejected the request", error)
    } else {
        error
    }
}

fn close_after_init_failure<T: transport::Connection>(transport: &T, error: &Error) {
    transport.close(
        error.code().unwrap_or(Code::H3_INTERNAL_ERROR),
        error.to_string().as_bytes(),
    );
}

async fn watch_transport_closed<T: transport::Connection>(transport: Arc<T>, shared: Arc<Shared>) {
    shared.fail(map_connection_error(transport.closed().await));
}

async fn supervise_qpack_decoder_writer<T: transport::Connection>(
    transport: Arc<T>,
    shared: Arc<Shared>,
    writer: qpack::DecoderWriter,
    mut shutdown: watch::Receiver<bool>,
) {
    let result = tokio::select! {
        result = writer.run() => Some(result),
        _ = shutdown.changed() => None,
        _ = shared.wait_closed() => None,
    };
    if let Some(Err(error)) = result {
        fail_protocol(&*transport, &shared, error);
    }
}

async fn supervise_qpack_lifecycle(shared: Arc<Shared>, qpack: Arc<qpack::Qpack>) {
    qpack.fail(shared.wait_closed().await);
}

#[cfg(feature = "webtransport")]
async fn supervise_webtransport_datagrams<T: transport::Connection>(
    transport: Arc<T>,
    shared: Arc<Shared>,
    webtransport: Arc<crate::webtransport::Runtime>,
    mut shutdown: watch::Receiver<bool>,
) {
    let result = tokio::select! {
        result = webtransport.run_datagrams() => Some(result),
        _ = shutdown.changed() => None,
        _ = shared.wait_closed() => None,
    };
    if let Some(Err(error)) = result {
        webtransport.fail(error.clone());
        fail_protocol(&*transport, &shared, error);
    }
}

#[cfg(feature = "webtransport")]
async fn supervise_webtransport_lifecycle(
    shared: Arc<Shared>,
    webtransport: Arc<crate::webtransport::Runtime>,
) {
    webtransport.fail(shared.wait_closed().await);
}

#[derive(Clone)]
struct RequestDispatch {
    shared: Arc<Shared>,
    requests: mpsc::Sender<AcceptedRequest>,
    qpack: Arc<qpack::Qpack>,
    fail_connection: FailConnection,
    shutdown: watch::Receiver<bool>,
    #[cfg(feature = "webtransport")]
    connection: Option<Arc<dyn Send + Sync>>,
}

impl RequestDispatch {
    async fn enqueue(
        &self,
        first: Option<FrameHeader>,
        reader: FrameReader,
        writer: BoxSendStream,
        stream_id: StreamId,
        #[cfg(feature = "webtransport")] webtransport: Option<Arc<crate::webtransport::Runtime>>,
    ) -> Result<(), Error> {
        #[cfg(feature = "webtransport")]
        let webtransport_enabled = webtransport.is_some();
        let resolver = RequestResolver {
            first,
            stream_id,
            shared: Arc::clone(&self.shared),
            reader: Some(reader),
            writer: Some(writer),
            qpack: Arc::clone(&self.qpack),
            fail_connection: Arc::clone(&self.fail_connection),
            qpack_cancellation_armed: true,
            #[cfg(feature = "webtransport")]
            webtransport,
            #[cfg(feature = "webtransport")]
            connection: self.connection.clone(),
        };
        #[cfg(feature = "webtransport")]
        if webtransport_enabled {
            let permit = match self.requests.try_reserve() {
                Ok(permit) => permit,
                Err(mpsc::error::TrySendError::Full(_)) => return Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
            };
            let request = resolver.resolve().await?;
            permit.send(request);
            return Ok(());
        }

        let mut shutdown = self.shutdown.clone();
        let permit = tokio::select! {
            result = self.requests.reserve() => match result {
                Ok(permit) => permit,
                Err(_) => return Ok(()),
            },
            _ = shutdown.changed() => return Ok(()),
            _ = self.shared.wait_closed() => return Ok(()),
        };
        let request = resolver.resolve().await?;
        permit.send(request);
        Ok(())
    }
}

async fn accept_bidi_streams<T: transport::Connection>(
    transport: Arc<T>,
    dispatch: RequestDispatch,
    webtransport: OptionalWebTransport<T::SendStream>,
) {
    #[cfg(not(feature = "webtransport"))]
    let _ = &webtransport;
    let mut shutdown = dispatch.shutdown.clone();
    let mut classifiers: JoinSet<Result<(), Error>> = JoinSet::new();
    let classifier_limit = dispatch.requests.max_capacity();

    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = transport.accept_bi(), if classifiers.len() < classifier_limit => Some(accepted),
            _ = dispatch.shared.wait_closed() => break,
            completed = classifiers.join_next(), if !classifiers.is_empty() => {
                match completed {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) if error.is_connection() => {
                        fail_protocol(&*transport, &dispatch.shared, error);
                        break;
                    }
                    Some(Ok(Err(_stream_error))) => {}
                    Some(Err(join_error)) => {
                        let error = Error::connection(
                            Some(Code::H3_INTERNAL_ERROR),
                            "bidirectional stream classifier failed",
                            join_error,
                        );
                        fail_protocol(&*transport, &dispatch.shared, error);
                        break;
                    }
                    None => {}
                }
                None
            }
        };
        let Some(accepted) = accepted else {
            continue;
        };
        let (reader, mut writer) = match accepted {
            Ok(streams) => streams,
            Err(error) => {
                dispatch.shared.fail(map_connection_error(error));
                break;
            }
        };

        let stream_id = reader.id();
        if stream_id != writer.id() || stream_id.as_u64() & 0x02 != 0 {
            let error = Error::connection_protocol(
                Code::H3_ID_ERROR,
                "transport returned an invalid bidirectional stream pair",
            );
            writer
                .reset(error.code().expect("protocol error has a code"))
                .ok();
            fail_protocol(&*transport, &dispatch.shared, error);
            break;
        }
        #[cfg(feature = "webtransport")]
        if let Some(hooks) = webtransport.hooks.clone() {
            let dispatch = dispatch.clone();
            classifiers.spawn(async move {
                classify_bidi_stream(reader, writer, stream_id, dispatch, hooks).await
            });
            continue;
        }

        if !dispatch.shared.register_incoming(stream_id) {
            let mut reader = reader;
            let _ = reader.stop(Code::H3_REQUEST_REJECTED);
            let _ = writer.reset(Code::H3_REQUEST_REJECTED);
            continue;
        }
        let request_dispatch = dispatch.clone();
        classifiers.spawn(async move {
            request_dispatch
                .enqueue(
                    None,
                    FrameReader::new(
                        ChunkReader::new(reader),
                        request_dispatch.shared.payload_budget.clone(),
                    ),
                    Box::new(writer),
                    stream_id,
                    #[cfg(feature = "webtransport")]
                    None,
                )
                .await
        });
    }

    classifiers.abort_all();
    while classifiers.join_next().await.is_some() {}
}

#[cfg(feature = "webtransport")]
async fn classify_bidi_stream<R, S>(
    reader: R,
    writer: S,
    stream_id: StreamId,
    dispatch: RequestDispatch,
    hooks: crate::webtransport::Hooks<S>,
) -> Result<(), Error>
where
    R: transport::RecvStream,
    S: transport::SendStream,
{
    let mut reader = ChunkReader::new(reader);
    let first_type = reader.read_varint().await?;
    if first_type == wire::WEBTRANSPORT_BIDI_SIGNAL {
        let session_id = crate::stream_id::try_from_u64(reader.read_varint().await?)?;
        if let Err(error) = hooks.runtime().wait_client_support().await {
            if error.is_connection() {
                return Err(error);
            }
            let code = error.code().unwrap_or(Code::H3_MESSAGE_ERROR);
            let _ = reader.stop(code);
            let mut writer = hooks.wrap_writer(writer);
            let _ = writer.reset_at(code, 0);
            return Ok(());
        }
        return hooks
            .runtime()
            .route_bidi(session_id, reader, hooks.wrap_writer(writer));
    }

    let length = reader.read_varint().await?;
    let first = FrameHeader {
        frame_type: first_type.into(),
        length,
    };
    let mut reader =
        FrameReader::after_header(reader, dispatch.shared.payload_budget.clone(), length);

    if !dispatch.shared.register_incoming(stream_id) {
        let _ = reader.stop(Code::H3_REQUEST_REJECTED);
        let mut writer = writer;
        let _ = writer.reset(Code::H3_REQUEST_REJECTED);
        return Ok(());
    }
    dispatch
        .enqueue(
            Some(first),
            reader,
            Box::new(writer),
            stream_id,
            Some(Arc::clone(hooks.runtime())),
        )
        .await
}

async fn accept_uni_streams<T: transport::Connection>(
    transport: Arc<T>,
    shared: Arc<Shared>,
    peer_critical: Arc<PeerCriticalStreams>,
    qpack: Arc<qpack::Qpack>,
    fail_connection: FailConnection,
    mut shutdown: watch::Receiver<bool>,
    webtransport: OptionalWebTransport<T::SendStream>,
) {
    #[cfg(not(feature = "webtransport"))]
    let _ = &webtransport;
    let mut streams = JoinSet::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = shared.wait_closed() => break,
            accepted = transport.accept_uni() => match accepted {
                Ok(stream) => {
                    let shared = Arc::clone(&shared);
                    let peer_critical = Arc::clone(&peer_critical);
                    let qpack = Arc::clone(&qpack);
                    let fail_connection = Arc::clone(&fail_connection);
                    #[cfg(feature = "webtransport")]
                    let webtransport = webtransport.runtime();
                    streams.spawn(async move {
                        handle_uni_stream(
                            ChunkReader::new(stream),
                            shared,
                            peer_critical,
                            qpack,
                            fail_connection,
                            #[cfg(feature = "webtransport")]
                            webtransport,
                        )
                        .await
                    });
                }
                Err(error) => {
                    shared.fail(map_connection_error(error));
                    break;
                }
            },
            completed = streams.join_next(), if !streams.is_empty() => {
                match completed {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) if error.is_connection() => {
                        fail_protocol(&*transport, &shared, error);
                        break;
                    }
                    Some(Ok(Err(_stream_error))) => {}
                    Some(Err(join_error)) => {
                        let error = Error::connection(
                            Some(Code::H3_INTERNAL_ERROR),
                            "unidirectional stream task failed",
                            join_error,
                        );
                        fail_protocol(&*transport, &shared, error);
                        break;
                    }
                    None => {}
                }
            }
        }
    }

    streams.abort_all();
    while streams.join_next().await.is_some() {}
}

async fn handle_uni_stream(
    mut reader: ChunkReader,
    shared: Arc<Shared>,
    peer_critical: Arc<PeerCriticalStreams>,
    qpack: Arc<qpack::Qpack>,
    fail_connection: FailConnection,
    #[cfg(feature = "webtransport")] webtransport: Option<Arc<crate::webtransport::Runtime>>,
) -> Result<(), Error> {
    match reader.read_varint().await? {
        CONTROL_STREAM_TYPE => {
            PeerCriticalStreams::claim(&peer_critical.control, "control")?;
            critical_stream_result(
                handle_control_stream(
                    reader,
                    shared,
                    qpack,
                    fail_connection,
                    #[cfg(feature = "webtransport")]
                    webtransport,
                )
                .await,
                "control",
            )
        }
        QPACK_ENCODER_STREAM_TYPE => {
            PeerCriticalStreams::claim(&peer_critical.qpack_encoder, "QPACK encoder")?;
            critical_stream_result(qpack.handle_encoder_stream(reader).await, "QPACK encoder")
        }
        QPACK_DECODER_STREAM_TYPE => {
            PeerCriticalStreams::claim(&peer_critical.qpack_decoder, "QPACK decoder")?;
            critical_stream_result(qpack.handle_decoder_stream(reader).await, "QPACK decoder")
        }
        PUSH_STREAM_TYPE => Err(Error::connection_protocol(
            if shared.local_role_bit == 1 {
                Code::H3_STREAM_CREATION_ERROR
            } else {
                Code::H3_ID_ERROR
            },
            "server push is not supported by the symmetric h3x profile",
        )),
        #[cfg(feature = "webtransport")]
        wire::WEBTRANSPORT_UNI_STREAM_TYPE => {
            let Some(webtransport) = webtransport else {
                return reader.drain_to_end().await;
            };
            let session_id = crate::stream_id::try_from_u64(reader.read_varint().await?)?;
            if let Err(error) = webtransport.wait_client_support().await {
                if error.is_connection() {
                    return Err(error);
                }
                let _ = reader.stop(error.code().unwrap_or(Code::H3_MESSAGE_ERROR));
                return Ok(());
            }
            webtransport.route_uni(session_id, reader)
        }
        _unknown => reader.drain_to_end().await,
    }
}

fn critical_stream_result(result: Result<(), Error>, name: &'static str) -> Result<(), Error> {
    match result {
        Err(error) if error.is_stream() => Err(Error::connection(
            Some(Code::H3_CLOSED_CRITICAL_STREAM),
            format!("peer {name} stream was reset"),
            error,
        )),
        other => other,
    }
}

async fn handle_control_stream(
    reader: ChunkReader,
    shared: Arc<Shared>,
    qpack: Arc<qpack::Qpack>,
    fail_connection: FailConnection,
    #[cfg(feature = "webtransport")] webtransport: Option<Arc<crate::webtransport::Runtime>>,
) -> Result<(), Error> {
    let mut reader = FrameReader::new(reader, shared.payload_budget.clone());
    let Some(first) = read_h3_frame(
        &mut reader,
        &fail_connection,
        #[cfg(feature = "webtransport")]
        webtransport.as_ref(),
    )
    .await?
    else {
        return Err(Error::connection_protocol(
            Code::H3_CLOSED_CRITICAL_STREAM,
            "peer control stream closed before SETTINGS",
        ));
    };
    if first.frame_type != FrameType::Settings {
        return Err(Error::connection_protocol(
            Code::H3_MISSING_SETTINGS,
            "SETTINGS is not the first frame on the peer control stream",
        ));
    }
    let peer_settings = {
        let payload = read_h3_payload(&mut reader, &fail_connection).await?;
        wire::decode_settings_payload(&payload)?
    };
    qpack.apply_peer_settings(&peer_settings).await?;
    #[cfg(feature = "webtransport")]
    if let Some(ref webtransport) = webtransport {
        webtransport.apply_peer_settings(&peer_settings);
    }

    let mut max_push_id = None;
    while let Some(frame) = read_h3_frame(
        &mut reader,
        &fail_connection,
        #[cfg(feature = "webtransport")]
        webtransport.as_ref(),
    )
    .await?
    {
        match frame.frame_type {
            FrameType::Settings => {
                return Err(Error::connection_protocol(
                    Code::H3_FRAME_UNEXPECTED,
                    "peer sent a second SETTINGS frame",
                ));
            }
            FrameType::Goaway => {
                let boundary = reader.read_id_payload().await?;
                if boundary & 0x02 != 0 {
                    return Err(Error::connection_protocol(
                        Code::H3_ID_ERROR,
                        "GOAWAY does not identify a bidirectional stream",
                    ));
                }
                shared.apply_peer_goaway(crate::stream_id::try_from_u64(boundary)?)?;
                #[cfg(feature = "webtransport")]
                if let Some(webtransport) = &webtransport {
                    webtransport.mark_active_draining();
                }
            }
            FrameType::MaxPushId => {
                let value = reader.read_id_payload().await?;
                if max_push_id.is_some_and(|previous| value < previous) {
                    return Err(Error::connection_protocol(
                        Code::H3_ID_ERROR,
                        "MAX_PUSH_ID decreased",
                    ));
                }
                max_push_id = Some(value);
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
                    "message frame received on the control stream",
                ));
            }
        }
    }

    Err(Error::connection_protocol(
        Code::H3_CLOSED_CRITICAL_STREAM,
        "peer control stream closed",
    ))
}

fn fail_protocol<T: transport::Connection>(transport: &T, shared: &Shared, error: Error) {
    transport.close(
        error.code().unwrap_or(Code::H3_INTERNAL_ERROR),
        error.to_string().as_bytes(),
    );
    shared.fail(error);
}
