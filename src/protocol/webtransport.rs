//! WebTransport over HTTP/3.
//!
//! The module owns only the WebTransport wire protocol. Identity, URL
//! authorization and application dispatch remain the caller's responsibility.

#![expect(
    dead_code,
    reason = "WebTransport connection integration is pending; see README"
)]

use std::{
    collections::BTreeSet,
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::Bytes;
use dquic::prelude::StreamWriter;
use futures::{SinkExt, future::BoxFuture};
use http::{Method, Request, Response as HttpResponse};
use qbase::varint::{VARINT_MAX, VarInt, WriteVarInt, be_varint};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot};

use crate::{ChunkBody, Code, Error, ResponseSender, Settings, StreamId, transport, wire};

mod capsule;
mod stream;

pub use stream::{RecvStream, SendStream};

pub const PROTOCOL: &str = "webtransport-h3";

/// Result of an outbound WebTransport CONNECT request.
#[derive(Debug)]
pub enum ConnectResponse {
    Accepted {
        response: HttpResponse<()>,
        session: Session,
    },
    Rejected(HttpResponse<ChunkBody>),
}

const CLOSE_MESSAGE_LIMIT: usize = 1024;
const APPLICATION_ERROR_FIRST: u64 = 0x52e4_a40f_a8db;
const APPLICATION_ERROR_LAST: u64 = 0x52e5_ac98_3162;

pub(crate) type TaskList = mpsc::UnboundedSender<BoxFuture<'static, ()>>;

/// Local queue limits for the optional WebTransport module.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    pending_stream_limit: usize,
    pending_datagram_limit: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pending_stream_limit: 64,
            pending_datagram_limit: 256,
        }
    }
}

/// Application close information carried by WT_CLOSE_SESSION.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Close {
    code: u32,
    message: String,
}

impl Close {
    pub const fn code(&self) -> u32 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    fn new(code: u32, message: impl Into<String>) -> Result<Self, Error> {
        let message = message.into();
        if message.len() > CLOSE_MESSAGE_LIMIT {
            return Err(Error::stream(
                Some(Code::H3_MESSAGE_ERROR),
                "WebTransport close message exceeds 1024 UTF-8 bytes",
            ));
        }
        Ok(Self { code, message })
    }
}

/// Maps a WebTransport application's 32-bit error to its HTTP/3 code.
pub const fn map_application_error(code: u32) -> Code {
    let code = code as u64;
    // The largest u32 value maps below the QUIC varint limit by construction.
    Code::new_unchecked(APPLICATION_ERROR_FIRST + code + code / 0x1e)
}

/// Reverses [`map_application_error`] for peer stream errors.
pub const fn application_error_code(code: Code) -> Option<u32> {
    let code = code.as_u64();
    if code < APPLICATION_ERROR_FIRST || code > APPLICATION_ERROR_LAST {
        return None;
    }
    if code.wrapping_sub(0x21).is_multiple_of(0x1f) {
        return None;
    }
    let shifted = code - APPLICATION_ERROR_FIRST;
    Some((shifted - shifted / 0x1f) as u32)
}

#[derive(Clone, Debug)]
pub(crate) struct ProtocolMarker;

/// Returns whether a decoded request is a WebTransport extended CONNECT.
pub fn is_request<B>(request: &Request<B>) -> bool {
    request.method() == Method::CONNECT && request.extensions().get::<ProtocolMarker>().is_some()
}

trait Driver: Send + Sync {
    fn open_bi(&self) -> BoxFuture<'static, Result<(wire::ChunkReader, stream::BoxWriter), Error>>;

    fn open_uni(&self) -> BoxFuture<'static, Result<stream::BoxWriter, Error>>;

    fn max_datagram_size(&self) -> usize;

    fn send_datagram(&self, datagram: Bytes) -> BoxFuture<'static, Result<(), Error>>;

    fn receive_datagram(&self) -> BoxFuture<'static, Result<Bytes, Error>>;

    fn close(&self, code: Code, reason: &[u8]);
}

struct DriverImpl<T: transport::webtransport::Connection> {
    transport: Arc<T>,
}

impl<T: transport::webtransport::Connection> Driver for DriverImpl<T> {
    fn open_bi(&self) -> BoxFuture<'static, Result<(wire::ChunkReader, stream::BoxWriter), Error>> {
        let transport = Arc::clone(&self.transport);
        Box::pin(async move {
            let (id, (reader, writer)) = transport.open_bi().await.map_err(map_connection_error)?;
            if u64::from(id) & 0x02 != 0 {
                return Err(Error::connection_protocol(
                    Code::H3_ID_ERROR,
                    "transport returned an invalid WebTransport bidirectional stream pair",
                ));
            }
            Ok((
                wire::ChunkReader::new(id, reader),
                stream::adapt_writer(transport, id, writer),
            ))
        })
    }

    fn open_uni(&self) -> BoxFuture<'static, Result<stream::BoxWriter, Error>> {
        let transport = Arc::clone(&self.transport);
        Box::pin(async move {
            let (id, writer) = transport.open_uni().await.map_err(map_connection_error)?;
            if u64::from(id) & 0x02 == 0 {
                return Err(Error::connection_protocol(
                    Code::H3_STREAM_CREATION_ERROR,
                    "transport returned a bidirectional stream from WebTransport open_uni",
                ));
            }
            Ok(stream::adapt_writer(transport, id, writer))
        })
    }

    fn max_datagram_size(&self) -> usize {
        self.transport.max_datagram_size()
    }

    fn send_datagram(&self, datagram: Bytes) -> BoxFuture<'static, Result<(), Error>> {
        let transport = Arc::clone(&self.transport);
        Box::pin(async move {
            transport
                .send_datagram(datagram)
                .await
                .map_err(map_connection_error)
        })
    }

    fn receive_datagram(&self) -> BoxFuture<'static, Result<Bytes, Error>> {
        let transport = Arc::clone(&self.transport);
        Box::pin(async move {
            transport
                .receive_datagram()
                .await
                .map_err(map_connection_error)
        })
    }

    fn close(&self, code: Code, reason: &[u8]) {
        self.transport.close(code, reason);
    }
}

type WrapWriter<S> = Arc<dyn Fn(StreamId, S) -> stream::BoxWriter + Send + Sync>;

pub(crate) struct Hooks<S> {
    runtime: Arc<Runtime>,
    wrap_writer: WrapWriter<S>,
}

impl<S> Clone for Hooks<S> {
    fn clone(&self) -> Self {
        Self {
            runtime: Arc::clone(&self.runtime),
            wrap_writer: Arc::clone(&self.wrap_writer),
        }
    }
}

impl<S> Hooks<S> {
    pub(crate) fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    pub(crate) fn wrap_writer(&self, id: StreamId, writer: S) -> stream::BoxWriter {
        (self.wrap_writer)(id, writer)
    }
}

pub(crate) fn configure<T>(
    transport: Arc<T>,
    config: Config,
    tasks: TaskList,
) -> Result<Hooks<StreamWriter>, Error>
where
    T: transport::webtransport::Connection,
{
    if !transport.supports_reset_stream_at() {
        return Err(Error::connection_protocol(
            Code::WT_REQUIREMENTS_NOT_MET,
            "WebTransport requires negotiated RESET_STREAM_AT support",
        ));
    }
    if transport.max_datagram_size() == 0 {
        return Err(Error::connection_protocol(
            Code::WT_REQUIREMENTS_NOT_MET,
            "WebTransport requires negotiated QUIC DATAGRAM support",
        ));
    }

    let driver: Arc<dyn Driver> = Arc::new(DriverImpl {
        transport: Arc::clone(&transport),
    });
    let runtime = Arc::new(Runtime::new(driver, config, tasks));
    let wrap_writer =
        Arc::new(move |id, writer| stream::adapt_writer(Arc::clone(&transport), id, writer));
    Ok(Hooks {
        runtime,
        wrap_writer,
    })
}

struct Registry {
    active: Option<Weak<SessionState>>,
    closed: BTreeSet<StreamId>,
}

impl Registry {
    fn new() -> Self {
        Self {
            active: None,
            closed: BTreeSet::new(),
        }
    }
}

pub(crate) struct Runtime {
    driver: Arc<dyn Driver>,
    config: Config,
    tasks: TaskList,
    registry: Mutex<Registry>,
    peer_settings: Mutex<Option<PeerSettings>>,
    peer_settings_changed: Notify,
    failure: Mutex<Option<Error>>,
    failed: Notify,
}

#[derive(Clone, Copy)]
struct PeerSettings {
    connect_protocol: bool,
    h3_datagram: bool,
    webtransport: bool,
}

impl PeerSettings {
    fn server_supports_webtransport(self) -> bool {
        self.connect_protocol && self.h3_datagram && self.webtransport
    }

    fn client_supports_webtransport(self) -> bool {
        self.h3_datagram && self.webtransport
    }
}

impl Runtime {
    fn new(driver: Arc<dyn Driver>, config: Config, tasks: TaskList) -> Self {
        Self {
            driver,
            config,
            tasks,
            registry: Mutex::new(Registry::new()),
            peer_settings: Mutex::new(None),
            peer_settings_changed: Notify::new(),
            failure: Mutex::new(None),
            failed: Notify::new(),
        }
    }

    pub(crate) fn apply_peer_settings(&self, settings: &Settings) {
        let settings = PeerSettings {
            connect_protocol: settings.enable_connect_protocol(),
            h3_datagram: settings.h3_datagram(),
            webtransport: settings.webtransport(),
        };
        *self
            .peer_settings
            .lock()
            .expect("WebTransport peer settings lock poisoned") = Some(settings);
        self.peer_settings_changed.notify_waiters();
    }

    pub(crate) async fn wait_server_support(&self) -> Result<(), Error> {
        self.wait_peer_support(PeerSettings::server_supports_webtransport)
            .await
    }

    pub(crate) async fn wait_client_support(&self) -> Result<(), Error> {
        self.wait_peer_support(PeerSettings::client_supports_webtransport)
            .await
    }

    async fn wait_peer_support(
        &self,
        supports_webtransport: impl Fn(PeerSettings) -> bool,
    ) -> Result<(), Error> {
        loop {
            let settings_changed = self.peer_settings_changed.notified();
            let failed = self.failed.notified();
            if let Some(error) = self
                .failure
                .lock()
                .expect("WebTransport failure lock poisoned")
                .clone()
            {
                return Err(error);
            }
            if let Some(settings) = *self
                .peer_settings
                .lock()
                .expect("WebTransport peer settings lock poisoned")
            {
                return if supports_webtransport(settings) {
                    Ok(())
                } else {
                    Err(Error::stream(
                        Some(Code::WT_REQUIREMENTS_NOT_MET),
                        "peer SETTINGS do not enable WebTransport",
                    ))
                };
            }
            tokio::select! {
                _ = settings_changed => {}
                _ = failed => {}
            }
        }
    }

    pub(crate) fn fail(&self, error: Error) {
        let mut failure = self
            .failure
            .lock()
            .expect("WebTransport failure lock poisoned");
        if failure.is_some() {
            return;
        }
        *failure = Some(error.clone());
        drop(failure);
        self.failed.notify_waiters();
        self.peer_settings_changed.notify_waiters();
        if let Some(session) = self.active_session() {
            session.terminate(Err(error));
        }
    }

    pub(crate) fn fail_protocol(&self, error: Error) {
        self.driver.close(
            error.code().unwrap_or(Code::H3_INTERNAL_ERROR),
            error.to_string().as_bytes(),
        );
        self.fail(error);
    }

    fn register(
        self: &Arc<Self>,
        id: StreamId,
        connection: std::sync::Arc<dyn Send + Sync>,
    ) -> Result<PreparedSession, Error> {
        validate_session_id(id)?;
        if let Some(error) = self
            .failure
            .lock()
            .expect("WebTransport failure lock poisoned")
            .clone()
        {
            return Err(error);
        }

        let mut registry = self
            .registry
            .lock()
            .expect("WebTransport registry lock poisoned");
        if registry.active.as_ref().and_then(Weak::upgrade).is_some() {
            return Err(Error::request_rejected(
                "only one WebTransport session may be active without session flow control",
            ));
        }

        let (bidi_tx, bidi_rx) = mpsc::channel(self.config.pending_stream_limit);
        let (uni_tx, uni_rx) = mpsc::channel(self.config.pending_stream_limit);
        let (datagram_tx, datagram_rx) = mpsc::channel(self.config.pending_datagram_limit);
        let (commands, command_rx) = mpsc::channel(8);
        let state = Arc::new(SessionState {
            id,
            runtime: Arc::downgrade(self),
            driver: Arc::clone(&self.driver),
            inner: Mutex::new(SessionInner {
                terminal: None,
                streams: Vec::new(),
            }),
            closed: Notify::new(),
            drained: AtomicBool::new(false),
            drain_changed: Notify::new(),
            bidi_tx,
            bidi_rx: AsyncMutex::new(bidi_rx),
            uni_tx,
            uni_rx: AsyncMutex::new(uni_rx),
            datagram_tx,
            datagram_rx: AsyncMutex::new(datagram_rx),
        });
        registry.active = Some(Arc::downgrade(&state));
        Ok(PreparedSession {
            session: Session {
                state,
                commands,
                _connection: connection,
            },
            command_rx,
        })
    }

    pub(crate) fn prepare(
        self: &Arc<Self>,
        id: StreamId,
        connection: std::sync::Arc<dyn Send + Sync>,
    ) -> Result<PendingSession, Error> {
        Ok(PendingSession {
            prepared: Some(self.register(id, connection)?),
        })
    }

    fn active_session(&self) -> Option<Arc<SessionState>> {
        let active = self
            .registry
            .lock()
            .expect("WebTransport registry lock poisoned")
            .active
            .clone();
        active
            .as_ref()
            .and_then(Weak::upgrade)
            .filter(|session| session.is_open())
    }

    pub(crate) fn mark_active_draining(&self) {
        if let Some(session) = self.active_session() {
            session.mark_drained();
        }
    }

    fn session_for(&self, id: StreamId) -> Result<Arc<SessionState>, Code> {
        validate_session_id(id).map_err(|_| Code::H3_ID_ERROR)?;
        let (active, closed) = {
            let registry = self
                .registry
                .lock()
                .expect("WebTransport registry lock poisoned");
            (registry.active.clone(), registry.closed.contains(&id))
        };
        if let Some(session) = active.as_ref().and_then(Weak::upgrade)
            && session.id == id
            && session.is_open()
        {
            return Ok(session);
        }
        if closed {
            Err(Code::WT_SESSION_GONE)
        } else {
            Err(Code::WT_BUFFERED_STREAM_REJECTED)
        }
    }

    fn unregister(&self, id: StreamId) {
        let mut registry = self
            .registry
            .lock()
            .expect("WebTransport registry lock poisoned");
        if registry
            .active
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|session| session.id == id)
        {
            registry.active = None;
        }
        registry.closed.insert(id);
    }

    pub(crate) fn route_bidi(
        &self,
        id: StreamId,
        mut reader: wire::ChunkReader,
        mut writer: stream::BoxWriter,
    ) -> Result<(), Error> {
        let session = match self.session_for(id) {
            Ok(session) => session,
            Err(Code::H3_ID_ERROR) => return Err(invalid_session_id_error(id)),
            Err(code) => {
                reader.stop(code);
                let _ = writer.reset_at(code, 0);
                return Ok(());
            }
        };
        session.deliver_bidi(reader, writer);
        Ok(())
    }

    pub(crate) fn route_uni(
        &self,
        id: StreamId,
        mut reader: wire::ChunkReader,
    ) -> Result<(), Error> {
        let session = match self.session_for(id) {
            Ok(session) => session,
            Err(Code::H3_ID_ERROR) => return Err(invalid_session_id_error(id)),
            Err(code) => {
                reader.stop(code);
                return Ok(());
            }
        };
        session.deliver_uni(reader);
        Ok(())
    }

    pub(crate) async fn run_datagrams(&self) -> Result<(), Error> {
        loop {
            let datagram = self.driver.receive_datagram().await?;
            let (remaining, quarter_id) = be_varint(&datagram).map_err(|_| {
                Error::connection_protocol(
                    Code::H3_DATAGRAM_ERROR,
                    "HTTP/3 datagram is missing a valid Quarter Stream ID",
                )
            })?;
            let consumed = datagram.len() - remaining.len();
            let quarter_id = quarter_id.into_u64();
            if quarter_id > VARINT_MAX / 4 {
                return Err(Error::connection_protocol(
                    Code::H3_DATAGRAM_ERROR,
                    "HTTP/3 datagram Quarter Stream ID is too large",
                ));
            }
            let id = VarInt::try_from(quarter_id * 4)
                .map(StreamId::from)
                .map_err(|_| Error::invalid_stream_id(quarter_id * 4))?;
            if let Ok(session) = self.session_for(id) {
                let _ = session.datagram_tx.try_send(datagram.slice(consumed..));
            }
        }
    }

    pub(crate) fn track(&self, task: BoxFuture<'static, ()>) {
        let _ = self.tasks.send(task);
    }
}

struct SessionInner {
    terminal: Option<Result<Close, Error>>,
    streams: Vec<Weak<dyn stream::AbortStream>>,
}

pub(crate) struct SessionState {
    id: StreamId,
    runtime: Weak<Runtime>,
    driver: Arc<dyn Driver>,
    inner: Mutex<SessionInner>,
    closed: Notify,
    drained: AtomicBool,
    drain_changed: Notify,
    bidi_tx: mpsc::Sender<(RecvStream, SendStream)>,
    bidi_rx: AsyncMutex<mpsc::Receiver<(RecvStream, SendStream)>>,
    uni_tx: mpsc::Sender<RecvStream>,
    uni_rx: AsyncMutex<mpsc::Receiver<RecvStream>>,
    datagram_tx: mpsc::Sender<Bytes>,
    datagram_rx: AsyncMutex<mpsc::Receiver<Bytes>>,
}

impl SessionState {
    fn is_open(&self) -> bool {
        self.inner
            .lock()
            .expect("WebTransport session lock poisoned")
            .terminal
            .is_none()
    }

    fn check_open(&self) -> Result<(), Error> {
        match self
            .inner
            .lock()
            .expect("WebTransport session lock poisoned")
            .terminal
            .clone()
        {
            None => Ok(()),
            Some(Ok(_)) => Err(Error::stream(
                Some(Code::WT_SESSION_GONE),
                "WebTransport session is closed",
            )),
            Some(Err(error)) => Err(error),
        }
    }

    fn register_stream(&self, stream: Arc<dyn stream::AbortStream>) {
        let terminal = {
            let mut inner = self
                .inner
                .lock()
                .expect("WebTransport session lock poisoned");
            inner
                .streams
                .retain(|stream| stream.upgrade().is_some_and(|stream| !stream.finished()));
            if inner.terminal.is_none() {
                inner.streams.push(Arc::downgrade(&stream));
                None
            } else {
                Some(Code::WT_SESSION_GONE)
            }
        };
        if let Some(code) = terminal {
            stream.abort(code);
        }
    }

    fn prune_streams(&self) {
        self.inner
            .lock()
            .expect("WebTransport session lock poisoned")
            .streams
            .retain(|stream| stream.upgrade().is_some_and(|stream| !stream.finished()));
    }

    fn terminate(&self, result: Result<Close, Error>) {
        let streams = {
            let mut inner = self
                .inner
                .lock()
                .expect("WebTransport session lock poisoned");
            if inner.terminal.is_some() {
                return;
            }
            inner.terminal = Some(result);
            inner
                .streams
                .drain(..)
                .filter_map(|stream| stream.upgrade())
                .collect::<Vec<_>>()
        };
        for stream in streams {
            stream.abort(Code::WT_SESSION_GONE);
        }
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.unregister(self.id);
        }
        self.closed.notify_waiters();
        self.drain_changed.notify_waiters();
    }

    fn mark_drained(&self) {
        if !self.drained.swap(true, Ordering::AcqRel) {
            self.drain_changed.notify_waiters();
        }
    }

    async fn wait_closed(&self) -> Result<Close, Error> {
        loop {
            let notified = self.closed.notified();
            if let Some(result) = self
                .inner
                .lock()
                .expect("WebTransport session lock poisoned")
                .terminal
                .clone()
            {
                return result;
            }
            notified.await;
        }
    }

    fn deliver_bidi(self: &Arc<Self>, reader: wire::ChunkReader, writer: stream::BoxWriter) {
        if self.check_open().is_err() {
            reject_bidi(reader, writer, Code::WT_SESSION_GONE);
            return;
        }
        let recv = RecvStream::new(reader, self);
        let send = SendStream::new(writer, 0, self);
        if let Err(error) = self.bidi_tx.try_send((recv, send)) {
            let (mut recv, mut send) = error.into_inner();
            let _ = recv.stop_with_code(Code::WT_BUFFERED_STREAM_REJECTED);
            let _ = send.reset_with_code(Code::WT_BUFFERED_STREAM_REJECTED);
        }
    }

    fn deliver_uni(self: &Arc<Self>, reader: wire::ChunkReader) {
        if self.check_open().is_err() {
            reject_uni(reader, Code::WT_SESSION_GONE);
            return;
        }
        let recv = RecvStream::new(reader, self);
        if let Err(error) = self.uni_tx.try_send(recv) {
            let mut recv = error.into_inner();
            let _ = recv.stop_with_code(Code::WT_BUFFERED_STREAM_REJECTED);
        }
    }
}

struct PreparedSession {
    session: Session,
    command_rx: mpsc::Receiver<ControlCommand>,
}

pub(crate) struct PendingSession {
    prepared: Option<PreparedSession>,
}

impl PendingSession {
    pub(crate) fn start(mut self, body: ChunkBody, writer: StreamWriter) -> Session {
        let prepared = self
            .prepared
            .take()
            .expect("pending WebTransport session is present");
        let session = prepared.session.clone();
        start_control(prepared, body, writer);
        session
    }

    pub(crate) fn fail(mut self, error: Error) {
        if let Some(prepared) = self.prepared.take() {
            prepared.session.state.terminate(Err(error));
        }
    }
}

impl Drop for PendingSession {
    fn drop(&mut self) {
        if let Some(prepared) = self.prepared.take() {
            prepared.session.state.terminate(Err(Error::stream(
                Some(Code::H3_REQUEST_CANCELLED),
                "WebTransport handshake was abandoned",
            )));
        }
    }
}

pub(crate) enum ControlCommand {
    Drain(oneshot::Sender<Result<(), Error>>),
    Close(Close, oneshot::Sender<Result<(), Error>>),
}

/// An established WebTransport session.
#[derive(Clone)]
pub struct Session {
    state: Arc<SessionState>,
    commands: mpsc::Sender<ControlCommand>,
    _connection: std::sync::Arc<dyn Send + Sync>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn id(&self) -> StreamId {
        self.state.id
    }

    pub fn max_datagram_size(&self) -> usize {
        let mut prefix = Vec::with_capacity(8);
        prefix.put_varint(
            &VarInt::try_from(u64::from(self.id()) / 4).expect("valid Quarter Stream ID"),
        );
        self.state
            .driver
            .max_datagram_size()
            .saturating_sub(prefix.len())
    }

    pub async fn open_bi(&self) -> Result<(RecvStream, SendStream), Error> {
        self.state.check_open()?;
        let (reader, mut writer) = self.state.driver.open_bi().await?;
        let reliable_size =
            write_stream_header(&mut writer, wire::WEBTRANSPORT_BIDI_SIGNAL, self.id()).await?;
        let recv = RecvStream::new(reader, &self.state);
        let send = SendStream::new(writer, reliable_size, &self.state);
        self.state.check_open()?;
        Ok((recv, send))
    }

    pub async fn open_uni(&self) -> Result<SendStream, Error> {
        self.state.check_open()?;
        let mut writer = self.state.driver.open_uni().await?;
        let reliable_size = write_stream_header(
            &mut writer,
            u64::from(wire::StreamType::WebTransport),
            self.id(),
        )
        .await?;
        let send = SendStream::new(writer, reliable_size, &self.state);
        self.state.check_open()?;
        Ok(send)
    }

    pub async fn accept_bi(&self) -> Result<(RecvStream, SendStream), Error> {
        let mut streams = self.state.bidi_rx.lock().await;
        tokio::select! {
            biased;
            result = self.state.wait_closed() => {
                result.and_then(|_| Err(session_gone()))
            }
            stream = streams.recv() => stream.ok_or_else(session_gone),
        }
    }

    pub async fn accept_uni(&self) -> Result<RecvStream, Error> {
        let mut streams = self.state.uni_rx.lock().await;
        tokio::select! {
            biased;
            result = self.state.wait_closed() => {
                result.and_then(|_| Err(session_gone()))
            }
            stream = streams.recv() => stream.ok_or_else(session_gone),
        }
    }

    pub async fn send_datagram(&self, payload: Bytes) -> Result<(), Error> {
        self.state.check_open()?;
        let mut datagram = Vec::with_capacity(8 + payload.len());
        datagram.put_varint(
            &VarInt::try_from(u64::from(self.id()) / 4).expect("valid Quarter Stream ID"),
        );
        datagram.extend_from_slice(&payload);
        if datagram.len() > self.state.driver.max_datagram_size() {
            return Err(Error::stream(
                None,
                "WebTransport datagram exceeds the transport limit",
            ));
        }
        self.state.driver.send_datagram(Bytes::from(datagram)).await
    }

    pub async fn receive_datagram(&self) -> Result<Bytes, Error> {
        let mut datagrams = self.state.datagram_rx.lock().await;
        tokio::select! {
            biased;
            result = self.state.wait_closed() => {
                result.and_then(|_| Err(session_gone()))
            }
            datagram = datagrams.recv() => datagram.ok_or_else(session_gone),
        }
    }

    pub async fn drain(&self) -> Result<(), Error> {
        self.command(ControlCommand::Drain).await
    }

    pub async fn drained(&self) -> Result<(), Error> {
        loop {
            let changed = self.state.drain_changed.notified();
            if self.state.drained.load(Ordering::Acquire) {
                return Ok(());
            }
            if let Some(result) = self
                .state
                .inner
                .lock()
                .expect("WebTransport session lock poisoned")
                .terminal
                .clone()
            {
                return match result {
                    Ok(_) => Err(session_gone()),
                    Err(error) => Err(error),
                };
            }
            changed.await;
        }
    }

    pub async fn close(&self, code: u32, message: impl Into<String>) -> Result<(), Error> {
        let close = Close::new(code, message)?;
        self.command(|reply| ControlCommand::Close(close, reply))
            .await
    }

    pub async fn closed(&self) -> Result<Close, Error> {
        self.state.wait_closed().await
    }

    async fn command(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<(), Error>>) -> ControlCommand,
    ) -> Result<(), Error> {
        self.state.check_open()?;
        let (reply, result) = oneshot::channel();
        self.commands
            .send(make(reply))
            .await
            .map_err(|_| session_gone())?;
        result.await.map_err(|_| session_gone())?
    }
}

/// Accepts a decoded WebTransport CONNECT after the caller has authorized it.
pub async fn accept(
    request: Request<ChunkBody>,
    response_sender: ResponseSender,
    response: HttpResponse<()>,
) -> Result<Session, Error> {
    if !is_request(&request) {
        let error = Error::stream(
            Some(Code::H3_MESSAGE_ERROR),
            "request is not a WebTransport extended CONNECT",
        );
        response_sender.reject(Code::H3_MESSAGE_ERROR);
        return Err(error);
    }
    if request.headers().contains_key(http::header::CONTENT_LENGTH) {
        let error = Error::stream(
            Some(Code::H3_MESSAGE_ERROR),
            "WebTransport CONNECT request cannot declare Content-Length",
        );
        response_sender.reject(Code::H3_MESSAGE_ERROR);
        return Err(error);
    }
    if !response.status().is_success() {
        let error = Error::stream(
            Some(Code::H3_MESSAGE_ERROR),
            "accepting WebTransport requires a 2xx response",
        );
        response_sender.reject(Code::H3_MESSAGE_ERROR);
        return Err(error);
    }
    let request_id = request
        .extensions()
        .get::<StreamId>()
        .copied()
        .ok_or_else(|| Error::stream(None, "WebTransport request is missing its stream ID"))?;
    if request_id != response_sender.stream_id() {
        return Err(Error::stream(
            Some(Code::H3_ID_ERROR),
            "WebTransport request and response sender use different streams",
        ));
    }
    let runtime = response_sender
        .webtransport_runtime()
        .ok_or_else(webtransport_disabled)?;
    if let Err(error) = validate_session_id(request_id) {
        runtime.fail_protocol(error.clone());
        response_sender.reject(Code::H3_ID_ERROR);
        return Err(error);
    }
    let connection = response_sender.webtransport_keepalive();
    if let Err(error) = runtime.wait_client_support().await {
        response_sender.reject(Code::H3_MESSAGE_ERROR);
        return Err(error);
    }
    let pending = match runtime.prepare(request_id, connection) {
        Ok(pending) => pending,
        Err(error) => {
            response_sender.reject(Code::H3_REQUEST_REJECTED);
            return Err(error);
        }
    };
    let (parts, body) = request.into_parts();
    drop(parts);
    let writer = match response_sender.start_webtransport_response(response).await {
        Ok(writer) => writer,
        Err(error) => {
            pending.fail(error.clone());
            return Err(error);
        }
    };
    Ok(pending.start(body, writer))
}

fn start_control(prepared: PreparedSession, body: ChunkBody, writer: StreamWriter) {
    let PreparedSession {
        session,
        command_rx,
    } = prepared;
    let state = Arc::clone(&session.state);
    let runtime = state
        .runtime
        .upgrade()
        .expect("a registered WebTransport session retains its runtime");
    drop(session);
    let task = Box::pin(async move {
        capsule::run(Arc::clone(&state), body, writer, command_rx).await;
    });
    runtime.track(task);
}

async fn write_stream_header(
    writer: &mut stream::BoxWriter,
    discriminator: u64,
    session_id: StreamId,
) -> Result<u64, Error> {
    let mut header = Vec::with_capacity(16);
    header.put_varint(&VarInt::try_from(discriminator).expect("known WebTransport stream type"));
    header.put_varint(&VarInt::try_from(u64::from(session_id)).expect("valid session ID"));
    let reliable_size = header.len() as u64;
    if let Err(source) = writer.feed(Bytes::from(header)).await {
        let error = map_data_stream_error(source);
        let _ = writer.reset_at(error.code().unwrap_or(Code::WT_SESSION_GONE), reliable_size);
        return Err(error);
    }
    Ok(reliable_size)
}

fn reject_bidi(mut reader: wire::ChunkReader, mut writer: stream::BoxWriter, code: Code) {
    reader.stop(code);
    let _ = writer.reset_at(code, 0);
}

fn reject_uni(mut reader: wire::ChunkReader, code: Code) {
    reader.stop(code);
}

fn validate_session_id(id: StreamId) -> Result<(), Error> {
    if u64::from(id) & 0x03 == 0 {
        Ok(())
    } else {
        Err(invalid_session_id_error(id))
    }
}

fn invalid_session_id_error(id: StreamId) -> Error {
    Error::connection_protocol(
        Code::H3_ID_ERROR,
        format!(
            "WebTransport session ID {} is not client-initiated bidi",
            u64::from(id)
        ),
    )
}

fn webtransport_disabled() -> Error {
    Error::stream(
        Some(Code::WT_REQUIREMENTS_NOT_MET),
        "connection was not created with WebTransport enabled",
    )
}

fn session_gone() -> Error {
    Error::stream(
        Some(Code::WT_SESSION_GONE),
        "WebTransport session is closed",
    )
}

fn map_connection_error(error: transport::ConnectionError) -> Error {
    Error::connection(error.code(), "QUIC WebTransport operation failed", error)
}

fn map_data_stream_error(error: transport::StreamError) -> Error {
    let code = error.code();
    if error.is_connection() {
        Error::connection(
            code,
            "QUIC connection failed on a WebTransport stream",
            error,
        )
    } else {
        Error::stream_with_source(code, "WebTransport stream was reset", error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_settings_do_not_need_enable_connect_protocol() {
        let settings = PeerSettings {
            connect_protocol: false,
            h3_datagram: true,
            webtransport: true,
        };

        assert!(settings.client_supports_webtransport());
        assert!(!settings.server_supports_webtransport());
    }

    #[test]
    fn application_error_mapping_matches_the_draft_boundaries() {
        for code in [0, 29, 30, 59, 60, u32::MAX] {
            let mapped = map_application_error(code);
            assert_eq!(application_error_code(mapped), Some(code));
        }
        assert_eq!(map_application_error(0).as_u64(), APPLICATION_ERROR_FIRST);
        assert_eq!(
            map_application_error(u32::MAX).as_u64(),
            APPLICATION_ERROR_LAST
        );
        assert_eq!(application_error_code(Code::WT_SESSION_GONE), None);
        assert_eq!(
            application_error_code(Code::new_unchecked(APPLICATION_ERROR_FIRST + 0x1e)),
            None
        );
    }

    #[test]
    fn close_message_limit_is_measured_in_utf8_bytes() {
        assert!(Close::new(0, "a".repeat(CLOSE_MESSAGE_LIMIT)).is_ok());
        assert!(Close::new(0, "界".repeat(342)).is_err());
    }
}
