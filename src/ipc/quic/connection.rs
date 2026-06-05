//! Connection-level IPC adapters and RTC trait.
//!
//! # RTC trait
//!
//! [`IpcConnection`] defines the RPC interface for connection-level stream
//! management over IPC.  Each stream-opening method receives a caller-chosen
//! FD transfer ID and returns the underlying QUIC stream ID after the FD
//! delivery has been queued to the local mux writer FIFO.
//!
//! # Server side
//!
//! [`ConnectionAdapter`] wraps a `quic::Connection` and implements
//! [`IpcConnection`].  Each `open_bi` / `accept_bi` call:
//! 1. Opens a real QUIC stream pair via the inner connection.
//! 2. Creates 2 Unix socketpairs (one per direction).
//! 3. Delivers the client-side FDs through the connection [`FdTransfer`].
//! 4. Spawns bridge tasks that execute typed stream-frame IPC against the real
//!    QUIC streams.
//! 5. Returns the stream ID over RPC.
//!
//! # Client side
//!
//! [`IpcConnectionHandle`] wraps an [`IpcConnectionClient`] and implements
//! [`quic::Connection`].  Each `open_bi` call:
//! 1. Reserves a receiver-chosen FD transfer ID.
//! 2. Calls the RPC method with that ID while concurrently receiving the FDs.
//! 3. Wraps them as boxed QUIC stream handles backed by typed IPC frame IO.
//!
//! # Bootstrap
//!
//! [`ConnectionBootstrap`] is the one-shot value sent over the remoc base
//! channel when a new connection is established.  It carries the
//! [`IpcConnectionClient`] for stream management and authority access.

use std::{
    borrow::Cow,
    future::Future,
    io,
    sync::{Arc, Mutex},
};

use remoc::prelude::ServerShared;
use serde::{Deserialize, Serialize};
use smallvec::smallvec;
use tokio::net::UnixStream;
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, debug};

use crate::{
    error::Code,
    ipc::{
        error::{IpcAcceptError, IpcOpenError, IpcPlumbingError},
        quic::stream::{
            IpcBiHandle, IpcUniHandle,
            reader::{self as ipc_reader, IpcReadHypervisorIo},
            writer::{self as ipc_writer, IpcWriteHypervisorIo},
        },
        transport::{FdDelivery, FdTransfer, ReceivedFds},
    },
    quic::{
        self, BoxQuicStreamReader, BoxQuicStreamWriter, ConnectionError, GetStreamIdExt,
        ManageStream, ReadStream, ResetStreamExt, StopStreamExt, StreamError, WriteStream,
    },
    rpc::{
        lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt},
        quic::{
            CachedLocalAuthority, CachedRemoteAuthority, LocalAuthorityClient,
            LocalAuthorityServerShared, RemoteAuthorityClient, RemoteAuthorityServerShared,
        },
    },
    util::deferred::Resolved,
    varint::VarInt,
};

// ---------------------------------------------------------------------------
// IPC RTC trait for connection-level stream management
// ---------------------------------------------------------------------------

/// Remote trait for IPC connection-level stream management.
///
/// Each stream-opening method receives a receiver-chosen FD transfer ID and
/// returns a handle carrying the underlying QUIC stream ID. Server-side
/// implementations must not return until the FD delivery has been
/// queued to the local mux writer FIFO.
///
/// Agent and lifecycle methods mirror [`crate::rpc::quic::Connection`] and
/// are forwarded over the same remoc channel — only bulk stream data travels
/// through dedicated socketpairs.
///
/// # FD semantics
///
/// - **`open_bi` / `accept_bi`**: 2 FDs are delivered (2 independent socketpairs).
///   The first FD carries read-side frame IO; the second carries write-side
///   frame IO.
///
/// - **`open_uni` / `accept_uni`**: 1 FD is delivered (a single socketpair).
#[remoc::rtc::remote]
pub trait IpcConnection: Send + Sync {
    /// Open a bidirectional stream.
    ///
    /// Returns `Resolved<IpcBiHandle, StreamError>` on success — the handle
    /// may carry a stream error (e.g. stream_id retrieval failed) wrapped in
    /// [`Resolved::Error`].  Infrastructure failures yield [`IpcOpenError`].
    async fn open_bi(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcBiHandle, StreamError>, IpcOpenError>;

    /// Accept an incoming bidirectional stream.
    ///
    /// Returns `Resolved<IpcBiHandle, StreamError>` on success.
    async fn accept_bi(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcBiHandle, StreamError>, IpcAcceptError>;

    /// Open a unidirectional (send-only) stream.
    ///
    /// Returns `Resolved<IpcUniHandle, StreamError>` on success.
    async fn open_uni(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcUniHandle, StreamError>, IpcOpenError>;

    /// Accept an incoming unidirectional (receive-only) stream.
    ///
    /// Returns `Resolved<IpcUniHandle, StreamError>` on success.
    async fn accept_uni(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcUniHandle, StreamError>, IpcAcceptError>;

    /// Obtain the local authority (signing / identity) handle, if available.
    async fn local_authority(&self) -> Result<Option<LocalAuthorityClient>, ConnectionError>;

    /// Obtain the remote authority (verification) handle, if available.
    async fn remote_authority(&self) -> Result<Option<RemoteAuthorityClient>, ConnectionError>;

    /// Close the connection with an application error code and reason.
    async fn close(&self, code: Code, reason: Cow<'static, str>) -> Result<(), ConnectionError>;

    /// Wait until the connection is closed, returning the terminal error.
    async fn closed(&self) -> Result<ConnectionError, ConnectionError>;
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/// One-shot bootstrap payload sent over the remoc base channel when a new
/// IPC connection is established.
///
/// Carries the [`IpcConnectionClient`] which provides both stream management
/// RPC and authority access — authority methods are part of the [`IpcConnection`]
/// trait alongside stream operations.
#[derive(Serialize, Deserialize)]
pub struct ConnectionBootstrap {
    /// RPC client for stream operations, authority access, and lifecycle.
    pub connection: IpcConnectionClient,
}

// ---------------------------------------------------------------------------
// Bridge helpers: forward data between real QUIC streams and pipe socketpairs
// ---------------------------------------------------------------------------

/// Execute a QUIC [`ReadStream`] through hypervisor-side IPC read frame IO.
///
/// Worker pipe EOF is stream-handle abandonment on this side. Already received
/// commands are drained by the shared hypervisor bridge; no EOF-derived QUIC
/// control is synthesized.
pub async fn bridge_reader(quic_reader: impl ReadStream + Unpin, pipe: UnixStream) {
    crate::rpc::stream::hypervisor::read::run_read_bridge(
        quic_reader,
        IpcReadHypervisorIo::new(pipe),
    )
    .await;
}

/// Execute hypervisor-side IPC write frame IO against a QUIC [`WriteStream`].
///
/// Worker pipe EOF is stream-handle abandonment on this side. Already received
/// commands are drained by the shared hypervisor bridge; no EOF-derived FIN or
/// RESET_STREAM is synthesized.
pub async fn bridge_writer(pipe: UnixStream, quic_writer: impl WriteStream + Unpin) {
    crate::rpc::stream::hypervisor::write::run_write_bridge(
        quic_writer,
        IpcWriteHypervisorIo::new(pipe),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Server side: ConnectionAdapter
// ---------------------------------------------------------------------------

/// Server-side adapter that wraps a real `quic::Connection` and implements
/// [`IpcConnection`].
///
/// The inner connection is shared via `Arc` so that:
/// - Bridge tasks execute stream-frame IPC against concrete QUIC streams.
/// - The [`FdTransfer`] delivers client-side FDs for each new stream.
pub struct ConnectionAdapter<M> {
    inner: Arc<M>,
    fd_transfer: FdTransfer,
    tasks: Mutex<Vec<AbortOnDropHandle<()>>>,
}

impl<M> ConnectionAdapter<M> {
    pub fn new(inner: Arc<M>, fd_transfer: FdTransfer) -> Self {
        Self {
            inner,
            fd_transfer,
            tasks: Mutex::new(Vec::new()),
        }
    }

    fn spawn_task(&self, task: impl Future<Output = ()> + Send + 'static) {
        let handle = AbortOnDropHandle::new(tokio::spawn(task.in_current_span()));
        let mut tasks = self
            .tasks
            .lock()
            .expect("connection adapter task registry should not be poisoned");
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
    }
}

impl<M> IpcConnection for ConnectionAdapter<M>
where
    M: ManageStream
        + quic::Lifecycle
        + quic::WithLocalAuthority
        + quic::WithRemoteAuthority
        + Send
        + Sync
        + 'static,
    M::StreamReader: Unpin + 'static,
    M::StreamWriter: Unpin + 'static,
    M::LocalAuthority: Send + Sync,
    M::RemoteAuthority: Send + Sync,
{
    async fn open_bi(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcBiHandle, StreamError>, IpcOpenError> {
        self.open_bi_impl(fd_id).await
    }

    async fn accept_bi(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcBiHandle, StreamError>, IpcAcceptError> {
        self.accept_bi_impl(fd_id).await
    }

    async fn open_uni(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcUniHandle, StreamError>, IpcOpenError> {
        self.open_uni_impl(fd_id).await
    }

    async fn accept_uni(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcUniHandle, StreamError>, IpcAcceptError> {
        self.accept_uni_impl(fd_id).await
    }

    async fn local_authority(&self) -> Result<Option<LocalAuthorityClient>, ConnectionError> {
        match quic::WithLocalAuthority::local_authority(self.inner.as_ref()).await? {
            Some(agent) => {
                let (server, client) = LocalAuthorityServerShared::new(Arc::new(agent), 1);
                self.spawn_task(async move {
                    let _ = server.serve(true).await;
                });
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn remote_authority(&self) -> Result<Option<RemoteAuthorityClient>, ConnectionError> {
        match quic::WithRemoteAuthority::remote_authority(self.inner.as_ref()).await? {
            Some(agent) => {
                let (server, client) = RemoteAuthorityServerShared::new(Arc::new(agent), 1);
                self.spawn_task(async move {
                    let _ = server.serve(true).await;
                });
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn close(&self, code: Code, reason: Cow<'static, str>) -> Result<(), ConnectionError> {
        quic::Lifecycle::close(self.inner.as_ref(), code, reason);
        Ok(())
    }

    async fn closed(&self) -> Result<ConnectionError, ConnectionError> {
        Ok(quic::Lifecycle::closed(self.inner.as_ref()).await)
    }
}

impl<M> ConnectionAdapter<M>
where
    M: ManageStream
        + quic::Lifecycle
        + quic::WithLocalAuthority
        + quic::WithRemoteAuthority
        + Send
        + Sync
        + 'static,
    M::StreamReader: Unpin + 'static,
    M::StreamWriter: Unpin + 'static,
    M::LocalAuthority: Send + Sync,
    M::RemoteAuthority: Send + Sync,
{
    async fn open_bi_impl(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcBiHandle, StreamError>, IpcOpenError> {
        let delivery = self.fd_transfer.delivery(fd_id);
        let (mut reader, writer) = ManageStream::open_bi(self.inner.as_ref()).await?;
        let stream_id = match reader.stream_id().await {
            Ok(id) => id,
            Err(stream_err) => return Ok(Resolved::err(stream_err)),
        };
        self.bridge_bi(delivery, reader, writer, stream_id)
            .await
            .map(Resolved::ok)
            .map_err(IpcOpenError::from)
    }

    async fn accept_bi_impl(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcBiHandle, StreamError>, IpcAcceptError> {
        let delivery = self.fd_transfer.delivery(fd_id);
        let (mut reader, writer) = ManageStream::accept_bi(self.inner.as_ref()).await?;
        let stream_id = match reader.stream_id().await {
            Ok(id) => id,
            Err(stream_err) => return Ok(Resolved::err(stream_err)),
        };
        self.bridge_bi(delivery, reader, writer, stream_id)
            .await
            .map(Resolved::ok)
            .map_err(IpcAcceptError::from)
    }

    /// Shared logic for open_bi / accept_bi after obtaining the real streams.
    async fn bridge_bi(
        &self,
        delivery: FdDelivery,
        mut reader: M::StreamReader,
        mut writer: M::StreamWriter,
        stream_id: VarInt,
    ) -> Result<IpcBiHandle, IpcPlumbingError> {
        // Socketpair for the reader direction: server read hypervisor ↔ client read bridge
        let (srv_a, cli_a) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;
        // Socketpair for the writer direction: server write hypervisor ↔ client write bridge
        let (srv_b, cli_b) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;

        let cli_a_std = cli_a
            .into_std()
            .map_err(|e| ipc_io_plumbing(e, "into_std"))?;
        let cli_b_std = cli_b
            .into_std()
            .map_err(|e| ipc_io_plumbing(e, "into_std"))?;

        if let Err(error) = delivery
            .deliver(smallvec![cli_a_std.into(), cli_b_std.into()])
            .await
        {
            let code = Code::H3_REQUEST_CANCELLED.into_inner();
            let _ = reader.stop(code).await;
            let _ = writer.reset(code).await;
            return Err(ipc_io_plumbing(error, "deliver fds"));
        }

        // Bridge reader direction: real QUIC reader ↔ read frame IO on srv_a.
        self.spawn_task(bridge_reader(reader, srv_a));

        // Bridge writer direction: write frame IO on srv_b ↔ real QUIC writer.
        self.spawn_task(bridge_writer(srv_b, writer));

        Ok(IpcBiHandle { stream_id })
    }

    async fn open_uni_impl(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcUniHandle, StreamError>, IpcOpenError> {
        let delivery = self.fd_transfer.delivery(fd_id);
        let mut writer = ManageStream::open_uni(self.inner.as_ref()).await?;
        let stream_id = match writer.stream_id().await {
            Ok(id) => id,
            Err(stream_err) => return Ok(Resolved::err(stream_err)),
        };
        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_io_plumbing(e, "into_std"))?;
        if let Err(error) = delivery.deliver(smallvec![cli_std.into()]).await {
            let _ = writer.reset(Code::H3_REQUEST_CANCELLED.into_inner()).await;
            return Err(IpcOpenError::from(ipc_io_plumbing(error, "deliver fds")));
        }

        // Write frame IO on srv ↔ real QUIC writer.
        self.spawn_task(bridge_writer(srv, writer));

        Ok(Resolved::ok(IpcUniHandle { stream_id }))
    }

    async fn accept_uni_impl(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcUniHandle, StreamError>, IpcAcceptError> {
        let delivery = self.fd_transfer.delivery(fd_id);
        let mut reader = ManageStream::accept_uni(self.inner.as_ref()).await?;
        let stream_id = match reader.stream_id().await {
            Ok(id) => id,
            Err(stream_err) => return Ok(Resolved::err(stream_err)),
        };
        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_io_plumbing(e, "into_std"))?;
        if let Err(error) = delivery.deliver(smallvec![cli_std.into()]).await {
            let _ = reader.stop(Code::H3_REQUEST_CANCELLED.into_inner()).await;
            return Err(IpcAcceptError::from(ipc_io_plumbing(error, "deliver fds")));
        }

        // Real QUIC reader ↔ read frame IO on srv.
        self.spawn_task(bridge_reader(reader, srv));

        Ok(Resolved::ok(IpcUniHandle { stream_id }))
    }
}

// ---------------------------------------------------------------------------
// Client side: IpcConnectionHandle
// ---------------------------------------------------------------------------

/// Client-side connection handle that wraps an [`IpcConnectionClient`] and
/// implements [`quic::Connection`].
///
/// Created by the client after receiving a [`ConnectionBootstrap`] over the
/// remoc base channel of a connection-level [`MuxChannel`].
pub struct IpcConnectionHandle {
    rpc: IpcConnectionClient,
    fd_transfer: FdTransfer,
    _remoc_task: AbortOnDropHandle<()>,
    lifecycle: Arc<IpcLifecycle>,
}

/// Internal lifecycle state for [`IpcConnectionHandle`].
///
/// Owns the latch that enforces first-wins error semantics across every
/// operation on the connection and its descendant streams.  Implements
/// [`quic::Lifecycle`] so the shared `Arc<IpcLifecycle>` can be handed to
/// direct IPC stream-frame bridge handles.
struct IpcLifecycle {
    connection: IpcConnectionClient,
    latch: ConnectionErrorLatch,
    close_tasks: Mutex<Vec<AbortOnDropHandle<()>>>,
}

impl HasLatch for IpcLifecycle {
    fn latch(&self) -> &ConnectionErrorLatch {
        &self.latch
    }
}

impl quic::Lifecycle for IpcLifecycle {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        let rpc = self.connection.clone();
        let handle = AbortOnDropHandle::new(tokio::spawn(
            (async move {
                let _ = IpcConnection::close(&rpc, code, reason).await;
            })
            .in_current_span(),
        ));
        let mut tasks = self
            .close_tasks
            .lock()
            .expect("ipc lifecycle close task registry should not be poisoned");
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
    }

    fn check(&self) -> Result<(), ConnectionError> {
        self.check_with_probe(|| {
            remoc::rtc::Client::is_closed(&self.connection)
                .then(IpcConnectionHandle::ipc_channel_error)
        })
    }

    async fn closed(&self) -> ConnectionError {
        self.resolve_closed(async {
            IpcConnection::closed(&self.connection)
                .await
                .unwrap_or_else(|_| IpcConnectionHandle::ipc_channel_error())
        })
        .await
    }
}

impl IpcConnectionHandle {
    /// Create a new handle from bootstrap data and FD registry.
    pub fn new(
        rpc: IpcConnectionClient,
        fd_transfer: FdTransfer,
        remoc_task: AbortOnDropHandle<()>,
    ) -> Self {
        let lifecycle = Arc::new(IpcLifecycle {
            connection: rpc.clone(),
            latch: ConnectionErrorLatch::new(),
            close_tasks: Mutex::new(Vec::new()),
        });
        Self {
            rpc,
            fd_transfer,
            _remoc_task: remoc_task,
            lifecycle,
        }
    }

    /// Synthesize a transport error for IPC channel failures.
    fn ipc_channel_error() -> ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: IPC_CHANNEL_ERROR_KIND,
                frame_type: IPC_FRAME_TYPE,
                reason: "ipc connection channel closed".into(),
            },
        }
    }
}

impl quic::ManageStream for IpcConnectionHandle {
    type StreamReader = Resolved<BoxQuicStreamReader, StreamError>;
    type StreamWriter = Resolved<BoxQuicStreamWriter, StreamError>;

    async fn open_bi(&self) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
        let (resolved, received) = self.open_bi_with_fds().await?;
        match resolved {
            Resolved::Value { value: handle } => {
                let received = received.expect("value response must include received fds");
                let (r, w) = self.fds_to_bi(handle, received).await?;
                Ok((Resolved::ok(r), Resolved::ok(w)))
            }
            Resolved::Error { error } => Ok((Resolved::err(error.clone()), Resolved::err(error))),
        }
    }

    async fn accept_bi(&self) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
        let (resolved, received) = self.accept_bi_with_fds().await?;
        match resolved {
            Resolved::Value { value: handle } => {
                let received = received.expect("value response must include received fds");
                let (r, w) = self.fds_to_bi(handle, received).await?;
                Ok((Resolved::ok(r), Resolved::ok(w)))
            }
            Resolved::Error { error } => Ok((Resolved::err(error.clone()), Resolved::err(error))),
        }
    }

    async fn open_uni(&self) -> Result<Self::StreamWriter, ConnectionError> {
        let (resolved, received) = self.open_uni_with_fds().await?;
        match resolved {
            Resolved::Value { value: handle } => {
                let received = received.expect("value response must include received fds");
                let w = self.fds_to_uni_writer(handle, received).await?;
                Ok(Resolved::ok(w))
            }
            Resolved::Error { error } => Ok(Resolved::err(error)),
        }
    }

    async fn accept_uni(&self) -> Result<Self::StreamReader, ConnectionError> {
        let (resolved, received) = self.accept_uni_with_fds().await?;
        match resolved {
            Resolved::Value { value: handle } => {
                let received = received.expect("value response must include received fds");
                let r = self.fds_to_uni_reader(handle, received).await?;
                Ok(Resolved::ok(r))
            }
            Resolved::Error { error } => Ok(Resolved::err(error)),
        }
    }
}

impl IpcConnectionHandle {
    async fn open_bi_with_fds(
        &self,
    ) -> Result<(Resolved<IpcBiHandle, StreamError>, Option<ReceivedFds>), ConnectionError> {
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        self.lifecycle
            .guard(self.resolve_open_with_fds(receiver, IpcConnection::open_bi(&self.rpc, fd_id)))
            .await
    }

    async fn accept_bi_with_fds(
        &self,
    ) -> Result<(Resolved<IpcBiHandle, StreamError>, Option<ReceivedFds>), ConnectionError> {
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        self.lifecycle
            .guard(
                self.resolve_accept_with_fds(receiver, IpcConnection::accept_bi(&self.rpc, fd_id)),
            )
            .await
    }

    async fn open_uni_with_fds(
        &self,
    ) -> Result<(Resolved<IpcUniHandle, StreamError>, Option<ReceivedFds>), ConnectionError> {
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        self.lifecycle
            .guard(self.resolve_open_with_fds(receiver, IpcConnection::open_uni(&self.rpc, fd_id)))
            .await
    }

    async fn accept_uni_with_fds(
        &self,
    ) -> Result<(Resolved<IpcUniHandle, StreamError>, Option<ReceivedFds>), ConnectionError> {
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        self.lifecycle
            .guard(
                self.resolve_accept_with_fds(receiver, IpcConnection::accept_uni(&self.rpc, fd_id)),
            )
            .await
    }

    async fn resolve_open_with_fds<H>(
        &self,
        receiver: crate::ipc::transport::FdReceiver,
        rpc: impl Future<Output = Result<Resolved<H, StreamError>, IpcOpenError>>,
    ) -> Result<(Resolved<H, StreamError>, Option<ReceivedFds>), ConnectionError> {
        let receive = receiver.into_future();
        tokio::pin!(receive);
        tokio::pin!(rpc);

        tokio::select! {
            biased;
            receive_result = &mut receive => {
                let received = receive_result.map_err(|e| ipc_transport_error(e, "receive fds"))?;
                let resolved = rpc.await.map_err(map_open_err)?;
                Ok((resolved, Some(received)))
            }
            rpc_result = &mut rpc => {
                let resolved = rpc_result.map_err(map_open_err)?;
                match resolved {
                    Resolved::Value { value } => {
                        let received = receive.await.map_err(|e| ipc_transport_error(e, "receive fds"))?;
                        Ok((Resolved::ok(value), Some(received)))
                    }
                    Resolved::Error { error } => Ok((Resolved::err(error), None)),
                }
            }
        }
    }

    async fn resolve_accept_with_fds<H>(
        &self,
        receiver: crate::ipc::transport::FdReceiver,
        rpc: impl Future<Output = Result<Resolved<H, StreamError>, IpcAcceptError>>,
    ) -> Result<(Resolved<H, StreamError>, Option<ReceivedFds>), ConnectionError> {
        let receive = receiver.into_future();
        tokio::pin!(receive);
        tokio::pin!(rpc);

        tokio::select! {
            biased;
            receive_result = &mut receive => {
                let received = receive_result.map_err(|e| ipc_transport_error(e, "receive fds"))?;
                let resolved = rpc.await.map_err(map_accept_err)?;
                Ok((resolved, Some(received)))
            }
            rpc_result = &mut rpc => {
                let resolved = rpc_result.map_err(map_accept_err)?;
                match resolved {
                    Resolved::Value { value } => {
                        let received = receive.await.map_err(|e| ipc_transport_error(e, "receive fds"))?;
                        Ok((Resolved::ok(value), Some(received)))
                    }
                    Resolved::Error { error } => Ok((Resolved::err(error), None)),
                }
            }
        }
    }

    /// Retrieve 2 FDs and construct boxed IPC stream-frame bridge handles.
    async fn fds_to_bi(
        &self,
        handle: IpcBiHandle,
        received: ReceivedFds,
    ) -> Result<(BoxQuicStreamReader, BoxQuicStreamWriter), ConnectionError> {
        let IpcBiHandle { stream_id } = handle;
        self.lifecycle.guard_sync(|| {
            let (fd_a, fd_b) = received
                .into_pair()
                .map_err(|e| ipc_transport_error(e, "fd count"))?;

            let lifecycle = self.lifecycle.clone();

            // fd_a → reader pipe (matches server's read hypervisor on srv_a)
            let sock_a = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_a))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            let reader = Box::pin(ipc_reader::reader(stream_id, sock_a, lifecycle.clone()))
                as BoxQuicStreamReader;

            // fd_b → writer pipe (matches server's write hypervisor on srv_b)
            let sock_b = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_b))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            let writer =
                Box::pin(ipc_writer::writer(stream_id, sock_b, lifecycle)) as BoxQuicStreamWriter;

            Ok((reader, writer))
        })
    }

    /// Retrieve 1 FD and construct a boxed IPC write bridge (for open_uni).
    async fn fds_to_uni_writer(
        &self,
        handle: IpcUniHandle,
        received: ReceivedFds,
    ) -> Result<BoxQuicStreamWriter, ConnectionError> {
        let IpcUniHandle { stream_id } = handle;
        self.lifecycle.guard_sync(|| {
            let fd = received
                .into_one()
                .map_err(|e| ipc_transport_error(e, "fd count"))?;
            let lifecycle = self.lifecycle.clone();
            let sock = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            Ok(Box::pin(ipc_writer::writer(stream_id, sock, lifecycle)) as BoxQuicStreamWriter)
        })
    }

    /// Retrieve 1 FD and construct a boxed IPC read bridge (for accept_uni).
    async fn fds_to_uni_reader(
        &self,
        handle: IpcUniHandle,
        received: ReceivedFds,
    ) -> Result<BoxQuicStreamReader, ConnectionError> {
        let IpcUniHandle { stream_id } = handle;
        self.lifecycle.guard_sync(|| {
            let fd = received
                .into_one()
                .map_err(|e| ipc_transport_error(e, "fd count"))?;
            let lifecycle = self.lifecycle.clone();
            let sock = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            Ok(Box::pin(ipc_reader::reader(stream_id, sock, lifecycle)) as BoxQuicStreamReader)
        })
    }
}

impl quic::WithLocalAuthority for IpcConnectionHandle {
    type LocalAuthority = CachedLocalAuthority;

    async fn local_authority(&self) -> Result<Option<CachedLocalAuthority>, ConnectionError> {
        match self
            .lifecycle
            .guard(IpcConnection::local_authority(&self.rpc))
            .await?
        {
            Some(client) => Ok(Some(
                self.lifecycle
                    .guard(CachedLocalAuthority::from_client(client))
                    .await?,
            )),
            None => Ok(None),
        }
    }
}

impl quic::WithRemoteAuthority for IpcConnectionHandle {
    type RemoteAuthority = CachedRemoteAuthority;

    async fn remote_authority(&self) -> Result<Option<CachedRemoteAuthority>, ConnectionError> {
        match self
            .lifecycle
            .guard(IpcConnection::remote_authority(&self.rpc))
            .await?
        {
            Some(client) => Ok(Some(
                self.lifecycle
                    .guard(CachedRemoteAuthority::from_client(client))
                    .await?,
            )),
            None => Ok(None),
        }
    }
}

impl quic::Lifecycle for IpcConnectionHandle {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        quic::Lifecycle::close(self.lifecycle.as_ref(), code, reason);
    }

    fn check(&self) -> Result<(), ConnectionError> {
        quic::Lifecycle::check(self.lifecycle.as_ref())
    }

    async fn closed(&self) -> ConnectionError {
        quic::Lifecycle::closed(self.lifecycle.as_ref()).await
    }
}

// ---------------------------------------------------------------------------
// Error constants & helpers
// ---------------------------------------------------------------------------

/// Error kind for general IPC transport failures.
pub(crate) const IPC_ERROR_KIND: VarInt = VarInt::from_u32(0x0a);

/// Error kind for IPC channel closure.
const IPC_CHANNEL_ERROR_KIND: VarInt = VarInt::from_u32(0x01);

/// Frame type placeholder for IPC-synthesized transport errors.
pub(crate) const IPC_FRAME_TYPE: VarInt = VarInt::from_u32(0x00);

fn ipc_io_error(err: io::Error, context: &str) -> ConnectionError {
    debug!(error = %snafu::Report::from_error(err), context, "ipc i/o error");
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: format!("ipc: {context}").into(),
        },
    }
}

fn ipc_transport_error(err: impl std::error::Error, context: &str) -> ConnectionError {
    debug!(error = %snafu::Report::from_error(&err), context, "ipc transport error");
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: format!("ipc: {context}").into(),
        },
    }
}

/// Convert an infrastructure error into an [`IpcPlumbingError`] (server side).
fn ipc_io_plumbing(err: impl std::error::Error, context: &str) -> IpcPlumbingError {
    debug!(error = %snafu::Report::from_error(&err), context, "ipc plumbing i/o error");
    IpcPlumbingError::Io {
        message: format!("{context}: {err}"),
    }
}

/// Convert an [`IpcPlumbingError`] into a [`ConnectionError`] (client side).
fn plumbing_to_conn(err: &IpcPlumbingError) -> ConnectionError {
    ConnectionError::Transport {
        source: quic::TransportError {
            kind: IPC_ERROR_KIND,
            frame_type: IPC_FRAME_TYPE,
            reason: err.to_string().into(),
        },
    }
}

/// Map an [`IpcOpenError`] into a [`ConnectionError`] for `guard_with` closures.
fn map_open_err(error: IpcOpenError) -> ConnectionError {
    match error {
        IpcOpenError::Connection { source } => source,
        IpcOpenError::Plumbing { source } => plumbing_to_conn(&source),
    }
}

/// Map an [`IpcAcceptError`] into a [`ConnectionError`] for `guard_with` closures.
fn map_accept_err(error: IpcAcceptError) -> ConnectionError {
    match error {
        IpcAcceptError::Connection { source } => source,
        IpcAcceptError::Plumbing { source } => plumbing_to_conn(&source),
    }
}

// ---------------------------------------------------------------------------
// IpcConnectionClient convenience
// ---------------------------------------------------------------------------

impl IpcConnectionClient {
    /// Convert into an [`IpcConnectionHandle`].
    pub fn into_handle(
        self,
        fd_transfer: FdTransfer,
        remoc_task: AbortOnDropHandle<()>,
    ) -> IpcConnectionHandle {
        IpcConnectionHandle::new(self, fd_transfer, remoc_task)
    }
}
