//! Connection-level IPC adapters and RTC trait.
//!
//! # RTC trait
//!
//! [`IpcConnection`] defines the RPC interface for connection-level stream
//! management over IPC.  Each stream-opening method receives a caller-chosen
//! FD transfer ID and returns the underlying QUIC stream ID after the FD
//! delivery has been acknowledged.
//!
//! # Server side
//!
//! [`ConnectionAdapter`] wraps a `quic::Connection` and implements
//! [`IpcConnection`].  Each `open_bi` / `accept_bi` call:
//! 1. Opens a real QUIC stream pair via the inner connection.
//! 2. Creates 2 Unix socketpairs (one per direction).
//! 3. Delivers the client-side FDs through the connection [`FdTransfer`].
//! 4. Spawns bridge tasks that forward data between the real QUIC
//!    streams and local [`IpcWriteStream`] / [`IpcReadStream`] endpoints.
//! 5. Returns the stream ID over RPC.
//!
//! # Client side
//!
//! [`IpcConnectionHandle`] wraps an [`IpcConnectionClient`] and implements
//! [`quic::Connection`].  Each `open_bi` call:
//! 1. Reserves a receiver-chosen FD transfer ID.
//! 2. Calls the RPC method with that ID while concurrently receiving the FDs.
//! 3. Wraps them as [`IpcReadStream`] / [`IpcWriteStream`].
//!
//! # Bootstrap
//!
//! [`ConnectionBootstrap`] is the one-shot value sent over the remoc base
//! channel when a new connection is established.  It carries the
//! [`IpcConnectionClient`] for stream management and authority access.

use std::{borrow::Cow, future::Future, io, sync::Arc};

use futures::{SinkExt, StreamExt};
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
        quic::stream::{IpcBiHandle, IpcReadStream, IpcUniHandle, IpcWriteStream},
        transport::{FdDelivery, FdTransfer, ReceivedFds},
    },
    quic::{
        self, ConnectionError, DynLifecycle, GetStreamIdExt, ManageStream, ReadStream, StreamError,
        WriteStream,
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
/// acknowledged by the receiver.
///
/// Agent and lifecycle methods mirror [`crate::rpc::quic::Connection`] and
/// are forwarded over the same remoc channel — only bulk stream data travels
/// through dedicated socketpairs.
///
/// # FD semantics
///
/// - **`open_bi` / `accept_bi`**: 2 FDs are delivered (2 independent socketpairs).
///   The first FD carries the reader-side pipe (server's IpcWriteStream ↔
///   client's IpcReadStream), the second carries the writer-side pipe
///   (server's IpcReadStream ↔ client's IpcWriteStream).
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

/// Forward data from a QUIC [`ReadStream`] to a [`IpcWriteStream`] (server side).
///
/// Reads chunks from the QUIC stream and sinks them into the pipe.
/// Terminates when either side closes or errors.
pub async fn bridge_reader(
    mut quic_reader: impl ReadStream + Unpin,
    mut pipe_writer: IpcWriteStream,
) {
    while let Some(Ok(chunk)) = quic_reader.next().await {
        if pipe_writer.send(chunk).await.is_err() {
            break;
        }
    }
    let _ = pipe_writer.close().await;
}

/// Forward data from a [`IpcReadStream`] to a QUIC [`WriteStream`] (server side).
///
/// Reads chunks from the pipe and sinks them into the QUIC stream.
/// Terminates when either side closes or errors.
pub async fn bridge_writer(
    mut pipe_reader: IpcReadStream,
    mut quic_writer: impl WriteStream + Unpin,
) {
    while let Some(Ok(chunk)) = pipe_reader.next().await {
        if quic_writer.send(chunk).await.is_err() {
            break;
        }
    }
    let _ = quic_writer.close().await;
}

// ---------------------------------------------------------------------------
// Server side: ConnectionAdapter
// ---------------------------------------------------------------------------

/// Server-side adapter that wraps a real `quic::Connection` and implements
/// [`IpcConnection`].
///
/// The inner connection is shared via `Arc` so that:
/// - Bridge tasks can reference it as `Arc<dyn DynLifecycle>`.
/// - The [`FdTransfer`] delivers client-side FDs for each new stream.
pub struct ConnectionAdapter<M> {
    inner: Arc<M>,
    fd_transfer: FdTransfer,
}

impl<M> ConnectionAdapter<M> {
    pub fn new(inner: Arc<M>, fd_transfer: FdTransfer) -> Self {
        Self { inner, fd_transfer }
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
                tokio::spawn(
                    (async move {
                        let _ = server.serve(true).await;
                    })
                    .in_current_span(),
                );
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn remote_authority(&self) -> Result<Option<RemoteAuthorityClient>, ConnectionError> {
        match quic::WithRemoteAuthority::remote_authority(self.inner.as_ref()).await? {
            Some(agent) => {
                let (server, client) = RemoteAuthorityServerShared::new(Arc::new(agent), 1);
                tokio::spawn(
                    (async move {
                        let _ = server.serve(true).await;
                    })
                    .in_current_span(),
                );
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
        let mut delivery = self.fd_transfer.delivery(fd_id);
        let (mut reader, writer) = tokio::select! {
            _ = delivery.cancelled() => return Err(ipc_cancelled_plumbing("open_bi").into()),
            result = ManageStream::open_bi(self.inner.as_ref()) => {
                result.map_err(|e| IpcOpenError::Connection { source: e })?
            }
        };
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
        let mut delivery = self.fd_transfer.delivery(fd_id);
        let (mut reader, writer) = tokio::select! {
            _ = delivery.cancelled() => return Err(ipc_cancelled_plumbing("accept_bi").into()),
            result = ManageStream::accept_bi(self.inner.as_ref()) => {
                result.map_err(|e| IpcAcceptError::Connection { source: e })?
            }
        };
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
        reader: M::StreamReader,
        writer: M::StreamWriter,
        stream_id: VarInt,
    ) -> Result<IpcBiHandle, IpcPlumbingError> {
        let lifecycle: Arc<dyn DynLifecycle> = self.inner.clone();

        // Socketpair for the reader direction: server IpcWriteStream ↔ client IpcReadStream
        let (srv_a, cli_a) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;
        // Socketpair for the writer direction: server IpcReadStream ↔ client IpcWriteStream
        let (srv_b, cli_b) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;

        let cli_a_std = cli_a
            .into_std()
            .map_err(|e| ipc_io_plumbing(e, "into_std"))?;
        let cli_b_std = cli_b
            .into_std()
            .map_err(|e| ipc_io_plumbing(e, "into_std"))?;

        delivery
            .deliver(smallvec![cli_a_std.into(), cli_b_std.into()])
            .await
            .map_err(|e| ipc_io_plumbing(e, "deliver fds"))?;

        // Bridge reader direction: real QUIC reader → IpcWriteStream on srv_a
        let pipe_w = IpcWriteStream::new(stream_id, srv_a, lifecycle.clone());
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

        // Bridge writer direction: IpcReadStream on srv_b → real QUIC writer
        let pipe_r = IpcReadStream::new(stream_id, srv_b, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok(IpcBiHandle { stream_id })
    }

    async fn open_uni_impl(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcUniHandle, StreamError>, IpcOpenError> {
        let mut delivery = self.fd_transfer.delivery(fd_id);
        let mut writer = tokio::select! {
            _ = delivery.cancelled() => return Err(ipc_cancelled_plumbing("open_uni").into()),
            result = ManageStream::open_uni(self.inner.as_ref()) => {
                result.map_err(|e| IpcOpenError::Connection { source: e })?
            }
        };
        let stream_id = match writer.stream_id().await {
            Ok(id) => id,
            Err(stream_err) => return Ok(Resolved::err(stream_err)),
        };
        let lifecycle: Arc<dyn DynLifecycle> = self.inner.clone();

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_io_plumbing(e, "into_std"))?;
        delivery
            .deliver(smallvec![cli_std.into()])
            .await
            .map_err(|e| ipc_io_plumbing(e, "deliver fds"))?;

        // IpcReadStream on srv → real QUIC writer
        let pipe_r = IpcReadStream::new(stream_id, srv, lifecycle);
        tokio::spawn(bridge_writer(pipe_r, writer).in_current_span());

        Ok(Resolved::ok(IpcUniHandle { stream_id }))
    }

    async fn accept_uni_impl(
        &self,
        fd_id: VarInt,
    ) -> Result<Resolved<IpcUniHandle, StreamError>, IpcAcceptError> {
        let mut delivery = self.fd_transfer.delivery(fd_id);
        let mut reader = tokio::select! {
            _ = delivery.cancelled() => return Err(ipc_cancelled_plumbing("accept_uni").into()),
            result = ManageStream::accept_uni(self.inner.as_ref()) => {
                result.map_err(|e| IpcAcceptError::Connection { source: e })?
            }
        };
        let stream_id = match reader.stream_id().await {
            Ok(id) => id,
            Err(stream_err) => return Ok(Resolved::err(stream_err)),
        };
        let lifecycle: Arc<dyn DynLifecycle> = self.inner.clone();

        let (srv, cli) = UnixStream::pair().map_err(|e| ipc_io_plumbing(e, "socketpair"))?;
        let cli_std = cli.into_std().map_err(|e| ipc_io_plumbing(e, "into_std"))?;
        delivery
            .deliver(smallvec![cli_std.into()])
            .await
            .map_err(|e| ipc_io_plumbing(e, "deliver fds"))?;

        // Real QUIC reader → IpcWriteStream on srv
        let pipe_w = IpcWriteStream::new(stream_id, srv, lifecycle);
        tokio::spawn(bridge_reader(reader, pipe_w).in_current_span());

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
/// [`IpcReadStream`] / [`IpcWriteStream`] as `Arc<dyn DynLifecycle>`.
struct IpcLifecycle {
    connection: IpcConnectionClient,
    latch: ConnectionErrorLatch,
}

impl HasLatch for IpcLifecycle {
    fn latch(&self) -> &ConnectionErrorLatch {
        &self.latch
    }
}

impl quic::Lifecycle for IpcLifecycle {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        let rpc = self.connection.clone();
        tokio::spawn(
            async move {
                let _ = IpcConnection::close(&rpc, code, reason).await;
            }
            .in_current_span(),
        );
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
    type StreamReader = Resolved<IpcReadStream, StreamError>;
    type StreamWriter = Resolved<IpcWriteStream, StreamError>;

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
            receive_result = &mut receive => {
                let received = receive_result.map_err(|e| ipc_transport_error(e, "receive fds"))?;
                let resolved = rpc.await.map_err(map_open_err)?;
                Ok((resolved, Some(received)))
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
            receive_result = &mut receive => {
                let received = receive_result.map_err(|e| ipc_transport_error(e, "receive fds"))?;
                let resolved = rpc.await.map_err(map_accept_err)?;
                Ok((resolved, Some(received)))
            }
        }
    }

    /// Retrieve 2 FDs and construct a (IpcReadStream, IpcWriteStream) pair.
    async fn fds_to_bi(
        &self,
        handle: IpcBiHandle,
        received: ReceivedFds,
    ) -> Result<(IpcReadStream, IpcWriteStream), ConnectionError> {
        let IpcBiHandle { stream_id } = handle;
        self.lifecycle.guard_sync(|| {
            let (fd_a, fd_b) = received
                .into_pair()
                .map_err(|e| ipc_transport_error(e, "fd count"))?;

            let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();

            // fd_a → reader pipe (matches server's IpcWriteStream on srv_a)
            let sock_a = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_a))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            let reader = IpcReadStream::new(stream_id, sock_a, lifecycle.clone());

            // fd_b → writer pipe (matches server's IpcReadStream on srv_b)
            let sock_b = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd_b))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            let writer = IpcWriteStream::new(stream_id, sock_b, lifecycle);

            Ok((reader, writer))
        })
    }

    /// Retrieve 1 FD and construct a IpcWriteStream (for open_uni).
    async fn fds_to_uni_writer(
        &self,
        handle: IpcUniHandle,
        received: ReceivedFds,
    ) -> Result<IpcWriteStream, ConnectionError> {
        let IpcUniHandle { stream_id } = handle;
        self.lifecycle.guard_sync(|| {
            let fd = received
                .into_one()
                .map_err(|e| ipc_transport_error(e, "fd count"))?;
            let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();
            let sock = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            Ok(IpcWriteStream::new(stream_id, sock, lifecycle))
        })
    }

    /// Retrieve 1 FD and construct a IpcReadStream (for accept_uni).
    async fn fds_to_uni_reader(
        &self,
        handle: IpcUniHandle,
        received: ReceivedFds,
    ) -> Result<IpcReadStream, ConnectionError> {
        let IpcUniHandle { stream_id } = handle;
        self.lifecycle.guard_sync(|| {
            let fd = received
                .into_one()
                .map_err(|e| ipc_transport_error(e, "fd count"))?;
            let lifecycle: Arc<dyn DynLifecycle> = self.lifecycle.clone();
            let sock = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
                .map_err(|e| ipc_io_error(e, "UnixStream::from_std"))?;
            Ok(IpcReadStream::new(stream_id, sock, lifecycle))
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

/// Convert an I/O error into an [`IpcPlumbingError`] (server side).
fn ipc_io_plumbing(err: impl std::fmt::Display, context: &str) -> IpcPlumbingError {
    debug!(error = %err, context, "ipc plumbing i/o error");
    IpcPlumbingError::Io {
        message: format!("{context}: {err}"),
    }
}

fn ipc_cancelled_plumbing(context: &str) -> IpcPlumbingError {
    debug!(context, "ipc fd transfer cancelled");
    IpcPlumbingError::Io {
        message: format!("{context}: fd transfer cancelled"),
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
