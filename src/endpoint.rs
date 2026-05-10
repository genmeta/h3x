//! Generic HTTP/3 endpoint.
//!
//! [`H3Endpoint`] wraps a [`quic::Connect`] implementation with an HTTP/3
//! connection pool and a user-configurable [`ConnectionBuilder`], providing
//! the foundation for both client and server functionality.
//!
//! [`ConnectionBuilder`]: crate::connection::ConnectionBuilder

use std::{error::Error, future::Future, sync::Arc};

use http::{Method, Uri, uri::Authority};
use tower_service::Service;
use tracing::Instrument;

use crate::{
    connection::{Connection as H3Connection, ConnectionBuilder},
    endpoint::{client::PendingRequest, server::UnresolvedRequest},
    message::stream::{ReadStream, WriteStream},
    pool::{self, Pool},
    quic::{self, GetStreamIdExt},
    stream_id::StreamId,
};

pub mod client;
pub mod server;

/// Generic HTTP/3 endpoint.
///
/// `H3Endpoint` is the central abstraction that combines a QUIC transport
/// implementation with an HTTP/3 connection pool. Parameterized over
/// `T: quic::Connect`, it can work with any QUIC backend.
pub struct H3Endpoint<T: quic::Connect> {
    pub(crate) quic: T,
    pub(crate) pool: Pool<T::Connection>,
    pub(crate) builder: Arc<ConnectionBuilder<T::Connection>>,
}

impl<T: quic::Connect> H3Endpoint<T> {
    /// Construct a new HTTP/3 endpoint.
    #[must_use]
    pub fn new(
        quic: T,
        pool: Pool<T::Connection>,
        builder: Arc<ConnectionBuilder<T::Connection>>,
    ) -> Self {
        Self {
            quic,
            pool,
            builder,
        }
    }

    /// Obtain (or reuse) an HTTP/3 connection to `server` from the pool.
    pub async fn connect(
        &self,
        server: Authority,
    ) -> Result<Arc<H3Connection<T::Connection>>, pool::ConnectError<T::Error>> {
        self.pool
            .reuse_or_connect_with(&self.quic, self.builder.clone(), server)
            .await
    }

    /// Create a new pending HTTP request builder.
    pub fn new_request(&self) -> PendingRequest<T, &Self> {
        PendingRequest {
            endpoint: self,
            request: crate::message::unify::Message::unresolved_request(),
            auto_close: true,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a new pending HTTP request builder from a shared endpoint.
    pub fn new_request_owned(self: &Arc<Self>) -> PendingRequest<T, Arc<Self>> {
        PendingRequest {
            endpoint: Arc::clone(self),
            request: crate::message::unify::Message::unresolved_request(),
            auto_close: true,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Convenience method to create a GET request for `uri`.
    pub fn get(&self, uri: Uri) -> PendingRequest<T, &Self> {
        self.new_request().with_method(Method::GET).with_uri(uri)
    }

    /// Convenience method to create a POST request for `uri`.
    pub fn post(&self, uri: Uri) -> PendingRequest<T, &Self> {
        self.new_request().with_method(Method::POST).with_uri(uri)
    }

    /// Convenience method to create a PUT request for `uri`.
    pub fn put(&self, uri: Uri) -> PendingRequest<T, &Self> {
        self.new_request().with_method(Method::PUT).with_uri(uri)
    }

    /// Convenience method to create a DELETE request for `uri`.
    pub fn delete(&self, uri: Uri) -> PendingRequest<T, &Self> {
        self.new_request().with_method(Method::DELETE).with_uri(uri)
    }

    /// Convenience method to create a PATCH request for `uri`.
    pub fn patch(&self, uri: Uri) -> PendingRequest<T, &Self> {
        self.new_request().with_method(Method::PATCH).with_uri(uri)
    }

    /// Convenience method to create a HEAD request for `uri`.
    pub fn head(&self, uri: Uri) -> PendingRequest<T, &Self> {
        self.new_request().with_method(Method::HEAD).with_uri(uri)
    }

    /// Convenience method to create an OPTIONS request for `uri`.
    pub fn options(&self, uri: Uri) -> PendingRequest<T, &Self> {
        self.new_request()
            .with_method(Method::OPTIONS)
            .with_uri(uri)
    }

    /// Convenience method to create a TRACE request for `uri`.
    pub fn trace(&self, uri: Uri) -> PendingRequest<T, &Self> {
        self.new_request().with_method(Method::TRACE).with_uri(uri)
    }
}

impl<T> H3Endpoint<T>
where
    T: quic::Listen<Connection = <T as quic::Connect>::Connection> + quic::Connect,
    <T as quic::Connect>::Connection: quic::Connection,
{
    /// Accept and serve HTTP/3 connections in a loop.
    pub async fn serve<S>(&mut self, service: S) -> Result<(), <T as quic::Listen>::Error>
    where
        S: Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
        S::Future: Send,
        S::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        loop {
            let quic_conn = self.quic.accept().await?;
            let h3_conn = match self.builder.build(quic_conn).await {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    let report = snafu::Report::from_error(&e);
                    tracing::debug!(error = %report, "failed to build H3 connection");
                    continue;
                }
            };
            // Inherent termination: spawned task exits when accept_raw_message_stream
            // returns an error (connection closed) or qpack is no longer available.
            tokio::spawn(serve_connection(h3_conn, service.clone()).in_current_span());
        }
    }

    /// Serve HTTP/3 requests on an `Arc<H3Endpoint<T>>`.
    ///
    /// The returned future does not capture `&self`, so it can be spawned:
    ///
    /// ```ignore
    /// let h3: Arc<H3Endpoint<QuicEndpoint>> = ...;
    /// tokio::spawn(h3.serve(router));
    /// ```
    pub fn serve_owned<S>(
        self: &Arc<Self>,
        service: S,
    ) -> impl Future<Output = Result<(), <T as quic::Listen>::Error>> + use<S, T>
    where
        S: Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
        S::Future: Send,
        S::Error: Into<Box<dyn Error + Send + Sync>>,
        for<'a> &'a T: quic::Listen<
                Connection = <T as quic::Connect>::Connection,
                Error = <T as quic::Listen>::Error,
            >,
    {
        let this = Arc::clone(self);
        let pool = this.pool.clone();
        let builder = this.builder.clone();
        async move {
            let mut ref_ep = H3Endpoint::new(&this.quic, pool, builder);
            ref_ep.serve(service).await
        }
    }
}

/// Serve requests from a single accepted H3 connection.
///
/// Inherent termination: returns when [`H3Connection::accept_raw_message_stream`]
/// produces an error (connection closed) or when the QPACK module is no longer
/// available.
async fn serve_connection<C, S>(h3_conn: Arc<H3Connection<C>>, mut service: S)
where
    C: quic::Connection,
    S: Service<UnresolvedRequest, Response = ()> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let erased = Arc::new(h3_conn.erase());

    loop {
        let (mut reader, writer) = match h3_conn.accept_raw_message_stream().await {
            Ok(s) => s,
            Err(e) => {
                let report = snafu::Report::from_error(&e);
                tracing::debug!(error = %report, "stopping request handler for connection");
                return;
            }
        };
        let stream_id = match GetStreamIdExt::stream_id(&mut reader).await {
            Ok(id) => StreamId(id),
            Err(e) => {
                let report = snafu::Report::from_error(&e);
                tracing::debug!(error = %report, "failed to get stream id, skipping request");
                continue;
            }
        };
        let qpack = match h3_conn.qpack() {
            Ok(q) => q,
            Err(e) => {
                let report = snafu::Report::from_error(&e);
                tracing::debug!(error = %report, "qpack unavailable, stopping handler");
                return;
            }
        };
        let dhttp = h3_conn.dhttp();

        let read_stream = ReadStream::new(
            reader,
            qpack.decoder.clone(),
            h3_conn.quic().clone() as Arc<dyn quic::DynLifecycle + Send + Sync>,
            dhttp.state.clone(),
        );
        let write_stream = WriteStream::new(
            writer,
            qpack.encoder.clone(),
            h3_conn.quic().clone() as Arc<dyn quic::DynLifecycle + Send + Sync>,
            dhttp.state.clone(),
        );

        let request = UnresolvedRequest {
            stream_id,
            read_stream,
            write_stream,
            connection: erased.clone(),
        };

        // Inherent termination: the spawned task exits when the service future resolves.
        tokio::spawn(serve_request(&mut service, request).in_current_span());
    }
}

/// Spawn a task to process a single request through `service`.
///
/// Inherent termination: the spawned task exits when the service future resolves.
fn serve_request<S>(
    service: &mut S,
    request: UnresolvedRequest,
) -> impl Future<Output = ()> + use<S>
where
    S: Service<UnresolvedRequest, Response = ()> + Send + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let fut = service.call(request);
    async move {
        if let Err(error) = fut.await {
            let boxed: Box<dyn Error + Send + Sync> = error.into();
            let report = snafu::Report::from_error(boxed.as_ref());
            tracing::debug!(error = %report, "request handler returned error");
        }
    }
}
