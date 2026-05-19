//! Generic HTTP/3 endpoint.
//!
//! [`H3Endpoint`] combines a QUIC transport `Q` with a selected connection
//! type `C`, providing the foundation for both client and server
//! functionality.  Client methods require `Q: quic::Connect<Connection = C>`;
//! server methods require `Q: quic::Listen<Connection = C>`.
//!
//! [`ConnectionBuilder`]: crate::connection::ConnectionBuilder

use std::{error::Error, future::Future, sync::Arc};

use bon::bon;
use http::{Method, Uri, uri::Authority};
use tower_service::Service;
use tracing::Instrument;

use crate::{
    connection::{Connection as H3Connection, ConnectionBuilder},
    endpoint::{
        client::{Arbiter, Request as ClientRequest},
        server::UnresolvedRequest,
    },
    message::{
        stream::{ReadStream, WriteStream},
        unify::Message,
    },
    pool::{self, Pool},
    quic::{self, GetStreamIdExt},
    stream_id::StreamId,
};

pub mod client;
pub mod server;

/// Generic HTTP/3 endpoint parameterized over a QUIC transport `Q` and a
/// connection type `C`.
///
/// `Q` carries no struct-level constraint — abilities are encoded at the
/// method level:
///
/// | Capability | Bound |
/// |---|---|
/// | Client (connect, new_request, get, …) | `Q: quic::Connect<Connection = C>` |
/// | Server (serve, serve_owned)            | `Q: quic::Listen<Connection = C>`  |
pub struct H3Endpoint<Q, C: quic::Connection> {
    pub(crate) quic: Q,
    pub(crate) builder: Arc<ConnectionBuilder<C>>,
    pub(crate) pool: Pool<C>,
}

/// RAII guard for mutable access to [`H3Endpoint`]'s QUIC transport.
///
/// On drop, clears the endpoint's connection pool via [`Pool::clear`],
/// ensuring no stale connections remain after QUIC configuration changes.
pub struct QuicMutGuard<'a, Q, C: quic::Connection> {
    quic: &'a mut Q,
    pool: &'a Pool<C>,
}

impl<Q, C: quic::Connection> std::ops::Deref for QuicMutGuard<'_, Q, C> {
    type Target = Q;
    fn deref(&self) -> &Self::Target {
        self.quic
    }
}

impl<Q, C: quic::Connection> std::ops::DerefMut for QuicMutGuard<'_, Q, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.quic
    }
}

impl<Q, C: quic::Connection> Drop for QuicMutGuard<'_, Q, C> {
    fn drop(&mut self) {
        self.pool.clear();
    }
}

#[bon]
impl<Q, C: quic::Connection> H3Endpoint<Q, C> {
    /// Construct a new HTTP/3 endpoint.
    #[builder]
    pub fn new(quic: Q, #[builder(default)] builder: Arc<ConnectionBuilder<C>>) -> Self {
        Self {
            quic,
            builder,
            pool: Pool::empty(),
        }
    }
}

impl<Q, C: quic::Connection> H3Endpoint<Q, C>
where
    Q: quic::Connect<Connection = C>,
{
    /// Construct a new HTTP/3 endpoint with default pool and builder.
    pub fn new(quic: Q) -> Self {
        H3Endpoint::builder().quic(quic).build()
    }
}

impl<Q, C: quic::Connection> H3Endpoint<Q, C> {
    /// Obtain a mutable guard for the QUIC transport.
    ///
    /// The guard implements [`DerefMut`](std::ops::DerefMut) targeting `Q`.
    /// On drop, the connection pool is cleared via [`Pool::clear`].
    pub fn quic_mut(&mut self) -> QuicMutGuard<'_, Q, C> {
        QuicMutGuard {
            quic: &mut self.quic,
            pool: &self.pool,
        }
    }

    /// Shared reference to the underlying QUIC transport.
    pub fn quic(&self) -> &Q {
        &self.quic
    }
}

impl<Q, C: quic::Connection> H3Endpoint<Q, C>
where
    Q: quic::Connect<Connection = C>,
{
    /// Obtain (or reuse) an HTTP/3 connection to `server` from the pool.
    pub async fn connect(
        &self,
        server: Authority,
    ) -> Result<Arc<H3Connection<C>>, pool::ConnectError<Q::Error>> {
        self.pool
            .reuse_or_connect_with(&self.quic, self.builder.clone(), server)
            .await
    }
}

impl<Q, C: quic::Connection> H3Endpoint<Q, C>
where
    Q: quic::Connect<Connection = C>,
    Q::Error: std::error::Error + Send + Sync + 'static,
{
    /// Create a new request owned by this endpoint (shared via [`Arc`]).
    ///
    /// Authority is NOT set at construction time — use [`.uri()`] on the
    /// returned [`Request`] to set both the request URI and the authority.
    /// If `.uri()` is never called, [`Request::into_future`] will fail with
    /// [`RequestError::MalformedRequestHeader`] containing
    /// `EmptyAuthorityOrHost`.
    ///
    /// [`Request`]: client::Request
    /// [`Request::into_future`]: client::Request::into_future
    pub fn new_request_owned(self: &Arc<Self>) -> ClientRequest<Q, Arc<Self>> {
        let msg = Message::unresolved_request();
        let arbiter = Arc::new(Arbiter::new(Arc::clone(self), msg));
        ClientRequest::new(arbiter)
    }

    /// Create a new request borrowing this endpoint.
    ///
    /// This is the primary method for creating requests. It borrows the
    /// endpoint (returning a non-`'static` request type) so you can build
    /// requests inline without cloning an [`Arc`].
    /// Authority is NOT set at construction time — use [`.uri()`] on the
    /// returned [`Request`] to set both the request URI and the authority.
    ///
    /// If you need a `'static` request (e.g. for async spawning), use
    /// [`new_request_owned`] instead.
    ///
    /// [`Request`]: client::Request
    pub fn new_request(&self) -> ClientRequest<Q, &H3Endpoint<Q, C>> {
        let msg = Message::unresolved_request();
        let arbiter = Arc::new(Arbiter::new(self, msg));
        ClientRequest::new(arbiter)
    }

    /// Convenience method to create a GET request for `uri`.
    pub fn get(&self, uri: Uri) -> ClientRequest<Q, &H3Endpoint<Q, C>> {
        self.new_request().method(Method::GET).uri(uri)
    }

    /// Convenience method to create a POST request for `uri`.
    pub fn post(&self, uri: Uri) -> ClientRequest<Q, &H3Endpoint<Q, C>> {
        self.new_request().method(Method::POST).uri(uri)
    }

    /// Convenience method to create a PUT request for `uri`.
    pub fn put(&self, uri: Uri) -> ClientRequest<Q, &H3Endpoint<Q, C>> {
        self.new_request().method(Method::PUT).uri(uri)
    }

    /// Convenience method to create a DELETE request for `uri`.
    pub fn delete(&self, uri: Uri) -> ClientRequest<Q, &H3Endpoint<Q, C>> {
        self.new_request().method(Method::DELETE).uri(uri)
    }

    /// Convenience method to create a PATCH request for `uri`.
    pub fn patch(&self, uri: Uri) -> ClientRequest<Q, &H3Endpoint<Q, C>> {
        self.new_request().method(Method::PATCH).uri(uri)
    }

    /// Convenience method to create a HEAD request for `uri`.
    pub fn head(&self, uri: Uri) -> ClientRequest<Q, &H3Endpoint<Q, C>> {
        self.new_request().method(Method::HEAD).uri(uri)
    }

    /// Convenience method to create a OPTIONS request for `uri`.
    pub fn options(&self, uri: Uri) -> ClientRequest<Q, &H3Endpoint<Q, C>> {
        self.new_request().method(Method::OPTIONS).uri(uri)
    }

    /// Convenience method to create a TRACE request for `uri`.
    pub fn trace(&self, uri: Uri) -> ClientRequest<Q, &H3Endpoint<Q, C>> {
        self.new_request().method(Method::TRACE).uri(uri)
    }
}

impl<Q, C: quic::Connection> H3Endpoint<Q, C>
where
    Q: quic::Listen<Connection = C>,
{
    /// Accept and serve HTTP/3 connections in a loop.
    pub async fn serve<S>(&mut self, service: S) -> Result<(), <Q as quic::Listen>::Error>
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

    /// Serve HTTP/3 requests on an `Arc<H3Endpoint<Q, C>>`.
    ///
    /// The returned future does not capture `&self`, so it can be spawned:
    ///
    /// ```ignore
    /// let h3: Arc<H3Endpoint<QuicEndpoint, Connection>> = ...;
    /// tokio::spawn(h3.serve(router));
    /// ```
    pub fn serve_owned<S>(
        self: &Arc<Self>,
        service: S,
    ) -> impl Future<Output = Result<(), <Q as quic::Listen>::Error>> + use<S, Q, C>
    where
        S: Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
        S::Future: Send,
        S::Error: Into<Box<dyn Error + Send + Sync>>,
        for<'a> &'a Q: quic::Listen<Connection = C, Error = <Q as quic::Listen>::Error>,
    {
        let this = Arc::clone(self);
        let pool = this.pool.clone();
        let builder = this.builder.clone();
        async move {
            let mut ref_ep = H3Endpoint {
                quic: &this.quic,
                builder,
                pool,
            };
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
        let read_stream = ReadStream::new(reader, qpack.decoder.clone(), (*erased).clone());
        let write_stream = WriteStream::new(writer, qpack.encoder.clone(), (*erased).clone());

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http::uri::Authority;

    use super::*;
    use crate::{connection::tests::MockConnection, pool::ReuseableConnection};

    /// Minimal quic::Connect implementation for testing QuicMutGuard.
    struct MockConnect;

    impl quic::Connect for MockConnect {
        type Connection = MockConnection;
        type Error = quic::ConnectionError;

        async fn connect<'a>(
            &'a self,
            _server: &'a Authority,
        ) -> Result<Arc<Self::Connection>, Self::Error> {
            unreachable!("connect is not called in guard tests")
        }
    }

    /// Verify that QuicMutGuard provides mutable access to the inner QUIC transport.
    #[test]
    fn test_quic_mut_guard_deref_mut() {
        let mut quic = MockConnect;
        let pool = Pool::<MockConnection>::empty();
        let mut guard = QuicMutGuard {
            quic: &mut quic,
            pool: &pool,
        };

        // Verify Deref produces &MockConnect
        let _reference: &MockConnect = &guard;
        let _ = _reference;

        // Verify DerefMut produces &mut MockConnect
        let _mut_reference: &mut MockConnect = &mut guard;
        let _ = _mut_reference;

        drop(guard);
    }

    /// Verify that dropping QuicMutGuard clears the connection pool.
    #[test]
    fn test_quic_mut_guard_drop_clears_pool() {
        let mut quic = MockConnect;
        let pool = Pool::<MockConnection>::empty();

        // Insert an entry into the pool to verify clearing
        let auth: Authority = "example.com:443".parse().unwrap();
        pool.connections
            .entry(auth)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));

        assert_eq!(pool.len(), 1);

        {
            let guard = QuicMutGuard {
                quic: &mut quic,
                pool: &pool,
            };
            // Guard holds reference; pool still has entries
            assert_eq!(pool.len(), 1);
            drop(guard);
        } // guard dropped, pool.clear() called

        assert_eq!(pool.len(), 0);
    }

    /// Verify that H3Endpoint::quic_mut provides mutable access to the inner
    /// QUIC transport.
    #[test]
    fn test_quic_mut_access() {
        let mut h3 = H3Endpoint::new(MockConnect);

        let guard = h3.quic_mut();
        let _: &MockConnect = &guard; // verify Deref works
        drop(guard);
    }

    /// Verify that dropping the guard from H3Endpoint::quic_mut clears the
    /// connection pool.
    #[test]
    fn test_quic_mut_drop_clears_pool() {
        let mut h3 = H3Endpoint::new(MockConnect);

        // Insert an entry into the pool
        let auth: Authority = "example.com:443".parse().unwrap();
        h3.pool
            .connections
            .entry(auth)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));

        assert_eq!(h3.pool.len(), 1);

        {
            let _guard = h3.quic_mut();
        } // guard dropped, pool.clear() called

        assert_eq!(h3.pool.len(), 0);
    }
}
