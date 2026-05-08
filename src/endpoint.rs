//! Generic HTTP/3 endpoint.
//!
//! [`H3Endpoint`] wraps a [`quic::Connect`] implementation with an HTTP/3
//! connection pool and a user-configurable [`ConnectionBuilder`], providing
//! the foundation for both client and server functionality.
//!
//! [`ConnectionBuilder`]: crate::connection::ConnectionBuilder

use std::{error::Error, sync::Arc};

use http::{Method, Uri, uri::Authority};
use tower_service::Service;
use tracing::Instrument;

use crate::{
    connection::{Connection as H3Connection, ConnectionBuilder},
    endpoint::server::UnresolvedRequest,
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
    pub fn new_request(&self) -> crate::endpoint::client::PendingRequest<'_, T> {
        crate::endpoint::client::PendingRequest::new(self)
    }

    /// Convenience method to create a GET request for `uri`.
    pub fn get<U>(&self, uri: U) -> crate::endpoint::client::PendingRequest<'_, T>
    where
        U: TryInto<Uri>,
        U::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let uri = uri
            .try_into()
            .unwrap_or_else(|e| panic!("invalid uri: {}", e.into()));
        self.new_request().with_method(Method::GET).with_uri(uri)
    }

    /// Convenience method to create a POST request for `uri`.
    pub fn post<U>(&self, uri: U) -> crate::endpoint::client::PendingRequest<'_, T>
    where
        U: TryInto<Uri>,
        U::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let uri = uri
            .try_into()
            .unwrap_or_else(|e| panic!("invalid uri: {}", e.into()));
        self.new_request().with_method(Method::POST).with_uri(uri)
    }

    /// Convenience method to create a PUT request for `uri`.
    pub fn put<U>(&self, uri: U) -> crate::endpoint::client::PendingRequest<'_, T>
    where
        U: TryInto<Uri>,
        U::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let uri = uri
            .try_into()
            .unwrap_or_else(|e| panic!("invalid uri: {}", e.into()));
        self.new_request().with_method(Method::PUT).with_uri(uri)
    }

    /// Convenience method to create a DELETE request for `uri`.
    pub fn delete<U>(&self, uri: U) -> crate::endpoint::client::PendingRequest<'_, T>
    where
        U: TryInto<Uri>,
        U::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let uri = uri
            .try_into()
            .unwrap_or_else(|e| panic!("invalid uri: {}", e.into()));
        self.new_request().with_method(Method::DELETE).with_uri(uri)
    }

    /// Convenience method to create a PATCH request for `uri`.
    pub fn patch<U>(&self, uri: U) -> crate::endpoint::client::PendingRequest<'_, T>
    where
        U: TryInto<Uri>,
        U::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let uri = uri
            .try_into()
            .unwrap_or_else(|e| panic!("invalid uri: {}", e.into()));
        self.new_request().with_method(Method::PATCH).with_uri(uri)
    }

    /// Convenience method to create a HEAD request for `uri`.
    pub fn head<U>(&self, uri: U) -> crate::endpoint::client::PendingRequest<'_, T>
    where
        U: TryInto<Uri>,
        U::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let uri = uri
            .try_into()
            .unwrap_or_else(|e| panic!("invalid uri: {}", e.into()));
        self.new_request().with_method(Method::HEAD).with_uri(uri)
    }

    /// Convenience method to create an OPTIONS request for `uri`.
    pub fn options<U>(&self, uri: U) -> crate::endpoint::client::PendingRequest<'_, T>
    where
        U: TryInto<Uri>,
        U::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let uri = uri
            .try_into()
            .unwrap_or_else(|e| panic!("invalid uri: {}", e.into()));
        self.new_request().with_method(Method::OPTIONS).with_uri(uri)
    }

    /// Convenience method to create a TRACE request for `uri`.
    pub fn trace<U>(&self, uri: U) -> crate::endpoint::client::PendingRequest<'_, T>
    where
        U: TryInto<Uri>,
        U::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let uri = uri
            .try_into()
            .unwrap_or_else(|e| panic!("invalid uri: {}", e.into()));
        self.new_request().with_method(Method::TRACE).with_uri(uri)
    }
}

impl<T> H3Endpoint<T>
where
    T: quic::Listen<Connection = <T as quic::Connect>::Connection> + quic::Connect,
    <T as quic::Connect>::Connection: quic::Connection,
{
    /// Accept and serve HTTP/3 connections in a loop (internal).
    ///
    /// The dquic-specific [`crate::dquic::H3Endpoint::serve`] wraps this
    /// with a `&self` interface.
    pub(crate) async fn serve_inner<S>(
        &mut self,
        service: S,
    ) -> Result<(), <T as quic::Listen>::Error>
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
                    tracing::error!(error = %report, "failed to build H3 connection");
                    continue;
                }
            };
            let erased = Arc::new(h3_conn.erase());
            let service = service.clone();

            tokio::spawn(
                async move {
                    let mut service = service;
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
                                tracing::debug!(?e, "failed to get stream id, skipping request");
                                continue;
                            }
                        };
                        let qpack = match h3_conn.qpack() {
                            Ok(q) => q,
                            Err(e) => {
                                let report = snafu::Report::from_error(&e);
                                tracing::debug!(error = %report, "QPACK unavailable, stopping handler");
                                return;
                            }
                        };
                        let dhttp = h3_conn.dhttp();

                        let read_stream = crate::message::stream::ReadStream::new(
                            reader,
                            qpack.decoder.clone(),
                            h3_conn.quic().clone() as Arc<dyn quic::DynLifecycle + Send + Sync>,
                            dhttp.state.clone(),
                        );
                        let write_stream = crate::message::stream::WriteStream::new(
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

                        let fut = service.call(request);
                        tokio::spawn(async move {
                            if let Err(e) = fut.await {
                                let boxed: Box<dyn Error + Send + Sync> = e.into();
                                let report = snafu::Report::from_error(boxed.as_ref());
                                tracing::debug!(error = %report, "request handler returned error");
                            }
                        }.in_current_span());
                    }
                }
                .in_current_span(),
            );
        }
    }
}
