//! Erased connection capability trait for the runtime protocol layer.
//!
//! [`ErasedConnection`] provides an object-safe subset of [`quic::Connection`]
//! by boxing the associated stream types. Runtime protocols that only need to
//! open streams and manage the connection lifecycle can depend on
//! `dyn ErasedConnection` instead of being generic over `C: quic::Connection`.

use std::{borrow::Cow, pin::Pin, sync::Arc};

use futures::future::BoxFuture;

use crate::{error::Code, quic};

/// Boxed, type-erased read stream.
pub type BoxReadStream = Pin<Box<dyn quic::ReadStream + Send + Unpin>>;

/// Boxed, type-erased write stream.
pub type BoxWriteStream = Pin<Box<dyn quic::WriteStream + Send + Unpin>>;

/// Object-safe, type-erased connection capability trait.
///
/// Exposes only the minimal methods that runtime protocols need:
/// opening streams and managing the connection lifecycle. Accept methods
/// are intentionally excluded — they belong to the protocol dispatch loop
/// which remains generic.
pub trait ErasedConnection: Send + Sync {
    /// Open a unidirectional stream, returning a boxed write stream.
    fn open_uni(&self) -> BoxFuture<'_, Result<BoxWriteStream, quic::ConnectionError>>;

    /// Open a bidirectional stream, returning boxed read and write streams.
    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), quic::ConnectionError>>;

    /// Wait for the connection to close, returning the terminal error.
    fn closed(&self) -> BoxFuture<'_, quic::ConnectionError>;

    /// Check whether the connection is still alive and usable.
    fn check(&self) -> Result<(), quic::ConnectionError>;

    /// Initiate a graceful close with the given error code and reason.
    fn close(&self, code: Code, reason: Cow<'static, str>);
}

impl<C: quic::Connection> ErasedConnection for Arc<C> {
    fn open_uni(&self) -> BoxFuture<'_, Result<BoxWriteStream, quic::ConnectionError>> {
        Box::pin(async {
            let writer = quic::ManageStream::open_uni(self.as_ref()).await?;
            Ok(Box::pin(writer) as BoxWriteStream)
        })
    }

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), quic::ConnectionError>> {
        Box::pin(async {
            let (reader, writer) = quic::ManageStream::open_bi(self.as_ref()).await?;
            Ok((
                Box::pin(reader) as BoxReadStream,
                Box::pin(writer) as BoxWriteStream,
            ))
        })
    }

    fn closed(&self) -> BoxFuture<'_, quic::ConnectionError> {
        quic::Lifecycle::closed(self.as_ref())
    }

    fn check(&self) -> Result<(), quic::ConnectionError> {
        quic::Lifecycle::check(self.as_ref())
    }

    fn close(&self, code: Code, reason: Cow<'static, str>) {
        quic::Lifecycle::close(self.as_ref(), code, reason);
    }
}
