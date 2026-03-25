//! Erased connection capability trait for the runtime protocol layer.
//!
//! [`ErasedConnection`] provides an object-safe subset of [`quic::Connection`]
//! by boxing the associated stream types. Runtime protocols that only need to
//! open streams and manage the connection lifecycle can depend on
//! `dyn ErasedConnection` instead of being generic over `C: quic::Connection`.

use std::pin::Pin;

use futures::future::BoxFuture;

use crate::quic;

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
///
/// Lifecycle methods (`close`, `check`, `closed`) are inherited from
/// [`quic::DynLifecycle`] via the supertrait bound.
pub trait ErasedConnection: quic::DynLifecycle + Send + Sync {
    /// Open a unidirectional stream, returning a boxed write stream.
    fn open_uni(&self) -> BoxFuture<'_, Result<BoxWriteStream, quic::ConnectionError>>;

    /// Open a bidirectional stream, returning boxed read and write streams.
    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), quic::ConnectionError>>;
}

impl<C: quic::Connection> ErasedConnection for C {
    fn open_uni(&self) -> BoxFuture<'_, Result<BoxWriteStream, quic::ConnectionError>> {
        Box::pin(async {
            let writer = quic::ManageStream::open_uni(self).await?;
            Ok(Box::pin(writer) as BoxWriteStream)
        })
    }

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), quic::ConnectionError>> {
        Box::pin(async {
            let (reader, writer) = quic::ManageStream::open_bi(self).await?;
            Ok((
                Box::pin(reader) as BoxReadStream,
                Box::pin(writer) as BoxWriteStream,
            ))
        })
    }
}
