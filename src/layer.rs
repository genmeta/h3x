use std::{any::Any, pin::Pin};

use futures::future::BoxFuture;

use crate::{codec::peekable::PeekableStreamReader, quic::ConnectionError};

/// Protocol layer trait for handling QUIC streams in a layered architecture.
/// Layers can inspect, accept, or pass through streams to underlying layers.
pub trait ProtocolLayer<C: ?Sized>: Any + Send + Sync {
    /// Returns the name of this protocol layer.
    fn name(&self) -> &'static str;

    /// Initializes the layer with the QUIC connection.
    fn init(&self, quic: &C) -> BoxFuture<'_, Result<(), ConnectionError>>;

    /// Handles an incoming unidirectional stream.
    /// Returns whether the stream was accepted or should be passed to the next layer.
    fn accept_uni(
        &self,
        stream: PeekableUniStream,
    ) -> BoxFuture<'_, Result<StreamVerdict<PeekableUniStream>, ConnectionError>>;

    /// Handles an incoming bidirectional stream.
    /// Returns whether the stream was accepted or should be passed to the next layer.
    fn accept_bi(
        &self,
        stream: PeekableBiStream,
    ) -> BoxFuture<'_, Result<StreamVerdict<PeekableBiStream>, ConnectionError>>;
}

/// Verdict for stream handling in protocol layers.
#[derive(Debug)]
pub enum StreamVerdict<S> {
    /// The stream was accepted and handled by this layer.
    Accepted,
    /// The stream was not handled and should be passed to the next layer.
    Passed(S),
}

/// Type alias for a peekable unidirectional stream.
pub type PeekableUniStream = PeekableStreamReader<Pin<Box<dyn crate::quic::ReadStream + Send>>>;

/// Type alias for a peekable bidirectional stream pair.
pub type PeekableBiStream = (
    PeekableStreamReader<Pin<Box<dyn crate::quic::ReadStream + Send>>>,
    Pin<Box<dyn crate::quic::WriteStream + Send>>,
);

pub mod dhttp;
pub mod qpack;
