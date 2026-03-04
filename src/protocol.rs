use std::{
    any::{Any, TypeId},
    collections::HashMap,
    fmt::Debug,
    sync::Arc,
};

use futures::future::BoxFuture;

use crate::{
    codec::{BoxPeekableBiStream, BoxPeekableUniStream},
    connection::{QuicConnection, StreamError},
    quic::{self, ConnectionError},
};

pub struct Protocols<C: ?Sized> {
    layers: HashMap<TypeId, Arc<dyn Protocol<C>>>,
}

impl<C: ?Sized> Default for Protocols<C> {
    fn default() -> Self {
        Self {
            layers: Default::default(),
        }
    }
}

impl<C: ?Sized> Debug for Protocols<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_list();
        for layer in self.layers.values() {
            f.entry(layer.as_ref());
        }
        f.finish()
    }
}

impl<C: ?Sized> Protocols<C> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get<L: Any>(&self) -> Option<&L> {
        self.layers.get(&TypeId::of::<L>()).map(|layer| {
            (layer.as_ref() as &dyn Any)
                .downcast_ref()
                .expect("TypeId collision for protocol layers, this is a bug")
        })
    }
}

impl<C: quic::Connection + ?Sized> Protocols<C> {
    pub fn insert<L: Protocol<C>>(&mut self, layer: L) {
        self.layers.insert(TypeId::of::<L>(), Arc::new(layer));
    }

    pub(crate) async fn accept_uni<'a>(
        &'a self,
        conn: &'a Arc<QuicConnection<C>>,
        mut stream: BoxPeekableUniStream<C>,
    ) -> Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError>
    where
        C: quic::Connection,
    {
        for layer in self.layers.values() {
            match layer.accept_uni(conn, stream).await? {
                StreamVerdict::Accepted => return Ok(StreamVerdict::Accepted),
                StreamVerdict::Passed(mut passed) => {
                    passed.reset();
                    stream = passed
                }
            }
        }
        Ok(StreamVerdict::Passed(stream))
    }

    pub(crate) async fn accept_bi<'a>(
        &'a self,
        conn: &'a Arc<QuicConnection<C>>,
        mut stream: BoxPeekableBiStream<C>,
    ) -> Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>
    where
        C: quic::Connection,
    {
        for layer in self.layers.values() {
            match layer.accept_bi(conn, stream).await? {
                StreamVerdict::Accepted => return Ok(StreamVerdict::Accepted),
                StreamVerdict::Passed(passed) => stream = passed,
            }
        }
        Ok(StreamVerdict::Passed(stream))
    }
}

pub trait ProductProtocol<C: quic::Connection + ?Sized>: Any + Send + Sync {
    type Protocol: Protocol<C>;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<QuicConnection<C>>,
        layers: &'a Protocols<C>,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>>;
}

pub(crate) trait InitProtocols<C: quic::Connection + ?Sized> {
    fn init_protocols<'a>(
        &'a self,
        conn: &'a Arc<QuicConnection<C>>,
        layers: &'a mut Protocols<C>,
    ) -> BoxFuture<'a, Result<(), ConnectionError>>;
}

impl<C: quic::Connection + ?Sized, P: ProductProtocol<C>> InitProtocols<C> for P {
    fn init_protocols<'a>(
        &'a self,
        conn: &'a Arc<QuicConnection<C>>,
        layers: &'a mut Protocols<C>,
    ) -> BoxFuture<'a, Result<(), ConnectionError>> {
        Box::pin(async move {
            if layers
                .get::<<Self as ProductProtocol<C>>::Protocol>()
                .is_some()
            {
                return Ok(());
            }
            let layer = ProductProtocol::init(self, conn, layers).await?;
            layers.insert(layer);
            Ok(())
        })
    }
}
/// Protocol layer trait for handling QUIC streams in a layered architecture.
/// Layers can inspect, accept, or pass through streams to underlying layers.
pub trait Protocol<C: quic::Connection + ?Sized>: Any + Send + Sync + Debug {
    /// Handles an incoming unidirectional stream.
    /// Returns whether the stream was accepted or should be passed to the next layer.
    fn accept_uni<'a>(
        &'a self,
        connection: &'a Arc<QuicConnection<C>>,
        stream: BoxPeekableUniStream<C>,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError>>;

    /// Handles an incoming bidirectional stream.
    /// Returns whether the stream was accepted or should be passed to the next layer.
    fn accept_bi<'a>(
        &'a self,
        connection: &'a Arc<QuicConnection<C>>,
        stream: BoxPeekableBiStream<C>,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>>;
}

/// Verdict for stream handling in protocol layers.
#[derive(Debug)]
pub enum StreamVerdict<S> {
    /// The stream was accepted and handled by this layer.
    Accepted,
    /// The stream was not handled and should be passed to the next layer.
    Passed(S),
}
