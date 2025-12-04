use std::{ops::DerefMut, pin::Pin};

use bytes::Bytes;
use futures::future::BoxFuture;

use crate::quic::ConnectionError;

pub trait WithLocalIdentity {
    fn local_cert(self: Pin<&mut Self>) -> Result<Bytes, ConnectionError>;

    fn local_name(self: Pin<&mut Self>) -> Result<String, ConnectionError>;
}

impl<P: DerefMut<Target: WithLocalIdentity>> WithLocalIdentity for Pin<P> {
    fn local_cert(self: Pin<&mut Self>) -> Result<Bytes, ConnectionError> {
        <P::Target as WithLocalIdentity>::local_cert(self.as_deref_mut())
    }

    fn local_name(self: Pin<&mut Self>) -> Result<String, ConnectionError> {
        <P::Target as WithLocalIdentity>::local_name(self.as_deref_mut())
    }
}

impl<I: WithLocalIdentity + Unpin + ?Sized> WithLocalIdentity for &mut I {
    fn local_cert(self: Pin<&mut Self>) -> Result<Bytes, ConnectionError> {
        I::local_cert(Pin::new(self.get_mut()))
    }

    fn local_name(self: Pin<&mut Self>) -> Result<String, ConnectionError> {
        I::local_name(Pin::new(self.get_mut()))
    }
}

pub trait WithPeerIdentity {
    fn peer_cert(self: Pin<&mut Self>) -> BoxFuture<'static, Result<Bytes, ConnectionError>>;

    fn peer_name(self: Pin<&mut Self>) -> BoxFuture<'static, Result<String, ConnectionError>>;
}

impl<P: DerefMut<Target: WithPeerIdentity>> WithPeerIdentity for Pin<P> {
    fn peer_cert(self: Pin<&mut Self>) -> BoxFuture<'static, Result<Bytes, ConnectionError>> {
        <P::Target as WithPeerIdentity>::peer_cert(self.as_deref_mut())
    }

    fn peer_name(self: Pin<&mut Self>) -> BoxFuture<'static, Result<String, ConnectionError>> {
        <P::Target as WithPeerIdentity>::peer_name(self.as_deref_mut())
    }
}

impl<I: WithPeerIdentity + Unpin + ?Sized> WithPeerIdentity for &mut I {
    fn peer_cert(self: Pin<&mut Self>) -> BoxFuture<'static, Result<Bytes, ConnectionError>> {
        I::peer_cert(Pin::new(self.get_mut()))
    }

    fn peer_name(self: Pin<&mut Self>) -> BoxFuture<'static, Result<String, ConnectionError>> {
        I::peer_name(Pin::new(self.get_mut()))
    }
}
