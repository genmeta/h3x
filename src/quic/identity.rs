use std::{
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::quic::ConnectionError;

pub trait WithIdentity {
    fn poll_cert(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<Bytes, ConnectionError>>;

    fn poll_name(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<String, ConnectionError>>;
}

impl<P: DerefMut<Target: WithIdentity>> WithIdentity for Pin<P> {
    fn poll_cert(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<Bytes, ConnectionError>> {
        <P::Target as WithIdentity>::poll_cert(self.as_deref_mut(), cx)
    }

    fn poll_name(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<String, ConnectionError>> {
        <P::Target as WithIdentity>::poll_name(self.as_deref_mut(), cx)
    }
}

impl<I: WithIdentity + Unpin + ?Sized> WithIdentity for &mut I {
    fn poll_cert(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<Bytes, ConnectionError>> {
        I::poll_cert(Pin::new(self.get_mut()), cx)
    }

    fn poll_name(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<String, ConnectionError>> {
        I::poll_name(Pin::new(self.get_mut()), cx)
    }
}

pin_project_lite::pin_project! {
    pub struct Cert<I: ?Sized> {
        #[pin]
        with_identity: I,
    }
}

impl<I: WithIdentity + ?Sized> Future for Cert<I> {
    type Output = Result<Bytes, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        self.project().with_identity.poll_cert(cx)
    }
}

pin_project_lite::pin_project! {
    pub struct Name<I: ?Sized> {
        #[pin]
        with_identity: I,
    }
}

impl<I: WithIdentity + ?Sized> Future for Name<I> {
    type Output = Result<String, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        self.project().with_identity.poll_name(cx)
    }
}

fn assert_future<Output, F: Future<Output = Output>>(f: F) -> F {
    f
}

pub trait WithIdentityExt: WithIdentity {
    fn cert(&mut self) -> Cert<&mut Self>
    where
        Self: Unpin,
    {
        assert_future::<Result<Bytes, ConnectionError>, _>(Cert {
            with_identity: self,
        })
    }

    fn name(&mut self) -> Name<&mut Self>
    where
        Self: Unpin,
    {
        assert_future::<Result<String, ConnectionError>, _>(Name {
            with_identity: self,
        })
    }
}

impl<I: WithIdentity + ?Sized> WithIdentityExt for I {}
