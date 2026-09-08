use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{ChunkBody, Error, RemoteAuthority};

/// An HTTP response accompanied by authentication facts from its connection.
pub struct Response<B = ChunkBody> {
    message: http::Response<B>,
    authority: Option<RemoteAuthority>,
}
impl<B> Response<B> {
    pub(crate) fn new(message: http::Response<B>, authority: Option<RemoteAuthority>) -> Self {
        Self { message, authority }
    }

    pub fn status(&self) -> http::StatusCode {
        self.message.status()
    }

    pub fn headers(&self) -> &http::HeaderMap {
        self.message.headers()
    }

    pub fn authority(&self) -> Option<&RemoteAuthority> {
        self.authority.as_ref()
    }

    pub fn into_body(self) -> B {
        self.message.into_body()
    }

    pub fn into_http(mut self) -> http::Response<B> {
        self.message.extensions_mut().remove::<RemoteAuthority>();
        if let Some(authority) = self.authority {
            self.message.extensions_mut().insert(authority);
        }
        self.message
    }
}

/// Adds runtime authentication facts to a protocol response without owning upload.
pub struct ResponseFuture {
    inner: crate::protocol::ResponseFuture,
    authority: Option<RemoteAuthority>,
}
impl ResponseFuture {
    pub(crate) fn new(
        inner: crate::protocol::ResponseFuture,
        authority: Option<RemoteAuthority>,
    ) -> Self {
        Self { inner, authority }
    }
}
impl Future for ResponseFuture {
    type Output = Result<Response, Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let response = std::task::ready!(Pin::new(&mut self.inner).poll(cx))?;
        Poll::Ready(Ok(Response::new(response, self.authority.take())))
    }
}
