use crate::{ChunkBody, RemoteAuthority};

/// An HTTP response accompanied by authentication facts from its connection.
pub struct Response<B = ChunkBody> {
    message: http::Response<B>,
    authority: RemoteAuthority,
}
impl<B> Response<B> {
    pub(crate) fn new(message: http::Response<B>, authority: RemoteAuthority) -> Self {
        Self { message, authority }
    }

    pub fn status(&self) -> http::StatusCode {
        self.message.status()
    }

    pub fn headers(&self) -> &http::HeaderMap {
        self.message.headers()
    }

    pub fn authority(&self) -> &RemoteAuthority {
        &self.authority
    }

    pub fn into_body(self) -> B {
        self.message.into_body()
    }

    pub fn into_http(mut self) -> http::Response<B> {
        self.message.extensions_mut().remove::<RemoteAuthority>();
        self.message.extensions_mut().insert(self.authority);
        self.message
    }
}
