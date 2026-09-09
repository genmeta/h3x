use crate::{ChunkBody, LocalAuthority, RemoteAuthority};

/// An incoming HTTP request with authentication facts from its connection.
/// Request headers and extensions cannot replace these facts.
pub struct Request<B = ChunkBody> {
    message: http::Request<B>,
    local: LocalAuthority,
    remote: Option<RemoteAuthority>,
}

impl<B> Request<B> {
    pub(crate) fn new(
        mut message: http::Request<B>,
        local: LocalAuthority,
        remote: Option<RemoteAuthority>,
    ) -> Self {
        message.extensions_mut().remove::<LocalAuthority>();
        message.extensions_mut().remove::<RemoteAuthority>();
        Self {
            message,
            local,
            remote,
        }
    }

    pub fn request(&self) -> &http::Request<B> {
        &self.message
    }

    pub fn local_authority(&self) -> &LocalAuthority {
        &self.local
    }

    pub fn remote_authority(&self) -> Option<&RemoteAuthority> {
        self.remote.as_ref()
    }

    /// Builds a response using this request's authenticated connection identities.
    pub fn response<T>(&self, message: http::Response<T>) -> super::Response<T> {
        super::Response::new(message, self.local.clone(), self.remote.clone())
    }

    pub fn into_body(self) -> B {
        self.message.into_body()
    }

    /// Converts for HTTP services, preserving only connection-supplied identities.
    pub fn into_http(mut self) -> http::Request<B> {
        self.message.extensions_mut().insert(self.local);
        if let Some(remote) = self.remote {
            self.message.extensions_mut().insert(remote);
        }
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_identity_survives_conversion_and_anonymous_requests_stay_anonymous() {
        let certificate = rcgen::generate_simple_self_signed(vec!["peer.example".into()]).unwrap();
        let remote = RemoteAuthority::from_authenticated(
            "peer.example",
            vec![certificate.cert.der().clone()],
        )
        .unwrap();
        let local = LocalAuthority(
            crate::Endpoint::new(
                "peer.example",
                vec![certificate.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    certificate.signing_key.serialize_der(),
                )
                .into(),
                None,
            )
            .unwrap(),
        );
        let mut message = http::Request::new("body");
        message.extensions_mut().insert(remote.clone());
        let anonymous = Request::new(message, local.clone(), None);
        assert!(anonymous.remote_authority().is_none());
        assert!(
            anonymous
                .request()
                .extensions()
                .get::<RemoteAuthority>()
                .is_none()
        );
        assert!(
            anonymous
                .into_http()
                .extensions()
                .get::<RemoteAuthority>()
                .is_none()
        );
        let request = Request::new(http::Request::new("body"), local, Some(remote));
        assert_eq!(request.remote_authority().unwrap().name(), "peer.example");
        let message = request.into_http();
        assert_eq!(
            message
                .extensions()
                .get::<RemoteAuthority>()
                .unwrap()
                .name(),
            "peer.example"
        );
        assert_eq!(message.into_body(), "body");
    }
}
