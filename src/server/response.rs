use crate::{ChunkBody, LocalAuthority, RemoteAuthority};

/// An outgoing HTTP response with identities inherited from its request.
pub struct Response<B = ChunkBody> {
    message: http::Response<B>,
    local: LocalAuthority,
    remote: Option<RemoteAuthority>,
}

impl<B> Response<B> {
    pub(crate) fn new(
        mut message: http::Response<B>,
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

    pub fn response(&self) -> &http::Response<B> {
        &self.message
    }
    pub fn status(&self) -> http::StatusCode {
        self.message.status()
    }
    pub fn headers(&self) -> &http::HeaderMap {
        self.message.headers()
    }
    pub fn local_authority(&self) -> &LocalAuthority {
        &self.local
    }
    pub fn remote_authority(&self) -> Option<&RemoteAuthority> {
        self.remote.as_ref()
    }
    pub fn into_body(self) -> B {
        self.message.into_body()
    }

    pub(crate) fn matches_authorities(
        &self,
        local: &LocalAuthority,
        remote: Option<&RemoteAuthority>,
    ) -> bool {
        let local_matches = std::sync::Arc::ptr_eq(&self.local.0, &local.0);
        let remote_matches = match (self.remote_authority(), remote) {
            (Some(a), Some(b)) => a.name() == b.name() && a.cert_chain() == b.cert_chain(),
            (None, None) => true,
            _ => false,
        };
        local_matches && remote_matches
    }

    pub fn map<T>(self, f: impl FnOnce(B) -> T) -> Response<T> {
        Response::new(self.message.map(f), self.local, self.remote)
    }

    /// Converts for HTTP services, preserving only connection-supplied identities.
    pub fn into_http(mut self) -> http::Response<B> {
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
    fn response_inherits_identity_and_preserves_it_through_conversion() {
        let certificate = rcgen::generate_simple_self_signed(vec!["peer.example".into()]).unwrap();
        let certs = vec![certificate.cert.der().clone()];
        let local = LocalAuthority(
            crate::Endpoint::new(
                "peer.example",
                certs.clone(),
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    certificate.signing_key.serialize_der(),
                )
                .into(),
                None,
            )
            .unwrap(),
        );
        let remote = RemoteAuthority::from_authenticated("peer.example", certs).unwrap();
        let request = crate::server::Request::new(
            http::Request::new(()),
            local.clone(),
            Some(remote.clone()),
        );
        let response = request
            .response(http::Response::new("body"))
            .map(str::to_owned);
        assert!(response.matches_authorities(&local, Some(&remote)));
        assert!(!response.matches_authorities(&local, None));
        let other = rcgen::generate_simple_self_signed(vec!["peer.example".into()]).unwrap();
        let other =
            RemoteAuthority::from_authenticated("peer.example", vec![other.cert.der().clone()])
                .unwrap();
        assert!(!response.matches_authorities(&local, Some(&other)));
        let http = response.into_http();
        assert_eq!(
            http.extensions().get::<RemoteAuthority>().unwrap().name(),
            "peer.example"
        );
        assert!(std::sync::Arc::ptr_eq(
            &http.extensions().get::<LocalAuthority>().unwrap().0,
            &local.0
        ));
        assert_eq!(http.body(), "body");

        let anonymous = crate::server::Request::new(http::Request::new(()), local.clone(), None);
        let mut message = http::Response::new(());
        message.extensions_mut().insert(local.clone());
        message.extensions_mut().insert(remote);
        let response = anonymous.response(message);
        assert!(response.matches_authorities(&local, None));
        assert!(
            response
                .response()
                .extensions()
                .get::<RemoteAuthority>()
                .is_none()
        );
        let http = response.into_http();
        assert!(http.extensions().get::<LocalAuthority>().is_some());
        assert!(http.extensions().get::<RemoteAuthority>().is_none());
    }
}
