use std::{fmt, sync::Arc};

use bytes::Bytes;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::CertifiedKey,
};

pub use crate::runtime::identity::{LocalAuthority, RemoteAuthority};
use crate::{Chunk, Error, Fixed, client::Request, runtime::identity};

/// A local name and immutable certificate/key/OCSP material for this process.
/// 移动到 dquic，在这里实现 http trait
pub struct Endpoint {
    name: String,
    certificate: Arc<CertifiedKey>,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    pub fn new(
        name: &str,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        ocsp: Option<Bytes>,
    ) -> Result<Arc<Self>, Error> {
        let name = identity::normalize_name(name)?;
        identity::check_name(&name, &certs)?;
        let mut certificate =
            CertifiedKey::from_der(certs, key, &rustls::crypto::ring::default_provider())
                .map_err(identity::invalid)?;
        // from_der permits unknown key consistency; endpoints require a match.
        certificate.keys_match().map_err(identity::invalid)?;
        certificate.ocsp = ocsp.map(|bytes| bytes.to_vec());
        identity::check_current(&certificate)?;
        Ok(Arc::new(Self {
            name,
            certificate: Arc::new(certificate),
        }))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn certificate(&self) -> Arc<CertifiedKey> {
        self.certificate.clone()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl rustls::client::ResolvesClientCert for Endpoint {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.certificate.key.choose_scheme(sigschemes)?;
        Some(self.certificate())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl Endpoint {
    /// Registers a service receiving server::Request with connection identity.
    pub async fn listen<S, B>(self: &Arc<Self>, service: S) -> Result<(), Error>
    where
        S: tower_service::Service<crate::server::Request, Response = crate::server::Response<B>>
            + Send
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<crate::BoxError>,
        B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<crate::BoxError>,
    {
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::runtime::Runtime::listen(self, service)
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = service;
            Err(Error::Unsupported {
                operation: "pooled endpoint listening",
            })
        }
    }
}

macro_rules! methods {
    ($($name:ident: $method:ident),* $(,)?) => { impl Endpoint { $(
        pub fn $name(self: &Arc<Self>, url: &str) -> Result<Request<Fixed>, Error> {
            Request::new(http::Method::$method, url, Fixed::default())
                .map(|request| request.with_identity(self.clone()))
        }
    )* } };
}
methods! { get: GET, head: HEAD, post: POST, put: PUT, patch: PATCH, delete: DELETE,
options: OPTIONS, trace: TRACE, connect: CONNECT }

impl Endpoint {
    pub fn streaming_post(self: &Arc<Self>, url: &str) -> Result<Request<Chunk>, Error> {
        Request::new(http::Method::POST, url, Chunk)
            .map(|request| request.with_identity(self.clone()))
    }

    pub fn streaming_put(self: &Arc<Self>, url: &str) -> Result<Request<Chunk>, Error> {
        Request::new(http::Method::PUT, url, Chunk)
            .map(|request| request.with_identity(self.clone()))
    }
}
