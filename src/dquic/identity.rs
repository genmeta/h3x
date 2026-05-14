//! Identity used by a [`QuicEndpoint`](super::QuicEndpoint) when performing
//! TLS handshakes.
//!
//! An [`Identity`] bundles the SNI (server name) with the certificate chain
//! and private key. When stored in an endpoint as `Option<Arc<Identity>>`,
//! cloning is cheap — the identity is shared through an `Arc`.
//!
//! The endpoint's identity selects between client-auth / server-auth paths
//! and keys the SNI registry for inbound connection multiplexing.

use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    ops::Deref,
    sync::Arc,
};

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Case-insensitive server name for SNI registry keys.
///
/// Always stored as ASCII lowercase so that [`DashMap`](dashmap::DashMap)
/// keyed by [`ServerName`] supports O(1) lookup via `get::<str>(&sni)`.
#[derive(Clone, Debug)]
pub struct ServerName(Bytes);

impl ServerName {
    /// Construct a new [`ServerName`], normalising to ASCII lowercase.
    pub fn new(name: &str) -> Self {
        Self(Bytes::copy_from_slice(name.to_ascii_lowercase().as_bytes()))
    }

    /// Return the name as a `&str`.
    pub fn as_str(&self) -> &str {
        // SAFETY: constructed from valid ASCII via to_ascii_lowercase
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

impl Borrow<str> for ServerName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Deref for ServerName {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

/// Hash delegates to `str::hash` so that [`DashMap`](dashmap::DashMap) lookups
/// via `get::<str>(&sni)` land in the same bucket as stored [`ServerName`] keys.
impl Hash for ServerName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        <str as Hash>::hash(Borrow::<str>::borrow(self), state)
    }
}

impl PartialEq for ServerName {
    fn eq(&self, other: &Self) -> bool {
        Borrow::<str>::borrow(self) == Borrow::<str>::borrow(other)
    }
}

impl Eq for ServerName {}

impl std::fmt::Display for ServerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A TLS identity backed by a certificate chain and its matching private key.
///
/// Endpoints store this as `Option<Arc<Identity>>`: `Some` for named
/// endpoints that can serve and authenticate, `None` for anonymous
/// client-only endpoints.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Server name advertised in TLS SNI (also used by h3x as the SNI registry key).
    pub name: ServerName,
    /// End-entity certificate followed by any intermediates.
    pub certs: Arc<Vec<CertificateDer<'static>>>,
    /// Private key matching the end-entity certificate.
    pub key: Arc<PrivateKeyDer<'static>>,
    /// OCSP response (optional).
    pub ocsp: Arc<Option<Vec<u8>>>,
}

impl Identity {
    /// Build a [`CertifiedKey`] from this identity for use in rustls.
    ///
    /// The returned key is wrapped in [`Arc`] so it can be shared across
    /// many TLS sessions.
    pub(crate) fn build_certified_key(
        &self,
    ) -> Result<Arc<rustls::sign::CertifiedKey>, crate::dquic::network::BindServerError> {
        use snafu::ResultExt;

        use crate::dquic::network::bind_server_error::LoadKeySnafu;

        let provider = rustls::ServerConfig::builder().crypto_provider().clone();
        let key = provider
            .key_provider
            .load_private_key(self.key.clone_key())
            .context(LoadKeySnafu)?;
        Ok(Arc::new(rustls::sign::CertifiedKey {
            cert: self.certs.iter().cloned().collect(),
            key,
            ocsp: self.ocsp.as_ref().clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certs_arc_sharing() {
        let certs = vec![];
        let id1 = Identity {
            name: ServerName::new("test"),
            certs: Arc::new(certs),
            key: Arc::new(PrivateKeyDer::Pkcs8(b"dummy".to_vec().into())),
            ocsp: Arc::new(None),
        };
        let id2 = id1.clone();
        assert!(
            Arc::ptr_eq(&id1.certs, &id2.certs),
            "certs should be shared via Arc"
        );
    }

    #[test]
    fn test_ocsp_default_none() {
        let id = Identity {
            name: ServerName::new("test"),
            certs: Arc::new(vec![]),
            key: Arc::new(PrivateKeyDer::Pkcs8(b"dummy".to_vec().into())),
            ocsp: Arc::new(None),
        };
        assert!(id.ocsp.is_none(), "ocsp should be None by default");
    }

    #[test]
    fn test_ocsp_update_independent() {
        let id1 = Identity {
            name: ServerName::new("test"),
            certs: Arc::new(vec![]),
            key: Arc::new(PrivateKeyDer::Pkcs8(b"dummy".to_vec().into())),
            ocsp: Arc::new(None),
        };
        let mut id2 = id1.clone();
        // Simulate updating id2's ocsp by creating a new Arc
        id2.ocsp = Arc::new(Some(vec![1, 2, 3]));
        assert!(id1.ocsp.is_none(), "id1.ocsp should remain None");
        assert!(id2.ocsp.is_some(), "id2.ocsp should be Some");
    }

    #[test]
    fn test_server_name_lowercase_normalization() {
        let name = ServerName::new("LOCALHOST");
        assert_eq!(name.as_str(), "localhost");
    }

    #[test]
    fn test_server_name_display() {
        let name = ServerName::new("MyHost");
        assert_eq!(format!("{}", name), "myhost");
    }

    #[test]
    fn test_server_name_deref() {
        let name = ServerName::new("AbCdEfG");
        let s: &str = &name;
        assert_eq!(s, "abcdefg", "ServerName should deref to lowercased str");
    }

    #[test]
    fn test_server_name_borrow() {
        use std::borrow::Borrow;
        let name = ServerName::new("BorrowTest");
        let s: &str = Borrow::<str>::borrow(&name);
        assert_eq!(
            s, "borrowtest",
            "Borrow<str> should return the lowercased name"
        );
    }

    #[test]
    fn test_server_name_eq() {
        let a = ServerName::new("EXAMPLE");
        let b = ServerName::new("example");
        assert_eq!(a, b, "same name in different case should be equal");

        let c = ServerName::new("other");
        assert_ne!(a, c, "different names should not be equal");
    }

    #[test]
    fn test_server_name_hash_consistency() {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };

        let hash = |n: &ServerName| {
            let mut h = DefaultHasher::new();
            n.hash(&mut h);
            h.finish()
        };

        let a = ServerName::new("MiXeDcAsE");
        let b = ServerName::new("mixedcase");
        assert_eq!(
            hash(&a),
            hash(&b),
            "same logical name should hash to same value regardless of input case"
        );
    }

    #[test]
    fn test_identity_clone_preserves_fields() {
        let key = PrivateKeyDer::Pkcs8(b"dummy".to_vec().into());
        let id1 = Identity {
            name: ServerName::new("clone-test"),
            certs: Arc::new(vec![]),
            key: Arc::new(key),
            ocsp: Arc::new(None),
        };
        let id2 = id1.clone();

        assert_eq!(id1.name, id2.name, "cloned name should equal original");
        assert!(
            Arc::ptr_eq(&id1.certs, &id2.certs),
            "certs should be Arc-shared after clone"
        );
        assert!(
            Arc::ptr_eq(&id1.key, &id2.key),
            "key should be Arc-shared after clone"
        );
    }

    #[test]
    fn test_identity_build_certified_key_with_valid_key() {
        use dquic::prelude::handy::{ToCertificate, ToPrivateKey};

        const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
        const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

        let certs = SERVER_CERT.to_certificate();
        let key = SERVER_KEY.to_private_key();

        let identity = Identity {
            name: ServerName::new("localhost"),
            certs: Arc::new(certs),
            key: Arc::new(key),
            ocsp: Arc::new(None),
        };

        let result = identity.build_certified_key();
        assert!(
            result.is_ok(),
            "build_certified_key should succeed with valid key material"
        );
    }
}
