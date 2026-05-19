//! Identity used by a [`QuicEndpoint`](super::QuicEndpoint) when performing
//! TLS handshakes.
//!
//! An [`Identity`] bundles the SNI (server name) with the certificate chain
//! and private key. When stored in an endpoint as `Option<Arc<Identity>>`,
//! cloning is cheap — the identity is shared through an `Arc`.
//!
//! The endpoint's identity selects between client-auth / server-auth paths
//! and keys the SNI registry for inbound connection multiplexing.

use std::sync::Arc;

pub use dhttp_identity::{identity::Identity, name::Name};

/// Build a [`CertifiedKey`](rustls::sign::CertifiedKey) from an [`Identity`]
/// for use in rustls.
///
/// The returned key is wrapped in [`Arc`] so it can be shared across
/// many TLS sessions.
pub(crate) fn build_certified_key(
    identity: &Identity,
) -> Result<Arc<rustls::sign::CertifiedKey>, crate::dquic::network::BindServerError> {
    use snafu::ResultExt;

    use crate::dquic::network::bind_server_error::LoadKeySnafu;

    let provider = rustls::ServerConfig::builder().crypto_provider().clone();
    let key = provider
        .key_provider
        .load_private_key(identity.key.clone_key())
        .context(LoadKeySnafu)?;
    Ok(Arc::new(rustls::sign::CertifiedKey {
        cert: identity.certs.iter().cloned().collect(),
        key,
        ocsp: identity.ocsp.as_ref().clone(),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::pki_types::PrivateKeyDer;

    use super::*;

    #[test]
    fn test_certs_arc_sharing() {
        let certs = vec![];
        let id1 = Identity {
            name: "test".parse().unwrap(),
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
            name: "test".parse().unwrap(),
            certs: Arc::new(vec![]),
            key: Arc::new(PrivateKeyDer::Pkcs8(b"dummy".to_vec().into())),
            ocsp: Arc::new(None),
        };
        assert!(id.ocsp.is_none(), "ocsp should be None by default");
    }

    #[test]
    fn test_ocsp_update_independent() {
        let id1 = Identity {
            name: "test".parse().unwrap(),
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
    fn test_name_lowercase_normalization() {
        let name: Name = "LOCALHOST".parse().unwrap();
        assert_eq!(name.as_str(), "localhost");
    }

    #[test]
    fn test_name_display() {
        let name: Name = "MyHost".parse().unwrap();
        assert_eq!(format!("{name}"), "myhost");
    }

    #[test]
    fn test_name_deref() {
        let name: Name = "AbCdEfG".parse().unwrap();
        let s: &str = &name;
        assert_eq!(s, "abcdefg", "Name should deref to lowercased str");
    }

    #[test]
    fn test_name_borrow() {
        use std::borrow::Borrow;
        let name: Name = "BorrowTest".parse().unwrap();
        let s: &str = Borrow::<str>::borrow(&name);
        assert_eq!(
            s, "borrowtest",
            "Borrow<str> should return the lowercased name"
        );
    }

    #[test]
    fn test_name_eq() {
        let a: Name = "EXAMPLE".parse().unwrap();
        let b: Name = "example".parse().unwrap();
        assert_eq!(a, b, "same name in different case should be equal");

        let c: Name = "other".parse().unwrap();
        assert_ne!(a, c, "different names should not be equal");
    }

    #[test]
    fn test_name_hash_consistency() {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };

        let hash = |n: &Name| {
            let mut h = DefaultHasher::new();
            n.hash(&mut h);
            h.finish()
        };

        let a: Name = "MiXeDcAsE".parse().unwrap();
        let b: Name = "mixedcase".parse().unwrap();
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
            name: "clone-test".parse().unwrap(),
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
    fn test_build_certified_key_with_valid_key() {
        use dquic::prelude::handy::{ToCertificate, ToPrivateKey};

        const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
        const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

        let certs = SERVER_CERT.to_certificate();
        let key = SERVER_KEY.to_private_key();

        let identity = Identity {
            name: "localhost".parse().unwrap(),
            certs: Arc::new(certs),
            key: Arc::new(key),
            ocsp: Arc::new(None),
        };

        let result = build_certified_key(&identity);
        assert!(
            result.is_ok(),
            "build_certified_key should succeed with valid key material"
        );
    }
}
