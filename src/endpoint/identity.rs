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

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Name used to advertise a server in TLS SNI.
pub type ServerName = Arc<str>;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certs_arc_sharing() {
        let certs = vec![];
        let id1 = Identity {
            name: Arc::from("test"),
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
            name: Arc::from("test"),
            certs: Arc::new(vec![]),
            key: Arc::new(PrivateKeyDer::Pkcs8(b"dummy".to_vec().into())),
            ocsp: Arc::new(None),
        };
        assert!(id.ocsp.is_none(), "ocsp should be None by default");
    }

    #[test]
    fn test_ocsp_update_independent() {
        let id1 = Identity {
            name: Arc::from("test"),
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
}
