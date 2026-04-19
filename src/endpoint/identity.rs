//! Identity used by a [`QuicEndpoint`](super::QuicEndpoint) when performing
//! TLS handshakes.
//!
//! A [`NamedIdentity`] bundles the SNI (server name) with the certificate
//! chain and private key. When stored in an endpoint, cloning is cheap — the
//! identity is shared through an `Arc`.
//!
//! The endpoint's identity selects between client-auth / server-auth paths
//! and keys the SNI registry for inbound connection multiplexing.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Name used to advertise a server in TLS SNI.
pub type ServerName = Arc<str>;

/// A named identity backed by a TLS certificate chain and its matching private key.
#[derive(Debug, Clone)]
pub struct NamedIdentity {
    /// Server name advertised in TLS SNI (also used by h3x as the SNI registry key).
    pub name: ServerName,
    /// End-entity certificate followed by any intermediates.
    pub certs: Vec<CertificateDer<'static>>,
    /// Private key matching the end-entity certificate.
    pub key: Arc<PrivateKeyDer<'static>>,
}

/// The identity that an endpoint presents.
///
/// Cloning is cheap: `Named` variants share the underlying [`NamedIdentity`]
/// through an `Arc`, and `Anonymous` is trivial.
#[derive(Debug, Clone, Default)]
pub enum Identity {
    /// No TLS identity is presented. Client-only endpoints may use this when
    /// the peer does not require client authentication; server endpoints with
    /// an `Anonymous` identity will refuse `accept()` operations.
    #[default]
    Anonymous,
    /// A named identity carrying a certificate chain and private key.
    Named(Arc<NamedIdentity>),
}

impl Identity {
    /// Returns the server name for this identity, if any.
    #[must_use]
    pub fn name(&self) -> Option<&ServerName> {
        match self {
            Self::Anonymous => None,
            Self::Named(id) => Some(&id.name),
        }
    }

    /// Returns `true` if this identity has a server name attached.
    #[must_use]
    pub fn is_named(&self) -> bool {
        matches!(self, Self::Named(_))
    }
}

impl From<NamedIdentity> for Identity {
    fn from(id: NamedIdentity) -> Self {
        Self::Named(Arc::new(id))
    }
}

impl From<Arc<NamedIdentity>> for Identity {
    fn from(id: Arc<NamedIdentity>) -> Self {
        Self::Named(id)
    }
}
