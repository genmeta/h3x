use std::{fmt, sync::Arc};

use rustls::{
    pki_types::{CertificateDer, ServerName},
    sign::CertifiedKey,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{Endpoint, Error};

#[path = "ocsp.rs"]
mod ocsp;

pub(crate) fn check_current(certificate: &CertifiedKey) -> Result<(), Error> {
    for der in &certificate.cert {
        let (rest, cert) = X509Certificate::from_der(der).map_err(invalid)?;
        if !rest.is_empty() || !cert.validity().is_valid() {
            return Err(invalid("malformed or expired certificate"));
        }
    }
    if let Some(staple) = &certificate.ocsp {
        ocsp::check(&certificate.cert, staple)?;
    }
    Ok(())
}

/// Read-only authentication facts supplied by a trusted transport adapter.
#[derive(Clone)]
pub struct RemoteAuthority {
    name: Arc<str>,
    cert: Arc<[CertificateDer<'static>]>,
}

impl fmt::Debug for RemoteAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteAuthority")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl RemoteAuthority {
    /// For transport adapters after authenticated TLS completion. This validates
    /// name/material consistency; the adapter must establish trust in the chain.
    pub fn from_authenticated(
        name: &str,
        cert: Vec<CertificateDer<'static>>,
    ) -> Result<Self, Error> {
        let name = normalize_name(name)?;
        check_name(&name, &cert)?;
        Ok(Self {
            name: name.into(),
            cert: cert.into(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert
    }

    pub fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, dhttp_identity::identity::VerifyError> {
        dhttp_identity::identity::verify_signature(
            dhttp_identity::identity::extract_public_key(&self.cert),
            data,
            signature,
        )
    }
}

#[derive(Debug, Clone)]
pub enum RequestAuthority {
    Local(Arc<Endpoint>),
    Peer(RemoteAuthority),
}

pub(crate) fn invalid(message: impl fmt::Display) -> Error {
    Error::InvalidEndpoint {
        source: Arc::new(std::io::Error::other(message.to_string())),
    }
}

pub(crate) fn normalize_name(name: &str) -> Result<String, Error> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let name =
        dhttp_identity::name::Name::try_from(name).map_err(|source| Error::InvalidEndpoint {
            source: Arc::new(source),
        })?;
    if name.is_wildcard() {
        return Err(invalid("an endpoint requires a concrete name"));
    }
    Ok(name.as_str().to_owned())
}

pub(crate) fn check_name(name: &str, certs: &[CertificateDer<'_>]) -> Result<(), Error> {
    let leaf = certs
        .first()
        .ok_or_else(|| invalid("empty certificate chain"))?;
    let parsed = rustls::server::ParsedCertificate::try_from(leaf).map_err(|source| {
        Error::InvalidEndpoint {
            source: Arc::new(source),
        }
    })?;
    let server_name = ServerName::try_from(name).map_err(|source| Error::InvalidEndpoint {
        source: Arc::new(source),
    })?;
    rustls::client::verify_server_name(&parsed, &server_name).map_err(|source| {
        Error::InvalidEndpoint {
            source: Arc::new(source),
        }
    })?;
    if name == "dhttp.net" || name.ends_with(".dhttp.net") {
        dhttp_identity::identity::extract_dhttp_subject_key_identifier(certs).map_err(
            |source| Error::InvalidEndpoint {
                source: Arc::new(source),
            },
        )?;
    }
    Ok(())
}
