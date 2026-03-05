use std::str::FromStr;

use rustls::{
    SignatureScheme,
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer},
};

/// Serializable wrapper for [`http::uri::Authority`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerdeAuthority(String);

impl From<&http::uri::Authority> for SerdeAuthority {
    fn from(authority: &http::uri::Authority) -> Self {
        Self(authority.as_str().to_owned())
    }
}

impl TryFrom<SerdeAuthority> for http::uri::Authority {
    type Error = http::uri::InvalidUri;

    fn try_from(value: SerdeAuthority) -> Result<Self, Self::Error> {
        http::uri::Authority::from_str(&value.0)
    }
}

/// Serializable wrapper for [`CertificateDer`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerdeCertificateDer(Vec<u8>);

impl From<CertificateDer<'static>> for SerdeCertificateDer {
    fn from(cert: CertificateDer<'static>) -> Self {
        Self(cert.as_ref().to_vec())
    }
}

impl From<SerdeCertificateDer> for CertificateDer<'static> {
    fn from(value: SerdeCertificateDer) -> Self {
        CertificateDer::from(value.0)
    }
}

/// Serializable wrapper for [`SignatureScheme`] (`#[repr(u16)]`).
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct SerdeSignatureScheme(u16);

impl From<SignatureScheme> for SerdeSignatureScheme {
    fn from(scheme: SignatureScheme) -> Self {
        Self(u16::from(scheme))
    }
}

impl From<SerdeSignatureScheme> for SignatureScheme {
    fn from(value: SerdeSignatureScheme) -> Self {
        SignatureScheme::from(value.0)
    }
}

/// Serializable wrapper for [`rustls::SignatureAlgorithm`] (`#[repr(u8)]`, `#[non_exhaustive]`).
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct SerdeSignatureAlgorithm(u8);

impl From<rustls::SignatureAlgorithm> for SerdeSignatureAlgorithm {
    fn from(alg: rustls::SignatureAlgorithm) -> Self {
        Self(u8::from(alg))
    }
}

impl From<SerdeSignatureAlgorithm> for rustls::SignatureAlgorithm {
    fn from(value: SerdeSignatureAlgorithm) -> Self {
        rustls::SignatureAlgorithm::from(value.0)
    }
}

/// Serializable wrapper for [`SubjectPublicKeyInfoDer`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerdeSubjectPublicKeyInfoDer(Vec<u8>);

impl From<SubjectPublicKeyInfoDer<'_>> for SerdeSubjectPublicKeyInfoDer {
    fn from(spki: SubjectPublicKeyInfoDer<'_>) -> Self {
        Self(spki.as_ref().to_vec())
    }
}

impl From<SerdeSubjectPublicKeyInfoDer> for SubjectPublicKeyInfoDer<'static> {
    fn from(value: SerdeSubjectPublicKeyInfoDer) -> Self {
        SubjectPublicKeyInfoDer::from(value.0)
    }
}
