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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_round_trips_through_serde_wrapper() {
        let authority = http::uri::Authority::from_static("example.test:443");

        let wrapped = SerdeAuthority::from(&authority);
        let decoded = http::uri::Authority::try_from(wrapped).expect("valid authority");

        assert_eq!(decoded, authority);
    }

    #[test]
    fn invalid_authority_is_rejected_after_unwrap() {
        let wrapped = SerdeAuthority("not a valid authority".to_owned());

        assert!(http::uri::Authority::try_from(wrapped).is_err());
    }

    #[test]
    fn certificate_der_round_trips_through_serde_wrapper() {
        let certificate = CertificateDer::from(vec![1, 2, 3, 4]);

        let wrapped = SerdeCertificateDer::from(certificate);
        let decoded = CertificateDer::from(wrapped);

        assert_eq!(decoded.as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn signature_scheme_round_trips_through_serde_wrapper() {
        let scheme = SignatureScheme::ECDSA_NISTP256_SHA256;

        let wrapped = SerdeSignatureScheme::from(scheme);
        let decoded = SignatureScheme::from(wrapped);

        assert_eq!(decoded, scheme);
    }

    #[test]
    fn signature_algorithm_round_trips_through_serde_wrapper() {
        let algorithm = rustls::SignatureAlgorithm::ECDSA;

        let wrapped = SerdeSignatureAlgorithm::from(algorithm);
        let decoded = rustls::SignatureAlgorithm::from(wrapped);

        assert_eq!(decoded, algorithm);
    }

    #[test]
    fn subject_public_key_info_round_trips_through_serde_wrapper() {
        let public_key = SubjectPublicKeyInfoDer::from(vec![5, 6, 7, 8]);

        let wrapped = SerdeSubjectPublicKeyInfoDer::from(public_key);
        let decoded = SubjectPublicKeyInfoDer::from(wrapped);

        assert_eq!(decoded.as_ref(), &[5, 6, 7, 8]);
    }
}
