use rustls::pki_types::CertificateDer;
use snafu::Snafu;

#[derive(Debug)]
pub struct DangerousServerCertVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousServerCertVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidIdentity {
    #[snafu(transparent)]
    Tls { source: rustls::Error },
    #[snafu(display("certificate for identity cannot be parsed"))]
    InvalidCertificated {
        source: x509_parser::nom::Err<x509_parser::error::X509Error>,
    },
    #[snafu(display("SAN extensions in certificate is invalid"))]
    InvalidSAN {
        source: x509_parser::error::X509Error,
    },
    #[snafu(display("certificate for identity is missing SAN extensions"))]
    MissingSAN,
    #[snafu(display("identify name not found in certificate SAN"))]
    NameNotFound,
}

pub fn verify_certficate_for_name(
    certificate: &CertificateDer<'static>,
    client_name: &str,
) -> Result<(), InvalidIdentity> {
    use x509_parser::prelude::*;

    let cert = match x509_parser::parse_x509_certificate(certificate) {
        Ok((_remain, cert)) => cert,
        Err(source) => return Err(InvalidIdentity::InvalidCertificated { source }),
    };
    let san = match cert.subject_alternative_name() {
        Ok(Some(san)) => san,
        Ok(None) => return Err(InvalidIdentity::MissingSAN),
        Err(source) => return Err(InvalidIdentity::InvalidSAN { source }),
    };

    if san.value.general_names.iter().any(|name| match name {
        GeneralName::DNSName(name) => *name == client_name,
        _ => false,
    }) {
        return Ok(());
    }

    Err(InvalidIdentity::NameNotFound)
}
