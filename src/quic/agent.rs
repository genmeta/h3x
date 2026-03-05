use std::fmt::Debug;

use futures::future::BoxFuture;
use rustls::{
    SignatureScheme,
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer},
};
use snafu::Snafu;
use x509_parser::prelude::FromDer;

use crate::quic;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SignError {
    #[snafu(display("unsupported signature scheme {scheme:?}"))]
    UnsupportedScheme { scheme: SignatureScheme },
    #[snafu(transparent)]
    Crypto { source: rustls::Error },
    #[snafu(transparent)]
    Connection { source: quic::ConnectionError },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum VerifyError {
    #[snafu(display("unsupported signature scheme {scheme:?}"))]
    UnsupportedScheme { scheme: SignatureScheme },
    #[snafu(transparent)]
    Connection { source: quic::ConnectionError },
}

pub trait LocalAgent: Send + Sync + Debug {
    fn name(&self) -> &str;

    fn cert_chain(&self) -> &[CertificateDer<'static>];

    fn sign_algorithm(&self) -> rustls::SignatureAlgorithm;

    fn sign(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
    ) -> BoxFuture<'_, Result<Vec<u8>, SignError>>;

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        extract_public_key(self.cert_chain())
    }

    fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = verify_signature(self.public_key(), scheme, data, signature);
        Box::pin(std::future::ready(result))
    }
}

pub trait RemoteAgent: Send + Sync + Debug {
    fn name(&self) -> &str;
    fn cert_chain(&self) -> &[CertificateDer<'static>];

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        extract_public_key(self.cert_chain())
    }

    fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = verify_signature(self.public_key(), scheme, data, signature);
        Box::pin(std::future::ready(result))
    }
}

pub fn extract_public_key<'d>(cert_chain: &'d [CertificateDer<'d>]) -> SubjectPublicKeyInfoDer<'d> {
    use x509_parser::prelude::*;

    match x509_parser::certificate::X509Certificate::from_der(&cert_chain[0]) {
        Ok((_remain, certificate)) => {
            let spki = certificate.public_key().raw;
            spki.to_owned().into()
        }
        Err(_error) if cert_chain.len() == 1 => cert_chain[0].as_ref().into(),
        Err(_error) => unreachable!("rustls returned an invalid peer_certificates."),
    }
}

pub fn sign_with_key(
    key: &(impl rustls::sign::SigningKey + ?Sized),
    scheme: SignatureScheme,
    data: &[u8],
) -> Result<Vec<u8>, SignError> {
    // FIXME: same as load spki then sign with ring?
    let signer = key
        .choose_scheme(&[scheme])
        .ok_or(SignError::UnsupportedScheme { scheme })?;
    Ok(signer.sign(data)?)
}

pub fn verify_signature(
    spki: SubjectPublicKeyInfoDer,
    scheme: SignatureScheme,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let algorithm: &'static dyn ring::signature::VerificationAlgorithm = match scheme {
        SignatureScheme::ECDSA_NISTP384_SHA384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
        SignatureScheme::ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        SignatureScheme::ED25519 => &ring::signature::ED25519,
        SignatureScheme::RSA_PKCS1_SHA256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
        SignatureScheme::RSA_PSS_SHA256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
        SignatureScheme::RSA_PSS_SHA384 => &ring::signature::RSA_PSS_2048_8192_SHA384,
        SignatureScheme::RSA_PSS_SHA512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
        _ => return Err(VerifyError::UnsupportedScheme { scheme }),
    };

    let public_key = match x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki) {
        Ok((_remain, spki)) => spki.subject_public_key,
        Err(_error) => unreachable!("rustls returned an invalid peer_certificates."),
    };

    Ok(
        ring::signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(data, signature)
            .is_ok(),
    )
}
