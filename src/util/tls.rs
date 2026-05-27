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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::ServerCertVerifier,
        internal::msgs::codec::{Codec, Reader},
        pki_types::{CertificateDer, ServerName, UnixTime},
    };

    use super::*;

    fn digitally_signed_struct_for_test(scheme: SignatureScheme) -> DigitallySignedStruct {
        // rustls exposes `DigitallySignedStruct` publicly because verifier
        // traits take it by reference, but its constructor is crate-private.
        // Decode the same wire representation that rustls uses internally so
        // these verifier tests can exercise the signature callbacks without
        // depending on unsafe construction.
        let mut signature = Vec::new();
        scheme.encode(&mut signature);
        0u16.encode(&mut signature);
        DigitallySignedStruct::read(&mut Reader::init(&signature))
            .expect("digitally signed struct decodes")
    }

    #[test]
    fn dangerous_verifier_accepts_server_cert_without_validation() {
        let verifier = DangerousServerCertVerifier;
        assert_eq!(format!("{verifier:?}"), "DangerousServerCertVerifier");
        let end_entity = CertificateDer::from(Vec::new());
        let server_name = ServerName::try_from("example.com").expect("server name");

        verifier
            .verify_server_cert(
                &end_entity,
                &[],
                &server_name,
                &[],
                UnixTime::since_unix_epoch(Duration::ZERO),
            )
            .expect("dangerous verifier should accept any certificate");
    }

    #[test]
    fn dangerous_verifier_advertises_all_supported_signature_schemes() {
        let schemes = DangerousServerCertVerifier.supported_verify_schemes();

        assert_eq!(
            schemes,
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        );
    }

    #[test]
    fn dangerous_verifier_accepts_tls_signatures_without_validation() {
        let verifier = DangerousServerCertVerifier;
        let end_entity = CertificateDer::from(Vec::new());
        let signature = digitally_signed_struct_for_test(SignatureScheme::RSA_PSS_SHA256);

        verifier
            .verify_tls12_signature(&[], &end_entity, &signature)
            .expect("dangerous verifier should accept any TLS 1.2 signature");
        verifier
            .verify_tls13_signature(&[], &end_entity, &signature)
            .expect("dangerous verifier should accept any TLS 1.3 signature");
    }
}
