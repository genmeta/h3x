use dhttp_identity::identity::{self as authority, SignError, VerifyError};
use futures::future::BoxFuture;
use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer};

use super::serde_types::{SerdeCertificateDer, SerdeSubjectPublicKeyInfoDer};
use crate::quic;

/// Remote trait for [`authority::LocalAuthority`], exposing authority methods over remoc RTC.
#[remoc::rtc::remote]
pub trait LocalAuthority: Send + Sync {
    async fn name(&self) -> Result<String, quic::ConnectionError>;
    async fn cert_chain(&self) -> Result<Vec<SerdeCertificateDer>, quic::ConnectionError>;
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>, quic::ConnectionError>;
    async fn public_key(&self) -> Result<SerdeSubjectPublicKeyInfoDer, quic::ConnectionError>;
    async fn verify(
        &self,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, quic::ConnectionError>;
}

/// Remote trait for [`authority::RemoteAuthority`], exposing authority methods over remoc RTC.
#[remoc::rtc::remote]
pub trait RemoteAuthority: Send + Sync {
    async fn name(&self) -> Result<String, quic::ConnectionError>;
    async fn cert_chain(&self) -> Result<Vec<SerdeCertificateDer>, quic::ConnectionError>;
    async fn public_key(&self) -> Result<SerdeSubjectPublicKeyInfoDer, quic::ConnectionError>;
    async fn verify(
        &self,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, quic::ConnectionError>;
}

pub struct CachedLocalAuthority {
    client: LocalAuthorityClient,
    name: String,
    cert_chain: Vec<CertificateDer<'static>>,
}

impl std::fmt::Debug for CachedLocalAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedRemoteLocalAuthority")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl CachedLocalAuthority {
    /// Create a new cached wrapper by eagerly fetching synchronous fields from
    /// the remote authority.
    pub async fn from_client(client: LocalAuthorityClient) -> Result<Self, quic::ConnectionError> {
        let name = client.name().await?;
        let cert_chain: Vec<CertificateDer<'static>> = client
            .cert_chain()
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(Self {
            client,
            name,
            cert_chain,
        })
    }
}

impl authority::LocalAuthority for CachedLocalAuthority {
    fn name(&self) -> &str {
        &self.name
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }

    fn sign(&self, data: &[u8]) -> BoxFuture<'_, Result<Vec<u8>, SignError>> {
        let owned_data = data.to_vec();
        let client = self.client.clone();
        Box::pin(async move {
            client
                .sign(owned_data)
                .await
                // lossy: rustls API requires String for General error variant
                .map_err(|e| SignError::Crypto {
                    source: rustls::Error::General(e.to_string()),
                })
        })
    }

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        authority::extract_public_key(authority::LocalAuthority::cert_chain(self))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = authority::verify_signature(
            authority::LocalAuthority::public_key(self),
            data,
            signature,
        );
        Box::pin(std::future::ready(result))
    }
}

pub struct CachedRemoteAuthority {
    #[allow(dead_code)]
    client: RemoteAuthorityClient,
    name: String,
    cert_chain: Vec<CertificateDer<'static>>,
}

impl std::fmt::Debug for CachedRemoteAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedRemoteRemoteAuthority")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl CachedRemoteAuthority {
    /// Create a new cached wrapper by eagerly fetching synchronous fields from
    /// the remote authority.
    pub async fn from_client(client: RemoteAuthorityClient) -> Result<Self, quic::ConnectionError> {
        let name = client.name().await?;
        let cert_chain: Vec<CertificateDer<'static>> = client
            .cert_chain()
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(Self {
            client,
            name,
            cert_chain,
        })
    }
}

impl authority::RemoteAuthority for CachedRemoteAuthority {
    fn name(&self) -> &str {
        &self.name
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        authority::extract_public_key(authority::RemoteAuthority::cert_chain(self))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = authority::verify_signature(
            authority::RemoteAuthority::public_key(self),
            data,
            signature,
        );
        Box::pin(std::future::ready(result))
    }
}

impl<A> LocalAuthority for A
where
    A: authority::LocalAuthority + Send + Sync,
{
    async fn name(&self) -> Result<String, quic::ConnectionError> {
        Ok(authority::LocalAuthority::name(self).to_owned())
    }

    async fn cert_chain(&self) -> Result<Vec<SerdeCertificateDer>, quic::ConnectionError> {
        Ok(self
            .cert_chain()
            .iter()
            .cloned()
            .map(SerdeCertificateDer::from)
            .collect())
    }

    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>, quic::ConnectionError> {
        authority::LocalAuthority::sign(self, &data)
            .await
            // lossy: TransportError.reason is a protocol string field
            .map_err(|e| quic::ConnectionError::Transport {
                source: quic::TransportError {
                    kind: crate::varint::VarInt::from_u32(0x01),
                    frame_type: crate::varint::VarInt::from_u32(0x00),
                    reason: format!("sign error: {e}").into(),
                },
            })
    }

    async fn public_key(&self) -> Result<SerdeSubjectPublicKeyInfoDer, quic::ConnectionError> {
        Ok(SerdeSubjectPublicKeyInfoDer::from(
            authority::LocalAuthority::public_key(self),
        ))
    }

    async fn verify(
        &self,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, quic::ConnectionError> {
        authority::LocalAuthority::verify(self, &data, &signature)
            .await
            // lossy: TransportError.reason is a protocol string field
            .map_err(|e| quic::ConnectionError::Transport {
                source: quic::TransportError {
                    kind: crate::varint::VarInt::from_u32(0x01),
                    frame_type: crate::varint::VarInt::from_u32(0x00),
                    reason: format!("verify error: {e}").into(),
                },
            })
    }
}

impl<A> RemoteAuthority for A
where
    A: authority::RemoteAuthority + Send + Sync,
{
    async fn name(&self) -> Result<String, quic::ConnectionError> {
        Ok(authority::RemoteAuthority::name(self).to_owned())
    }

    async fn cert_chain(&self) -> Result<Vec<SerdeCertificateDer>, quic::ConnectionError> {
        Ok(self
            .cert_chain()
            .iter()
            .cloned()
            .map(SerdeCertificateDer::from)
            .collect())
    }

    async fn public_key(&self) -> Result<SerdeSubjectPublicKeyInfoDer, quic::ConnectionError> {
        Ok(SerdeSubjectPublicKeyInfoDer::from(
            authority::RemoteAuthority::public_key(self),
        ))
    }

    async fn verify(
        &self,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, quic::ConnectionError> {
        authority::RemoteAuthority::verify(self, &data, &signature)
            .await
            // lossy: TransportError.reason is a protocol string field
            .map_err(|e| quic::ConnectionError::Transport {
                source: quic::TransportError {
                    kind: crate::varint::VarInt::from_u32(0x01),
                    frame_type: crate::varint::VarInt::from_u32(0x00),
                    reason: format!("verify error: {e}").into(),
                },
            })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use remoc::prelude::ServerShared;
    use tokio_util::task::AbortOnDropHandle;
    use tracing::Instrument;

    use super::*;
    use crate::dquic::cert::handy::ToCertificate;

    const SERVER_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.cert");

    #[derive(Clone, Debug)]
    struct TestLocalAuthority {
        name: &'static str,
        cert_chain: Vec<CertificateDer<'static>>,
        fail_sign: bool,
    }

    impl TestLocalAuthority {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                cert_chain: SERVER_CERT.to_certificate(),
                fail_sign: false,
            }
        }

        fn failing_signer() -> Self {
            Self {
                fail_sign: true,
                ..Self::new("failing-local")
            }
        }

        fn invalid_cert_chain(name: &'static str) -> Self {
            Self {
                name,
                cert_chain: vec![CertificateDer::from(vec![0x01, 0x02, 0x03])],
                fail_sign: false,
            }
        }
    }

    impl authority::LocalAuthority for TestLocalAuthority {
        fn name(&self) -> &str {
            self.name
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &self.cert_chain
        }

        fn sign(&self, data: &[u8]) -> BoxFuture<'_, Result<Vec<u8>, SignError>> {
            let fail_sign = self.fail_sign;
            let data = data.to_vec();
            Box::pin(async move {
                if fail_sign {
                    return Err(SignError::UnsupportedKey);
                }
                Ok(expected_signature(&data))
            })
        }
    }

    #[derive(Clone, Debug)]
    struct TestRemoteAuthority {
        name: &'static str,
        cert_chain: Vec<CertificateDer<'static>>,
    }

    impl TestRemoteAuthority {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                cert_chain: SERVER_CERT.to_certificate(),
            }
        }

        fn invalid_cert_chain(name: &'static str) -> Self {
            Self {
                name,
                cert_chain: vec![CertificateDer::from(vec![0x04, 0x05, 0x06])],
            }
        }
    }

    impl authority::RemoteAuthority for TestRemoteAuthority {
        fn name(&self) -> &str {
            self.name
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &self.cert_chain
        }
    }

    fn expected_signature(data: &[u8]) -> Vec<u8> {
        let mut signature = b"canonical:".to_vec();
        signature.extend_from_slice(data);
        signature
    }

    fn assert_transport_reason(error: quic::ConnectionError, fragment: &str) {
        let quic::ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert!(
            source.reason.contains(fragment),
            "transport reason {:?} should contain {fragment:?}",
            source.reason,
        );
    }

    fn spawn_local_authority_server(
        authority: TestLocalAuthority,
    ) -> (AbortOnDropHandle<()>, LocalAuthorityClient) {
        let (server, client) = LocalAuthorityServerShared::new(Arc::new(authority), 1);
        let task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        (task, client)
    }

    fn spawn_remote_authority_server(
        authority: TestRemoteAuthority,
    ) -> (AbortOnDropHandle<()>, RemoteAuthorityClient) {
        let (server, client) = RemoteAuthorityServerShared::new(Arc::new(authority), 1);
        let task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        (task, client)
    }

    #[tokio::test]
    async fn blanket_local_authority_delegates_all_methods() {
        let authority = TestLocalAuthority::new("local.example");

        assert_eq!(
            super::LocalAuthority::name(&authority).await.expect("name"),
            "local.example",
        );
        let certs = super::LocalAuthority::cert_chain(&authority)
            .await
            .expect("cert chain");
        let cert = CertificateDer::from(certs.into_iter().next().expect("certificate"));
        assert_eq!(cert.as_ref(), authority.cert_chain[0].as_ref());

        let signature = super::LocalAuthority::sign(&authority, b"payload".to_vec())
            .await
            .expect("sign");
        assert_eq!(signature, expected_signature(b"payload"));

        let public_key = SubjectPublicKeyInfoDer::from(
            super::LocalAuthority::public_key(&authority)
                .await
                .expect("public key"),
        );
        assert_eq!(
            public_key.as_ref(),
            authority::LocalAuthority::public_key(&authority).as_ref(),
        );

        let verified = super::LocalAuthority::verify(
            &authority,
            b"payload".to_vec(),
            b"not a real signature".to_vec(),
        )
        .await
        .expect("verify");
        assert!(!verified);
    }

    #[tokio::test]
    async fn blanket_remote_authority_delegates_all_methods() {
        let authority = TestRemoteAuthority::new("remote.example");

        assert_eq!(
            super::RemoteAuthority::name(&authority)
                .await
                .expect("name"),
            "remote.example",
        );
        let certs = super::RemoteAuthority::cert_chain(&authority)
            .await
            .expect("cert chain");
        let cert = CertificateDer::from(certs.into_iter().next().expect("certificate"));
        assert_eq!(cert.as_ref(), authority.cert_chain[0].as_ref());

        let public_key = SubjectPublicKeyInfoDer::from(
            super::RemoteAuthority::public_key(&authority)
                .await
                .expect("public key"),
        );
        assert_eq!(
            public_key.as_ref(),
            authority::RemoteAuthority::public_key(&authority).as_ref(),
        );

        let verified = super::RemoteAuthority::verify(
            &authority,
            b"payload".to_vec(),
            b"not a real signature".to_vec(),
        )
        .await
        .expect("verify");
        assert!(!verified);
    }

    #[tokio::test]
    async fn blanket_authority_errors_become_transport_errors() {
        let local = TestLocalAuthority::failing_signer();
        let local_with_invalid_key = TestLocalAuthority::invalid_cert_chain("invalid-local");
        let remote_with_invalid_key = TestRemoteAuthority::invalid_cert_chain("invalid-remote");

        let error = super::LocalAuthority::sign(&local, b"payload".to_vec())
            .await
            .expect_err("sign error should be mapped");
        assert_transport_reason(error, "sign error");

        let error = super::LocalAuthority::verify(
            &local_with_invalid_key,
            b"payload".to_vec(),
            b"signature".to_vec(),
        )
        .await
        .expect_err("local verify error should be mapped");
        assert_transport_reason(error, "verify error");

        let error = super::RemoteAuthority::verify(
            &remote_with_invalid_key,
            b"payload".to_vec(),
            b"signature".to_vec(),
        )
        .await
        .expect_err("remote verify error should be mapped");
        assert_transport_reason(error, "verify error");
    }

    #[tokio::test]
    async fn cached_local_authority_fetches_remote_fields_and_delegates_sign() {
        let authority = TestLocalAuthority::new("cached-local.example");
        let (_task, client) = spawn_local_authority_server(authority.clone());

        let cached = CachedLocalAuthority::from_client(client)
            .await
            .expect("cached local authority");

        assert_eq!(authority::LocalAuthority::name(&cached), authority.name);
        assert_eq!(
            authority::LocalAuthority::cert_chain(&cached)[0].as_ref(),
            authority.cert_chain[0].as_ref(),
        );
        assert!(
            format!("{cached:?}").contains("CachedRemoteLocalAuthority"),
            "debug output should name cached local authority",
        );

        let signature = authority::LocalAuthority::sign(&cached, b"payload")
            .await
            .expect("cached sign");
        assert_eq!(signature, expected_signature(b"payload"));

        let public_key = authority::LocalAuthority::public_key(&cached);
        assert_eq!(
            public_key.as_ref(),
            authority::LocalAuthority::public_key(&authority).as_ref()
        );
        let verified =
            authority::LocalAuthority::verify(&cached, b"payload", b"not a real signature")
                .await
                .expect("cached verify");
        assert!(!verified);
    }

    #[tokio::test]
    async fn cached_remote_authority_fetches_remote_fields() {
        let authority = TestRemoteAuthority::new("cached-remote.example");
        let (_task, client) = spawn_remote_authority_server(authority.clone());

        let cached = CachedRemoteAuthority::from_client(client)
            .await
            .expect("cached remote authority");

        assert_eq!(authority::RemoteAuthority::name(&cached), authority.name);
        assert_eq!(
            authority::RemoteAuthority::cert_chain(&cached)[0].as_ref(),
            authority.cert_chain[0].as_ref(),
        );
        assert!(
            format!("{cached:?}").contains("CachedRemoteRemoteAuthority"),
            "debug output should name cached remote authority",
        );

        let public_key = authority::RemoteAuthority::public_key(&cached);
        assert_eq!(
            public_key.as_ref(),
            authority::RemoteAuthority::public_key(&authority).as_ref(),
        );
        let verified =
            authority::RemoteAuthority::verify(&cached, b"payload", b"not a real signature")
                .await
                .expect("cached verify");
        assert!(!verified);
    }
}
