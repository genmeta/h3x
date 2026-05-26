use dhttp_identity::identity::{self as agent, SignError, VerifyError};
use futures::future::BoxFuture;
use rustls::{
    SignatureScheme,
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer},
};

use super::serde_types::{
    SerdeCertificateDer, SerdeSignatureAlgorithm, SerdeSignatureScheme,
    SerdeSubjectPublicKeyInfoDer,
};
use crate::quic;

/// Remote trait for [`agent::LocalAgent`], exposing all 6 methods over remoc RTC.
#[remoc::rtc::remote]
pub trait LocalAgent: Send + Sync {
    async fn name(&self) -> Result<String, quic::ConnectionError>;
    async fn cert_chain(&self) -> Result<Vec<SerdeCertificateDer>, quic::ConnectionError>;
    async fn sign_algorithm(&self) -> Result<SerdeSignatureAlgorithm, quic::ConnectionError>;
    async fn sign(
        &self,
        scheme: SerdeSignatureScheme,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, quic::ConnectionError>;
    async fn public_key(&self) -> Result<SerdeSubjectPublicKeyInfoDer, quic::ConnectionError>;
    async fn verify(
        &self,
        scheme: SerdeSignatureScheme,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, quic::ConnectionError>;
}

/// Remote trait for [`agent::RemoteAgent`], exposing all 4 methods over remoc RTC.
#[remoc::rtc::remote]
pub trait RemoteAgent: Send + Sync {
    async fn name(&self) -> Result<String, quic::ConnectionError>;
    async fn cert_chain(&self) -> Result<Vec<SerdeCertificateDer>, quic::ConnectionError>;
    async fn public_key(&self) -> Result<SerdeSubjectPublicKeyInfoDer, quic::ConnectionError>;
    async fn verify(
        &self,
        scheme: SerdeSignatureScheme,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, quic::ConnectionError>;
}

pub struct CachedLocalAgent {
    client: LocalAgentClient,
    name: String,
    cert_chain: Vec<CertificateDer<'static>>,
    sign_algorithm: rustls::SignatureAlgorithm,
}

impl std::fmt::Debug for CachedLocalAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedRemoteLocalAgent")
            .field("name", &self.name)
            .field("sign_algorithm", &self.sign_algorithm)
            .finish_non_exhaustive()
    }
}

impl CachedLocalAgent {
    /// Create a new cached wrapper by eagerly fetching synchronous fields from
    /// the remote agent.
    pub async fn from_client(client: LocalAgentClient) -> Result<Self, quic::ConnectionError> {
        let name = client.name().await?;
        let cert_chain: Vec<CertificateDer<'static>> = client
            .cert_chain()
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        let sign_algorithm: rustls::SignatureAlgorithm = client.sign_algorithm().await?.into();
        Ok(Self {
            client,
            name,
            cert_chain,
            sign_algorithm,
        })
    }
}

impl agent::LocalAgent for CachedLocalAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }

    fn sign_algorithm(&self) -> rustls::SignatureAlgorithm {
        self.sign_algorithm
    }

    fn sign(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
    ) -> BoxFuture<'_, Result<Vec<u8>, SignError>> {
        let serde_scheme = SerdeSignatureScheme::from(scheme);
        let owned_data = data.to_vec();
        let client = self.client.clone();
        Box::pin(async move {
            client
                .sign(serde_scheme, owned_data)
                .await
                // lossy: rustls API requires String for General error variant
                .map_err(|e| SignError::Crypto {
                    source: rustls::Error::General(e.to_string()),
                })
        })
    }

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        agent::extract_public_key(agent::LocalAgent::cert_chain(self))
    }

    fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result =
            agent::verify_signature(agent::LocalAgent::public_key(self), scheme, data, signature);
        Box::pin(std::future::ready(result))
    }
}

pub struct CachedRemoteAgent {
    #[allow(dead_code)]
    client: RemoteAgentClient,
    name: String,
    cert_chain: Vec<CertificateDer<'static>>,
}

impl std::fmt::Debug for CachedRemoteAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedRemoteRemoteAgent")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl CachedRemoteAgent {
    /// Create a new cached wrapper by eagerly fetching synchronous fields from
    /// the remote agent.
    pub async fn from_client(client: RemoteAgentClient) -> Result<Self, quic::ConnectionError> {
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

impl agent::RemoteAgent for CachedRemoteAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        agent::extract_public_key(agent::RemoteAgent::cert_chain(self))
    }

    fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = agent::verify_signature(
            agent::RemoteAgent::public_key(self),
            scheme,
            data,
            signature,
        );
        Box::pin(std::future::ready(result))
    }
}

impl<A> LocalAgent for A
where
    A: agent::LocalAgent + Send + Sync,
{
    async fn name(&self) -> Result<String, quic::ConnectionError> {
        Ok(agent::LocalAgent::name(self).to_owned())
    }

    async fn cert_chain(&self) -> Result<Vec<SerdeCertificateDer>, quic::ConnectionError> {
        Ok(self
            .cert_chain()
            .iter()
            .cloned()
            .map(SerdeCertificateDer::from)
            .collect())
    }

    async fn sign_algorithm(&self) -> Result<SerdeSignatureAlgorithm, quic::ConnectionError> {
        Ok(SerdeSignatureAlgorithm::from(
            agent::LocalAgent::sign_algorithm(self),
        ))
    }

    async fn sign(
        &self,
        scheme: SerdeSignatureScheme,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, quic::ConnectionError> {
        agent::LocalAgent::sign(self, SignatureScheme::from(scheme), &data)
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
            agent::LocalAgent::public_key(self),
        ))
    }

    async fn verify(
        &self,
        scheme: SerdeSignatureScheme,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, quic::ConnectionError> {
        agent::LocalAgent::verify(self, SignatureScheme::from(scheme), &data, &signature)
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

impl<A> RemoteAgent for A
where
    A: agent::RemoteAgent + Send + Sync,
{
    async fn name(&self) -> Result<String, quic::ConnectionError> {
        Ok(agent::RemoteAgent::name(self).to_owned())
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
            agent::RemoteAgent::public_key(self),
        ))
    }

    async fn verify(
        &self,
        scheme: SerdeSignatureScheme,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, quic::ConnectionError> {
        agent::RemoteAgent::verify(self, SignatureScheme::from(scheme), &data, &signature)
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
    struct TestLocalAgent {
        name: &'static str,
        cert_chain: Vec<CertificateDer<'static>>,
        fail_sign: bool,
    }

    impl TestLocalAgent {
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
    }

    impl agent::LocalAgent for TestLocalAgent {
        fn name(&self) -> &str {
            self.name
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &self.cert_chain
        }

        fn sign_algorithm(&self) -> rustls::SignatureAlgorithm {
            rustls::SignatureAlgorithm::ECDSA
        }

        fn sign(
            &self,
            scheme: SignatureScheme,
            data: &[u8],
        ) -> BoxFuture<'_, Result<Vec<u8>, SignError>> {
            let fail_sign = self.fail_sign;
            let data = data.to_vec();
            Box::pin(async move {
                if fail_sign {
                    return Err(SignError::UnsupportedScheme { scheme });
                }
                Ok(expected_signature(scheme, &data))
            })
        }
    }

    #[derive(Clone, Debug)]
    struct TestRemoteAgent {
        name: &'static str,
        cert_chain: Vec<CertificateDer<'static>>,
    }

    impl TestRemoteAgent {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                cert_chain: SERVER_CERT.to_certificate(),
            }
        }
    }

    impl agent::RemoteAgent for TestRemoteAgent {
        fn name(&self) -> &str {
            self.name
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &self.cert_chain
        }
    }

    fn expected_signature(scheme: SignatureScheme, data: &[u8]) -> Vec<u8> {
        let mut signature = u16::from(scheme).to_be_bytes().to_vec();
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

    fn spawn_local_agent_server(
        agent: TestLocalAgent,
    ) -> (AbortOnDropHandle<()>, LocalAgentClient) {
        let (server, client) = LocalAgentServerShared::new(Arc::new(agent), 1);
        let task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        (task, client)
    }

    fn spawn_remote_agent_server(
        agent: TestRemoteAgent,
    ) -> (AbortOnDropHandle<()>, RemoteAgentClient) {
        let (server, client) = RemoteAgentServerShared::new(Arc::new(agent), 1);
        let task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        (task, client)
    }

    #[tokio::test]
    async fn blanket_local_agent_delegates_all_methods() {
        let agent = TestLocalAgent::new("local.example");
        let scheme = SignatureScheme::ECDSA_NISTP256_SHA256;

        assert_eq!(
            super::LocalAgent::name(&agent).await.expect("name"),
            "local.example",
        );
        let certs = super::LocalAgent::cert_chain(&agent)
            .await
            .expect("cert chain");
        let cert = CertificateDer::from(certs.into_iter().next().expect("certificate"));
        assert_eq!(cert.as_ref(), agent.cert_chain[0].as_ref());
        assert_eq!(
            rustls::SignatureAlgorithm::from(
                super::LocalAgent::sign_algorithm(&agent)
                    .await
                    .expect("sign algorithm"),
            ),
            rustls::SignatureAlgorithm::ECDSA,
        );

        let signature = super::LocalAgent::sign(
            &agent,
            SerdeSignatureScheme::from(scheme),
            b"payload".to_vec(),
        )
        .await
        .expect("sign");
        assert_eq!(signature, expected_signature(scheme, b"payload"));

        let public_key = SubjectPublicKeyInfoDer::from(
            super::LocalAgent::public_key(&agent)
                .await
                .expect("public key"),
        );
        assert_eq!(
            public_key.as_ref(),
            agent::LocalAgent::public_key(&agent).as_ref(),
        );

        let verified = super::LocalAgent::verify(
            &agent,
            SerdeSignatureScheme::from(scheme),
            b"payload".to_vec(),
            b"not a real signature".to_vec(),
        )
        .await
        .expect("verify");
        assert!(!verified);
    }

    #[tokio::test]
    async fn blanket_remote_agent_delegates_all_methods() {
        let agent = TestRemoteAgent::new("remote.example");
        let scheme = SignatureScheme::ECDSA_NISTP256_SHA256;

        assert_eq!(
            super::RemoteAgent::name(&agent).await.expect("name"),
            "remote.example",
        );
        let certs = super::RemoteAgent::cert_chain(&agent)
            .await
            .expect("cert chain");
        let cert = CertificateDer::from(certs.into_iter().next().expect("certificate"));
        assert_eq!(cert.as_ref(), agent.cert_chain[0].as_ref());

        let public_key = SubjectPublicKeyInfoDer::from(
            super::RemoteAgent::public_key(&agent)
                .await
                .expect("public key"),
        );
        assert_eq!(
            public_key.as_ref(),
            agent::RemoteAgent::public_key(&agent).as_ref(),
        );

        let verified = super::RemoteAgent::verify(
            &agent,
            SerdeSignatureScheme::from(scheme),
            b"payload".to_vec(),
            b"not a real signature".to_vec(),
        )
        .await
        .expect("verify");
        assert!(!verified);
    }

    #[tokio::test]
    async fn blanket_agent_errors_become_transport_errors() {
        let local = TestLocalAgent::failing_signer();
        let remote = TestRemoteAgent::new("remote.example");
        let unsupported = SerdeSignatureScheme::from(SignatureScheme::from(0xffff));

        let error = super::LocalAgent::sign(&local, unsupported, b"payload".to_vec())
            .await
            .expect_err("sign error should be mapped");
        assert_transport_reason(error, "sign error");

        let error = super::LocalAgent::verify(
            &local,
            unsupported,
            b"payload".to_vec(),
            b"signature".to_vec(),
        )
        .await
        .expect_err("local verify error should be mapped");
        assert_transport_reason(error, "verify error");

        let error = super::RemoteAgent::verify(
            &remote,
            unsupported,
            b"payload".to_vec(),
            b"signature".to_vec(),
        )
        .await
        .expect_err("remote verify error should be mapped");
        assert_transport_reason(error, "verify error");
    }

    #[tokio::test]
    async fn cached_local_agent_fetches_remote_fields_and_delegates_sign() {
        let agent = TestLocalAgent::new("cached-local.example");
        let (_task, client) = spawn_local_agent_server(agent.clone());

        let cached = CachedLocalAgent::from_client(client)
            .await
            .expect("cached local agent");

        assert_eq!(agent::LocalAgent::name(&cached), agent.name);
        assert_eq!(
            agent::LocalAgent::cert_chain(&cached)[0].as_ref(),
            agent.cert_chain[0].as_ref(),
        );
        assert_eq!(
            agent::LocalAgent::sign_algorithm(&cached),
            rustls::SignatureAlgorithm::ECDSA,
        );
        assert!(
            format!("{cached:?}").contains("CachedRemoteLocalAgent"),
            "debug output should name cached local agent",
        );

        let scheme = SignatureScheme::ECDSA_NISTP256_SHA256;
        let signature = agent::LocalAgent::sign(&cached, scheme, b"payload")
            .await
            .expect("cached sign");
        assert_eq!(signature, expected_signature(scheme, b"payload"));

        let public_key = agent::LocalAgent::public_key(&cached);
        assert_eq!(
            public_key.as_ref(),
            agent::LocalAgent::public_key(&agent).as_ref()
        );
        let verified =
            agent::LocalAgent::verify(&cached, scheme, b"payload", b"not a real signature")
                .await
                .expect("cached verify");
        assert!(!verified);
    }

    #[tokio::test]
    async fn cached_remote_agent_fetches_remote_fields() {
        let agent = TestRemoteAgent::new("cached-remote.example");
        let (_task, client) = spawn_remote_agent_server(agent.clone());

        let cached = CachedRemoteAgent::from_client(client)
            .await
            .expect("cached remote agent");

        assert_eq!(agent::RemoteAgent::name(&cached), agent.name);
        assert_eq!(
            agent::RemoteAgent::cert_chain(&cached)[0].as_ref(),
            agent.cert_chain[0].as_ref(),
        );
        assert!(
            format!("{cached:?}").contains("CachedRemoteRemoteAgent"),
            "debug output should name cached remote agent",
        );

        let public_key = agent::RemoteAgent::public_key(&cached);
        assert_eq!(
            public_key.as_ref(),
            agent::RemoteAgent::public_key(&agent).as_ref(),
        );
        let verified = agent::RemoteAgent::verify(
            &cached,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            b"payload",
            b"not a real signature",
        )
        .await
        .expect("cached verify");
        assert!(!verified);
    }
}
