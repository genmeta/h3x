use futures::future::BoxFuture;
use rustls::{
    SignatureScheme,
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer},
};

use super::serde_types::{
    SerdeCertificateDer, SerdeSignatureAlgorithm, SerdeSignatureScheme,
    SerdeSubjectPublicKeyInfoDer,
};
use crate::quic::{
    self,
    agent::{self, SignError, VerifyError},
};

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
                .map_err(|e| SignError::Crypto {
                    source: rustls::Error::General(e.to_string()),
                })
        })
    }

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        agent::extract_public_key(quic::agent::LocalAgent::cert_chain(self))
    }

    fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = agent::verify_signature(
            quic::agent::LocalAgent::public_key(self),
            scheme,
            data,
            signature,
        );
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
        agent::extract_public_key(quic::agent::RemoteAgent::cert_chain(self))
    }

    fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = agent::verify_signature(
            quic::agent::RemoteAgent::public_key(self),
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
            .map_err(|e| quic::ConnectionError::Transport {
                source: quic::TransportError {
                    kind: crate::varint::VarInt::from_u32(0x01),
                    frame_type: crate::varint::VarInt::from_u32(0x00),
                    reason: format!("verify error: {e}").into(),
                },
            })
    }
}
