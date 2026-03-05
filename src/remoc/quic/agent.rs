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

/// Client-side wrapper around [`RemoteLocalAgentClient`] that caches synchronous
/// fields eagerly and implements [`agent::LocalAgent`].
pub struct RemoteLocalAgent {
    client: LocalAgentClient,
    name: String,
    cert_chain: Vec<CertificateDer<'static>>,
    sign_algorithm: rustls::SignatureAlgorithm,
}

impl std::fmt::Debug for RemoteLocalAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedRemoteLocalAgent")
            .field("name", &self.name)
            .field("sign_algorithm", &self.sign_algorithm)
            .finish_non_exhaustive()
    }
}

impl RemoteLocalAgent {
    /// Create a new cached wrapper by eagerly fetching synchronous fields from
    /// the remote agent.
    pub async fn new(client: LocalAgentClient) -> Result<Self, quic::ConnectionError> {
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

impl agent::LocalAgent for RemoteLocalAgent {
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
        agent::extract_public_key(self.cert_chain())
    }

    fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = agent::verify_signature(self.public_key(), scheme, data, signature);
        Box::pin(std::future::ready(result))
    }
}

/// Client-side wrapper around [`RemoteRemoteAgentClient`] that caches synchronous
/// fields eagerly and implements [`agent::RemoteAgent`].
pub struct RemoteRemoteAgent {
    #[allow(dead_code)]
    client: RemoteAgentClient,
    name: String,
    cert_chain: Vec<CertificateDer<'static>>,
}

impl std::fmt::Debug for RemoteRemoteAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedRemoteRemoteAgent")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl RemoteRemoteAgent {
    /// Create a new cached wrapper by eagerly fetching synchronous fields from
    /// the remote agent.
    pub async fn new(client: RemoteAgentClient) -> Result<Self, quic::ConnectionError> {
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

impl agent::RemoteAgent for RemoteRemoteAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }

    fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        agent::extract_public_key(self.cert_chain())
    }

    fn verify(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> BoxFuture<'_, Result<bool, VerifyError>> {
        let result = agent::verify_signature(self.public_key(), scheme, data, signature);
        Box::pin(std::future::ready(result))
    }
}
