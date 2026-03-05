use futures::future::BoxFuture;
use rustls::{
    SignatureScheme,
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer},
};

use crate::quic::agent::{self, SignError, VerifyError};

use super::{
    RemoteError, SerdeCertificateDer, SerdeSignatureAlgorithm, SerdeSignatureScheme,
    SerdeSubjectPublicKeyInfoDer,
};

/// Remote trait for [`agent::LocalAgent`], exposing all 6 methods over remoc RTC.
#[remoc::rtc::remote]
pub trait RemoteLocalAgent: Send + Sync {
    async fn name(&self) -> Result<String, RemoteError>;
    async fn cert_chain(&self) -> Result<Vec<SerdeCertificateDer>, RemoteError>;
    async fn sign_algorithm(&self) -> Result<SerdeSignatureAlgorithm, RemoteError>;
    async fn sign(
        &self,
        scheme: SerdeSignatureScheme,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, RemoteError>;
    async fn public_key(&self) -> Result<SerdeSubjectPublicKeyInfoDer, RemoteError>;
    async fn verify(
        &self,
        scheme: SerdeSignatureScheme,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, RemoteError>;
}

/// Remote trait for [`agent::RemoteAgent`], exposing all 4 methods over remoc RTC.
#[remoc::rtc::remote]
pub trait RemoteRemoteAgent: Send + Sync {
    async fn name(&self) -> Result<String, RemoteError>;
    async fn cert_chain(&self) -> Result<Vec<SerdeCertificateDer>, RemoteError>;
    async fn public_key(&self) -> Result<SerdeSubjectPublicKeyInfoDer, RemoteError>;
    async fn verify(
        &self,
        scheme: SerdeSignatureScheme,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, RemoteError>;
}

/// Client-side wrapper around [`RemoteLocalAgentClient`] that caches synchronous
/// fields eagerly and implements [`agent::LocalAgent`].
pub struct CachedRemoteLocalAgent {
    client: RemoteLocalAgentClient,
    name: String,
    cert_chain: Vec<CertificateDer<'static>>,
    sign_algorithm: rustls::SignatureAlgorithm,
}

impl std::fmt::Debug for CachedRemoteLocalAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedRemoteLocalAgent")
            .field("name", &self.name)
            .field("sign_algorithm", &self.sign_algorithm)
            .finish_non_exhaustive()
    }
}

impl CachedRemoteLocalAgent {
    /// Create a new cached wrapper by eagerly fetching synchronous fields from
    /// the remote agent.
    pub async fn new(client: RemoteLocalAgentClient) -> Result<Self, RemoteError> {
        let name = client.name().await?;
        let cert_chain: Vec<CertificateDer<'static>> =
            client.cert_chain().await?.into_iter().map(Into::into).collect();
        let sign_algorithm: rustls::SignatureAlgorithm = client.sign_algorithm().await?.into();
        Ok(Self {
            client,
            name,
            cert_chain,
            sign_algorithm,
        })
    }
}

impl agent::LocalAgent for CachedRemoteLocalAgent {
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
pub struct CachedRemoteRemoteAgent {
    #[allow(dead_code)]
    client: RemoteRemoteAgentClient,
    name: String,
    cert_chain: Vec<CertificateDer<'static>>,
}

impl std::fmt::Debug for CachedRemoteRemoteAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedRemoteRemoteAgent")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl CachedRemoteRemoteAgent {
    /// Create a new cached wrapper by eagerly fetching synchronous fields from
    /// the remote agent.
    pub async fn new(client: RemoteRemoteAgentClient) -> Result<Self, RemoteError> {
        let name = client.name().await?;
        let cert_chain: Vec<CertificateDer<'static>> =
            client.cert_chain().await?.into_iter().map(Into::into).collect();
        Ok(Self {
            client,
            name,
            cert_chain,
        })
    }
}

impl agent::RemoteAgent for CachedRemoteRemoteAgent {
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
