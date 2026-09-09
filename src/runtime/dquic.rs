use std::{io, sync::Arc};

use dquic::prelude::{StreamReader, StreamWriter};

use crate::{Endpoint, Error, RemoteAuthority};

impl crate::transport::Connection for Arc<dquic::prelude::Connection> {
    fn role(&self) -> Result<crate::transport::Role, crate::transport::ConnectionError> {
        self.as_ref()
            .role()
            .map_err(crate::transport::ConnectionError::from)
    }

    async fn open_bi(
        &self,
    ) -> Result<(crate::StreamId, (StreamReader, StreamWriter)), crate::transport::ConnectionError>
    {
        let Some((id, (recv, send))) = self
            .as_ref()
            .open_bi_stream()
            .await
            .map_err(crate::transport::ConnectionError::from)?
        else {
            return Err(crate::transport::ConnectionError::transport(
                io::Error::other("QUIC bidirectional stream ID space exhausted"),
            ));
        };
        Ok((id, (recv, send)))
    }

    async fn open_uni(
        &self,
    ) -> Result<(crate::StreamId, StreamWriter), crate::transport::ConnectionError> {
        let Some((id, send)) = self
            .as_ref()
            .open_uni_stream()
            .await
            .map_err(crate::transport::ConnectionError::from)?
        else {
            return Err(crate::transport::ConnectionError::transport(
                io::Error::other("QUIC unidirectional stream ID space exhausted"),
            ));
        };
        Ok((id, send))
    }

    async fn accept_bi(
        &self,
    ) -> Result<(crate::StreamId, (StreamReader, StreamWriter)), crate::transport::ConnectionError>
    {
        let (id, (recv, send)) = self
            .as_ref()
            .accept_bi_stream()
            .await
            .map_err(crate::transport::ConnectionError::from)?;
        Ok((id, (recv, send)))
    }

    async fn accept_uni(
        &self,
    ) -> Result<(crate::StreamId, StreamReader), crate::transport::ConnectionError> {
        let (id, recv) = self
            .as_ref()
            .accept_uni_stream()
            .await
            .map_err(crate::transport::ConnectionError::from)?;
        Ok((id, recv))
    }

    fn close(&self, code: crate::Code, reason: &[u8]) {
        let _ = self
            .as_ref()
            .close(String::from_utf8_lossy(reason).into_owned(), code.as_u64());
    }

    async fn closed(&self) -> crate::transport::ConnectionError {
        crate::transport::ConnectionError::from(self.as_ref().terminated().await)
    }
}

pub(crate) fn transport_error(source: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Transport {
        source: Arc::new(source),
    }
}

// TODO：这个有 quic 交付一个带身份握手完成的 Connection
pub(crate) async fn authenticate(
    transport: Arc<dquic::prelude::Connection>,
    local: Option<Arc<Endpoint>>,
    target: Option<&str>,
) -> Result<Authenticated, Error> {
    let raw = &transport;
    raw.handshaked().await.map_err(transport_error)?;
    if raw
        .negotiated_alpn()
        .await
        .map_err(transport_error)?
        .as_deref()
        != Some(crate::ALPN)
    {
        return Err(Error::IdentityMismatch);
    }
    let actual_local = raw.local_authority().await.map_err(transport_error)?;
    match (&local, actual_local) {
        (None, None) => {}
        (Some(local), Some(actual)) => {
            let expected = local.certificate();
            let actual_cert = actual.certificate();
            if actual.name() != local.name()
                || actual_cert.cert != expected.cert
                || !Arc::ptr_eq(&actual_cert.key, &expected.key)
                || actual_cert.ocsp != expected.ocsp
            {
                return Err(Error::IdentityMismatch);
            }
        }
        _ => return Err(Error::IdentityMismatch),
    }
    let remote = raw
        .remote_authority()
        .await
        .map_err(transport_error)?
        .map(|remote| {
            RemoteAuthority::from_authenticated(remote.name(), remote.cert_chain().to_vec())
        })
        .transpose()?;
    if let Some(target) = target
        && remote.as_ref().map(RemoteAuthority::name) != Some(target)
    {
        return Err(Error::IdentityMismatch);
    }
    Ok(Authenticated {
        transport,
        local,
        remote,
    })
}

/// Authentication facts remain in the runtime when transport is adopted by HTTP/3.
pub(super) struct Authenticated {
    pub(super) transport: Arc<dquic::prelude::Connection>,
    pub(super) local: Option<Arc<Endpoint>>,
    pub(super) remote: Option<RemoteAuthority>,
}
