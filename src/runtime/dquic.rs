use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream};
use http::uri::Authority;

use crate::{Endpoint, Error, RemoteAuthority, transport::PendingTransport};

#[derive(Clone)]
pub struct DquicTransport(pub(crate) Arc<dquic::prelude::Connection>);

fn connection_error(error: dquic::prelude::Error) -> crate::transport::ConnectionError {
    match error {
        dquic::prelude::Error::Quic(error) => crate::transport::ConnectionError::transport(error),
        dquic::prelude::Error::App(error) => {
            crate::transport::ConnectionError::application_with_source(
                crate::Code::try_from(error.error_code())
                    .expect("QUIC application code fits a varint"),
                Bytes::copy_from_slice(error.reason().as_bytes()),
                error,
            )
        }
    }
}

fn stream_error(error: dquic::prelude::StreamError) -> crate::transport::StreamError {
    match error {
        dquic::prelude::StreamError::Connection(error) => connection_error(error).into(),
        dquic::prelude::StreamError::Reset(error) => crate::transport::StreamError::reset(
            crate::Code::try_from(error.error_code()).expect("QUIC reset code fits a varint"),
        ),
        dquic::prelude::StreamError::EosSent => {
            crate::transport::ConnectionError::transport(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC send direction already finished",
            ))
            .into()
        }
    }
}

impl crate::transport::RecvStream for dquic::prelude::StreamReader {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, crate::transport::StreamError>>> {
        Stream::poll_next(Pin::new(self), cx)
            .map(|item| item.map(|item| item.map_err(stream_error)))
    }

    fn stop(&mut self, code: crate::Code) -> Result<(), crate::transport::StreamError> {
        dquic::prelude::StopSending::stop(self, code.as_u64());
        Ok(())
    }
}

impl crate::transport::SendStream for dquic::prelude::StreamWriter {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), crate::transport::StreamError>> {
        Sink::poll_ready(Pin::new(self), cx).map_err(stream_error)
    }

    fn start_send(&mut self, item: Bytes) -> Result<(), crate::transport::StreamError> {
        Sink::start_send(Pin::new(self), item).map_err(stream_error)
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), crate::transport::StreamError>> {
        Sink::poll_close(Pin::new(self), cx).map_err(stream_error)
    }

    fn reset(&mut self, code: crate::Code) -> Result<(), crate::transport::StreamError> {
        dquic::prelude::CancelStream::cancel(self, code.as_u64());
        Ok(())
    }
}

impl crate::transport::Connection for DquicTransport {
    type RecvStream = dquic::prelude::StreamReader;
    type SendStream = dquic::prelude::StreamWriter;

    fn role(&self) -> Result<crate::transport::Role, crate::transport::ConnectionError> {
        self.0.role().map_err(connection_error)
    }

    async fn open_bi(&self) -> Result<(crate::StreamId, (Self::RecvStream, Self::SendStream)), crate::transport::ConnectionError> {
        let Some((id, (recv, send))) = self.0.open_bi_stream().await.map_err(connection_error)?
        else {
            return Err(crate::transport::ConnectionError::transport(
                io::Error::other("QUIC bidirectional stream ID space exhausted"),
            ));
        };
        Ok((id, (recv, send)))
    }

    async fn open_uni(&self) -> Result<(crate::StreamId, Self::SendStream), crate::transport::ConnectionError> {
        let Some((id, send)) = self.0.open_uni_stream().await.map_err(connection_error)? else {
            return Err(crate::transport::ConnectionError::transport(
                io::Error::other("QUIC unidirectional stream ID space exhausted"),
            ));
        };
        Ok((id, send))
    }

    async fn accept_bi(
        &self,
    ) -> Result<(crate::StreamId, (Self::RecvStream, Self::SendStream)), crate::transport::ConnectionError> {
        let (id, (recv, send)) = self.0.accept_bi_stream().await.map_err(connection_error)?;
        Ok((id, (recv, send)))
    }

    async fn accept_uni(&self) -> Result<(crate::StreamId, Self::RecvStream), crate::transport::ConnectionError> {
        let (id, recv) = self.0.accept_uni_stream().await.map_err(connection_error)?;
        Ok((id, recv))
    }

    fn close(&self, code: crate::Code, reason: &[u8]) {
        let _ = self
            .0
            .close(String::from_utf8_lossy(reason).into_owned(), code.as_u64());
    }

    async fn closed(&self) -> crate::transport::ConnectionError {
        connection_error(self.0.terminated().await)
    }
}

pub(crate) fn transport_error(source: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Transport {
        source: Arc::new(source),
    }
}

pub(crate) async fn authenticate(
    handshake: PendingTransport<DquicTransport>,
    local: Option<Arc<Endpoint>>,
    target: Option<Authority>,
) -> Result<Authenticated, Error> {
    let raw = &handshake.transport.as_ref().expect("unadopted transport").0;
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
    let target = match target {
        Some(target) => {
            if remote.as_ref().map(RemoteAuthority::name) != Some(target.host()) {
                return Err(Error::IdentityMismatch);
            }
            Some(target)
        }
        None => remote
            .as_ref()
            .filter(|remote| remote.name() == "dhttp.net" || remote.name().ends_with(".dhttp.net"))
            .map(|remote| {
                remote
                    .name()
                    .parse()
                    .expect("validated DHTTP name is an authority")
            }),
    };
    Ok(Authenticated {
        transport: handshake,
        local,
        remote,
        target,
    })
}

/// Authentication facts remain in the runtime when transport is adopted by HTTP/3.
pub(super) struct Authenticated {
    pub(super) transport: PendingTransport<DquicTransport>,
    pub(super) local: Option<Arc<Endpoint>>,
    pub(super) remote: Option<RemoteAuthority>,
    pub(super) target: Option<Authority>,
}
