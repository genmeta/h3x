use std::{future::Future, sync::Arc};

use futures::future::{BoxFuture, FutureExt};
use snafu::ResultExt;

use crate::{
    connection::ConnectionState,
    message::stream::{MessageReader, MessageWriter},
    qpack::field::Protocol,
    quic,
    stream_id::StreamId,
};

mod error;
mod tunnel;

#[cfg(feature = "hyper")]
pub mod hyper;
pub mod settings;

pub use error::{
    IntoStreamsError, PendingWriteStreamError, into_streams_error, pending_write_stream_error,
};
pub use tunnel::ConnectTunnel;

pub struct EstablishedConnect {
    stream_id: StreamId,
    protocol: Option<Protocol>,
    connection: Arc<ConnectionState<dyn quic::DynConnection>>,
    control: ConnectControl,
}

#[allow(dead_code)]
enum ConnectControl {
    Ready {
        read: MessageReader,
        write: MessageWriter,
    },
    Pending {
        read: MessageReader,
        write: BoxFuture<'static, Result<MessageWriter, PendingWriteStreamError>>,
    },
}

impl EstablishedConnect {
    #[allow(dead_code)]
    pub(crate) fn ready(
        stream_id: StreamId,
        protocol: Option<Protocol>,
        connection: Arc<ConnectionState<dyn quic::DynConnection>>,
        read: MessageReader,
        write: MessageWriter,
    ) -> Self {
        Self {
            stream_id,
            protocol,
            connection,
            control: ConnectControl::Ready { read, write },
        }
    }

    #[allow(dead_code)]
    pub(crate) fn pending(
        stream_id: StreamId,
        protocol: Option<Protocol>,
        connection: Arc<ConnectionState<dyn quic::DynConnection>>,
        read: MessageReader,
        write: impl Future<Output = Result<MessageWriter, PendingWriteStreamError>> + Send + 'static,
    ) -> Self {
        Self {
            stream_id,
            protocol,
            connection,
            control: ConnectControl::Pending {
                read,
                write: write.boxed(),
            },
        }
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub fn protocol(&self) -> Option<&Protocol> {
        self.protocol.as_ref()
    }

    pub fn connection(&self) -> &Arc<ConnectionState<dyn quic::DynConnection>> {
        &self.connection
    }

    pub async fn into_streams(self) -> Result<(MessageReader, MessageWriter), IntoStreamsError> {
        match self.control {
            ConnectControl::Ready { read, write } => Ok((read, write)),
            ConnectControl::Pending { read, write } => {
                let write = write
                    .await
                    .context(into_streams_error::PendingWriteStreamSnafu)?;
                Ok((read, write))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::future;

    use super::*;
    use crate::{
        connection::{ConnectionState, tests::MockConnection},
        message::test::{read_stream_for_test, write_stream_for_test},
        protocol::Protocols,
        qpack::field::Protocol,
        quic,
        stream_id::StreamId,
        varint::VarInt,
    };

    fn state_for_test() -> Arc<ConnectionState<dyn quic::DynConnection>> {
        let quic = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = quic;
        Arc::new(ConnectionState::new_for_test(
            erased,
            Arc::new(Protocols::new()),
        ))
    }

    #[tokio::test]
    async fn ready_connect_returns_streams() {
        let stream_id = StreamId::from(VarInt::from_u32(4));
        let connect = EstablishedConnect::ready(
            stream_id,
            Some(Protocol::new("test-protocol")),
            state_for_test(),
            read_stream_for_test(stream_id.0),
            write_stream_for_test(stream_id.0),
        );

        assert_eq!(connect.stream_id(), stream_id);
        assert_eq!(
            connect.protocol().map(Protocol::as_str),
            Some("test-protocol")
        );

        let (_read, _write) = connect.into_streams().await.expect("streams are ready");
    }

    #[tokio::test]
    async fn pending_connect_waits_for_write_stream() {
        let stream_id = StreamId::from(VarInt::from_u32(8));
        let connect = EstablishedConnect::pending(
            stream_id,
            None,
            state_for_test(),
            read_stream_for_test(stream_id.0),
            future::ready(Ok(write_stream_for_test(stream_id.0))),
        );

        let (_read, _write) = connect
            .into_streams()
            .await
            .expect("pending write delivered");
    }

    #[tokio::test]
    async fn pending_write_failure_is_reported_by_into_streams() {
        let stream_id = StreamId::from(VarInt::from_u32(12));
        let connect = EstablishedConnect::pending(
            stream_id,
            None,
            state_for_test(),
            read_stream_for_test(stream_id.0),
            future::ready(Err(PendingWriteStreamError::Aborted)),
        );

        let error = match connect.into_streams().await {
            Ok(_) => panic!("pending write failed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            IntoStreamsError::PendingWriteStream {
                source: PendingWriteStreamError::Aborted,
            },
        ));
    }

    #[tokio::test]
    async fn connect_tunnel_delegates_to_established_connect() {
        let stream_id = StreamId::from(VarInt::from_u32(16));
        let connect = EstablishedConnect::ready(
            stream_id,
            Some(Protocol::new("raw-tunnel")),
            state_for_test(),
            read_stream_for_test(stream_id.0),
            write_stream_for_test(stream_id.0),
        );
        let tunnel = ConnectTunnel::from(connect);

        assert_eq!(tunnel.stream_id(), stream_id);
        assert_eq!(tunnel.protocol().map(Protocol::as_str), Some("raw-tunnel"));
        let (_read, _write) = tunnel.into_streams().await.expect("streams are ready");
    }
}
