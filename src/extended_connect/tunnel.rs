use crate::{
    extended_connect::{EstablishedConnect, IntoStreamsError},
    message::stream::{ReadStream, WriteStream},
    qpack::field::Protocol,
    stream_id::StreamId,
};

pub struct ConnectTunnel {
    connect: EstablishedConnect,
}

impl From<EstablishedConnect> for ConnectTunnel {
    fn from(connect: EstablishedConnect) -> Self {
        Self { connect }
    }
}

impl ConnectTunnel {
    pub fn stream_id(&self) -> StreamId {
        self.connect.stream_id()
    }

    pub fn protocol(&self) -> Option<&Protocol> {
        self.connect.protocol()
    }

    pub async fn into_streams(self) -> Result<(ReadStream, WriteStream), IntoStreamsError> {
        self.connect.into_streams().await
    }
}
