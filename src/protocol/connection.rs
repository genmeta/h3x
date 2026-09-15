use std::sync::Arc;

use qrecovery::{recv::StopSending, send::CancelStream};

use super::{
    qpack::Qpack,
    stream::{H3ReadStream, H3WriteStream, bi::BiStreams},
};
use crate::{Error, Result, Transport};

mod control;
mod settings;
mod stream_cursor;

pub use settings::Settings;
pub(crate) use stream_cursor::StreamCursor;

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Tasks run until the transport terminates.
/// Only an explicit goaway() drains requests and closes the transport.
pub struct H3Connection<T: Transport> {
    transport: Arc<T>,
    settings: Arc<Settings>,
    qpack: Arc<Qpack>,
    cursor: Arc<StreamCursor>,
    bi_streams: Arc<BiStreams<T::StreamReader, T::StreamWriter>>,
}

impl<T: Transport> H3Connection<T> {
    /// Start HTTP/3 using the supplied settings and the transport's endpoint role.
    /// Panics if called outside a Tokio runtime.
    pub fn new(transport: T, settings: Settings) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let bi = Arc::new(BiStreams::new());
        let (qpack, instruction, feedback) = Qpack::new(&settings)?;
        let cursor = Arc::new(StreamCursor::new(transport.role()));
        let connection = Self {
            transport,
            settings,
            qpack,
            cursor,
            bi_streams: bi,
        };
        tokio::spawn(connection.clone().send_qpack_encoder(instruction));
        tokio::spawn(connection.clone().send_qpack_decoder(feedback));
        tokio::spawn(connection.clone().send_uni());
        tokio::spawn(connection.clone().accept_uni());
        Ok(connection)
    }

    /// Compression state shared by messages on this connection.
    pub fn qpack(&self) -> &Arc<Qpack> {
        &self.qpack
    }

    /// Open a bidirectional stream, returning (send, receive).
    /// Admission stops on peer GOAWAY or connection close, not local GOAWAY.
    pub async fn open_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::StreamWriter>,
        H3ReadStream<T::StreamReader>,
    )> {
        self.cursor.remote.lock().unwrap().check_admission()?;
        let (id, (mut recv, mut send)) = self
            .transport
            .open_bi()
            .await?
            .ok_or(Error::H3_STREAM_CREATION_ERROR)?;
        let state = self.cursor.remote.lock().unwrap();
        if let Err(error) = state.check_admission() {
            drop(state);
            recv.stop(Error::H3_REQUEST_REJECTED.as_u64());
            send.cancel(Error::H3_REQUEST_REJECTED.as_u64());
            return Err(error);
        }
        self.bi_streams.insert(id, recv, send)
    }

    /// Consume this connection and exchange GOAWAY with the peer.
    /// The control task writes GOAWAY, waits for the peer and admitted requests, then closes QUIC.
    /// Waits for transport termination; H3_NO_ERROR is success.
    /// Cancelling this wait does not cancel the triggered drain.
    pub async fn goaway(self) -> Result<()> {
        self.cursor.goaway()?;
        match self.transport.terminated().await {
            Error::H3_NO_ERROR => Ok(()),
            error => Err(error),
        }
    }
}

impl<T: Transport> H3Connection<T> {
    /// Accept and register one peer bidirectional stream, returning (write, read).
    /// Admission stops on local GOAWAY or connection close, not peer GOAWAY.
    /// The application drives acceptance; no background request queue is maintained.
    pub async fn accept_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::StreamWriter>,
        H3ReadStream<T::StreamReader>,
    )> {
        self.cursor.local.lock().unwrap().check_admission()?;
        let (id, (mut read, mut write)) = self.transport.accept_bi().await?;
        let mut state = self.cursor.local.lock().unwrap();
        let stream_id = qbase::varint::VarInt::try_from(id)
            .map(qbase::sid::StreamId::from)
            .map_err(|_| Error::H3_ID_ERROR);
        if let Err(error) = stream_id.and_then(|id| state.accept(id)) {
            drop(state);
            read.stop(Error::H3_REQUEST_REJECTED.as_u64());
            write.cancel(Error::H3_REQUEST_REJECTED.as_u64());
            return Err(error);
        }
        // Keep admission and registration atomic with respect to local GOAWAY.
        self.bi_streams.insert(id, read, write)
    }
}

impl<T: Transport> Clone for H3Connection<T> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            settings: self.settings.clone(),
            qpack: self.qpack.clone(),
            cursor: self.cursor.clone(),
            bi_streams: self.bi_streams.clone(),
        }
    }
}
