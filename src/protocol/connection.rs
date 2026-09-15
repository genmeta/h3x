use std::sync::Arc;

use qrecovery::{recv::StopSending, send::CancelStream};

use super::{
    qpack::Qpack,
    stream::{H3ReadStream, H3WriteStream, bi::BiStreams},
};
use crate::{Error, Result, Transport};

mod goaway;
mod settings;
mod uni;

pub(crate) use goaway::StreamCursor;
pub use settings::Settings;

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Tasks run until the transport terminates.
/// Only an explicit goaway() drains requests and closes the transport.
pub struct H3Connection<T: Transport> {
    transport: Arc<T>,
    settings: Arc<Settings>,
    qpack: Arc<Qpack<T>>,
    cursor: Arc<StreamCursor>,
    goaway_write: qbase::ArcReceiving<Result<()>>,
    bi_streams: Arc<BiStreams<T::StreamReader, T::StreamWriter>>,
}

impl<T: Transport> H3Connection<T> {
    /// Start HTTP/3 using the supplied settings and the transport's endpoint role.
    /// Panics if called outside a Tokio runtime.
    pub fn new(transport: T, settings: Settings) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let bi = Arc::new(BiStreams::new());
        let qpack = Qpack::new(transport.clone(), &settings, bi.clone())?;
        let (cursor, goaway_write) = StreamCursor::new(
            transport.clone(),
            settings.clone(),
            qpack.clone(),
            bi.clone(),
        );
        let connection = Self {
            transport,
            settings,
            qpack,
            cursor,
            goaway_write,
            bi_streams: bi,
        };
        uni::spawn(connection.clone());
        Ok(connection)
    }

    /// Compression state shared by messages on this connection.
    pub fn qpack(&self) -> &Arc<Qpack<T>> {
        &self.qpack
    }

    /// Open a bidirectional stream, returning (send, receive).
    pub async fn open_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::StreamWriter, T::StreamReader>,
        H3ReadStream<T::StreamReader, T::StreamWriter>,
    )> {
        let (id, (recv, send)) = self
            .transport
            .open_bi()
            .await?
            .ok_or(Error::H3_STREAM_CREATION_ERROR)?;
        self.bi_streams.insert(id, recv, send)
    }

    /// Consume this connection and exchange GOAWAY with the peer.
    /// Writes GOAWAY, waits for the peer and admitted requests, then closes QUIC.
    pub async fn goaway(self) -> Result<()> {
        self.cursor.goaway()?;
        let transport = self.transport.as_ref();
        tokio::select! {
            biased;
            result = async {
                self.goaway_write.clone().await
                    .map_err(|_| Error::H3_INTERNAL_ERROR)?
                    .ok_or(Error::H3_INTERNAL_ERROR)??;
                self.cursor.peer_goaway().await?;
                self.bi_streams.drained(self.bi_streams.running()).await;
                transport.close(Error::H3_NO_ERROR.to_string(), Error::H3_NO_ERROR.as_u64())?;
                Ok::<_, Error>(())
            } => result?,
            error = transport.terminated() => return Err(error),
        }
        Ok(())
    }
}

impl<T: Transport> H3Connection<T> {
    /// Accept and register one peer bidirectional stream, returning (write, read).
    /// The application drives acceptance; no background request queue is maintained.
    pub async fn accept_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::StreamWriter, T::StreamReader>,
        H3ReadStream<T::StreamReader, T::StreamWriter>,
    )> {
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
            goaway_write: self.goaway_write.clone(),
            bi_streams: self.bi_streams.clone(),
        }
    }
}
