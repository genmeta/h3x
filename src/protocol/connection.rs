use std::sync::{Arc, Mutex};

use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::sync::mpsc;

use super::{
    qpack::Qpack,
    stream::{
        H3ReadStream, H3WriteStream,
        bi::{BiStreams, Halves},
        uni,
    },
};
use crate::{Error, Result, Transport};

mod goaway;
mod settings;

pub(crate) use goaway::StreamCursor;
pub use settings::Settings;

#[cfg(test)]
mod tests;

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Dropping the connection closes its transport.
/// Successful goaway() transfers draining and termination to the control reader.
pub struct H3Connection<T: Transport> {
    transport: Option<Arc<T>>,
    settings: Arc<Settings>,
    qpack: Arc<Qpack<T>>,
    cursor: Arc<Mutex<StreamCursor>>,
    bi: Arc<BiStreams<T::Recv, T::Send>>,
}

impl<T: Transport> H3Connection<T> {
    /// Start HTTP/3 using default settings and the transport's endpoint role.
    /// Panics if called outside a Tokio runtime.
    pub fn new(transport: T) -> Self {
        Self::with_settings(transport, Settings::default()).expect("valid default HTTP/3 settings")
    }

    pub fn with_settings(transport: T, settings: Settings) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let (bi, incoming) = BiStreams::new();
        let bi = Arc::new(bi);
        let qpack = Qpack::new(transport.clone(), &settings, bi.clone())?;
        let cursor = StreamCursor::new(
            transport.clone(),
            settings.clone(),
            qpack.clone(),
            bi.clone(),
        );
        let connection = Self {
            transport: Some(transport),
            settings,
            qpack,
            cursor,
            bi,
        };
        tokio::spawn({
            let (transport, settings, qpack, cursor, bi) = (
                connection.transport.as_ref().unwrap().clone(),
                connection.settings.clone(),
                connection.qpack.clone(),
                connection.cursor.clone(),
                connection.bi.clone(),
            );
            async move { uni::receive(&transport, &settings, &qpack, &cursor, &bi).await }
        });
        tokio::spawn({
            let (transport, cursor, bi) = (
                connection.transport.as_ref().unwrap().clone(),
                connection.cursor.clone(),
                connection.bi.clone(),
            );
            async move { accept_bi(transport.as_ref(), &cursor, &bi, incoming).await }
        });
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
        H3WriteStream<T::Send, T::Recv>,
        H3ReadStream<T::Recv, T::Send>,
    )> {
        let (id, (recv, send)) = self
            .transport
            .as_ref()
            .unwrap()
            .open_bi_stream()
            .await?
            .ok_or(Error::H3_STREAM_CREATION_ERROR)?;
        self.bi.insert(id, recv, send)
    }

    /// Take a stream admitted by the background accept task, returning (send, receive).
    pub async fn accept_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::Send, T::Recv>,
        H3ReadStream<T::Recv, T::Send>,
    )> {
        self.bi.accept().await
    }

    pub fn error(&self) -> Option<Error> {
        self.qpack.error()
    }

    /// Consume this connection and exchange GOAWAY with the peer.
    /// Returns after our frame is written and the peer's GOAWAY is received.
    /// The control reader then closes QUIC once the admitted requests finish.
    /// Dropping this future before completion closes the connection immediately.
    pub async fn goaway(mut self) -> Result<()> {
        let wake = self.cursor.lock().unwrap().goaway()?;
        if let Some(wake) = wake {
            wake.wake();
        }
        let transport = self.transport.as_ref().unwrap();
        tokio::select! {
            biased;
            result = async {
                StreamCursor::written(&self.cursor).await?;
                StreamCursor::received(&self.cursor).await;
                Ok::<_, Error>(())
            } => result?,
            error = transport.terminated() => return Err(error),
        }
        self.transport.take();
        Ok(())
    }
}

async fn accept_bi<T: Transport>(
    transport: &T,
    cursor: &Mutex<StreamCursor>,
    bi: &BiStreams<T::Recv, T::Send>,
    incoming: mpsc::UnboundedSender<Result<Halves<T::Recv, T::Send>>>,
) {
    loop {
        let (id, (mut recv, mut send)) = match transport.accept_bi_stream().await {
            Ok(stream) => stream,
            Err(error) => {
                let _ = incoming.send(Err(error));
                return;
            }
        };
        let mut state = cursor.lock().unwrap();
        if let Err(error) = state.accept(id) {
            drop(state);
            recv.stop(Error::H3_REQUEST_REJECTED.as_u64());
            send.cancel(Error::H3_REQUEST_REJECTED.as_u64());
            let _ = incoming.send(Err(error));
            return;
        }
        // Admission, registration, and delivery share the cursor lock with GOAWAY.
        match bi.insert(id, recv, send) {
            Ok(stream) => {
                if incoming.send(Ok(stream)).is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = incoming.send(Err(error));
                return;
            }
        }
    }
}

pub(super) fn close_connection<T: Transport>(
    transport: &T,
    qpack: &Qpack<T>,
    bi: &BiStreams<T::Recv, T::Send>,
    error: Error,
) {
    let error = qpack.close(error);
    let _ = transport.close(error.to_string(), error.as_u64());
    bi.close(error);
}

pub(super) fn finish_connection<T: Transport>(
    qpack: &Qpack<T>,
    bi: &BiStreams<T::Recv, T::Send>,
    error: Error,
) {
    let error = qpack.close(error);
    bi.close(error);
}

impl<T: Transport> Drop for H3Connection<T> {
    fn drop(&mut self) {
        self.bi.release_incoming();
        if let Some(transport) = &self.transport {
            close_connection(
                transport.as_ref(),
                &self.qpack,
                &self.bi,
                Error::H3_NO_ERROR,
            );
        }
    }
}
