use std::sync::Arc;

use qbase::varint::VARINT_MAX;
use tokio::{sync::Notify, task::JoinHandle};

use super::{
    frame,
    qpack::{self, Qpack},
    stream::{H3ReadStream, H3WriteStream, UniStreams, bi::BiStreams},
};
use crate::{Error, Result, Transport};

mod goaway;
mod settings;

pub(crate) use goaway::Goaway;
use goaway::send_goaway;
pub use settings::Settings;

#[cfg(test)]
mod tests;

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Dropping the connection closes it and stops its driver.
pub struct H3Connection<T: Transport> {
    transport: Arc<T>,
    uni: Arc<UniStreams>,
    bi: Arc<BiStreams<T::Recv, T::Send>>,
    shutdown: Arc<Notify>,
    task: JoinHandle<()>,
}

impl<T: Transport> H3Connection<T> {
    /// Start HTTP/3 using default settings and the transport's endpoint role.
    /// Panics if called outside a Tokio runtime.
    pub fn new(transport: T) -> Self {
        Self::with_settings(transport, Settings::default()).expect("valid default HTTP/3 settings")
    }

    pub fn with_settings(transport: T, settings: Settings) -> Result<Self> {
        let (local, max_fields) = qpack::limits(&settings.local);
        let qpack = Arc::new(Qpack::new(
            local,
            qpack::Settings::default(),
            frame::MAX_BUFFERED_FRAME_PAYLOAD,
        )?);
        qpack.local_limit(max_fields);
        let transport = Arc::new(transport);
        let uni = Arc::new(UniStreams::new(settings, qpack));
        let bi = Arc::new(BiStreams::default());
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn({
            let bi = Arc::clone(&bi);
            let transport = Arc::clone(&transport);
            let uni = Arc::clone(&uni);
            let shutdown = Arc::clone(&shutdown);
            async move {
                let _ = process_connection(transport.as_ref(), &uni, &bi, &shutdown).await;
            }
        });
        Ok(Self {
            transport,
            uni,
            bi,
            shutdown,
            task,
        })
    }

    /// Open a bidirectional stream, returning (send, receive).
    pub async fn open_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::Send, T::Recv>,
        H3ReadStream<T::Recv, T::Send>,
    )> {
        self.error().map_or(Ok(()), Err)?;
        if self.uni.goaway.is_draining() {
            return Err(Error::H3_REQUEST_REJECTED);
        }
        let stream = tokio::select! {
            biased;
            error = self.uni.qpack.terminated() => return Err(error),
            _ = self.uni.goaway.draining() => return Err(Error::H3_REQUEST_REJECTED),
            _ = self.uni.goaway.received() => return Err(Error::H3_REQUEST_REJECTED),
            stream = self.transport.open_bi_stream() => stream?,
        }
        .ok_or(Error::H3_STREAM_CREATION_ERROR)?;
        // Admission and the transition to draining share this lock. The driver
        // cannot observe an empty connection while a stream is being admitted.
        let state = self.uni.goaway.state.lock().unwrap();
        if state.local().or(state.peer()).is_some() {
            reject_stream::<T>(stream);
            return Err(Error::H3_REQUEST_REJECTED);
        }
        self.insert(stream)
    }

    /// Accept a bidirectional stream, returning (send, receive), before parsing HTTP.
    pub async fn accept_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::Send, T::Recv>,
        H3ReadStream<T::Recv, T::Send>,
    )> {
        self.error().map_or(Ok(()), Err)?;
        if self.uni.goaway.state.lock().unwrap().local().is_some() {
            return Err(Error::H3_REQUEST_REJECTED);
        }
        let stream = tokio::select! {
            biased;
            error = self.uni.qpack.terminated() => return Err(error),
            _ = self.uni.goaway.draining() => return Err(Error::H3_REQUEST_REJECTED),
            stream = self.transport.accept_bi_stream() => stream?,
        };
        if stream.0 > VARINT_MAX || !stream.0.is_multiple_of(4) {
            return Err(Error::H3_ID_ERROR);
        }
        let mut state = self.uni.goaway.state.lock().unwrap();
        if state.local().is_some() {
            reject_stream::<T>(stream);
            return Err(Error::H3_REQUEST_REJECTED);
        }
        let id = stream.0;
        let halves = self.insert(stream)?;
        state.accept(id)?;
        Ok(halves)
    }

    #[expect(
        clippy::type_complexity,
        reason = "Transport tuple keeps both halves and their ID together"
    )]
    fn insert(
        &self,
        (id, (recv, send)): (u64, (T::Recv, T::Send)),
    ) -> Result<(
        H3WriteStream<T::Send, T::Recv>,
        H3ReadStream<T::Recv, T::Send>,
    )> {
        if id > VARINT_MAX || !id.is_multiple_of(4) {
            return Err(Error::H3_ID_ERROR);
        }
        let stopped = T::send_stopped(&send);
        let (send, recv) = self.bi.insert(id, recv, send)?;
        let send = match stopped {
            Some(stopped) => send.with_stop_signal(stopped),
            None => send,
        };
        Ok((send, recv))
    }

    pub fn error(&self) -> Option<Error> {
        self.uni.qpack.error()
    }

    /// Explicitly close the QUIC connection. H3_NO_ERROR stops new request streams,
    /// sends GOAWAY, and waits for admitted streams to finish in the background.
    /// Other errors terminate QUIC immediately. Use closed() to wait.
    pub fn close(&self, error: Error) {
        if error == Error::H3_NO_ERROR && self.error().is_none() {
            match self.uni.goaway.begin_draining() {
                Ok(()) => {
                    self.shutdown.notify_one();
                    return;
                }
                Err(error) => {
                    close_connection(self.transport.as_ref(), &self.uni.qpack, &self.bi, error);
                    return;
                }
            }
        }
        close_connection(self.transport.as_ref(), &self.uni.qpack, &self.bi, error);
    }

    /// Wait until the transport connection has terminated.
    /// This wait does not initiate transport closure.
    pub async fn closed(&self) -> Result<()> {
        let error = self.transport.terminated().await;
        finish_connection(&self.uni.qpack, &self.bi, error)
    }

    /// Start draining and wait for the driver to finish writing GOAWAY.
    /// After admitted streams finish, keep the QUIC connection and its critical
    /// streams alive until transport termination, such as its configured idle timeout.
    /// Cancelling this wait does not cancel GOAWAY. Use close() to explicitly close QUIC.
    pub async fn goaway(&self) -> Result<()> {
        self.error().map_or(Ok(()), Err)?;
        self.uni.goaway.begin_draining()?;
        self.uni.goaway.written(&self.uni.qpack).await
    }
}

async fn process_connection<T: Transport>(
    transport: &T,
    uni: &UniStreams,
    bi: &BiStreams<T::Recv, T::Send>,
    shutdown: &Notify,
) -> Result<()> {
    uni.qpack.error().map_or(Ok(()), Err)?;
    // Keep critical streams alive until the transport is closed. Dropping them
    // first would expose FIN to the peer as H3_CLOSED_CRITICAL_STREAM.
    let send = uni.send(transport);
    let receive = uni.receive(transport, bi);
    tokio::pin!(send, receive);
    let error = tokio::select! {
        biased;
        error = transport.terminated() => return finish_connection(&uni.qpack, bi, error),
        error = uni.qpack.terminated() => error,
        result = &mut send => result.err().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM),
        result = &mut receive => result.err().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM),
        result = finish_close(uni, bi, shutdown) => result.err().unwrap_or(Error::H3_NO_ERROR),
        result = drain_connection(transport, uni, bi) => result.unwrap_err(),
    };
    close_connection(transport, &uni.qpack, bi, error);
    if error == Error::H3_NO_ERROR {
        Ok(())
    } else {
        Err(error)
    }
}

async fn finish_close<R, W>(
    uni: &UniStreams,
    bi: &BiStreams<R, W>,
    shutdown: &Notify,
) -> Result<()> {
    shutdown.notified().await;
    uni.goaway.written(&uni.qpack).await?;
    bi.drained().await;
    Ok(())
}

async fn drain_connection<T: Transport>(
    transport: &T,
    uni: &UniStreams,
    bi: &BiStreams<T::Recv, T::Send>,
) -> Result<()> {
    uni.goaway.draining().await;
    // Finishing HTTP/3 work must not end the critical-stream driver or close QUIC.
    tokio::try_join!(
        async {
            send_goaway(uni).await?;
            bi.drained().await;
            Ok(())
        },
        reject_new_streams(transport),
    )?;
    Ok(())
}

async fn reject_new_streams<T: Transport>(transport: &T) -> Result<()> {
    loop {
        reject_stream::<T>(transport.accept_bi_stream().await?);
        tokio::task::yield_now().await;
    }
}

fn reject_stream<T: Transport>((_, (mut recv, mut send)): (u64, (T::Recv, T::Send))) {
    T::stop(&mut recv, Error::H3_REQUEST_REJECTED.as_u64());
    T::cancel(&mut send, Error::H3_REQUEST_REJECTED.as_u64());
}

fn close_connection<T: Transport>(
    transport: &T,
    qpack: &Qpack,
    bi: &BiStreams<T::Recv, T::Send>,
    error: Error,
) {
    qpack.close(error);
    let error = qpack.error().unwrap_or(error);
    let _ = transport.close(error.to_string(), error.as_u64());
    bi.close(error);
}

fn finish_connection<R, W>(qpack: &Qpack, bi: &BiStreams<R, W>, error: Error) -> Result<()> {
    qpack.close(error);
    let error = qpack.error().unwrap_or(error);
    bi.close(error);
    if error == Error::H3_NO_ERROR {
        Ok(())
    } else {
        Err(error)
    }
}

impl<T: Transport> Drop for H3Connection<T> {
    fn drop(&mut self) {
        close_connection(
            self.transport.as_ref(),
            &self.uni.qpack,
            &self.bi,
            Error::H3_NO_ERROR,
        );
        self.task.abort();
    }
}
