use std::sync::{Arc, Mutex};

use qbase::varint::{VARINT_MAX, VarInt};
use tokio::{
    sync::{Notify, oneshot},
    task::JoinHandle,
};

use super::{
    frame::{self, Frame, H3Frame},
    qpack::{self, Qpack},
    stream::{H3ReadStream, H3WriteStream, UniStreams, bi::BiStreams},
};
use crate::{Error, Result, Transport};

/// Local advertised settings and the independently received peer settings.
pub struct Settings {
    pub(crate) local: frame::Settings,
    pub(crate) peer: Mutex<Option<frame::Settings>>,
}

impl Settings {
    pub fn new(
        max_field_section_size: u64,
        max_table_capacity: u64,
        blocked_streams: u64,
    ) -> Result<Self> {
        if max_field_section_size > frame::MAX_BUFFERED_FRAME_PAYLOAD as u64
            || max_table_capacity > frame::MAX_BUFFERED_FRAME_PAYLOAD as u64
        {
            return Err(Error::H3_SETTINGS_ERROR);
        }
        let values = [
            (frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, max_table_capacity),
            (
                frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
                max_field_section_size,
            ),
            (frame::SETTINGS_QPACK_BLOCKED_STREAMS, blocked_streams),
        ]
        .into_iter()
        .map(|(id, value)| {
            Ok((
                VarInt::from_u32(id),
                VarInt::try_from(value).map_err(|_| Error::H3_SETTINGS_ERROR)?,
            ))
        })
        .collect::<Result<_>>()?;
        Ok(Self {
            local: frame::Settings { values },
            peer: Mutex::new(None),
        })
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new(65536, 4096, 16).unwrap()
    }
}

#[derive(Default)]
pub(crate) struct GoawayState {
    local: Option<u64>,
    pub(crate) peer: Option<u64>,
    accepted_boundary: u64,
}

#[derive(Default)]
pub(crate) struct Goaway {
    pub(crate) state: Mutex<GoawayState>,
    pub(crate) changed: Notify,
}

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Dropping the connection closes it and stops its driver.
pub struct H3Connection<T: Transport> {
    transport: Arc<T>,
    uni: Arc<UniStreams>,
    bi: Arc<BiStreams<T::Recv, T::Send>>,
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
        let task = tokio::spawn({
            let bi = Arc::clone(&bi);
            let transport = Arc::clone(&transport);
            let uni = Arc::clone(&uni);
            async move {
                let _ = process_connection(transport.as_ref(), &uni, &bi).await;
            }
        });
        Ok(Self {
            transport,
            uni,
            bi,
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
        let changed = self.uni.goaway.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let draining = {
            let state = self.uni.goaway.state.lock().unwrap();
            state.local.or(state.peer).is_some()
        };
        if draining {
            return Err(Error::H3_REQUEST_REJECTED);
        }
        let stream = tokio::select! {
            biased;
            error = self.uni.qpack.terminated() => return Err(error),
            _ = &mut changed => return Err(Error::H3_REQUEST_REJECTED),
            stream = self.transport.open_bi_stream() => stream?,
        }
        .ok_or(Error::H3_STREAM_CREATION_ERROR)?;
        let draining = {
            let state = self.uni.goaway.state.lock().unwrap();
            state.local.or(state.peer).is_some()
        };
        if draining {
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
        let changed = self.uni.goaway.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let accept = self.transport.accept_bi_stream();
        tokio::pin!(accept);
        let stream = loop {
            self.error().map_or(Ok(()), Err)?;
            if self.uni.goaway.state.lock().unwrap().local.is_some() {
                return Err(Error::H3_REQUEST_REJECTED);
            }
            tokio::select! {
                biased;
                error = self.uni.qpack.terminated() => return Err(error),
                _ = &mut changed => {
                    changed.set(self.uni.goaway.changed.notified());
                    changed.as_mut().enable();
                }
                stream = &mut accept => break stream?,
            }
        };
        if stream.0 > VARINT_MAX || !stream.0.is_multiple_of(4) {
            return Err(Error::H3_ID_ERROR);
        }
        {
            let mut state = self.uni.goaway.state.lock().unwrap();
            if state.local.is_some() {
                return Err(Error::H3_REQUEST_REJECTED);
            }
            state.accepted_boundary = state.accepted_boundary.max(stream.0 + 4);
        }
        self.insert(stream)
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
        self.bi.insert(id, recv, send)
    }

    pub fn error(&self) -> Option<Error> {
        self.uni.qpack.error()
    }

    pub fn close(&self, error: Error) {
        close_connection(self.transport.as_ref(), &self.uni.qpack, error);
        self.bi.close(self.uni.qpack.error().unwrap_or(error));
    }

    pub async fn closed(&self) -> Result<()> {
        let error = tokio::select! {
            error = self.uni.qpack.terminated() => error,
            error = self.transport.terminated() => {
                self.close(error); self.error().unwrap_or(error)
        } };
        if error == Error::H3_NO_ERROR {
            Ok(())
        } else {
            Err(error)
        }
    }

    /// Queue GOAWAY and wait for the driver to finish writing it.
    /// Cancelling this wait does not cancel a frame already queued for sending.
    pub async fn goaway(&self) -> Result<()> {
        let permit = tokio::select! {
            biased;
            error = self.uni.qpack.terminated() => return Err(error),
            permit = self.uni.control.sender.reserve() => {
                permit.map_err(|_| self.error().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM))?
            }
        };
        let (completed, completion) = oneshot::channel();
        {
            let mut state = self.uni.goaway.state.lock().unwrap();
            self.error().map_or(Ok(()), Err)?;
            let id = state.accepted_boundary;
            if id > VARINT_MAX || state.local.is_some_and(|previous| id > previous) {
                return Err(Error::H3_ID_ERROR);
            }
            let frame = H3Frame::Goaway(Frame::new(frame::Goaway {
                id: VarInt::try_from(id).unwrap(),
            })?);
            state.local = Some(id);
            permit.send((frame, completed));
        }
        self.uni.goaway.changed.notify_waiters();
        tokio::select! {
            biased;
            error = self.uni.qpack.terminated() => Err(error),
            result = completion => {
                result.unwrap_or_else(|_| Err(self.error().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM)))
            }
        }
    }
}

async fn process_connection<T: Transport>(
    transport: &T,
    uni: &UniStreams,
    bi: &BiStreams<T::Recv, T::Send>,
) -> Result<()> {
    uni.qpack.error().map_or(Ok(()), Err)?;
    let result = tokio::select! {
        biased;
        error = uni.qpack.terminated() => Err(error),
        error = transport.terminated() => Err(error),
        result = uni.send(transport) => result,
        result = uni.receive(transport, bi) => result,
    };
    close_connection(
        transport,
        &uni.qpack,
        result.err().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM),
    );
    bi.close(uni.qpack.error().unwrap_or(Error::H3_INTERNAL_ERROR));
    if result == Err(Error::H3_NO_ERROR) {
        Ok(())
    } else {
        result
    }
}

fn close_connection<T: Transport>(transport: &T, qpack: &Qpack, error: Error) {
    let error = qpack.error().unwrap_or(error);
    qpack.close(error);
    let _ = transport.close(error.to_string(), error.as_u64());
}

impl<T: Transport> Drop for H3Connection<T> {
    fn drop(&mut self) {
        self.close(Error::H3_NO_ERROR);
        self.task.abort();
    }
}

#[cfg(test)]
mod tests;
