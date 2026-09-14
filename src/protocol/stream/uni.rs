//! Unidirectional stream reception and outgoing control/QPACK stream drivers.
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use super::{
    bi::BiStreams,
    control::{self, Control},
};
use crate::{
    Error, Result, Transport,
    protocol::{
        connection::{Goaway, Settings},
        frame,
        qpack::Qpack,
    },
};

// Bound the number of streams waiting for their type identifier.
const MAX_PENDING_STREAM_TYPES: usize = 16;

type Receiving<'a, O> = Pin<Box<dyn Future<Output = Result<O>> + Send + 'a>>;

/// Shared state maintained by the control and QPACK streams.
pub(crate) struct UniStreams {
    pub(crate) settings: Settings,
    pub(crate) qpack: Arc<Qpack>,
    pub(crate) goaway: Goaway,
    pub(crate) control: Control,
}

impl UniStreams {
    pub(crate) fn new(settings: Settings, qpack: Arc<Qpack>) -> Self {
        Self {
            settings,
            qpack,
            goaway: Goaway::default(),
            control: Control::default(),
        }
    }

    pub(crate) async fn send<T: Transport>(&self, transport: &T) -> Result<()> {
        tokio::try_join!(
            async {
                let mut send = open_stream(transport).await?;
                self.control.send(&mut send, &self.settings.local).await
            },
            async {
                let mut send = open_stream(transport).await?;
                self.qpack.send_encoder(&mut send).await
            },
            async {
                let mut send = open_stream(transport).await?;
                self.qpack.send_decoder(&mut send).await
            },
        )?;
        Ok(())
    }

    pub(crate) async fn receive<T: Transport>(
        &self,
        transport: &T,
        bi: &BiStreams<T::Recv, T::Send>,
    ) -> Result<()> {
        let role = transport.role();
        let mut pending_types: Vec<Receiving<'_, _>> = Vec::new();
        let mut critical: [Option<Receiving<'_, ()>>; 3] = [None, None, None];
        // Keep these futures across select iterations so partial reads are never restarted.
        loop {
            tokio::select! {
                accepted = transport.accept_uni_stream(),
                    if pending_types.len() < MAX_PENDING_STREAM_TYPES =>
                {
                    let (_, mut recv) = accepted?;
                    pending_types.push(Box::pin(async move {
                        // FIN/RESET is stream-local until its full type is known.
                        match frame::be_varint_or_eof(&mut recv).await {
                            Ok(Some(ty)) => Ok(Some((ty.into_u64(), recv))),
                            Ok(None) => Ok(None),
                            Err(error) if T::is_stream_reset(&error) => Ok(None),
                            Err(error) => Err(Error::from(error)),
                        }
                    }));
                }
                classified = poll_fn(|cx| {
                    for index in 0..pending_types.len() {
                        if let Poll::Ready(result) = pending_types[index].as_mut().poll(cx) {
                            drop(pending_types.swap_remove(index));
                            return Poll::Ready(result);
                        }
                    }
                    Poll::Pending
                }) => {
                    let Some((stream_type, mut recv)) = classified? else {
                        continue;
                    };
                    let (slot, receive): (_, Receiving<'_, ()>) = match stream_type {
                        0 => (0, Box::pin(async move {
                            control::receive_control(
                                &mut recv,
                                &role,
                                &self.settings,
                                &self.qpack,
                                &self.goaway,
                                bi,
                            ).await
                        })),
                        2 => (1, Box::pin(async move {
                            self.qpack.receive_encoder(&mut recv).await
                        })),
                        3 => (2, Box::pin(async move {
                            self.qpack.receive_decoder(&mut recv).await
                        })),
                        1 => return Err(Error::H3_ID_ERROR),
                        _ => {
                            T::stop(&mut recv, Error::H3_NO_ERROR.as_u64());
                            continue;
                        }
                    };
                    // Each critical stream kind may only be established once.
                    if critical[slot].is_some() {
                        return Err(Error::H3_STREAM_CREATION_ERROR);
                    }
                    critical[slot] = Some(receive);
                }
                result = poll_fn(|cx| {
                    for receive in critical.iter_mut().flatten() {
                        if let Poll::Ready(result) = receive.as_mut().poll(cx) {
                            return Poll::Ready(result);
                        }
                    }
                    Poll::Pending
                }) => {
                    // Completion of any critical stream ends the connection driver.
                    return result;
                }
            }
        }
    }
}

async fn open_stream<T: Transport>(transport: &T) -> Result<T::Send> {
    let (_, send) = transport
        .open_uni_stream()
        .await?
        .ok_or(Error::H3_STREAM_CREATION_ERROR)?;
    Ok(send)
}
