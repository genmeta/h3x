//! Unidirectional stream reception and outgoing control/QPACK stream drivers.
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWriteExt};

use super::control::{self, Control, ControlStream};
use crate::{
    Error, Result, Role, Transport,
    protocol::{
        connection::{Goaway, Settings},
        frame::{self, Frame, H3Frame},
        qpack::Qpack,
    },
};

/// Shared state maintained by the control and QPACK streams.
pub(in crate::protocol) struct UniStreams<S> {
    pub(in crate::protocol) settings: Settings,
    pub(in crate::protocol) qpack: Arc<Qpack>,
    pub(in crate::protocol) goaway: Goaway,
    pub(in crate::protocol) control: Control<S>,
}

impl<S> UniStreams<S> {
    pub(in crate::protocol) fn new(settings: Settings, qpack: Arc<Qpack>) -> Self {
        Self {
            settings,
            qpack,
            goaway: Goaway::default(),
            control: Control::default(),
        }
    }

    pub(in crate::protocol) async fn send<T: Transport<Send = S>>(
        &self,
        transport: &T,
    ) -> Result<()> {
        send_uni(transport, &self.settings.local, &self.qpack, &self.control).await
    }

    pub(in crate::protocol) async fn receive<T: Transport<Send = S>>(
        &self,
        transport: &T,
    ) -> Result<()> {
        UniStreamReceiver::new().receive(transport, self).await
    }
}

// Bound the number of streams waiting for their type identifier.
const MAX_PENDING_STREAM_TYPES: usize = 16;

type Receiving<'a, O> = Pin<Box<dyn Future<Output = Result<O>> + Send + 'a>>;

enum CriticalStreamKind {
    Control,
    QpackEncoder,
    QpackDecoder,
}

impl CriticalStreamKind {
    fn slot(&self) -> usize {
        match self {
            Self::Control => 0,
            Self::QpackEncoder => 1,
            Self::QpackDecoder => 2,
        }
    }
}

fn classify_stream_type(stream_type: u64) -> Result<Option<CriticalStreamKind>> {
    match stream_type {
        0 => Ok(Some(CriticalStreamKind::Control)),
        2 => Ok(Some(CriticalStreamKind::QpackEncoder)),
        3 => Ok(Some(CriticalStreamKind::QpackDecoder)),
        1 => Err(Error::H3_ID_ERROR),
        _ => Ok(None),
    }
}

fn read_stream_type<R: AsyncRead + Unpin + Send + 'static>(
    mut recv: R,
) -> Receiving<'static, (u64, R)> {
    Box::pin(async move {
        let stream_type = frame::be_varint(&mut recv)
            .await
            .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?
            .into_u64();
        Ok((stream_type, recv))
    })
}

fn poll_classified_stream<R>(
    stream_type_reads: &mut Vec<Receiving<'_, (u64, R)>>,
    cx: &mut Context<'_>,
) -> Poll<Result<(u64, R)>> {
    for index in 0..stream_type_reads.len() {
        if let Poll::Ready(result) = stream_type_reads[index].as_mut().poll(cx) {
            drop(stream_type_reads.swap_remove(index));
            return Poll::Ready(result);
        }
    }
    Poll::Pending
}

fn poll_critical_stream_receivers(
    critical_stream_receivers: &mut [Option<Receiving<'_, ()>>; 3],
    cx: &mut Context<'_>,
) -> Poll<Result<()>> {
    for receiver in critical_stream_receivers.iter_mut().flatten() {
        if let Poll::Ready(result) = receiver.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
    }
    Poll::Pending
}

/// Owns incoming stream classification and critical-stream receive progress.
struct UniStreamReceiver<'a, T: Transport> {
    stream_type_reads: Vec<Receiving<'static, (u64, T::Recv)>>,
    critical_stream_receivers: [Option<Receiving<'a, ()>>; 3],
}

impl<'a, T: Transport> UniStreamReceiver<'a, T> {
    fn new() -> Self {
        Self {
            stream_type_reads: Vec::new(),
            critical_stream_receivers: [None, None, None],
        }
    }

    async fn receive(mut self, transport: &T, streams: &'a UniStreams<T::Send>) -> Result<()> {
        loop {
            tokio::select! {
                accepted = transport.accept_uni_stream(),
                    if self.stream_type_reads.len() < MAX_PENDING_STREAM_TYPES =>
                {
                    let (_, recv) = accepted?;
                    self.stream_type_reads.push(read_stream_type(recv));
                }
                classified = poll_fn(|cx| {
                    poll_classified_stream(&mut self.stream_type_reads, cx)
                }) => {
                    let (stream_type, mut recv) = classified?;
                    let kind = match classify_stream_type(stream_type)? {
                        Some(kind) => kind,
                        None => {
                            T::stop(&mut recv, Error::H3_NO_ERROR.as_u64());
                            continue;
                        }
                    };
                    let slot = kind.slot();
                    // Each critical stream kind may only be established once.
                    if self.critical_stream_receivers[slot].is_some() {
                        return Err(Error::H3_STREAM_CREATION_ERROR);
                    }
                    self.critical_stream_receivers[slot] =
                        Some(Self::receive_critical_stream(kind, recv, transport.role(), streams));
                }
                result = poll_fn(|cx| {
                    poll_critical_stream_receivers(&mut self.critical_stream_receivers, cx)
                }) => {
                    // Completion of any critical stream ends the connection driver.
                    return result;
                }
            }
        }
    }

    fn receive_critical_stream(
        kind: CriticalStreamKind,
        mut recv: T::Recv,
        role: Role,
        streams: &'a UniStreams<T::Send>,
    ) -> Receiving<'a, ()> {
        Box::pin(async move {
            match kind {
                CriticalStreamKind::Control => {
                    control::receive_control(
                        &mut recv,
                        &role,
                        &streams.settings,
                        &streams.qpack,
                        &streams.goaway,
                    )
                    .await
                }
                CriticalStreamKind::QpackEncoder => streams.qpack.receive_encoder(&mut recv).await,
                CriticalStreamKind::QpackDecoder => streams.qpack.receive_decoder(&mut recv).await,
            }
        })
    }
}

/// Opens and drives the local control and QPACK streams.
async fn send_uni<T: Transport>(
    transport: &T,
    settings: &frame::Settings,
    qpack: &Qpack,
    control: &Control<T::Send>,
) -> Result<()> {
    tokio::try_join!(
        send_control(transport, settings, control),
        send_encoder(transport, qpack),
        send_decoder(transport, qpack),
    )?;
    Ok(())
}

async fn send_control<T: Transport>(
    transport: &T,
    settings: &frame::Settings,
    outgoing: &Control<T::Send>,
) -> Result<()> {
    let mut send = open_stream(transport).await?;
    send.write_all(&[0])
        .await
        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
    let mut control = ControlStream::new(send);
    control
        .write(&H3Frame::Settings(Frame::new(settings.clone())?))
        .await?;
    *outgoing.stream.lock().await = Some(control);
    outgoing.ready.notify_waiters();
    // Keep this driver pending while GOAWAY writes use the published control stream.
    std::future::pending::<Result<()>>().await
}

async fn send_encoder<T: Transport>(transport: &T, qpack: &Qpack) -> Result<()> {
    let mut send = open_stream(transport).await?;
    qpack.send_encoder(&mut send).await
}

async fn send_decoder<T: Transport>(transport: &T, qpack: &Qpack) -> Result<()> {
    let mut send = open_stream(transport).await?;
    qpack.send_decoder(&mut send).await
}

async fn open_stream<T: Transport>(transport: &T) -> Result<T::Send> {
    let (_, send) = transport
        .open_uni_stream()
        .await?
        .ok_or(Error::H3_STREAM_CREATION_ERROR)?;
    Ok(send)
}
