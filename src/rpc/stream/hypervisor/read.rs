use std::{collections::VecDeque, error::Error};

use futures::{SinkExt as _, StreamExt as _};

use crate::{
    quic::{self, GetStreamIdExt as _},
    rpc::stream::{
        frame::{ReadCommand, ReadEvent},
        io::FrameIo,
    },
};

pub(crate) async fn run_read_bridge<R, Io, E>(mut reader: R, mut bridge: Io)
where
    R: quic::ReadStream + Unpin,
    Io: FrameIo<ReadEvent, ReadCommand, E> + Send + Unpin,
    E: Error + Send + 'static,
{
    let stream_id = match reader.stream_id().await {
        Ok(stream_id) => Some(stream_id),
        Err(error) => {
            tracing::warn!(?error, "QUIC read bridge could not resolve stream id");
            None
        }
    };
    let mut queue = VecDeque::new();
    let mut inbound_closed = false;
    let mut first_push_logged = false;
    let mut event_sequence = 0_u64;

    tracing::trace!(
        boundary = "quic-root",
        stream_id = ?stream_id.map(|id| id.into_inner()),
        "QUIC read bridge started"
    );

    loop {
        if let Some(command) = queue.pop_front() {
            let stop_code = match &command {
                ReadCommand::Stop { code } => {
                    tracing::trace!(
                        boundary = "quic-root",
                        stream_id = ?stream_id.map(|id| id.into_inner()),
                        code = code.into_inner(),
                        "QUIC read bridge stop started"
                    );
                    Some(*code)
                }
                ReadCommand::Pull => None,
            };
            let event = {
                let mut current = Box::pin(run_read_job(&mut reader, command));
                loop {
                    tokio::select! {
                        event = &mut current => break event,
                        inbound = bridge.next(), if !inbound_closed => {
                            match inbound {
                                Some(Ok(command)) => queue.push_back(command),
                                Some(Err(error)) => {
                                    let report = snafu::Report::from_error(&error);
                                    tracing::warn!(error = %report, "stream frame read bridge input failed");
                                    return;
                                }
                                None => {
                                    inbound_closed = true;
                                    tracing::trace!(
                                        boundary = "quic-root",
                                        stream_id = ?stream_id.map(|id| id.into_inner()),
                                        "QUIC read bridge command input reached EOF while read was pending"
                                    );
                                }
                            }
                        }
                    }
                }
            };

            if let ReadEvent::Push { data } = &event
                && !first_push_logged
            {
                first_push_logged = true;
                tracing::trace!(
                    boundary = "quic-root",
                    stream_id = ?stream_id.map(|id| id.into_inner()),
                    bytes = data.len(),
                    "QUIC stream first payload chunk"
                );
            }

            if let Some(code) = stop_code {
                match &event {
                    ReadEvent::StopAck { code: actual } => tracing::trace!(
                        boundary = "quic-root",
                        stream_id = ?stream_id.map(|id| id.into_inner()),
                        code = code.into_inner(),
                        actual = actual.into_inner(),
                        "QUIC read bridge stop completed"
                    ),
                    other => tracing::warn!(
                        boundary = "quic-root",
                        stream_id = ?stream_id.map(|id| id.into_inner()),
                        code = code.into_inner(),
                        event = ?other,
                        "QUIC read bridge stop returned without matching ack"
                    ),
                }
            }

            let terminal = matches!(
                event,
                ReadEvent::Eos | ReadEvent::ErrReset { .. } | ReadEvent::ErrConn
            );
            event_sequence += 1;
            if !send_read_event(&mut bridge, event, stream_id, event_sequence).await {
                tracing::warn!(
                    boundary = "quic-root",
                    stream_id = ?stream_id.map(|id| id.into_inner()),
                    event_sequence,
                    "QUIC read bridge exited after IPC output failure"
                );
                return;
            }
            if terminal {
                tracing::trace!(
                    boundary = "quic-root",
                    stream_id = ?stream_id.map(|id| id.into_inner()),
                    event_sequence,
                    "QUIC read bridge exited after terminal QUIC event"
                );
                return;
            }
            continue;
        }

        if inbound_closed {
            tracing::trace!(
                boundary = "quic-root",
                stream_id = ?stream_id.map(|id| id.into_inner()),
                "QUIC read bridge exited after IPC command EOF"
            );
            return;
        }

        match bridge.next().await {
            Some(Ok(command)) => queue.push_back(command),
            Some(Err(error)) => {
                let report = snafu::Report::from_error(&error);
                tracing::warn!(error = %report, "stream frame read bridge input failed");
                return;
            }
            None => inbound_closed = true,
        }
    }
}

async fn run_read_job<R>(reader: &mut R, command: ReadCommand) -> ReadEvent
where
    R: quic::ReadStream + Unpin,
{
    match command {
        ReadCommand::Pull => match reader.next().await {
            Some(Ok(data)) => ReadEvent::Push { data },
            Some(Err(quic::StreamError::Reset { code })) => ReadEvent::ErrReset { code },
            Some(Err(quic::StreamError::Connection { .. })) => ReadEvent::ErrConn,
            None => ReadEvent::Eos,
        },
        ReadCommand::Stop { code } => match futures::future::poll_fn(|cx| {
            quic::StopStream::poll_stop(std::pin::Pin::new(&mut *reader), cx, code)
        })
        .await
        {
            Ok(()) => ReadEvent::StopAck { code },
            Err(quic::StreamError::Reset { code }) => ReadEvent::ErrReset { code },
            Err(quic::StreamError::Connection { .. }) => ReadEvent::ErrConn,
        },
    }
}

async fn send_read_event<Io, E>(
    bridge: &mut Io,
    event: ReadEvent,
    stream_id: Option<crate::varint::VarInt>,
    event_sequence: u64,
) -> bool
where
    Io: FrameIo<ReadEvent, ReadCommand, E> + Unpin,
    E: Error + 'static,
{
    let (event_kind, bytes) = match &event {
        ReadEvent::Push { data } => ("push", Some(data.len())),
        ReadEvent::Eos => ("eos", None),
        ReadEvent::StopAck { .. } => ("stop-ack", None),
        ReadEvent::ErrReset { .. } => ("reset", None),
        ReadEvent::ErrConn => ("connection-error", None),
    };

    match bridge.send(event).await {
        Ok(()) => {
            tracing::trace!(
                boundary = "quic-root-to-ipc",
                stream_id = ?stream_id.map(|id| id.into_inner()),
                event_sequence,
                event_kind,
                bytes,
                "QUIC read event IPC send completed"
            );
            true
        }
        Err(error) => {
            let report = snafu::Report::from_error(&error);
            tracing::warn!(
                boundary = "quic-root-to-ipc",
                stream_id = ?stream_id.map(|id| id.into_inner()),
                event_sequence,
                event_kind,
                bytes,
                error = %report,
                "QUIC read event IPC send failed"
            );
            false
        }
    }
}
