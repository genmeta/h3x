use std::{collections::VecDeque, error::Error};

use futures::{SinkExt as _, StreamExt as _};

use crate::{
    quic,
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
    let mut queue = VecDeque::new();
    let mut inbound_closed = false;

    loop {
        if let Some(command) = queue.pop_front() {
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
                                }
                            }
                        }
                    }
                }
            };

            let terminal = matches!(
                event,
                ReadEvent::Eos | ReadEvent::ErrReset { .. } | ReadEvent::ErrConn
            );
            send_read_event(&mut bridge, event).await;
            if terminal {
                return;
            }
            continue;
        }

        if inbound_closed {
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

async fn send_read_event<Io, E>(bridge: &mut Io, event: ReadEvent)
where
    Io: FrameIo<ReadEvent, ReadCommand, E> + Unpin,
    E: Error + 'static,
{
    if let Err(error) = bridge.send(event).await {
        let report = snafu::Report::from_error(&error);
        tracing::debug!(error = %report, "stream frame read bridge output failed");
    }
}
