use std::{collections::VecDeque, error::Error};

use bytes::Bytes;
use futures::{SinkExt as _, StreamExt as _};
use snafu::Snafu;

use crate::{
    quic,
    rpc::stream::{
        frame::{WriteCommand, WriteEvent},
        io::FrameIo,
    },
    varint::VarInt,
};

#[derive(Debug, Snafu)]
#[snafu(module)]
enum WriteBridgeProtocolError {
    #[snafu(display("received reset code {actual} after committed reset code {expected}"))]
    ConflictingReset { expected: VarInt, actual: VarInt },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HyperWriteJob {
    Push { data: Bytes },
    Flush,
    Eos,
    Reset { code: VarInt },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HyperWriteDone {
    Push,
    Flush,
    Eos,
    Reset { code: VarInt },
}

pub(crate) async fn run_write_bridge<W, Io, E>(mut writer: W, mut bridge: Io)
where
    W: quic::WriteStream + Unpin,
    Io: FrameIo<WriteEvent, WriteCommand, E> + Send + Unpin,
    E: Error + Send + 'static,
{
    send_write_event(&mut bridge, WriteEvent::Pull).await;

    let mut queue = VecDeque::new();
    let mut reset_code = None;
    let mut inbound_closed = false;

    loop {
        if let Some(job) = queue.pop_front() {
            let done = {
                let mut current = Box::pin(run_write_job(&mut writer, job));
                loop {
                    tokio::select! {
                        result = &mut current => break result,
                        inbound = bridge.next(), if !inbound_closed => {
                            match inbound {
                                Some(Ok(command)) => {
                                    if !record_command(&mut queue, &mut reset_code, command) {
                                        return;
                                    }
                                }
                                Some(Err(error)) => {
                                    let report = snafu::Report::from_error(&error);
                                    tracing::warn!(error = %report, "stream frame write bridge input failed");
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

            match done {
                Ok(HyperWriteDone::Push) => {
                    if should_send_credit(inbound_closed, reset_code, &queue) {
                        send_write_event(&mut bridge, WriteEvent::Pull).await;
                    }
                }
                Ok(HyperWriteDone::Flush) => {
                    send_write_event(&mut bridge, WriteEvent::FlushAck).await;
                }
                Ok(HyperWriteDone::Eos) => {
                    send_write_event(&mut bridge, WriteEvent::EosAck).await;
                    return;
                }
                Ok(HyperWriteDone::Reset { code }) => {
                    send_write_event(&mut bridge, WriteEvent::ResetAck { code }).await;
                    return;
                }
                Err(quic::StreamError::Reset { code }) => {
                    send_write_event(&mut bridge, WriteEvent::ErrReset { code }).await;
                    return;
                }
                Err(quic::StreamError::Connection { .. }) => {
                    send_write_event(&mut bridge, WriteEvent::ErrConn).await;
                    return;
                }
            }
            continue;
        }

        if inbound_closed {
            return;
        }

        match bridge.next().await {
            Some(Ok(command)) => {
                if !record_command(&mut queue, &mut reset_code, command) {
                    return;
                }
            }
            Some(Err(error)) => {
                let report = snafu::Report::from_error(&error);
                tracing::warn!(error = %report, "stream frame write bridge input failed");
                return;
            }
            None => inbound_closed = true,
        }
    }
}

fn record_command(
    queue: &mut VecDeque<HyperWriteJob>,
    reset_code: &mut Option<VarInt>,
    command: WriteCommand,
) -> bool {
    match command {
        WriteCommand::Push { data } => {
            if reset_code.is_none() && !has_terminal(queue) {
                queue.push_back(HyperWriteJob::Push { data });
            }
            true
        }
        WriteCommand::Flush => {
            if reset_code.is_none() && !has_terminal(queue) {
                queue.push_back(HyperWriteJob::Flush);
            }
            true
        }
        WriteCommand::Eos => {
            if reset_code.is_none() && !has_terminal(queue) {
                queue.push_back(HyperWriteJob::Eos);
            }
            true
        }
        WriteCommand::Reset { code } => match *reset_code {
            Some(committed) if committed == code => true,
            Some(expected) => {
                let error = WriteBridgeProtocolError::ConflictingReset {
                    expected,
                    actual: code,
                };
                let report = snafu::Report::from_error(&error);
                tracing::warn!(error = %report, "stream frame write bridge input failed");
                false
            }
            None => {
                *reset_code = Some(code);
                queue.clear();
                queue.push_back(HyperWriteJob::Reset { code });
                true
            }
        },
    }
}

fn has_terminal(queue: &VecDeque<HyperWriteJob>) -> bool {
    queue
        .iter()
        .any(|job| matches!(job, HyperWriteJob::Eos | HyperWriteJob::Reset { .. }))
}

fn should_send_credit(
    inbound_closed: bool,
    reset_code: Option<VarInt>,
    queue: &VecDeque<HyperWriteJob>,
) -> bool {
    !inbound_closed && reset_code.is_none() && !has_terminal(queue)
}

async fn run_write_job<W>(
    writer: &mut W,
    job: HyperWriteJob,
) -> Result<HyperWriteDone, quic::StreamError>
where
    W: quic::WriteStream + Unpin,
{
    match job {
        HyperWriteJob::Push { data } => {
            writer.send(data).await?;
            Ok(HyperWriteDone::Push)
        }
        HyperWriteJob::Flush => {
            writer.flush().await?;
            Ok(HyperWriteDone::Flush)
        }
        HyperWriteJob::Eos => {
            writer.close().await?;
            Ok(HyperWriteDone::Eos)
        }
        HyperWriteJob::Reset { code } => {
            quic::ResetStreamExt::reset(writer, code).await?;
            Ok(HyperWriteDone::Reset { code })
        }
    }
}

async fn send_write_event<Io, E>(bridge: &mut Io, event: WriteEvent)
where
    Io: FrameIo<WriteEvent, WriteCommand, E> + Unpin,
    E: Error + 'static,
{
    if let Err(error) = bridge.send(event).await {
        let report = snafu::Report::from_error(&error);
        tracing::debug!(error = %report, "stream frame write bridge output failed");
    }
}
