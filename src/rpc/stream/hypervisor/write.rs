use std::{collections::VecDeque, error::Error, pin::Pin, task::Poll};

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
enum WriteHypervisorProtocolError {
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
                    if should_send_credit(inbound_closed, reset_code, &queue)
                        && !send_write_credit(
                            &mut bridge,
                            &mut queue,
                            &mut reset_code,
                            &mut inbound_closed,
                        )
                        .await
                    {
                        return;
                    }
                }
                Ok(HyperWriteDone::Flush) => {
                    send_write_event(&mut bridge, WriteEvent::FlushAck).await;
                    if should_send_credit(inbound_closed, reset_code, &queue)
                        && !send_write_credit(
                            &mut bridge,
                            &mut queue,
                            &mut reset_code,
                            &mut inbound_closed,
                        )
                        .await
                    {
                        return;
                    }
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
                let error = WriteHypervisorProtocolError::ConflictingReset {
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

enum CreditSendState {
    Ready,
    Flush,
    Done,
}

async fn send_write_credit<Io, E>(
    bridge: &mut Io,
    queue: &mut VecDeque<HyperWriteJob>,
    reset_code: &mut Option<VarInt>,
    inbound_closed: &mut bool,
) -> bool
where
    Io: FrameIo<WriteEvent, WriteCommand, E> + Unpin,
    E: Error + 'static,
{
    let mut state = CreditSendState::Ready;
    futures::future::poll_fn(|cx| {
        if !*inbound_closed {
            match Pin::new(&mut *bridge).poll_next(cx) {
                Poll::Ready(Some(Ok(command))) => {
                    if record_command(queue, reset_code, command) {
                        return Poll::Ready(true);
                    }
                    return Poll::Ready(false);
                }
                Poll::Ready(Some(Err(error))) => {
                    let report = snafu::Report::from_error(&error);
                    tracing::warn!(error = %report, "stream frame write bridge input failed");
                    return Poll::Ready(false);
                }
                Poll::Ready(None) => {
                    *inbound_closed = true;
                    return Poll::Ready(true);
                }
                Poll::Pending => {}
            }
        }

        loop {
            match state {
                CreditSendState::Ready => match Pin::new(&mut *bridge).poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        if let Err(error) = Pin::new(&mut *bridge).start_send(WriteEvent::Pull) {
                            let report = snafu::Report::from_error(&error);
                            tracing::debug!(
                                error = %report,
                                "stream frame write bridge output failed"
                            );
                            state = CreditSendState::Done;
                            return Poll::Ready(true);
                        }
                        state = CreditSendState::Flush;
                    }
                    Poll::Ready(Err(error)) => {
                        let report = snafu::Report::from_error(&error);
                        tracing::debug!(error = %report, "stream frame write bridge output failed");
                        state = CreditSendState::Done;
                        return Poll::Ready(true);
                    }
                    Poll::Pending => return Poll::Pending,
                },
                CreditSendState::Flush => match Pin::new(&mut *bridge).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        state = CreditSendState::Done;
                        return Poll::Ready(true);
                    }
                    Poll::Ready(Err(error)) => {
                        let report = snafu::Report::from_error(&error);
                        tracing::debug!(error = %report, "stream frame write bridge output failed");
                        state = CreditSendState::Done;
                        return Poll::Ready(true);
                    }
                    Poll::Pending => return Poll::Pending,
                },
                CreditSendState::Done => return Poll::Ready(true),
            }
        }
    })
    .await
}
