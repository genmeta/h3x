use std::{
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::Sink;

use super::{
    error::{
        DeferredStreamError, DriverProtocolError, defer_err_conn, latch_frame_io_error,
        latch_protocol_error,
    },
    frame::{WriteCommand, WriteEvent},
    io::FrameIo,
};
use crate::{quic, rpc::lifecycle::LifecycleExt, varint::VarInt};

const WRITE_AFTER_EOS_PANIC: &str = "h3x write data after shutdown";

#[derive(Debug, Clone, PartialEq, Eq)]
enum WriteOperation {
    Push { data: Bytes },
    Flush { generation: u64 },
    Eos { covers_flush: bool },
    Reset { code: VarInt },
}

#[derive(Debug)]
enum SendState<Op> {
    Idle { ready: bool },
    Flush { inflight: Op },
}

impl<Op> Default for SendState<Op> {
    fn default() -> Self {
        Self::Idle { ready: false }
    }
}

#[derive(Debug, Default)]
struct PendingWrite {
    push: Option<Bytes>,
    control: Option<WriteBarrier>,
    reset: Option<VarInt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteBarrier {
    Flush { generation: u64 },
    Eos { covers_flush: bool },
}

#[derive(Debug, Default)]
enum WriterRecvState {
    #[default]
    Idle,
    Await {
        sent: WriterAwaited,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterAwaited {
    Flush { generation: u64 },
    Eos { covers_flush: bool },
    Reset { code: VarInt },
}

#[derive(Debug, Default)]
struct WriterResults {
    credit: bool,
    flush: Option<FlushCompletion>,
    eos: Option<EosAckResult>,
    reset: Option<ResetAckResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushCompletion {
    FlushAck { generation: u64 },
    CoveredByEos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EosAckResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResetAckResult {
    code: VarInt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitResult {
    Committed,
    Duplicate,
    Conflict,
}

enum WriterFault {
    Stream(quic::StreamError),
    Deferred(DeferredStreamError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DriveTerminal {
    None,
    Eos,
    Reset { code: VarInt },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResetDrive {
    Acked,
    CoveredByEos,
}

pin_project_lite::pin_project! {
    #[project = BridgeStreamWriterProj]
    #[project_replace = BridgeStreamWriterReplace]
    pub(crate) enum BridgeStreamWriter<Io, L, E> {
        Active {
            #[pin]
            active: ActiveBridgeStreamWriter<Io, L, E>,
        },
        Eos {
            stream_id: VarInt,
        },
        Reset {
            stream_id: VarInt,
            code: VarInt,
        },
        Closed {
            stream_id: VarInt,
            error: DeferredStreamError,
        },
    }
}

pin_project_lite::pin_project! {
    pub(crate) struct ActiveBridgeStreamWriter<Io, L, E> {
        stream_id: VarInt,
        lifecycle: Arc<L>,
        #[pin]
        bridge: Io,
        pending: PendingWrite,
        send_state: SendState<WriteOperation>,
        recv_state: WriterRecvState,
        results: WriterResults,
        write_generation: u64,
        _error: PhantomData<fn(E)>,
    }
}

impl<Io, L, E> BridgeStreamWriter<Io, L, E> {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "writer construction is wired into bridge assembly by a follow-up task"
        )
    )]
    pub(crate) fn new(stream_id: VarInt, bridge: Io, lifecycle: Arc<L>) -> Self {
        Self::Active {
            active: ActiveBridgeStreamWriter {
                stream_id,
                lifecycle,
                bridge,
                pending: PendingWrite::default(),
                send_state: SendState::default(),
                recv_state: WriterRecvState::default(),
                results: WriterResults::default(),
                write_generation: 0,
                _error: PhantomData,
            },
        }
    }
}

impl<Io, L, E> ActiveBridgeStreamWriter<Io, L, E> {
    fn committed_reset_code(&self) -> Option<VarInt> {
        if let Some(code) = self.pending.reset {
            return Some(code);
        }
        if let SendState::Flush {
            inflight: WriteOperation::Reset { code },
        } = &self.send_state
        {
            return Some(*code);
        }
        if let WriterRecvState::Await {
            sent: WriterAwaited::Reset { code },
        } = self.recv_state
        {
            return Some(code);
        }
        self.results.reset.as_ref().map(|result| result.code)
    }

    fn eos_committed(&self) -> bool {
        matches!(self.pending.control, Some(WriteBarrier::Eos { .. }))
            || matches!(
                self.send_state,
                SendState::Flush {
                    inflight: WriteOperation::Eos { .. }
                }
            )
            || matches!(
                self.recv_state,
                WriterRecvState::Await {
                    sent: WriterAwaited::Eos { .. }
                }
            )
            || self.results.eos.is_some()
    }

    fn eos_started_or_completed(&self) -> bool {
        matches!(
            self.send_state,
            SendState::Flush {
                inflight: WriteOperation::Eos { .. }
            }
        ) || matches!(
            self.recv_state,
            WriterRecvState::Await {
                sent: WriterAwaited::Eos { .. }
            }
        ) || self.results.eos.is_some()
    }

    fn has_unflushed_control_barrier(&self) -> bool {
        self.pending.control.is_some()
            || matches!(
                self.send_state,
                SendState::Flush {
                    inflight: WriteOperation::Flush { .. }
                        | WriteOperation::Eos { .. }
                        | WriteOperation::Reset { .. }
                }
            )
    }

    fn mark_eos_covers_flush_pinned(mut self: Pin<&mut Self>) {
        let mut this = self.as_mut().project();
        if let Some(WriteBarrier::Eos { covers_flush }) = &mut this.pending.control {
            *covers_flush = true;
        }
        if let SendState::Flush {
            inflight: WriteOperation::Eos { covers_flush },
        } = &mut this.send_state
        {
            *covers_flush = true;
        }
        if let WriterRecvState::Await {
            sent: WriterAwaited::Eos { covers_flush },
        } = &mut this.recv_state
        {
            *covers_flush = true;
        }
        if this.results.eos.is_some() {
            this.results.flush = Some(FlushCompletion::CoveredByEos);
        }
    }

    fn flush_committed_for(&self, generation: u64) -> bool {
        matches!(self.pending.control, Some(WriteBarrier::Flush { generation: committed }) if committed >= generation)
            || matches!(
                self.send_state,
                SendState::Flush {
                    inflight: WriteOperation::Flush {
                        generation: committed
                    }
                }
                if committed >= generation
            )
            || matches!(
                self.recv_state,
                WriterRecvState::Await {
                    sent: WriterAwaited::Flush {
                        generation: committed
                    }
                }
                if committed >= generation
            )
            || self.flush_result_covers(generation)
    }

    fn flush_result_covers(&self, generation: u64) -> bool {
        match self.results.flush {
            Some(FlushCompletion::FlushAck {
                generation: committed,
            }) => committed >= generation,
            Some(FlushCompletion::CoveredByEos) => true,
            None => false,
        }
    }

    fn reset_matches_result(&self, code: VarInt) -> bool {
        matches!(self.results.reset, Some(ResetAckResult { code: actual }) if actual == code)
    }

    fn take_flush_result_pinned(
        mut self: Pin<&mut Self>,
        generation: u64,
    ) -> Option<FlushCompletion> {
        let this = self.as_mut().project();
        if match this.results.flush {
            Some(FlushCompletion::FlushAck {
                generation: committed,
            }) => committed >= generation,
            Some(FlushCompletion::CoveredByEos) => true,
            None => false,
        } {
            this.results.flush.take()
        } else {
            None
        }
    }

    fn take_eos_result_pinned(mut self: Pin<&mut Self>) -> Option<EosAckResult> {
        self.as_mut().project().results.eos.take()
    }

    fn take_reset_result_pinned(mut self: Pin<&mut Self>, code: VarInt) -> Option<ResetAckResult> {
        let this = self.as_mut().project();
        match this.results.reset {
            Some(result) if result.code == code => this.results.reset.take(),
            _ => None,
        }
    }

    fn commit_flush_pinned(mut self: Pin<&mut Self>) -> (CommitResult, u64) {
        let generation = self.as_ref().get_ref().write_generation;
        if self.as_ref().get_ref().committed_reset_code().is_some() {
            return (CommitResult::Duplicate, generation);
        }
        if self.as_ref().get_ref().eos_committed() {
            self.as_mut().mark_eos_covers_flush_pinned();
            return (CommitResult::Duplicate, generation);
        }
        if self.as_ref().get_ref().flush_committed_for(generation) {
            return (CommitResult::Duplicate, generation);
        }
        self.as_mut().project().pending.control = Some(WriteBarrier::Flush { generation });
        (CommitResult::Committed, generation)
    }

    fn commit_eos_pinned(mut self: Pin<&mut Self>) -> CommitResult {
        if self.as_ref().get_ref().committed_reset_code().is_some() {
            return CommitResult::Duplicate;
        }
        if self.as_ref().get_ref().eos_committed() {
            return CommitResult::Duplicate;
        }

        let this = self.as_mut().project();
        this.results.credit = false;
        match this.pending.control {
            Some(WriteBarrier::Flush { .. }) => {
                this.pending.control = Some(WriteBarrier::Eos { covers_flush: true });
            }
            Some(WriteBarrier::Eos { .. }) => return CommitResult::Duplicate,
            None => {
                this.pending.control = Some(WriteBarrier::Eos {
                    covers_flush: false,
                });
            }
        }
        CommitResult::Committed
    }

    fn commit_reset_pinned(mut self: Pin<&mut Self>, code: VarInt) -> CommitResult {
        if self.as_ref().get_ref().eos_started_or_completed() {
            return CommitResult::Duplicate;
        }
        match self.as_ref().get_ref().committed_reset_code() {
            Some(committed) if committed == code => CommitResult::Duplicate,
            Some(_committed) => CommitResult::Conflict,
            None => {
                let this = self.as_mut().project();
                this.pending.push = None;
                this.pending.control = None;
                this.pending.reset = Some(code);
                this.results.credit = false;
                CommitResult::Committed
            }
        }
    }
}

impl<Io, L, E> ActiveBridgeStreamWriter<Io, L, E>
where
    L: LifecycleExt + 'static,
    Io: FrameIo<WriteCommand, WriteEvent, E>,
    quic::ConnectionError: From<E>,
{
    fn protocol_fault_for(lifecycle: &Arc<L>, error: DriverProtocolError) -> WriterFault {
        WriterFault::Stream(latch_protocol_error(lifecycle.as_ref(), error))
    }

    fn frame_io_fault_for(lifecycle: &Arc<L>, error: E) -> WriterFault {
        WriterFault::Stream(latch_frame_io_error(lifecycle.as_ref(), error))
    }

    fn commit_push_pinned(mut self: Pin<&mut Self>, data: Bytes) -> Result<(), quic::StreamError> {
        if self.as_ref().get_ref().eos_committed() {
            panic!("{WRITE_AFTER_EOS_PANIC}");
        }
        if let Some(code) = self.as_ref().get_ref().committed_reset_code() {
            return Err(quic::StreamError::Reset { code });
        }

        let this = self.as_mut().project();
        if !this.results.credit || this.pending.push.is_some() {
            return Err(latch_protocol_error(
                this.lifecycle.as_ref(),
                DriverProtocolError::StartSendWithoutCredit,
            ));
        }
        this.results.credit = false;
        *this.write_generation += 1;
        this.pending.push = Some(data);
        Ok(())
    }

    fn poll_bridge_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), WriterFault>> {
        let mut this = self.as_mut().project();
        match &mut *this.send_state {
            SendState::Idle { ready: true } => Poll::Ready(Ok(())),
            SendState::Idle { ready } => match ready!(this.bridge.as_mut().poll_ready(cx)) {
                Ok(()) => {
                    *ready = true;
                    Poll::Ready(Ok(()))
                }
                Err(error) => Poll::Ready(Err(Self::frame_io_fault_for(this.lifecycle, error))),
            },
            SendState::Flush { .. } => unreachable!("cannot ready writer sink while flushing"),
        }
    }

    fn start_operation_pinned(
        mut self: Pin<&mut Self>,
        operation: WriteOperation,
    ) -> Result<(), WriterFault> {
        let command = match &operation {
            WriteOperation::Push { data } => WriteCommand::Push { data: data.clone() },
            WriteOperation::Flush { .. } => WriteCommand::Flush,
            WriteOperation::Eos { .. } => WriteCommand::Eos,
            WriteOperation::Reset { code } => WriteCommand::Reset { code: *code },
        };

        let mut this = self.as_mut().project();
        match this.bridge.as_mut().start_send(command) {
            Ok(()) => {
                *this.send_state = SendState::Flush {
                    inflight: operation,
                };
                Ok(())
            }
            Err(error) => Err(Self::frame_io_fault_for(this.lifecycle, error)),
        }
    }

    fn poll_send_progress(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), WriterFault>> {
        loop {
            if matches!(self.as_ref().get_ref().send_state, SendState::Flush { .. }) {
                let mut this = self.as_mut().project();
                match ready!(this.bridge.as_mut().poll_flush(cx)) {
                    Ok(()) => {
                        let sent = match std::mem::replace(
                            this.send_state,
                            SendState::Idle { ready: false },
                        ) {
                            SendState::Flush { inflight } => inflight,
                            SendState::Idle { .. } => unreachable!("flush state checked above"),
                        };
                        match sent {
                            WriteOperation::Push { .. } => continue,
                            WriteOperation::Flush { generation } => {
                                *this.recv_state = WriterRecvState::Await {
                                    sent: WriterAwaited::Flush { generation },
                                };
                                return Poll::Ready(Ok(()));
                            }
                            WriteOperation::Eos { covers_flush } => {
                                *this.recv_state = WriterRecvState::Await {
                                    sent: WriterAwaited::Eos { covers_flush },
                                };
                                return Poll::Ready(Ok(()));
                            }
                            WriteOperation::Reset { code } => {
                                *this.recv_state = WriterRecvState::Await {
                                    sent: WriterAwaited::Reset { code },
                                };
                                return Poll::Ready(Ok(()));
                            }
                        }
                    }
                    Err(error) => {
                        return Poll::Ready(Err(Self::frame_io_fault_for(this.lifecycle, error)));
                    }
                }
            }

            if self.as_ref().get_ref().pending.push.is_some()
                && !matches!(
                    self.as_ref().get_ref().recv_state,
                    WriterRecvState::Await {
                        sent: WriterAwaited::Eos { .. } | WriterAwaited::Reset { .. }
                    }
                )
            {
                ready!(self.as_mut().poll_bridge_ready(cx))?;
                let data = self
                    .as_mut()
                    .project()
                    .pending
                    .push
                    .take()
                    .expect("pending push should exist");
                self.as_mut()
                    .start_operation_pinned(WriteOperation::Push { data })?;
                continue;
            }

            if matches!(
                self.as_ref().get_ref().recv_state,
                WriterRecvState::Await { .. }
            ) {
                return Poll::Ready(Ok(()));
            }

            if let Some(code) = self.as_ref().get_ref().pending.reset {
                ready!(self.as_mut().poll_bridge_ready(cx))?;
                self.as_mut().project().pending.reset = None;
                self.as_mut()
                    .start_operation_pinned(WriteOperation::Reset { code })?;
                continue;
            }

            if let Some(control) = self.as_ref().get_ref().pending.control {
                ready!(self.as_mut().poll_bridge_ready(cx))?;
                self.as_mut().project().pending.control = None;
                let operation = match control {
                    WriteBarrier::Flush { generation } => WriteOperation::Flush { generation },
                    WriteBarrier::Eos { covers_flush } => WriteOperation::Eos { covers_flush },
                };
                self.as_mut().start_operation_pinned(operation)?;
                continue;
            }

            return Poll::Ready(Ok(()));
        }
    }

    fn pair_awaited_response(
        lifecycle: &Arc<L>,
        results: &mut WriterResults,
        awaited: WriterAwaited,
        frame: WriteEvent,
    ) -> Result<(), WriterFault> {
        match (awaited, frame) {
            (WriterAwaited::Flush { generation }, WriteEvent::FlushAck) => {
                results.flush = Some(FlushCompletion::FlushAck { generation });
                Ok(())
            }
            (WriterAwaited::Eos { covers_flush }, WriteEvent::EosAck) => {
                results.eos = Some(EosAckResult);
                if covers_flush {
                    results.flush = Some(FlushCompletion::CoveredByEos);
                }
                Ok(())
            }
            (WriterAwaited::Reset { code }, WriteEvent::ResetAck { code: actual })
                if code == actual =>
            {
                results.reset = Some(ResetAckResult { code });
                Ok(())
            }
            (WriterAwaited::Reset { code }, WriteEvent::ResetAck { code: actual }) => {
                Err(Self::protocol_fault_for(
                    lifecycle,
                    DriverProtocolError::ResetAckCodeMismatch {
                        expected: code,
                        actual,
                    },
                ))
            }
            (_awaited, WriteEvent::ErrReset { code }) => {
                Err(WriterFault::Stream(quic::StreamError::Reset { code }))
            }
            (_awaited, WriteEvent::ErrConn) => {
                Err(WriterFault::Deferred(defer_err_conn(lifecycle.clone())))
            }
            (_awaited, _frame) => Err(Self::protocol_fault_for(
                lifecycle,
                DriverProtocolError::UnexpectedWriterAck,
            )),
        }
    }

    fn poll_recv_progress(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), WriterFault>> {
        let terminal_committed = self.as_ref().get_ref().eos_committed()
            || self.as_ref().get_ref().committed_reset_code().is_some();
        let mut this = self.as_mut().project();
        match ready!(this.bridge.as_mut().poll_next(cx)) {
            Some(Ok(WriteEvent::Pull)) if terminal_committed => Poll::Ready(Ok(())),
            Some(Ok(WriteEvent::Pull)) if this.results.credit => {
                Poll::Ready(Err(Self::protocol_fault_for(
                    this.lifecycle,
                    DriverProtocolError::DuplicateWriterCredit,
                )))
            }
            Some(Ok(WriteEvent::Pull)) => {
                this.results.credit = true;
                Poll::Ready(Ok(()))
            }
            Some(Ok(
                frame @ (WriteEvent::FlushAck | WriteEvent::EosAck | WriteEvent::ResetAck { .. }),
            )) => {
                let awaited = match std::mem::replace(this.recv_state, WriterRecvState::Idle) {
                    WriterRecvState::Await { sent } => sent,
                    WriterRecvState::Idle => {
                        return Poll::Ready(Err(Self::protocol_fault_for(
                            this.lifecycle,
                            DriverProtocolError::UnexpectedWriterAck,
                        )));
                    }
                };
                Poll::Ready(Self::pair_awaited_response(
                    this.lifecycle,
                    this.results,
                    awaited,
                    frame,
                ))
            }
            Some(Ok(WriteEvent::ErrReset { code })) => {
                Poll::Ready(Err(WriterFault::Stream(quic::StreamError::Reset { code })))
            }
            Some(Ok(WriteEvent::ErrConn)) => Poll::Ready(Err(WriterFault::Deferred(
                defer_err_conn(this.lifecycle.clone()),
            ))),
            Some(Err(error)) => Poll::Ready(Err(Self::frame_io_fault_for(this.lifecycle, error))),
            None => Poll::Ready(Err(Self::protocol_fault_for(
                this.lifecycle,
                DriverProtocolError::FrameEof,
            ))),
        }
    }

    fn drive_credit(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<DriveTerminal, WriterFault>> {
        loop {
            if self.as_ref().get_ref().eos_committed() {
                panic!("{WRITE_AFTER_EOS_PANIC}");
            }
            if let Some(code) = self.as_ref().get_ref().committed_reset_code() {
                return match ready!(self.as_mut().drive_reset(cx, code))? {
                    ResetDrive::Acked => Poll::Ready(Ok(DriveTerminal::Reset { code })),
                    ResetDrive::CoveredByEos => Poll::Ready(Ok(DriveTerminal::Eos)),
                };
            }
            if self.as_ref().get_ref().has_unflushed_control_barrier() {
                ready!(self.as_mut().poll_send_progress(cx))?;
                continue;
            }
            if self.as_ref().get_ref().results.credit {
                return Poll::Ready(Ok(DriveTerminal::None));
            }
            ready!(self.as_mut().poll_send_progress(cx))?;
            if self.as_ref().get_ref().results.credit {
                return Poll::Ready(Ok(DriveTerminal::None));
            }
            ready!(self.as_mut().poll_recv_progress(cx))?;
        }
    }

    fn drive_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        generation: u64,
    ) -> Poll<Result<DriveTerminal, WriterFault>> {
        loop {
            if let Some(code) = self.as_ref().get_ref().committed_reset_code() {
                return match ready!(self.as_mut().drive_reset(cx, code))? {
                    ResetDrive::Acked => Poll::Ready(Ok(DriveTerminal::Reset { code })),
                    ResetDrive::CoveredByEos => Poll::Ready(Ok(DriveTerminal::Eos)),
                };
            }
            if self.as_ref().get_ref().results.eos.is_some() {
                return Poll::Ready(Ok(DriveTerminal::Eos));
            }
            if self.as_ref().get_ref().flush_result_covers(generation) {
                return Poll::Ready(Ok(DriveTerminal::None));
            }
            ready!(self.as_mut().poll_send_progress(cx))?;
            if self.as_ref().get_ref().results.eos.is_some() {
                return Poll::Ready(Ok(DriveTerminal::Eos));
            }
            if self.as_ref().get_ref().flush_result_covers(generation) {
                return Poll::Ready(Ok(DriveTerminal::None));
            }
            ready!(self.as_mut().poll_recv_progress(cx))?;
        }
    }

    fn drive_eos(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<DriveTerminal, WriterFault>> {
        loop {
            if let Some(code) = self.as_ref().get_ref().committed_reset_code() {
                return match ready!(self.as_mut().drive_reset(cx, code))? {
                    ResetDrive::Acked => Poll::Ready(Ok(DriveTerminal::Reset { code })),
                    ResetDrive::CoveredByEos => Poll::Ready(Ok(DriveTerminal::Eos)),
                };
            }
            if self.as_ref().get_ref().results.eos.is_some() {
                return Poll::Ready(Ok(DriveTerminal::Eos));
            }
            ready!(self.as_mut().poll_send_progress(cx))?;
            if self.as_ref().get_ref().results.eos.is_some() {
                return Poll::Ready(Ok(DriveTerminal::Eos));
            }
            ready!(self.as_mut().poll_recv_progress(cx))?;
        }
    }

    fn drive_started_eos(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), WriterFault>> {
        loop {
            if self.as_ref().get_ref().results.eos.is_some() {
                return Poll::Ready(Ok(()));
            }
            ready!(self.as_mut().poll_send_progress(cx))?;
            if self.as_ref().get_ref().results.eos.is_some() {
                return Poll::Ready(Ok(()));
            }
            ready!(self.as_mut().poll_recv_progress(cx))?;
        }
    }

    fn drive_reset(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        committed_code: VarInt,
    ) -> Poll<Result<ResetDrive, WriterFault>> {
        loop {
            if self.as_ref().get_ref().eos_started_or_completed()
                && !matches!(
                    self.as_ref().get_ref().send_state,
                    SendState::Flush {
                        inflight: WriteOperation::Reset { .. }
                    }
                )
                && !matches!(
                    self.as_ref().get_ref().recv_state,
                    WriterRecvState::Await {
                        sent: WriterAwaited::Reset { .. }
                    }
                )
                && self.as_ref().get_ref().results.reset.is_none()
            {
                ready!(self.as_mut().drive_started_eos(cx))?;
                return Poll::Ready(Ok(ResetDrive::CoveredByEos));
            }
            if self.as_ref().get_ref().reset_matches_result(committed_code) {
                return Poll::Ready(Ok(ResetDrive::Acked));
            }
            ready!(self.as_mut().poll_send_progress(cx))?;
            if self.as_ref().get_ref().reset_matches_result(committed_code) {
                return Poll::Ready(Ok(ResetDrive::Acked));
            }
            ready!(self.as_mut().poll_recv_progress(cx))?;
        }
    }
}

fn poll_deferred_error(
    error: &mut DeferredStreamError,
    cx: &mut Context<'_>,
) -> Poll<quic::StreamError> {
    match error {
        DeferredStreamError::Ready { error } => Poll::Ready(error.clone()),
        DeferredStreamError::Pending { future } => {
            let stream_error = ready!(future.as_mut().poll(cx));
            *error = DeferredStreamError::Ready {
                error: stream_error.clone(),
            };
            Poll::Ready(stream_error)
        }
    }
}

fn ready_error(error: quic::StreamError) -> DeferredStreamError {
    DeferredStreamError::Ready { error }
}

impl<Io, L, E> BridgeStreamWriter<Io, L, E>
where
    L: LifecycleExt + 'static,
    Io: FrameIo<WriteCommand, WriteEvent, E>,
    quic::ConnectionError: From<E>,
{
    fn stream_id(self: Pin<&mut Self>) -> VarInt {
        match self.project() {
            BridgeStreamWriterProj::Active { active } => active.stream_id,
            BridgeStreamWriterProj::Eos { stream_id } => *stream_id,
            BridgeStreamWriterProj::Reset { stream_id, .. } => *stream_id,
            BridgeStreamWriterProj::Closed { stream_id, .. } => *stream_id,
        }
    }

    fn close_with_stream_error(
        mut self: Pin<&mut Self>,
        error: quic::StreamError,
    ) -> quic::StreamError {
        let stream_id = self.as_mut().stream_id();
        self.as_mut().project_replace(Self::Closed {
            stream_id,
            error: ready_error(error.clone()),
        });
        error
    }

    fn close_with_fault(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        fault: WriterFault,
    ) -> Poll<quic::StreamError> {
        match fault {
            WriterFault::Stream(error) => Poll::Ready(self.close_with_stream_error(error)),
            WriterFault::Deferred(error) => {
                let stream_id = self.as_mut().stream_id();
                self.as_mut()
                    .project_replace(Self::Closed { stream_id, error });
                match self.project() {
                    BridgeStreamWriterProj::Closed { error, .. } => poll_deferred_error(error, cx),
                    _ => unreachable!("writer should have transitioned to closed"),
                }
            }
        }
    }

    fn poll_closed_error(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<quic::StreamError> {
        match self.project() {
            BridgeStreamWriterProj::Closed { error, .. } => poll_deferred_error(error, cx),
            _ => unreachable!("poll_closed_error called outside closed state"),
        }
    }

    fn transition_eos(mut self: Pin<&mut Self>) {
        let stream_id = self.as_mut().stream_id();
        self.as_mut().project_replace(Self::Eos { stream_id });
    }

    fn transition_reset(mut self: Pin<&mut Self>, code: VarInt) {
        let stream_id = self.as_mut().stream_id();
        self.as_mut()
            .project_replace(Self::Reset { stream_id, code });
    }
}

impl<Io, L, E> Sink<Bytes> for BridgeStreamWriter<Io, L, E>
where
    L: LifecycleExt + 'static,
    Io: FrameIo<WriteCommand, WriteEvent, E>,
    quic::ConnectionError: From<E>,
{
    type Error = quic::StreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.as_mut().project() {
            BridgeStreamWriterProj::Active { mut active } => {
                match ready!(active.as_mut().drive_credit(cx)) {
                    Ok(DriveTerminal::None) => Poll::Ready(Ok(())),
                    Ok(DriveTerminal::Eos) => {
                        self.as_mut().transition_eos();
                        panic!("{WRITE_AFTER_EOS_PANIC}");
                    }
                    Ok(DriveTerminal::Reset { code }) => {
                        self.as_mut().transition_reset(code);
                        Poll::Ready(Err(quic::StreamError::Reset { code }))
                    }
                    Err(fault) => {
                        let error = ready!(self.as_mut().close_with_fault(cx, fault));
                        Poll::Ready(Err(error))
                    }
                }
            }
            BridgeStreamWriterProj::Eos { .. } => panic!("{WRITE_AFTER_EOS_PANIC}"),
            BridgeStreamWriterProj::Reset { code, .. } => {
                Poll::Ready(Err(quic::StreamError::Reset { code: *code }))
            }
            BridgeStreamWriterProj::Closed { .. } => {
                let error = ready!(self.as_mut().poll_closed_error(cx));
                Poll::Ready(Err(error))
            }
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        match self.as_mut().project() {
            BridgeStreamWriterProj::Active { active } => match active.commit_push_pinned(item) {
                Ok(()) => Ok(()),
                Err(error @ quic::StreamError::Connection { .. }) => {
                    self.as_mut().close_with_stream_error(error.clone());
                    Err(error)
                }
                Err(error) => Err(error),
            },
            BridgeStreamWriterProj::Eos { .. } => panic!("{WRITE_AFTER_EOS_PANIC}"),
            BridgeStreamWriterProj::Reset { code, .. } => {
                Err(quic::StreamError::Reset { code: *code })
            }
            BridgeStreamWriterProj::Closed { error, .. } => match error {
                DeferredStreamError::Ready { error } => Err(error.clone()),
                DeferredStreamError::Pending { .. } => {
                    panic!("start_send called while writer closed with pending error")
                }
            },
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.as_mut().project() {
            BridgeStreamWriterProj::Active { mut active } => {
                let (_commit, generation) = active.as_mut().commit_flush_pinned();
                match ready!(active.as_mut().drive_flush(cx, generation)) {
                    Ok(DriveTerminal::None) => {
                        active.as_mut().take_flush_result_pinned(generation);
                        Poll::Ready(Ok(()))
                    }
                    Ok(DriveTerminal::Eos) => {
                        self.as_mut().transition_eos();
                        Poll::Ready(Ok(()))
                    }
                    Ok(DriveTerminal::Reset { code }) => {
                        self.as_mut().transition_reset(code);
                        Poll::Ready(Err(quic::StreamError::Reset { code }))
                    }
                    Err(fault) => {
                        let error = ready!(self.as_mut().close_with_fault(cx, fault));
                        Poll::Ready(Err(error))
                    }
                }
            }
            BridgeStreamWriterProj::Eos { .. } => Poll::Ready(Ok(())),
            BridgeStreamWriterProj::Reset { code, .. } => {
                Poll::Ready(Err(quic::StreamError::Reset { code: *code }))
            }
            BridgeStreamWriterProj::Closed { .. } => {
                let error = ready!(self.as_mut().poll_closed_error(cx));
                Poll::Ready(Err(error))
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.as_mut().project() {
            BridgeStreamWriterProj::Active { mut active } => {
                let _commit = active.as_mut().commit_eos_pinned();
                match ready!(active.as_mut().drive_eos(cx)) {
                    Ok(DriveTerminal::Eos | DriveTerminal::None) => {
                        active.as_mut().take_eos_result_pinned();
                        self.as_mut().transition_eos();
                        Poll::Ready(Ok(()))
                    }
                    Ok(DriveTerminal::Reset { code }) => {
                        self.as_mut().transition_reset(code);
                        Poll::Ready(Err(quic::StreamError::Reset { code }))
                    }
                    Err(fault) => {
                        let error = ready!(self.as_mut().close_with_fault(cx, fault));
                        Poll::Ready(Err(error))
                    }
                }
            }
            BridgeStreamWriterProj::Eos { .. } => Poll::Ready(Ok(())),
            BridgeStreamWriterProj::Reset { code, .. } => {
                Poll::Ready(Err(quic::StreamError::Reset { code: *code }))
            }
            BridgeStreamWriterProj::Closed { .. } => {
                let error = ready!(self.as_mut().poll_closed_error(cx));
                Poll::Ready(Err(error))
            }
        }
    }
}

impl<Io, L, E> quic::GetStreamId for BridgeStreamWriter<Io, L, E>
where
    L: LifecycleExt + 'static,
    Io: FrameIo<WriteCommand, WriteEvent, E>,
    quic::ConnectionError: From<E>,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        match self.project() {
            BridgeStreamWriterProj::Active { active } => Poll::Ready(Ok(active.stream_id)),
            BridgeStreamWriterProj::Eos { stream_id } => Poll::Ready(Ok(*stream_id)),
            BridgeStreamWriterProj::Reset { code, .. } => {
                Poll::Ready(Err(quic::StreamError::Reset { code: *code }))
            }
            BridgeStreamWriterProj::Closed { error, .. } => {
                Poll::Ready(Err(ready!(poll_deferred_error(error, cx))))
            }
        }
    }
}

impl<Io, L, E> quic::ResetStream for BridgeStreamWriter<Io, L, E>
where
    L: LifecycleExt + 'static,
    Io: FrameIo<WriteCommand, WriteEvent, E>,
    quic::ConnectionError: From<E>,
{
    fn poll_reset(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        match self.as_mut().project() {
            BridgeStreamWriterProj::Active { mut active } => {
                let commit = active.as_mut().commit_reset_pinned(code);
                let committed_code = match commit {
                    CommitResult::Committed | CommitResult::Duplicate => {
                        active.as_ref().committed_reset_code().unwrap_or(code)
                    }
                    CommitResult::Conflict => active
                        .as_ref()
                        .committed_reset_code()
                        .expect("conflicting reset must have committed code"),
                };

                match ready!(active.as_mut().drive_reset(cx, committed_code)) {
                    Ok(ResetDrive::Acked) => {
                        active.as_mut().take_reset_result_pinned(committed_code);
                        self.as_mut().transition_reset(committed_code);
                        Poll::Ready(Ok(()))
                    }
                    Ok(ResetDrive::CoveredByEos) => {
                        active.as_mut().take_eos_result_pinned();
                        self.as_mut().transition_eos();
                        Poll::Ready(Ok(()))
                    }
                    Err(fault) => {
                        let error = ready!(self.as_mut().close_with_fault(cx, fault));
                        Poll::Ready(Err(error))
                    }
                }
            }
            BridgeStreamWriterProj::Eos { .. } => Poll::Ready(Ok(())),
            BridgeStreamWriterProj::Reset { code, .. } => {
                Poll::Ready(Err(quic::StreamError::Reset { code: *code }))
            }
            BridgeStreamWriterProj::Closed { .. } => {
                let error = ready!(self.as_mut().poll_closed_error(cx));
                Poll::Ready(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, future::pending, marker::PhantomData, panic, pin::Pin, sync::Arc};

    use bytes::Bytes;
    use futures::{FutureExt as _, Sink, SinkExt as _, future::poll_fn};

    use super::{
        ActiveBridgeStreamWriter, BridgeStreamWriter, PendingWrite, SendState, WriteBarrier,
        WriterRecvState, WriterResults,
    };
    use crate::{
        quic::{self, GetStreamIdExt as _, ResetStream, ResetStreamExt as _},
        rpc::{
            lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt},
            stream::{
                frame::{WriteCommand, WriteEvent},
                test_io::{MemoryFrameIo, TestFrameIoError, TestLifecycle, worker_writer_pair},
            },
        },
        varint::VarInt,
    };

    type WorkerWriterIo = MemoryFrameIo<WriteCommand, WriteEvent, TestFrameIoError>;
    type HypervisorWriterIo = MemoryFrameIo<WriteEvent, WriteCommand, TestFrameIoError>;
    type TestBridgeStreamWriter =
        BridgeStreamWriter<WorkerWriterIo, TestLifecycle, TestFrameIoError>;

    struct PendingClosedLifecycle {
        latch: ConnectionErrorLatch,
    }

    impl PendingClosedLifecycle {
        fn new() -> Self {
            Self {
                latch: ConnectionErrorLatch::new(),
            }
        }
    }

    impl HasLatch for PendingClosedLifecycle {
        fn latch(&self) -> &ConnectionErrorLatch {
            &self.latch
        }
    }

    impl quic::Lifecycle for PendingClosedLifecycle {
        fn close(&self, _code: crate::error::Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            self.check_with_probe(|| None)
        }

        async fn closed(&self) -> quic::ConnectionError {
            self.resolve_closed(pending()).await
        }
    }

    fn writer(
        stream_id: VarInt,
    ) -> (
        TestBridgeStreamWriter,
        HypervisorWriterIo,
        Arc<TestLifecycle>,
    ) {
        let lifecycle = Arc::new(TestLifecycle::new());
        let (worker, hypervisor) = worker_writer_pair::<TestFrameIoError>();
        (
            BridgeStreamWriter::new(stream_id, worker, lifecycle.clone()),
            hypervisor,
            lifecycle,
        )
    }

    fn pending_closed_writer(
        stream_id: VarInt,
    ) -> (
        BridgeStreamWriter<WorkerWriterIo, PendingClosedLifecycle, TestFrameIoError>,
        HypervisorWriterIo,
    ) {
        let lifecycle = Arc::new(PendingClosedLifecycle::new());
        let (worker, hypervisor) = worker_writer_pair::<TestFrameIoError>();
        (
            BridgeStreamWriter::new(stream_id, worker, lifecycle),
            hypervisor,
        )
    }

    fn writer_with_pending_flush_and_credit(
        stream_id: VarInt,
    ) -> (TestBridgeStreamWriter, HypervisorWriterIo) {
        let lifecycle = Arc::new(TestLifecycle::new());
        let (worker, hypervisor) = worker_writer_pair::<TestFrameIoError>();
        (
            BridgeStreamWriter::Active {
                active: ActiveBridgeStreamWriter {
                    stream_id,
                    lifecycle,
                    bridge: worker,
                    pending: PendingWrite {
                        push: None,
                        control: Some(WriteBarrier::Flush { generation: 0 }),
                        reset: None,
                    },
                    send_state: SendState::default(),
                    recv_state: WriterRecvState::default(),
                    results: WriterResults {
                        credit: true,
                        flush: None,
                        eos: None,
                        reset: None,
                    },
                    write_generation: 0,
                    _error: PhantomData,
                },
            },
            hypervisor,
        )
    }

    fn transport(error: &quic::ConnectionError) -> &quic::TransportError {
        let quic::ConnectionError::Transport { source } = error else {
            panic!("connection error should be transport-scoped");
        };
        source
    }

    fn stream_connection(error: quic::StreamError) -> quic::ConnectionError {
        let quic::StreamError::Connection { source } = error else {
            panic!("stream error should be connection-scoped");
        };
        source
    }

    fn assert_reset(error: quic::StreamError, expected: VarInt) {
        let quic::StreamError::Reset { code } = error else {
            panic!("stream error should be reset-scoped");
        };
        assert_eq!(code, expected);
    }

    async fn expect_command(hypervisor: &mut HypervisorWriterIo) -> WriteCommand {
        hypervisor
            .next_frame()
            .await
            .expect("bridge should send a frame")
            .expect("command frame should be readable")
    }

    fn expect_command_now(hypervisor: &mut HypervisorWriterIo) -> WriteCommand {
        match hypervisor.next_frame().now_or_never() {
            Some(Some(Ok(command))) => command,
            Some(Some(Err(_error))) => panic!("command frame should be readable"),
            Some(None) => panic!("bridge command stream should remain open"),
            None => panic!("expected command frame to be ready"),
        }
    }

    async fn grant_credit(
        writer: &mut TestBridgeStreamWriter,
        hypervisor: &mut HypervisorWriterIo,
    ) {
        hypervisor
            .send(WriteEvent::Pull)
            .await
            .expect("pull credit should send");
        poll_fn(|cx| Pin::new(&mut *writer).poll_ready(cx))
            .await
            .expect("writer should become ready");
    }

    fn assert_no_command_now(hypervisor: &mut HypervisorWriterIo, context: &str) {
        match hypervisor.next_frame().now_or_never() {
            None | Some(None) => {}
            Some(Some(frame)) => panic!("{context}: unexpected frame {frame:?}"),
        }
    }

    fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
        match payload.downcast::<String>() {
            Ok(message) => *message,
            Err(payload) => match payload.downcast::<&'static str>() {
                Ok(message) => (*message).to_owned(),
                Err(_payload) => panic!("panic payload should be a string"),
            },
        }
    }

    #[tokio::test]
    async fn poll_ready_waits_for_pull_without_consuming_start_send_credit() {
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(101));
        let data = Bytes::from_static(b"ready payload");

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
                .now_or_never()
                .is_none(),
            "poll_ready should wait for inbound pull credit"
        );
        assert_no_command_now(&mut hypervisor, "poll_ready must not send writer commands");

        hypervisor
            .send(WriteEvent::Pull)
            .await
            .expect("pull credit should send");
        poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
            .await
            .expect("pull should make the sink ready");

        Pin::new(&mut bridge)
            .start_send(data)
            .expect("start_send should consume the cached credit");
    }

    #[tokio::test]
    async fn start_send_consumes_credit_and_commits_push_without_polling_typed_io() {
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(102));
        let data = Bytes::from_static(b"push payload");

        grant_credit(&mut bridge, &mut hypervisor).await;
        Pin::new(&mut bridge)
            .start_send(data)
            .expect("start_send should commit push");

        assert_no_command_now(
            &mut hypervisor,
            "start_send must not poll or write typed frame IO",
        );
    }

    #[tokio::test]
    async fn cached_credit_waits_for_unsent_committed_flush_before_new_push() {
        let data = Bytes::from_static(b"after committed flush");
        let (mut bridge, mut hypervisor) =
            writer_with_pending_flush_and_credit(VarInt::from_u32(132));

        poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
            .await
            .expect("cached credit should become ready after sending committed flush");
        assert_eq!(expect_command_now(&mut hypervisor), WriteCommand::Flush);

        Pin::new(&mut bridge)
            .start_send(data.clone())
            .expect("cached credit should allow start_send after flush is sent");
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_flush(cx))
                .now_or_never()
                .is_none(),
            "flush should wait for the earlier FlushAck"
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            WriteCommand::Push { data }
        );
        hypervisor
            .send(WriteEvent::FlushAck)
            .await
            .expect("old flush ack should send");
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_flush(cx))
                .now_or_never()
                .is_none(),
            "old FlushAck must not cover data committed after that Flush"
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Flush);
        hypervisor
            .send(WriteEvent::FlushAck)
            .await
            .expect("new flush ack should send");
        bridge
            .flush()
            .await
            .expect("new FlushAck should cover later push");
    }

    #[tokio::test]
    async fn start_send_without_credit_closes_writer_with_protocol_error() {
        let (mut bridge, mut hypervisor, lifecycle) = writer(VarInt::from_u32(133));

        let error = Pin::new(&mut bridge)
            .start_send(Bytes::from_static(b"without credit"))
            .expect_err("start_send without credit should fail");
        let source = stream_connection(error);
        assert_eq!(
            transport(&source).reason.as_ref(),
            "start_send called without writer credit"
        );
        assert_eq!(
            transport(&source).reason.as_ref(),
            quic::Lifecycle::closed(lifecycle.as_ref())
                .await
                .transport()
                .reason
                .as_ref()
        );

        let Some(Err(error)) = poll_fn(|cx| Pin::new(&mut bridge).poll_flush(cx)).now_or_never()
        else {
            panic!("closed writer should return the latched protocol error immediately");
        };
        let source = stream_connection(error);
        assert_eq!(
            transport(&source).reason.as_ref(),
            "start_send called without writer credit"
        );
        assert_no_command_now(
            &mut hypervisor,
            "closed writer must not send frames after start_send protocol error",
        );
    }

    #[tokio::test]
    async fn poll_flush_writes_push_then_flush_and_completes_only_on_flush_ack() {
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(103));
        let data = Bytes::from_static(b"flush payload");

        grant_credit(&mut bridge, &mut hypervisor).await;
        Pin::new(&mut bridge)
            .start_send(data.clone())
            .expect("start_send should commit push");

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_flush(cx))
                .now_or_never()
                .is_none(),
            "flush should wait for FlushAck"
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            WriteCommand::Push { data }
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Flush);
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_flush(cx))
                .now_or_never()
                .is_none(),
            "flush must remain pending before FlushAck"
        );

        hypervisor
            .send(WriteEvent::FlushAck)
            .await
            .expect("flush ack should send");
        bridge
            .flush()
            .await
            .expect("flush ack should complete flush");
    }

    #[tokio::test]
    async fn poll_close_writes_eos_and_completes_only_on_eos_ack() {
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(104));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none(),
            "close should wait for EosAck"
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Eos);
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none(),
            "close must remain pending before EosAck"
        );

        hypervisor
            .send(WriteEvent::EosAck)
            .await
            .expect("eos ack should send");
        bridge.close().await.expect("eos ack should complete close");
    }

    #[tokio::test]
    async fn poll_close_waits_behind_committed_flush_ack_before_sending_eos() {
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(105));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_flush(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Flush);

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none(),
            "close should wait behind the in-flight flush ack"
        );
        assert_no_command_now(
            &mut hypervisor,
            "single-awaiting writer must not send Eos before FlushAck",
        );

        hypervisor
            .send(WriteEvent::FlushAck)
            .await
            .expect("flush ack should send");
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none(),
            "close should send Eos after FlushAck and then wait for EosAck"
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Eos);
        hypervisor
            .send(WriteEvent::EosAck)
            .await
            .expect("eos ack should send");
        bridge.close().await.expect("close should complete");
    }

    #[tokio::test]
    async fn poll_flush_after_awaiting_eos_sends_no_flush_and_completes_from_eos_ack() {
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(106));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Eos);

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_flush(cx))
                .now_or_never()
                .is_none(),
            "flush should wait for the already-awaiting EosAck"
        );
        assert_no_command_now(&mut hypervisor, "eos-covered flush must not send Flush");

        hypervisor
            .send(WriteEvent::EosAck)
            .await
            .expect("eos ack should send");
        bridge
            .flush()
            .await
            .expect("flush should complete from covering EosAck");
    }

    #[tokio::test]
    async fn reset_keeps_first_code_and_second_reset_completes_on_first_ack() {
        let first = VarInt::from_u32(107);
        let second = VarInt::from_u32(108);
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(109));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_reset(cx, first))
                .now_or_never()
                .is_none()
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            WriteCommand::Reset { code: first }
        );

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_reset(cx, second))
                .now_or_never()
                .is_none(),
            "second reset should continue first committed reset"
        );
        assert_no_command_now(
            &mut hypervisor,
            "different reset code must not replace first committed reset",
        );

        hypervisor
            .send(WriteEvent::ResetAck { code: first })
            .await
            .expect("reset ack should send");
        bridge
            .reset(second)
            .await
            .expect("second reset future should complete from first ack");
    }

    #[tokio::test]
    async fn wrong_reset_ack_latches_protocol_connection_error() {
        let expected = VarInt::from_u32(111);
        let actual = VarInt::from_u32(112);
        let (mut bridge, mut hypervisor, lifecycle) = writer(VarInt::from_u32(113));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_reset(cx, expected))
                .now_or_never()
                .is_none()
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            WriteCommand::Reset { code: expected }
        );
        hypervisor
            .send(WriteEvent::ResetAck { code: actual })
            .await
            .expect("wrong reset ack should send");

        let error = bridge.reset(expected).await.expect_err("reset should fail");
        let source = stream_connection(error);
        assert_eq!(
            transport(&source).reason.as_ref(),
            "reset ack code 112 does not match committed reset code 111"
        );
        assert_eq!(
            transport(&source).reason.as_ref(),
            quic::Lifecycle::closed(lifecycle.as_ref())
                .await
                .transport()
                .reason
                .as_ref()
        );
    }

    #[tokio::test]
    async fn reset_clears_not_started_pending_work_but_preserves_awaiting_flush_order() {
        let reset = VarInt::from_u32(114);
        let data = Bytes::from_static(b"discard me");
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(115));

        grant_credit(&mut bridge, &mut hypervisor).await;
        Pin::new(&mut bridge)
            .start_send(data)
            .expect("start_send should commit pending push");
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_reset(cx, reset))
                .now_or_never()
                .is_none(),
            "reset should wait for reset ack"
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            WriteCommand::Reset { code: reset }
        );
        assert_no_command_now(&mut hypervisor, "pending push should be cleared by reset");
        hypervisor
            .send(WriteEvent::ResetAck { code: reset })
            .await
            .expect("reset ack should send");
        bridge.reset(reset).await.expect("reset should complete");

        let reset = VarInt::from_u32(116);
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(117));
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_flush(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Flush);
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none(),
            "close should be pending behind flush"
        );
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_reset(cx, reset))
                .now_or_never()
                .is_none(),
            "reset must preserve the already awaiting flush before sending reset"
        );
        assert_no_command_now(
            &mut hypervisor,
            "reset must not remove an already awaiting flush",
        );
        hypervisor
            .send(WriteEvent::FlushAck)
            .await
            .expect("flush ack should send");
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_reset(cx, reset))
                .now_or_never()
                .is_none()
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            WriteCommand::Reset { code: reset }
        );
        assert_no_command_now(&mut hypervisor, "pending eos should be cleared by reset");
    }

    #[tokio::test]
    async fn eos_ack_transitions_to_eos_and_later_flush_close_are_immediate_no_frames() {
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(118));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Eos);
        hypervisor
            .send(WriteEvent::EosAck)
            .await
            .expect("eos ack should send");
        bridge.close().await.expect("close should complete");

        bridge.flush().await.expect("flush after eos is a no-op");
        bridge.close().await.expect("close after eos is a no-op");
        assert_no_command_now(&mut hypervisor, "eos terminal operations send no frames");
    }

    #[tokio::test]
    async fn poll_ready_and_start_send_panic_after_eos_is_committed() {
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(119));
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Eos);

        let ready_panic = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx)).now_or_never();
        }))
        .expect_err("poll_ready after eos commit should panic");
        assert_eq!(panic_text(ready_panic), "h3x write data after shutdown");

        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(120));
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Eos);
        let start_send_panic = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            Pin::new(&mut bridge)
                .start_send(Bytes::from_static(b"illegal"))
                .expect("start_send should panic before returning");
        }))
        .expect_err("start_send after eos commit should panic");
        assert_eq!(
            panic_text(start_send_panic),
            "h3x write data after shutdown"
        );
    }

    #[tokio::test]
    async fn reset_ack_transitions_to_reset_and_later_paths_observe_reset_error() {
        let stream_id = VarInt::from_u32(121);
        let reset = VarInt::from_u32(122);
        let (mut bridge, mut hypervisor, _lifecycle) = writer(stream_id);

        grant_credit(&mut bridge, &mut hypervisor).await;
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_reset(cx, reset))
                .now_or_never()
                .is_none()
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            WriteCommand::Reset { code: reset }
        );
        hypervisor
            .send(WriteEvent::Pull)
            .await
            .expect("post-reset cached pull should be suppressed");
        hypervisor
            .send(WriteEvent::ResetAck { code: reset })
            .await
            .expect("reset ack should send");
        bridge.reset(reset).await.expect("reset should complete");

        assert_reset(
            poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
                .await
                .expect_err("poll_ready after reset should fail"),
            reset,
        );
        assert_reset(
            Pin::new(&mut bridge)
                .start_send(Bytes::from_static(b"after reset"))
                .expect_err("start_send after reset should fail"),
            reset,
        );
        assert_reset(
            bridge
                .flush()
                .await
                .expect_err("flush after reset should fail"),
            reset,
        );
        assert_reset(
            bridge
                .close()
                .await
                .expect_err("close after reset should fail"),
            reset,
        );
        assert_reset(
            bridge
                .reset(reset)
                .await
                .expect_err("reset after reset should fail"),
            reset,
        );
        assert_reset(
            bridge
                .stream_id()
                .await
                .expect_err("stream id after reset should fail"),
            reset,
        );
    }

    #[tokio::test]
    async fn reset_after_already_started_eos_waits_for_eos_ack_and_sends_no_reset() {
        let reset = VarInt::from_u32(123);
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(124));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Eos);

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_reset(cx, reset))
                .now_or_never()
                .is_none(),
            "reset should wait for the already-started eos"
        );
        assert_no_command_now(&mut hypervisor, "eos-covered reset must not send Reset");

        hypervisor
            .send(WriteEvent::EosAck)
            .await
            .expect("eos ack should send");
        bridge
            .reset(reset)
            .await
            .expect("reset covered by eos should complete");
        assert_no_command_now(&mut hypervisor, "covered reset sends no frame");
    }

    #[tokio::test]
    async fn err_reset_and_err_conn_close_writer_correctly() {
        let reset = VarInt::from_u32(125);
        let (mut bridge, mut hypervisor, _lifecycle) = writer(VarInt::from_u32(126));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
                .now_or_never()
                .is_none()
        );
        hypervisor
            .send(WriteEvent::ErrReset { code: reset })
            .await
            .expect("reset event should send");
        assert_reset(
            poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
                .await
                .expect_err("err reset should fail readiness"),
            reset,
        );
        assert_reset(
            bridge
                .flush()
                .await
                .expect_err("closed reset should be cached"),
            reset,
        );

        let canonical = quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(127),
                frame_type: VarInt::from_u32(128),
                reason: "canonical writer close".into(),
            },
        };
        let (mut bridge, mut hypervisor, lifecycle) = writer(VarInt::from_u32(129));
        lifecycle.set_closed_error(canonical.clone());

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
                .now_or_never()
                .is_none()
        );
        hypervisor
            .send(WriteEvent::ErrConn)
            .await
            .expect("connection error event should send");
        let error = poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
            .await
            .expect_err("err conn should fail readiness");
        let source = stream_connection(error);
        assert_eq!(transport(&source).kind, transport(&canonical).kind);
        assert_eq!(
            transport(&source).frame_type,
            transport(&canonical).frame_type
        );
        assert_eq!(transport(&source).reason, transport(&canonical).reason);

        let (mut bridge, mut hypervisor) = pending_closed_writer(VarInt::from_u32(130));
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
                .now_or_never()
                .is_none()
        );
        hypervisor
            .send(WriteEvent::ErrConn)
            .await
            .expect("connection error event should send");
        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
                .now_or_never()
                .is_none(),
            "deferred ErrConn should remain pending while lifecycle close is pending"
        );
    }

    #[tokio::test]
    async fn frame_io_eof_before_terminal_ack_latches_connection_frame_eof() {
        let (mut bridge, mut hypervisor, lifecycle) = writer(VarInt::from_u32(131));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, WriteCommand::Eos);
        drop(hypervisor);

        let error = bridge
            .close()
            .await
            .expect_err("frame eof should fail close");
        let source = stream_connection(error);
        assert_eq!(
            transport(&source).reason.as_ref(),
            "typed frame stream ended before operation completed"
        );
        assert_eq!(
            transport(&source).reason.as_ref(),
            quic::Lifecycle::closed(lifecycle.as_ref())
                .await
                .transport()
                .reason
                .as_ref()
        );
    }

    trait TransportExt {
        fn transport(&self) -> &quic::TransportError;
    }

    impl TransportExt for quic::ConnectionError {
        fn transport(&self) -> &quic::TransportError {
            transport(self)
        }
    }
}
