use std::{
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Stream, stream::FusedStream};

use super::{
    drain,
    error::{
        DeferredStreamError, DriverProtocolError, defer_err_conn, latch_frame_io_error,
        latch_protocol_error,
    },
    frame::{ReadCommand, ReadEvent},
};
use crate::{quic, varint::VarInt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadOperation {
    Pull,
    Stop { code: VarInt },
}

#[derive(Debug, Default)]
struct PendingRead {
    pull: bool,
    stop: Option<VarInt>,
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
enum ReaderRecvState {
    #[default]
    Idle,
    Receive {
        sent: ReadOperation,
    },
}

#[derive(Debug, Default)]
struct ReaderResults {
    pull: Option<ReaderPullResult>,
    stop: Option<StopAckResult>,
}

#[derive(Debug)]
enum ReaderPullResult {
    Push(Bytes),
    Eos,
}

#[derive(Debug)]
struct StopAckResult {
    code: VarInt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitResult {
    Committed,
    Duplicate,
    Conflict,
}

enum ReaderFault {
    Stream(quic::StreamError),
    Deferred(DeferredStreamError),
}

pin_project_lite::pin_project! {
    #[project = BridgeStreamReaderProj]
    #[project_replace = BridgeStreamReaderReplace]
    pub(crate) enum BridgeStreamReader<Io, L, E>
    where
        L: drain::DrainLifecycle,
        Io: drain::ReadDrainIo<E>,
        E: 'static,
        quic::ConnectionError: From<E>,
    {
        Active {
            active: Pin<Box<ActiveBridgeStreamReader<Io, L, E>>>,
        },
        Eos {
            stream_id: VarInt,
        },
        Closed {
            stream_id: VarInt,
            error: DeferredStreamError,
        },
    }

    impl<Io, L, E> PinnedDrop for BridgeStreamReader<Io, L, E>
    where
        L: drain::DrainLifecycle,
        Io: drain::ReadDrainIo<E>,
        E: 'static,
        quic::ConnectionError: From<E>,
    {
        fn drop(mut this: Pin<&mut Self>) {
            let stream_id = match this.as_mut().project() {
                BridgeStreamReaderProj::Active { active } => active.as_ref().get_ref().stream_id,
                BridgeStreamReaderProj::Eos { .. } | BridgeStreamReaderProj::Closed { .. } => {
                    return;
                }
            };

            match this.project_replace(BridgeStreamReader::Eos { stream_id }) {
                BridgeStreamReaderReplace::Active { active }
                    if active.as_ref().get_ref().has_committed_outbound() =>
                {
                    drain::spawn_read_drain(active);
                }
                _ => {}
            }
        }
    }
}

pin_project_lite::pin_project! {
    pub(crate) struct ActiveBridgeStreamReader<Io, L, E> {
        stream_id: VarInt,
        lifecycle: Arc<L>,
        #[pin]
        bridge: Io,
        pending: PendingRead,
        send_state: SendState<ReadOperation>,
        recv_state: ReaderRecvState,
        results: ReaderResults,
        _error: PhantomData<fn(E)>,
    }
}

impl<Io, L, E> BridgeStreamReader<Io, L, E>
where
    L: drain::DrainLifecycle,
    Io: drain::ReadDrainIo<E>,
    E: 'static,
    quic::ConnectionError: From<E>,
{
    pub(crate) fn new(stream_id: VarInt, bridge: Io, lifecycle: Arc<L>) -> Self {
        Self::Active {
            active: Box::pin(ActiveBridgeStreamReader {
                stream_id,
                lifecycle,
                bridge,
                pending: PendingRead::default(),
                send_state: SendState::default(),
                recv_state: ReaderRecvState::default(),
                results: ReaderResults::default(),
                _error: PhantomData,
            }),
        }
    }
}

impl<Io, L, E> ActiveBridgeStreamReader<Io, L, E> {
    pub(super) fn has_committed_outbound(&self) -> bool {
        self.pending.pull
            || self.pending.stop.is_some()
            || matches!(self.send_state, SendState::Flush { .. })
    }

    fn committed_stop_code(&self) -> Option<VarInt> {
        if let Some(code) = self.pending.stop {
            return Some(code);
        }
        if let SendState::Flush {
            inflight: ReadOperation::Stop { code },
        } = self.send_state
        {
            return Some(code);
        }
        if let ReaderRecvState::Receive {
            sent: ReadOperation::Stop { code },
        } = self.recv_state
        {
            return Some(code);
        }
        self.results.stop.as_ref().map(|result| result.code)
    }

    fn stop_send_is_blocked_by_pull(&self) -> bool {
        self.pending.pull
            || matches!(
                self.send_state,
                SendState::Flush {
                    inflight: ReadOperation::Pull
                }
            )
            || matches!(
                self.recv_state,
                ReaderRecvState::Receive {
                    sent: ReadOperation::Pull
                }
            )
    }

    fn has_pull_eos(&self) -> bool {
        matches!(self.results.pull, Some(ReaderPullResult::Eos))
    }

    fn commit_pull_pinned(mut self: Pin<&mut Self>) -> CommitResult {
        let this = self.as_mut().project();
        if this.pending.pull
            || matches!(
                this.send_state,
                SendState::Flush {
                    inflight: ReadOperation::Pull
                }
            )
            || matches!(
                this.recv_state,
                ReaderRecvState::Receive {
                    sent: ReadOperation::Pull
                }
            )
            || this.results.pull.is_some()
        {
            return CommitResult::Duplicate;
        }
        this.pending.pull = true;
        CommitResult::Committed
    }

    fn commit_stop_pinned(mut self: Pin<&mut Self>, code: VarInt) -> CommitResult {
        match self.as_ref().get_ref().committed_stop_code() {
            Some(committed) if committed == code => CommitResult::Duplicate,
            Some(_committed) => CommitResult::Conflict,
            None => {
                let this = self.as_mut().project();
                this.pending.pull = false;
                this.pending.stop = Some(code);
                CommitResult::Committed
            }
        }
    }

    fn take_pull_result_pinned(mut self: Pin<&mut Self>) -> Option<ReaderPullResult> {
        self.as_mut().project().results.pull.take()
    }
}

impl<Io, L, E> ActiveBridgeStreamReader<Io, L, E>
where
    L: drain::DrainLifecycle,
    Io: drain::ReadDrainIo<E>,
    E: 'static,
    quic::ConnectionError: From<E>,
{
    fn protocol_fault_for(lifecycle: &Arc<L>, error: DriverProtocolError) -> ReaderFault {
        ReaderFault::Stream(latch_protocol_error(lifecycle.as_ref(), error))
    }

    fn frame_io_fault_for(lifecycle: &Arc<L>, error: E) -> ReaderFault {
        ReaderFault::Stream(latch_frame_io_error(lifecycle.as_ref(), error))
    }

    fn pair_response(
        lifecycle: &Arc<L>,
        results: &mut ReaderResults,
        sent: ReadOperation,
        frame: ReadEvent,
    ) -> Result<(), ReaderFault> {
        match (sent, frame) {
            (ReadOperation::Pull, ReadEvent::Push { data }) => {
                results.pull = Some(ReaderPullResult::Push(data));
                Ok(())
            }
            (ReadOperation::Pull, ReadEvent::Eos) => {
                results.pull = Some(ReaderPullResult::Eos);
                Ok(())
            }
            (ReadOperation::Stop { code }, ReadEvent::StopAck { code: actual })
                if code == actual =>
            {
                results.stop = Some(StopAckResult { code });
                Ok(())
            }
            (ReadOperation::Stop { code }, ReadEvent::StopAck { code: actual }) => {
                Err(Self::protocol_fault_for(
                    lifecycle,
                    DriverProtocolError::StopAckCodeMismatch {
                        expected: code,
                        actual,
                    },
                ))
            }
            (_sent, ReadEvent::ErrReset { code }) => {
                Err(ReaderFault::Stream(quic::StreamError::Reset { code }))
            }
            (_sent, ReadEvent::ErrConn) => {
                Err(ReaderFault::Deferred(defer_err_conn(lifecycle.clone())))
            }
            (_sent, _frame) => Err(Self::protocol_fault_for(
                lifecycle,
                DriverProtocolError::UnexpectedReaderFrame,
            )),
        }
    }

    fn clear_pending_stop_if_matches(mut self: Pin<&mut Self>, code: VarInt) {
        let this = self.as_mut().project();
        if this.pending.stop == Some(code) {
            this.pending.stop = None;
        }
    }

    fn pending_stop_matches(&self, code: VarInt) -> bool {
        self.pending.stop == Some(code)
    }

    fn stop_ready_to_send(&self, code: VarInt) -> bool {
        self.pending_stop_matches(code) && !self.stop_send_is_blocked_by_pull()
    }

    fn completed_stop_matches(&self, code: VarInt) -> bool {
        matches!(&self.results.stop, Some(result) if result.code == code)
    }

    fn completed_pull_result(&self) -> bool {
        self.results.pull.is_some()
    }

    fn poll_idle(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ReaderFault>> {
        loop {
            let mut this = self.as_mut().project();
            match (&mut *this.send_state, &mut *this.recv_state) {
                (SendState::Idle { .. }, ReaderRecvState::Idle) => {
                    return Poll::Ready(Ok(()));
                }
                (SendState::Flush { inflight }, ReaderRecvState::Idle) => {
                    match ready!(this.bridge.as_mut().poll_flush(cx)) {
                        Ok(()) => {
                            let sent = *inflight;
                            *this.send_state = SendState::Idle { ready: false };
                            *this.recv_state = ReaderRecvState::Receive { sent };
                        }
                        Err(error) => {
                            return Poll::Ready(Err(Self::frame_io_fault_for(
                                this.lifecycle,
                                error,
                            )));
                        }
                    }
                }
                (SendState::Idle { .. }, ReaderRecvState::Receive { sent }) => {
                    let sent = *sent;
                    match ready!(this.bridge.as_mut().poll_next(cx)) {
                        Some(Ok(frame)) => {
                            *this.recv_state = ReaderRecvState::Idle;
                            Self::pair_response(this.lifecycle, this.results, sent, frame)?;
                        }
                        Some(Err(error)) => {
                            return Poll::Ready(Err(Self::frame_io_fault_for(
                                this.lifecycle,
                                error,
                            )));
                        }
                        None => {
                            return Poll::Ready(Err(Self::protocol_fault_for(
                                this.lifecycle,
                                DriverProtocolError::FrameEof,
                            )));
                        }
                    }
                }
                (SendState::Flush { .. }, ReaderRecvState::Receive { .. }) => {
                    unreachable!("reader bridge cannot flush and receive simultaneously");
                }
            }
        }
    }

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ReaderFault>> {
        ready!(self.as_mut().poll_idle(cx))?;

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
            SendState::Flush { .. } => unreachable!("poll_idle must drive flush before readiness"),
        }
    }

    fn poll_drain_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), quic::StreamError>> {
        let mut this = self.as_mut().project();
        match &mut *this.send_state {
            SendState::Idle { ready: true } => Poll::Ready(Ok(())),
            SendState::Idle { ready } => match ready!(this.bridge.as_mut().poll_ready(cx)) {
                Ok(()) => {
                    *ready = true;
                    Poll::Ready(Ok(()))
                }
                Err(error) => {
                    Poll::Ready(Err(latch_frame_io_error(this.lifecycle.as_ref(), error)))
                }
            },
            SendState::Flush { .. } => unreachable!("reader drain readiness while flushing"),
        }
    }

    fn start_drain_operation(
        mut self: Pin<&mut Self>,
        operation: ReadOperation,
    ) -> Result<(), quic::StreamError> {
        let command = match operation {
            ReadOperation::Pull => ReadCommand::Pull,
            ReadOperation::Stop { code } => ReadCommand::Stop { code },
        };

        let mut this = self.as_mut().project();
        match this.bridge.as_mut().start_send(command) {
            Ok(()) => {
                *this.send_state = SendState::Flush {
                    inflight: operation,
                };
                Ok(())
            }
            Err(error) => Err(latch_frame_io_error(this.lifecycle.as_ref(), error)),
        }
    }

    pub(super) fn poll_drain(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if matches!(self.as_ref().get_ref().send_state, SendState::Flush { .. }) {
                let mut this = self.as_mut().project();
                match ready!(this.bridge.as_mut().poll_flush(cx)) {
                    Ok(()) => {
                        *this.send_state = SendState::Idle { ready: false };
                        continue;
                    }
                    Err(error) => {
                        let error = latch_frame_io_error(this.lifecycle.as_ref(), error);
                        drain::log_drain_error(&error, "reader");
                        return Poll::Ready(());
                    }
                }
            }

            if self.as_ref().get_ref().pending.pull {
                if let Err(error) = ready!(self.as_mut().poll_drain_ready(cx)) {
                    drain::log_drain_error(&error, "reader");
                    return Poll::Ready(());
                }
                self.as_mut().project().pending.pull = false;
                if let Err(error) = self.as_mut().start_drain_operation(ReadOperation::Pull) {
                    drain::log_drain_error(&error, "reader");
                    return Poll::Ready(());
                }
                continue;
            }

            if let Some(code) = self.as_ref().get_ref().pending.stop {
                if let Err(error) = ready!(self.as_mut().poll_drain_ready(cx)) {
                    drain::log_drain_error(&error, "reader");
                    return Poll::Ready(());
                }
                self.as_mut().project().pending.stop = None;
                if let Err(error) = self
                    .as_mut()
                    .start_drain_operation(ReadOperation::Stop { code })
                {
                    drain::log_drain_error(&error, "reader");
                    return Poll::Ready(());
                }
                continue;
            }

            return Poll::Ready(());
        }
    }

    fn drive_pull(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ReaderFault>> {
        loop {
            if self.as_ref().get_ref().completed_pull_result() {
                return Poll::Ready(Ok(()));
            }

            ready!(self.as_mut().poll_idle(cx))?;

            if self.as_ref().get_ref().completed_pull_result() {
                return Poll::Ready(Ok(()));
            }

            if self.as_ref().get_ref().pending.pull {
                ready!(self.as_mut().poll_ready(cx))?;

                let mut this = self.as_mut().project();
                this.pending.pull = false;
                match this.bridge.as_mut().start_send(ReadCommand::Pull) {
                    Ok(()) => {
                        *this.send_state = SendState::Flush {
                            inflight: ReadOperation::Pull,
                        };
                    }
                    Err(error) => {
                        return Poll::Ready(Err(Self::frame_io_fault_for(this.lifecycle, error)));
                    }
                }
                continue;
            }

            return Poll::Pending;
        }
    }

    fn drive_stop(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        committed_code: VarInt,
    ) -> Poll<Result<(), ReaderFault>> {
        loop {
            if self.as_ref().get_ref().has_pull_eos() {
                self.as_mut().clear_pending_stop_if_matches(committed_code);
                return Poll::Ready(Ok(()));
            }

            if self
                .as_ref()
                .get_ref()
                .completed_stop_matches(committed_code)
            {
                return Poll::Ready(Ok(()));
            }

            ready!(self.as_mut().poll_idle(cx))?;

            if self.as_ref().get_ref().has_pull_eos() {
                self.as_mut().clear_pending_stop_if_matches(committed_code);
                return Poll::Ready(Ok(()));
            }

            if self
                .as_ref()
                .get_ref()
                .completed_stop_matches(committed_code)
            {
                return Poll::Ready(Ok(()));
            }

            if self.as_ref().get_ref().stop_ready_to_send(committed_code) {
                ready!(self.as_mut().poll_ready(cx))?;

                let mut this = self.as_mut().project();
                this.pending.stop = None;
                match this.bridge.as_mut().start_send(ReadCommand::Stop {
                    code: committed_code,
                }) {
                    Ok(()) => {
                        *this.send_state = SendState::Flush {
                            inflight: ReadOperation::Stop {
                                code: committed_code,
                            },
                        };
                    }
                    Err(error) => {
                        return Poll::Ready(Err(Self::frame_io_fault_for(this.lifecycle, error)));
                    }
                }
                continue;
            }

            return Poll::Pending;
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

impl<Io, L, E> BridgeStreamReader<Io, L, E>
where
    L: drain::DrainLifecycle,
    Io: drain::ReadDrainIo<E>,
    E: 'static,
    quic::ConnectionError: From<E>,
{
    fn stream_id(self: Pin<&mut Self>) -> VarInt {
        match self.project() {
            BridgeStreamReaderProj::Active { active } => active.as_ref().get_ref().stream_id,
            BridgeStreamReaderProj::Eos { stream_id } => *stream_id,
            BridgeStreamReaderProj::Closed { stream_id, .. } => *stream_id,
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
        fault: ReaderFault,
    ) -> Poll<quic::StreamError> {
        match fault {
            ReaderFault::Stream(error) => Poll::Ready(self.close_with_stream_error(error)),
            ReaderFault::Deferred(error) => {
                let stream_id = self.as_mut().stream_id();
                self.as_mut()
                    .project_replace(Self::Closed { stream_id, error });
                match self.project() {
                    BridgeStreamReaderProj::Closed { error, .. } => poll_deferred_error(error, cx),
                    _ => unreachable!("reader should have transitioned to closed"),
                }
            }
        }
    }

    fn poll_closed_error(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<quic::StreamError> {
        match self.project() {
            BridgeStreamReaderProj::Closed { error, .. } => poll_deferred_error(error, cx),
            _ => unreachable!("poll_closed_error called outside closed state"),
        }
    }
}

impl<Io, L, E> Stream for BridgeStreamReader<Io, L, E>
where
    L: drain::DrainLifecycle,
    Io: drain::ReadDrainIo<E>,
    E: 'static,
    quic::ConnectionError: From<E>,
{
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.as_mut().project() {
            BridgeStreamReaderProj::Active { active } => {
                let _commit = active.as_mut().commit_pull_pinned();
                match ready!(active.as_mut().drive_pull(cx)) {
                    Ok(()) => match active.as_mut().take_pull_result_pinned() {
                        Some(ReaderPullResult::Push(data)) => Poll::Ready(Some(Ok(data))),
                        Some(ReaderPullResult::Eos) => {
                            let stream_id = active.as_ref().get_ref().stream_id;
                            self.as_mut().project_replace(Self::Eos { stream_id });
                            Poll::Ready(None)
                        }
                        None => Poll::Pending,
                    },
                    Err(fault) => {
                        let error = ready!(self.as_mut().close_with_fault(cx, fault));
                        Poll::Ready(Some(Err(error)))
                    }
                }
            }
            BridgeStreamReaderProj::Eos { .. } => Poll::Ready(None),
            BridgeStreamReaderProj::Closed { .. } => {
                let error = ready!(self.as_mut().poll_closed_error(cx));
                Poll::Ready(Some(Err(error)))
            }
        }
    }
}

impl<Io, L, E> FusedStream for BridgeStreamReader<Io, L, E>
where
    L: drain::DrainLifecycle,
    Io: drain::ReadDrainIo<E>,
    E: 'static,
    quic::ConnectionError: From<E>,
{
    fn is_terminated(&self) -> bool {
        matches!(
            self,
            Self::Eos { .. }
                | Self::Closed {
                    error: DeferredStreamError::Ready { .. },
                    ..
                }
        )
    }
}

impl<Io, L, E> quic::GetStreamId for BridgeStreamReader<Io, L, E>
where
    L: drain::DrainLifecycle,
    Io: drain::ReadDrainIo<E>,
    E: 'static,
    quic::ConnectionError: From<E>,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        match self.project() {
            BridgeStreamReaderProj::Active { active } => {
                Poll::Ready(Ok(active.as_ref().get_ref().stream_id))
            }
            BridgeStreamReaderProj::Eos { stream_id } => Poll::Ready(Ok(*stream_id)),
            BridgeStreamReaderProj::Closed { stream_id, .. } => Poll::Ready(Ok(*stream_id)),
        }
    }
}

impl<Io, L, E> quic::StopStream for BridgeStreamReader<Io, L, E>
where
    L: drain::DrainLifecycle,
    Io: drain::ReadDrainIo<E>,
    E: 'static,
    quic::ConnectionError: From<E>,
{
    fn poll_stop(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        match self.as_mut().project() {
            BridgeStreamReaderProj::Active { active } => {
                let commit = active.as_mut().commit_stop_pinned(code);
                let committed_code = match commit {
                    CommitResult::Committed | CommitResult::Duplicate => code,
                    CommitResult::Conflict => active
                        .as_ref()
                        .committed_stop_code()
                        .expect("conflicting stop must have committed code"),
                };

                match ready!(active.as_mut().drive_stop(cx, committed_code)) {
                    Ok(()) => {
                        if active.as_ref().has_pull_eos() {
                            let stream_id = active.as_ref().get_ref().stream_id;
                            self.as_mut().project_replace(Self::Eos { stream_id });
                        }
                        Poll::Ready(Ok(()))
                    }
                    Err(fault) => {
                        let error = ready!(self.as_mut().close_with_fault(cx, fault));
                        Poll::Ready(Err(error))
                    }
                }
            }
            BridgeStreamReaderProj::Eos { .. } => Poll::Ready(Ok(())),
            BridgeStreamReaderProj::Closed { .. } => {
                let error = ready!(self.as_mut().poll_closed_error(cx));
                Poll::Ready(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, future::pending, sync::Arc};

    use bytes::Bytes;
    use futures::{
        FutureExt as _, SinkExt as _, StreamExt as _, future::poll_fn, stream::FusedStream as _,
    };

    use super::BridgeStreamReader;
    use crate::{
        quic::{self, GetStreamIdExt as _, StopStream, StopStreamExt as _},
        rpc::{
            lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt},
            stream::{
                frame::{ReadCommand, ReadEvent},
                test_io::{MemoryFrameIo, TestFrameIoError, TestLifecycle, worker_reader_pair},
            },
        },
        varint::VarInt,
    };

    type WorkerReaderIo = MemoryFrameIo<ReadCommand, ReadEvent, TestFrameIoError>;
    type HypervisorReaderIo = MemoryFrameIo<ReadEvent, ReadCommand, TestFrameIoError>;
    type TestBridgeStreamReader =
        BridgeStreamReader<WorkerReaderIo, TestLifecycle, TestFrameIoError>;

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

    fn reader(
        stream_id: VarInt,
    ) -> (
        TestBridgeStreamReader,
        HypervisorReaderIo,
        Arc<TestLifecycle>,
    ) {
        let lifecycle = Arc::new(TestLifecycle::new());
        let (worker, hypervisor) = worker_reader_pair::<TestFrameIoError>();
        (
            BridgeStreamReader::new(stream_id, worker, lifecycle.clone()),
            hypervisor,
            lifecycle,
        )
    }

    fn pending_closed_reader(
        stream_id: VarInt,
    ) -> (
        BridgeStreamReader<WorkerReaderIo, PendingClosedLifecycle, TestFrameIoError>,
        HypervisorReaderIo,
    ) {
        let lifecycle = Arc::new(PendingClosedLifecycle::new());
        let (worker, hypervisor) = worker_reader_pair::<TestFrameIoError>();
        (
            BridgeStreamReader::new(stream_id, worker, lifecycle),
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

    async fn expect_command(hypervisor: &mut HypervisorReaderIo) -> ReadCommand {
        hypervisor
            .next_frame()
            .await
            .expect("bridge should send a frame")
            .expect("command frame should be readable")
    }

    #[tokio::test]
    async fn poll_next_sends_one_pull_and_returns_push_bytes() {
        let (mut bridge, mut hypervisor, _lifecycle) = reader(VarInt::from_u32(7));
        let data = Bytes::from_static(b"read payload");

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none(),
            "first poll_next should commit a pull and wait for a response"
        );
        assert_eq!(expect_command(&mut hypervisor).await, ReadCommand::Pull);
        assert!(
            hypervisor.next_frame().now_or_never().is_none(),
            "poll_next must not send a duplicate pull while the first is in flight"
        );

        hypervisor
            .send(ReadEvent::Push { data: data.clone() })
            .await
            .expect("push event should send");

        assert_eq!(
            bridge.next().await.expect("reader item").expect("read ok"),
            data
        );
    }

    #[tokio::test]
    async fn poll_next_returns_none_for_eos_and_stays_ended() {
        let stream_id = VarInt::from_u32(8);
        let (mut bridge, mut hypervisor, _lifecycle) = reader(stream_id);

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, ReadCommand::Pull);
        hypervisor
            .send(ReadEvent::Eos)
            .await
            .expect("eos event should send");

        assert!(bridge.next().await.is_none());
        assert_eq!(bridge.stream_id().await.expect("stream id"), stream_id);
        assert!(matches!(bridge.next().now_or_never(), Some(None)));
    }

    #[tokio::test]
    async fn poll_stop_keeps_first_code_until_matching_stop_ack_arrives() {
        let first = VarInt::from_u32(11);
        let second = VarInt::from_u32(12);
        let (mut bridge, mut hypervisor, _lifecycle) = reader(VarInt::from_u32(9));

        assert!(
            poll_fn(|cx| std::pin::Pin::new(&mut bridge).poll_stop(cx, first))
                .now_or_never()
                .is_none(),
            "first stop poll should commit and wait for ack"
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            ReadCommand::Stop { code: first }
        );

        assert!(
            poll_fn(|cx| std::pin::Pin::new(&mut bridge).poll_stop(cx, second))
                .now_or_never()
                .is_none(),
            "second stop poll should continue the first committed code"
        );
        assert!(
            hypervisor.next_frame().now_or_never().is_none(),
            "different stop code must not replace the first committed stop"
        );

        hypervisor
            .send(ReadEvent::StopAck { code: first })
            .await
            .expect("stop ack should send");
        bridge.stop(second).await.expect("stop should complete");
    }

    #[tokio::test]
    async fn poll_stop_after_completed_stop_ack_does_not_send_second_stop() {
        let first = VarInt::from_u32(21);
        let second = VarInt::from_u32(22);
        let (mut bridge, mut hypervisor, _lifecycle) = reader(VarInt::from_u32(10));

        assert!(
            poll_fn(|cx| std::pin::Pin::new(&mut bridge).poll_stop(cx, first))
                .now_or_never()
                .is_none()
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            ReadCommand::Stop { code: first }
        );
        hypervisor
            .send(ReadEvent::StopAck { code: first })
            .await
            .expect("stop ack should send");
        bridge
            .stop(first)
            .await
            .expect("first stop should complete");

        bridge
            .stop(second)
            .await
            .expect("completed stop should make later stop a no-op");
        assert!(
            hypervisor.next_frame().now_or_never().is_none(),
            "completed stop result must prevent a second stop frame"
        );
    }

    #[tokio::test]
    async fn poll_stop_during_pull_preserves_push_for_later_poll_next() {
        let stop_code = VarInt::from_u32(31);
        let data = Bytes::from_static(b"received before stop");
        let (mut bridge, mut hypervisor, _lifecycle) = reader(VarInt::from_u32(13));

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, ReadCommand::Pull);
        hypervisor
            .send(ReadEvent::Push { data: data.clone() })
            .await
            .expect("push event should send");

        let stop =
            poll_fn(|cx| std::pin::Pin::new(&mut bridge).poll_stop(cx, stop_code)).now_or_never();
        assert!(
            stop.is_none(),
            "stop should wait for stop ack after caching push"
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            ReadCommand::Stop { code: stop_code }
        );
        hypervisor
            .send(ReadEvent::StopAck { code: stop_code })
            .await
            .expect("stop ack should send");
        bridge
            .stop(stop_code)
            .await
            .expect("stop should complete after ack");

        assert_eq!(
            bridge
                .next()
                .await
                .expect("cached item should exist")
                .expect("cached read should be ok"),
            data
        );
        assert!(
            hypervisor.next_frame().now_or_never().is_none(),
            "cached push must be returned without issuing another pull"
        );
    }

    #[tokio::test]
    async fn poll_stop_during_pull_eos_completes_without_stop_frame() {
        let stop_code = VarInt::from_u32(32);
        let (mut bridge, mut hypervisor, _lifecycle) = reader(VarInt::from_u32(14));

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, ReadCommand::Pull);
        hypervisor
            .send(ReadEvent::Eos)
            .await
            .expect("eos event should send");

        bridge
            .stop(stop_code)
            .await
            .expect("eos should satisfy stop");
        match hypervisor.next_frame().now_or_never() {
            None | Some(None) => {}
            Some(Some(frame)) => panic!("eos stop should not send a frame, got {frame:?}"),
        }
        assert!(matches!(bridge.next().now_or_never(), Some(None)));
    }

    #[tokio::test]
    async fn wrong_stop_ack_latches_protocol_connection_error() {
        let expected = VarInt::from_u32(41);
        let actual = VarInt::from_u32(42);
        let (mut bridge, mut hypervisor, lifecycle) = reader(VarInt::from_u32(15));

        assert!(
            poll_fn(|cx| std::pin::Pin::new(&mut bridge).poll_stop(cx, expected))
                .now_or_never()
                .is_none()
        );
        assert_eq!(
            expect_command(&mut hypervisor).await,
            ReadCommand::Stop { code: expected }
        );
        hypervisor
            .send(ReadEvent::StopAck { code: actual })
            .await
            .expect("wrong stop ack should send");

        let error = bridge.stop(expected).await.expect_err("stop should fail");
        let source = stream_connection(error);
        assert_eq!(
            transport(&source).reason.as_ref(),
            "stop ack code 42 does not match committed stop code 41"
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
    async fn err_reset_closes_reader_with_reset_stream_error() {
        let reset_code = VarInt::from_u32(51);
        let (mut bridge, mut hypervisor, _lifecycle) = reader(VarInt::from_u32(16));

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, ReadCommand::Pull);
        hypervisor
            .send(ReadEvent::ErrReset { code: reset_code })
            .await
            .expect("reset event should send");

        match bridge.next().await {
            Some(Err(quic::StreamError::Reset { code })) if code == reset_code => {}
            result => panic!("expected reset stream error, got {result:?}"),
        }
    }

    #[tokio::test]
    async fn terminal_error_marks_reader_terminated() {
        let reset_code = VarInt::from_u32(52);
        let (mut bridge, mut hypervisor, _lifecycle) = reader(VarInt::from_u32(19));

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, ReadCommand::Pull);
        hypervisor
            .send(ReadEvent::ErrReset { code: reset_code })
            .await
            .expect("reset event should send");

        let Some(Err(quic::StreamError::Reset { code })) = bridge.next().await else {
            panic!("err reset should close the reader");
        };
        assert_eq!(code, reset_code);
        assert!(bridge.is_terminated());
    }

    #[tokio::test]
    async fn pending_terminal_error_does_not_mark_reader_terminated() {
        let (mut bridge, mut hypervisor) = pending_closed_reader(VarInt::from_u32(21));

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, ReadCommand::Pull);
        hypervisor
            .send(ReadEvent::ErrConn)
            .await
            .expect("connection error event should send");

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none(),
            "deferred connection error should remain pending"
        );
        assert!(!bridge.is_terminated());
    }

    #[tokio::test]
    async fn stream_id_remains_available_after_terminal_error() {
        let stream_id = VarInt::from_u32(20);
        let reset_code = VarInt::from_u32(53);
        let (mut bridge, mut hypervisor, _lifecycle) = reader(stream_id);

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, ReadCommand::Pull);
        hypervisor
            .send(ReadEvent::ErrReset { code: reset_code })
            .await
            .expect("reset event should send");

        let Some(Err(quic::StreamError::Reset { code })) = bridge.next().await else {
            panic!("err reset should close the reader");
        };
        assert_eq!(code, reset_code);
        assert_eq!(bridge.stream_id().await.expect("stream id"), stream_id);
    }

    #[tokio::test]
    async fn err_conn_deferred_error_returns_lifecycle_canonical_error() {
        let canonical = quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(61),
                frame_type: VarInt::from_u32(62),
                reason: "canonical closed error".into(),
            },
        };
        let (mut bridge, mut hypervisor, lifecycle) = reader(VarInt::from_u32(17));
        lifecycle.set_closed_error(canonical.clone());

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, ReadCommand::Pull);
        hypervisor
            .send(ReadEvent::ErrConn)
            .await
            .expect("connection error event should send");

        let Some(Err(error)) = bridge.next().await else {
            panic!("err conn should return a stream error");
        };
        let source = stream_connection(error);
        assert_eq!(transport(&source).kind, VarInt::from_u32(61));
        let closed = quic::Lifecycle::closed(lifecycle.as_ref()).await;
        assert_eq!(transport(&source).kind, transport(&closed).kind);
        assert_eq!(transport(&source).frame_type, transport(&closed).frame_type);
        assert_eq!(transport(&source).reason, transport(&closed).reason);
        assert_eq!(transport(&source).kind, transport(&canonical).kind);
        assert_eq!(
            transport(&source).frame_type,
            transport(&canonical).frame_type
        );
        assert_eq!(transport(&source).reason, transport(&canonical).reason);
    }

    #[tokio::test]
    async fn frame_io_eof_before_read_eos_latches_connection_frame_eof() {
        let (mut bridge, mut hypervisor, lifecycle) = reader(VarInt::from_u32(18));

        assert!(
            poll_fn(|cx| bridge.poll_next_unpin(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(expect_command(&mut hypervisor).await, ReadCommand::Pull);
        drop(hypervisor);

        let Some(Err(error)) = bridge.next().await else {
            panic!("frame eof should return a stream error");
        };
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
