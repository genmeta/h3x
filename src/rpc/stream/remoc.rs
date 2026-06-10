use std::{
    borrow::Cow,
    collections::VecDeque,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{
    Sink, Stream,
    future::{BoxFuture, FutureExt as _},
    ready,
};
use remoc::rch::{Sending, SendingError, mpsc};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt as _, Snafu};

use super::{
    frame::{ReadCommand, ReadEvent, WriteCommand, WriteEvent},
    reader::BridgeStreamReader,
    writer::BridgeStreamWriter,
};
use crate::{quic, rpc::lifecycle::LifecycleExt, varint::VarInt};

const CHANNEL_CAPACITY: usize = 8;
const RPC_FRAME_IO_ERROR_KIND: VarInt = VarInt::from_u32(0x0c);
const RPC_FRAME_IO_FRAME_TYPE: VarInt = VarInt::from_u32(0x00);

pub type ReadOutSender = mpsc::Sender<ReadCommand>;
pub type ReadInReceiver = mpsc::Receiver<ReadEvent>;
pub type WriteOutSender = mpsc::Sender<WriteCommand>;
pub type WriteInReceiver = mpsc::Receiver<WriteEvent>;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RpcFrameIoError {
    #[snafu(display("failed to send rpc stream frame"))]
    Send { source: mpsc::SendError<()> },
    #[snafu(display("failed to receive rpc stream frame"))]
    Receive { source: mpsc::RecvError },
}

impl From<RpcFrameIoError> for quic::ConnectionError {
    fn from(error: RpcFrameIoError) -> Self {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: RPC_FRAME_IO_ERROR_KIND,
                frame_type: RPC_FRAME_IO_FRAME_TYPE,
                // Lossy: QUIC transport error reason is a protocol string field
                // for local RPC frame-channel failures.
                reason: Cow::Owned(error.to_string()),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadFrameChannels {
    stream_id: VarInt,
    outbound: ReadOutSender,
    inbound: ReadInReceiver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteFrameChannels {
    stream_id: VarInt,
    outbound: WriteOutSender,
    inbound: WriteInReceiver,
}

impl ReadFrameChannels {
    pub(crate) fn pair(stream_id: VarInt) -> (Self, RpcFrameIo<ReadEvent, ReadCommand>) {
        let (command_tx, command_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(CHANNEL_CAPACITY);
        (
            Self {
                stream_id,
                outbound: command_tx,
                inbound: event_rx,
            },
            RpcFrameIo::new(event_tx, command_rx),
        )
    }

    pub(crate) fn into_quic<L>(
        self,
        lifecycle: Arc<L>,
    ) -> BridgeStreamReader<RpcFrameIo<ReadCommand, ReadEvent>, L, RpcFrameIoError>
    where
        L: LifecycleExt + 'static,
    {
        BridgeStreamReader::new(
            self.stream_id,
            RpcFrameIo::new(self.outbound, self.inbound),
            lifecycle,
        )
    }
}

impl WriteFrameChannels {
    pub(crate) fn pair(stream_id: VarInt) -> (Self, RpcFrameIo<WriteEvent, WriteCommand>) {
        let (command_tx, command_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(CHANNEL_CAPACITY);
        (
            Self {
                stream_id,
                outbound: command_tx,
                inbound: event_rx,
            },
            RpcFrameIo::new(event_tx, command_rx),
        )
    }

    pub(crate) fn into_quic<L>(
        self,
        lifecycle: Arc<L>,
    ) -> BridgeStreamWriter<RpcFrameIo<WriteCommand, WriteEvent>, L, RpcFrameIoError>
    where
        L: LifecycleExt + 'static,
    {
        BridgeStreamWriter::new(
            self.stream_id,
            RpcFrameIo::new(self.outbound, self.inbound),
            lifecycle,
        )
    }
}

type ReserveFuture<T> = BoxFuture<'static, Result<mpsc::Permit<T>, mpsc::SendError<()>>>;

pub(crate) struct RpcFrameIo<Out, In> {
    sender: Option<mpsc::Sender<Out>>,
    reserve: Option<ReserveFuture<Out>>,
    permit: Option<mpsc::Permit<Out>>,
    sending: VecDeque<Sending<Out>>,
    receiver: mpsc::Receiver<In>,
    _in: PhantomData<fn() -> In>,
}

impl<Out, In> RpcFrameIo<Out, In> {
    fn new(sender: mpsc::Sender<Out>, receiver: mpsc::Receiver<In>) -> Self
    where
        Out: Send + 'static,
    {
        Self {
            sender: Some(sender),
            reserve: None,
            permit: None,
            sending: VecDeque::new(),
            receiver,
            _in: PhantomData,
        }
    }

    fn reserve(sender: mpsc::Sender<Out>) -> ReserveFuture<Out>
    where
        Out: Send + 'static,
    {
        async move { sender.reserve().await }.boxed()
    }
}

fn sending_error_to_send_error<T>(error: SendingError<T>) -> mpsc::SendError<()> {
    match error {
        SendingError::Send(source) => mpsc::SendError::RemoteSend(source.kind),
        SendingError::Dropped => mpsc::SendError::Closed(()),
    }
}

impl<Out, In> Sink<Out> for RpcFrameIo<Out, In>
where
    Out: Send + 'static,
{
    type Error = RpcFrameIoError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.permit.is_some() {
            return Poll::Ready(Ok(()));
        }

        if self.reserve.is_none() {
            let Some(sender) = self.sender.clone() else {
                return Poll::Ready(Err(RpcFrameIoError::Send {
                    source: mpsc::SendError::Closed(()),
                }));
            };
            self.reserve = Some(Self::reserve(sender));
        }

        let reserve = self
            .reserve
            .as_mut()
            .expect("reserve future should be initialized");
        let result = ready!(reserve.as_mut().poll(cx)).context(rpc_frame_io_error::SendSnafu);
        self.reserve = None;
        match result {
            Ok(permit) => {
                self.permit = Some(permit);
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Out) -> Result<(), Self::Error> {
        let permit = self
            .permit
            .take()
            .expect("rpc frame io sender is not ready");
        self.sending.push_back(permit.send(item));
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        while let Some(sending) = self.sending.front_mut() {
            let result = ready!(sending.poll_unpin(cx));
            self.sending.pop_front();
            if let Err(error) = result {
                return Poll::Ready(Err(RpcFrameIoError::Send {
                    source: sending_error_to_send_error(error),
                }));
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.sender = None;
        self.reserve = None;
        self.permit = None;
        self.sending.clear();
        Poll::Ready(Ok(()))
    }
}

impl<Out, In> Stream for RpcFrameIo<Out, In> {
    type Item = Result<In, RpcFrameIoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(self.receiver.poll_recv(cx)).context(rpc_frame_io_error::ReceiveSnafu) {
            Ok(Some(frame)) => Poll::Ready(Some(Ok(frame))),
            Ok(None) => Poll::Ready(None),
            Err(error) => Poll::Ready(Some(Err(error))),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::{SinkExt as _, StreamExt as _, future::poll_fn};

    use super::*;
    use crate::rpc::stream::frame::{ReadCommand, ReadEvent};

    #[tokio::test]
    async fn read_frame_channel_pair_is_bidirectional() {
        let stream_id = VarInt::from_u32(701);
        let (channels, mut hypervisor) = ReadFrameChannels::pair(stream_id);
        let mut worker = RpcFrameIo::new(channels.outbound, channels.inbound);

        let send = worker.send(ReadCommand::Pull);
        let receive = hypervisor.next();
        let (send, received) = tokio::join!(send, receive);
        send.unwrap();
        assert_eq!(received.unwrap().unwrap(), ReadCommand::Pull);

        let send = hypervisor.send(ReadEvent::Push {
            data: Bytes::from_static(b"rpc frame"),
        });
        let receive = worker.next();
        let (send, received) = tokio::join!(send, receive);
        send.unwrap();
        assert_eq!(
            received.unwrap().unwrap(),
            ReadEvent::Push {
                data: Bytes::from_static(b"rpc frame"),
            }
        );
    }

    #[tokio::test]
    async fn flush_waits_until_remoc_send_is_observed() {
        let (outbound, mut outbound_rx): (ReadOutSender, mpsc::Receiver<ReadCommand>) =
            mpsc::channel(CHANNEL_CAPACITY);
        let (_inbound_tx, inbound): (mpsc::Sender<ReadEvent>, ReadInReceiver) =
            mpsc::channel(CHANNEL_CAPACITY);
        let mut io = RpcFrameIo::new(outbound, inbound);

        let send = io.send(ReadCommand::Pull);
        tokio::pin!(send);
        assert!(
            send.as_mut().now_or_never().is_none(),
            "flush must wait for remoc to finish sending the queued frame"
        );

        assert_eq!(outbound_rx.recv().await.unwrap(), Some(ReadCommand::Pull));
        send.await.unwrap();
    }

    #[tokio::test]
    async fn flush_waits_for_all_started_remoc_sends() {
        let (outbound, mut outbound_rx): (ReadOutSender, mpsc::Receiver<ReadCommand>) =
            mpsc::channel(CHANNEL_CAPACITY);
        let (_inbound_tx, inbound): (mpsc::Sender<ReadEvent>, ReadInReceiver) =
            mpsc::channel(CHANNEL_CAPACITY);
        let mut io = RpcFrameIo::new(outbound, inbound);
        let stop = VarInt::from_u32(9);

        poll_fn(|cx| Pin::new(&mut io).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut io).start_send(ReadCommand::Pull).unwrap();
        poll_fn(|cx| Pin::new(&mut io).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut io)
            .start_send(ReadCommand::Stop { code: stop })
            .unwrap();

        let flush = poll_fn(|cx| Pin::new(&mut io).poll_flush(cx));
        tokio::pin!(flush);
        assert!(
            flush.as_mut().now_or_never().is_none(),
            "flush must wait for the first started send"
        );

        assert_eq!(outbound_rx.recv().await.unwrap(), Some(ReadCommand::Pull));
        assert!(
            flush.as_mut().now_or_never().is_none(),
            "flush must wait for later started sends too"
        );

        assert_eq!(
            outbound_rx.recv().await.unwrap(),
            Some(ReadCommand::Stop { code: stop })
        );
        flush.await.unwrap();
    }
}
