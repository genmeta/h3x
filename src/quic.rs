mod gm_quic;

use std::{
    borrow::Cow,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{
    Sink, Stream,
    future::{BoxFuture, poll_fn},
};

use crate::{
    error::{Code, ConnectionError, StreamError},
    varint::VarInt,
};

pub trait QuicConnect {
    type StreamWriter: WriteStream;
    type StreamReader: ReadStream;

    fn open_bi(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>>;

    fn open_uni(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<Self::StreamWriter, ConnectionError>>;

    fn accept_bi(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>>;

    fn accept_uni(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<Self::StreamReader, ConnectionError>>;

    fn close(self: Pin<&mut Self>, code: Code, reason: Cow<'static, str>);
}

pub trait GetStreamId {
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>>;
}

impl<P> GetStreamId for Pin<P>
where
    P: DerefMut<Target: GetStreamId>,
{
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        <P::Target as GetStreamId>::poll_stream_id(self.as_deref_mut(), cx)
    }
}

impl<S> GetStreamId for &mut S
where
    S: GetStreamId + Unpin + ?Sized,
{
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        S::poll_stream_id(Pin::new(self.get_mut()), cx)
    }
}

pub trait GetStreamIdExt {
    async fn stream_id(&mut self) -> Result<VarInt, StreamError>
    where
        Self: Unpin;
}

impl<T: GetStreamId + ?Sized> GetStreamIdExt for T {
    async fn stream_id(&mut self) -> Result<VarInt, StreamError>
    where
        Self: Unpin,
    {
        let mut pin = Pin::new(self);
        poll_fn(|cx| pin.as_mut().poll_stream_id(cx)).await
    }
}

pub trait StopSending {
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>>;
}

impl<P> StopSending for Pin<P>
where
    P: DerefMut<Target: StopSending>,
{
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        <P::Target as StopSending>::poll_stop_sending(self.as_deref_mut(), cx, code)
    }
}

impl<S> StopSending for &mut S
where
    S: StopSending + Unpin + ?Sized,
{
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        S::poll_stop_sending(Pin::new(self.get_mut()), cx, code)
    }
}

pub trait StopSendingExt {
    async fn stop_sending(&mut self, code: VarInt) -> Result<(), StreamError>
    where
        Self: Unpin;
}

impl<T: StopSending + ?Sized> StopSendingExt for T {
    async fn stop_sending(&mut self, code: VarInt) -> Result<(), StreamError>
    where
        Self: Unpin,
    {
        let mut pin = Pin::new(self);
        poll_fn(|cx| pin.as_mut().poll_stop_sending(cx, code)).await
    }
}

pub trait ReadStream:
    StopSending + GetStreamId + Stream<Item = Result<Bytes, StreamError>>
{
}

impl<S: StopSending + GetStreamId + Stream<Item = Result<Bytes, StreamError>> + ?Sized> ReadStream
    for S
{
}

pub trait CancelStream {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>>;
}

impl<S> CancelStream for &mut S
where
    S: CancelStream + Unpin + ?Sized,
{
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        S::poll_cancel(Pin::new(self.get_mut()), cx, code)
    }
}

impl<P> CancelStream for Pin<P>
where
    P: DerefMut<Target: CancelStream>,
{
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        <P::Target as CancelStream>::poll_cancel(self.as_deref_mut(), cx, code)
    }
}

pub trait CancelStreamExt {
    async fn cancel(&mut self, code: VarInt) -> Result<(), StreamError>
    where
        Self: Unpin;
}

impl<T: CancelStream + ?Sized> CancelStreamExt for T {
    async fn cancel(&mut self, code: VarInt) -> Result<(), StreamError>
    where
        Self: Unpin,
    {
        let mut pin = Pin::new(self);
        poll_fn(|cx| pin.as_mut().poll_cancel(cx, code)).await
    }
}

pub trait WriteStream: CancelStream + GetStreamId + Sink<Bytes, Error = StreamError> {}

impl<S: CancelStream + GetStreamId + Sink<Bytes, Error = StreamError> + ?Sized> WriteStream for S {}

#[cfg(test)]
pub mod test {
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll, ready},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream, StreamExt};
    use tokio::sync::oneshot;

    use crate::{
        error::StreamError,
        quic::{CancelStream, GetStreamId, StopSending},
        varint::VarInt,
    };

    pin_project_lite::pin_project! {
        pub struct MockStreamWriter<S: ?Sized> {
            stream_id: VarInt,
            #[pin]
            stop_sending: oneshot::Receiver<VarInt>,
            #[pin]
            stream: S,
        }

        impl<S:? Sized> PinnedDrop for MockStreamWriter<S> {
            fn drop(this: Pin<&mut Self>) {
                println!("Dropping MockStreamWriter({})", this.stream_id);
            }
        }
    }

    pub enum Packet {
        Stream(Bytes),
        Reset(VarInt),
    }

    impl<S: ?Sized> GetStreamId for MockStreamWriter<S> {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, StreamError>> {
            Ok(self.stream_id).into()
        }
    }

    impl<S: Sink<Packet> + ?Sized> CancelStream for MockStreamWriter<S>
    where
        StreamError: From<S::Error>,
    {
        // fn poll_cancel(self: Pin<&mut Self>, code: VarInt) {
        //     let project = self.project();
        //     if matches!(project.reset, SenderResetState::None) {
        //         *project.reset = SenderResetState::ResetPending(code);
        //     }
        // }
        fn poll_cancel(
            self: Pin<&mut Self>,
            cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            let mut project = self.project();
            ready!(project.stream.as_mut().poll_ready(cx)?);
            project.stream.as_mut().start_send(Packet::Reset(code))?;
            Poll::Ready(Ok(()))
        }
    }

    impl<S: Sink<Packet> + ?Sized> Sink<Bytes> for MockStreamWriter<S>
    where
        StreamError: From<S::Error>,
    {
        type Error = StreamError;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.project().stream.poll_ready(cx).map_err(From::from)
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.project()
                .stream
                .start_send(Packet::Stream(item))
                .map_err(From::from)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.project().stream.poll_flush(cx).map_err(From::from)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.project().stream.poll_close(cx).map_err(From::from)
        }
    }

    enum ReceiverResetState {
        None,
        ResetReceived(VarInt),
    }

    pin_project_lite::pin_project! {
        pub struct MockStreamReader<S: ?Sized> {
            stream_id: VarInt,
            stop_sending_tx: Option<oneshot::Sender<VarInt>>,
            reset: ReceiverResetState,
            #[pin]
            stream: S,
        }

        impl<S:? Sized> PinnedDrop for MockStreamReader<S> {
            fn drop(this: Pin<&mut Self>) {
                println!("Dropping MockStreamReader({})", this.stream_id);
            }
        }
    }

    impl<S: ?Sized> GetStreamId for MockStreamReader<S> {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl<S: ?Sized> StopSending for MockStreamReader<S> {
        fn poll_stop_sending(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            let project = self.project();
            if let Some(tx) = project.stop_sending_tx.take() {
                let _ = tx.send(code);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl<S: Stream<Item = Result<Packet, StreamError>> + ?Sized> Stream for MockStreamReader<S> {
        type Item = Result<Bytes, StreamError>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut project = self.project();
            loop {
                if let ReceiverResetState::ResetReceived(code) = *project.reset {
                    return Poll::Ready(Some(Err(StreamError::Reset { code })));
                }
                match ready!(project.stream.as_mut().poll_next(cx)?) {
                    Some(Packet::Stream(bytes)) => return Poll::Ready(Some(Ok(bytes))),
                    Some(Packet::Reset(code)) => {
                        *project.reset = ReceiverResetState::ResetReceived(code);
                    }
                    None => return Poll::Ready(None),
                }
            }
        }
    }

    pub fn mock_stream_pair(
        stream_id: VarInt,
    ) -> (
        MockStreamReader<impl Stream<Item = Result<Packet, StreamError>>>,
        MockStreamWriter<impl Sink<Packet, Error = StreamError>>,
    ) {
        let (stop_sending_tx, stop_sending_rx) = oneshot::channel();
        let (packet_tx, packet_rx) = futures::channel::mpsc::channel(8);

        let writer = MockStreamWriter {
            stream_id,
            stop_sending: stop_sending_rx,
            stream: packet_tx.sink_map_err(|_| StreamError::Reset {
                code: VarInt::from_u32(0),
            }),
        };

        let reader = MockStreamReader {
            stream_id,
            stop_sending_tx: Some(stop_sending_tx),
            reset: ReceiverResetState::None,
            stream: packet_rx.map(Ok),
        };

        (reader, writer)
    }

    #[tokio::test]
    async fn pair() {
        let (mut reader, mut writer) = mock_stream_pair(VarInt::from_u32(37));

        let file = include_bytes!("./quic.rs");
        let send = async {
            for part in file.chunks(100) {
                writer.feed(Bytes::copy_from_slice(part)).await.unwrap();
            }
            writer.close().await.unwrap();
        };
        let recv = async {
            let mut received = Vec::new();
            while let Some(chunk) = reader.next().await {
                let chunk = chunk.unwrap();
                received.extend_from_slice(&chunk);
            }
            assert!(received == file);
        };
        tokio::join!(send, recv);
    }
}
