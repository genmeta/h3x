use std::{ops::Deref, pin::Pin};

use bytes::Bytes;
use futures::{Sink, Stream, future::BoxFuture};

use crate::error::{ConnectionError, StreamError};

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
}

pub trait GetStreamId {
    fn stream_id(&self) -> u64;
}

impl<S: ?Sized> GetStreamId for &S
where
    S: GetStreamId,
{
    fn stream_id(&self) -> u64 {
        S::stream_id(self)
    }
}

impl<S: ?Sized> GetStreamId for &mut S
where
    S: GetStreamId,
{
    fn stream_id(&self) -> u64 {
        S::stream_id(self)
    }
}

impl<P> GetStreamId for Pin<P>
where
    P: Deref<Target: GetStreamId>,
{
    fn stream_id(&self) -> u64 {
        <P::Target>::stream_id(self.deref())
    }
}

pub trait StopSending {
    fn stop_sending(self: Pin<&mut Self>, code: u64);
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
    fn cancel(self: Pin<&mut Self>, code: u64);
}

pub trait WriteStream: CancelStream + GetStreamId + Sink<Bytes, Error = StreamError> {}

impl<S: CancelStream + GetStreamId + Sink<Bytes, Error = StreamError> + ?Sized> WriteStream for S {}

#[cfg(test)]
pub mod test {
    use std::{
        pin::Pin,
        task::{Context, Poll, ready},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream, StreamExt};
    use tokio::sync::oneshot;

    use crate::{
        error::StreamError,
        quic::{CancelStream, GetStreamId, StopSending},
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SenderResetState {
        None,
        ResetPending(u64),
        ResetSent(u64),
    }

    pin_project_lite::pin_project! {
        pub struct MockStreamWriter<S: ?Sized> {
            stream_id: u64,
            reset: SenderResetState,
            #[pin]
            stop_sending: oneshot::Receiver<u64>,
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
        Reset(u64),
    }

    impl<S: ?Sized> GetStreamId for MockStreamWriter<S> {
        fn stream_id(&self) -> u64 {
            self.stream_id
        }
    }

    impl<S: ?Sized> CancelStream for MockStreamWriter<S> {
        fn cancel(self: Pin<&mut Self>, code: u64) {
            let project = self.project();
            if matches!(project.reset, SenderResetState::None) {
                *project.reset = SenderResetState::ResetPending(code);
            }
        }
    }

    impl<S: Sink<Packet> + ?Sized> Sink<Bytes> for MockStreamWriter<S>
    where
        StreamError: From<S::Error>,
    {
        type Error = StreamError;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let mut project = self.project();
            loop {
                match *project.reset {
                    SenderResetState::ResetPending(code) => {
                        ready!(project.stream.as_mut().poll_ready(cx)?);
                        project.stream.as_mut().start_send(Packet::Reset(code))?;
                        *project.reset = SenderResetState::ResetSent(code);
                        return Poll::Ready(Ok(()));
                    }
                    SenderResetState::ResetSent(code) => {
                        return Poll::Ready(Err(StreamError::Reset { code }));
                    }
                    _ => {}
                }
                if let SenderResetState::None = *project.reset
                    && let Poll::Ready(Ok(code)) = project.stop_sending.as_mut().poll(cx)
                {
                    *project.reset = SenderResetState::ResetPending(code);
                    continue;
                }

                ready!(project.stream.as_mut().poll_ready(cx)?);
                return Poll::Ready(Ok(()));
            }
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            let project = self.project();
            match *project.reset {
                SenderResetState::ResetPending(_) => panic!(),
                SenderResetState::ResetSent(_) => Err(StreamError::Reset { code: 0 }),
                SenderResetState::None => project
                    .stream
                    .start_send(Packet::Stream(item))
                    .map_err(From::from),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let mut project = self.project();
            loop {
                match *project.reset {
                    SenderResetState::ResetPending(code) => {
                        ready!(project.stream.as_mut().poll_ready(cx)?);
                        project.stream.as_mut().start_send(Packet::Reset(code))?;
                        *project.reset = SenderResetState::ResetSent(code);
                    }
                    SenderResetState::None => {
                        if let Poll::Ready(Ok(code)) = project.stop_sending.as_mut().poll(cx) {
                            *project.reset = SenderResetState::ResetPending(code);
                            continue;
                        }
                    }
                    SenderResetState::ResetSent(_) => todo!(),
                }
                ready!(project.stream.as_mut().poll_flush(cx)?);
                return Poll::Ready(Ok(()));
            }
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let mut project = self.project();
            loop {
                match *project.reset {
                    SenderResetState::ResetPending(code) => {
                        ready!(project.stream.as_mut().poll_ready(cx)?);
                        project.stream.as_mut().start_send(Packet::Reset(code))?;
                        *project.reset = SenderResetState::ResetSent(code);
                    }
                    SenderResetState::None => {
                        if let Poll::Ready(Ok(code)) = project.stop_sending.as_mut().poll(cx) {
                            *project.reset = SenderResetState::ResetPending(code);
                            continue;
                        }
                    }
                    SenderResetState::ResetSent(_) => todo!(),
                }
                ready!(project.stream.as_mut().poll_close(cx)?);
                return Poll::Ready(Ok(()));
            }
        }
    }

    enum ReceiverResetState {
        None,
        ResetReceived(u64),
    }

    pin_project_lite::pin_project! {
        pub struct MockStreamReader<S: ?Sized> {
            stream_id: u64,
            stop_sending_tx: Option<oneshot::Sender<u64>>,
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
        fn stream_id(&self) -> u64 {
            self.stream_id
        }
    }

    impl<S: ?Sized> StopSending for MockStreamReader<S> {
        fn stop_sending(self: Pin<&mut Self>, code: u64) {
            if let Some(tx) = self.project().stop_sending_tx.take() {
                let _ = tx.send(code);
            }
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
        stream_id: u64,
    ) -> (
        MockStreamReader<impl Stream<Item = Result<Packet, StreamError>>>,
        MockStreamWriter<impl Sink<Packet, Error = StreamError>>,
    ) {
        let (stop_sending_tx, stop_sending_rx) = oneshot::channel();
        let (packet_tx, packet_rx) = futures::channel::mpsc::channel(8);

        let writer = MockStreamWriter {
            stream_id,
            reset: SenderResetState::None,
            stop_sending: stop_sending_rx,
            stream: packet_tx.sink_map_err(|error| StreamError::Unknown {
                source: Box::new(error),
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
        let (mut reader, mut writer) = mock_stream_pair(42);

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
