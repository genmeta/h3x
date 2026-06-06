use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, stream::FusedStream};

use crate::{
    codec::{SinkWriter, StreamReader},
    dhttp::message::{BoxMessageReader, BoxMessageWriter, MessageStreamError},
    quic,
    rpc::{
        lifecycle::LifecycleExt,
        stream::remoc::{ReadFrameChannels, WriteFrameChannels},
    },
    stream,
};

pin_project_lite::pin_project! {
    struct MessageFrameReader<R> {
        #[pin]
        inner: R,
    }
}

impl<R> MessageFrameReader<R> {
    fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R> Stream for MessageFrameReader<R>
where
    R: Stream<Item = Result<Bytes, quic::StreamError>>,
{
    type Item = Result<Bytes, MessageStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().inner.poll_next(cx) {
            Poll::Ready(Some(Ok(data))) => Poll::Ready(Some(Ok(data))),
            Poll::Ready(Some(Err(source))) => {
                Poll::Ready(Some(Err(MessageStreamError::Quic { source })))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R> FusedStream for MessageFrameReader<R>
where
    R: FusedStream<Item = Result<Bytes, quic::StreamError>>,
{
    fn is_terminated(&self) -> bool {
        self.inner.is_terminated()
    }
}

impl<R> quic::GetStreamId for MessageFrameReader<R>
where
    R: quic::GetStreamId,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<crate::varint::VarInt, quic::StreamError>> {
        self.project().inner.poll_stream_id(cx)
    }
}

impl<R> quic::StopStream for MessageFrameReader<R>
where
    R: quic::StopStream,
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: crate::varint::VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.project().inner.poll_stop(cx, code)
    }
}

impl<R> stream::GetStreamId<quic::StreamError> for MessageFrameReader<R>
where
    R: quic::GetStreamId,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<crate::varint::VarInt, quic::StreamError>> {
        quic::GetStreamId::poll_stream_id(self, cx)
    }
}

impl<R> stream::StopStream<quic::StreamError> for MessageFrameReader<R>
where
    R: quic::StopStream,
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        code: crate::varint::VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        quic::StopStream::poll_stop(self, cx, code)
    }
}

pin_project_lite::pin_project! {
    struct MessageFrameWriter<W> {
        #[pin]
        inner: W,
    }
}

impl<W> MessageFrameWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W> Sink<Bytes> for MessageFrameWriter<W>
where
    W: Sink<Bytes, Error = quic::StreamError>,
{
    type Error = MessageStreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(source)) => Poll::Ready(Err(MessageStreamError::Quic { source })),
            Poll::Pending => Poll::Pending,
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        match self.project().inner.start_send(item) {
            Ok(()) => Ok(()),
            Err(source) => Err(MessageStreamError::Quic { source }),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(source)) => Poll::Ready(Err(MessageStreamError::Quic { source })),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(source)) => Poll::Ready(Err(MessageStreamError::Quic { source })),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<W> quic::GetStreamId for MessageFrameWriter<W>
where
    W: quic::GetStreamId,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<crate::varint::VarInt, quic::StreamError>> {
        self.project().inner.poll_stream_id(cx)
    }
}

impl<W> quic::ResetStream for MessageFrameWriter<W>
where
    W: quic::ResetStream,
{
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: crate::varint::VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.project().inner.poll_reset(cx, code)
    }
}

impl<W> stream::GetStreamId<quic::StreamError> for MessageFrameWriter<W>
where
    W: quic::GetStreamId,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<crate::varint::VarInt, quic::StreamError>> {
        quic::GetStreamId::poll_stream_id(self, cx)
    }
}

impl<W> stream::ResetStream<quic::StreamError> for MessageFrameWriter<W>
where
    W: quic::ResetStream,
{
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        code: crate::varint::VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        quic::ResetStream::poll_reset(self, cx, code)
    }
}

impl ReadFrameChannels {
    /// Convert RPC read frame channels into a poll-based message stream reader.
    pub fn into_message_stream<L>(
        self,
        lifecycle: Arc<L>,
    ) -> impl stream::ReadStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
    + Send
    + 'static
    where
        L: LifecycleExt + 'static,
    {
        MessageFrameReader::new(self.into_quic(lifecycle))
    }

    /// Convert RPC read frame channels into a boxed message stream reader.
    pub fn into_boxed_message_stream<L>(self, lifecycle: Arc<L>) -> BoxMessageReader
    where
        L: LifecycleExt + 'static,
    {
        Box::pin(MessageFrameReader::new(self.into_quic(lifecycle)))
    }

    /// Convert RPC read frame channels into a boxed message stream reader.
    pub fn into_box_reader<L>(self, lifecycle: Arc<L>) -> BoxMessageReader
    where
        L: LifecycleExt + 'static,
    {
        self.into_boxed_message_stream(lifecycle)
    }
}

impl WriteFrameChannels {
    /// Convert RPC write frame channels into a poll-based message stream writer.
    pub fn into_message_stream<L>(
        self,
        lifecycle: Arc<L>,
    ) -> impl stream::WriteStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
    + Send
    + 'static
    where
        L: LifecycleExt + 'static,
    {
        MessageFrameWriter::new(self.into_quic(lifecycle))
    }

    /// Convert RPC write frame channels into a boxed message stream writer.
    pub fn into_boxed_message_stream<L>(self, lifecycle: Arc<L>) -> BoxMessageWriter
    where
        L: LifecycleExt + 'static,
    {
        Box::pin(MessageFrameWriter::new(self.into_quic(lifecycle)))
    }

    /// Convert RPC write frame channels into a boxed message stream writer.
    pub fn into_box_writer<L>(self, lifecycle: Arc<L>) -> BoxMessageWriter
    where
        L: LifecycleExt + 'static,
    {
        self.into_boxed_message_stream(lifecycle)
    }
}

#[cfg(test)]
mod tests {
    use std::{pin::Pin, sync::Arc};

    use futures::{FutureExt as _, SinkExt as _, StreamExt as _, future::poll_fn};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::{
        rpc::stream::{
            frame::{ReadCommand, ReadEvent, WriteCommand, WriteEvent},
            remoc::RpcFrameIo,
            test_io::TestLifecycle,
        },
        stream::{GetStreamIdExt as _, ResetStreamExt as _, StopStreamExt as _},
        varint::VarInt,
    };

    fn lifecycle() -> Arc<TestLifecycle> {
        Arc::new(TestLifecycle::new())
    }

    fn assert_message_reset(error: MessageStreamError, expected: VarInt) {
        let MessageStreamError::Quic {
            source: quic::StreamError::Reset { code },
        } = error
        else {
            panic!("expected reset-backed message stream error");
        };
        assert_eq!(code, expected);
    }

    async fn send_write_credit(
        hypervisor: &mut RpcFrameIo<WriteEvent, WriteCommand>,
        writer: &mut (
                 impl stream::WriteStream<
            Bytes,
            MessageStreamError,
            quic::StreamError,
            quic::StreamError,
        > + Unpin
             ),
    ) {
        let ready = poll_fn(|cx| Pin::new(&mut *writer).poll_ready(cx));
        let credit = hypervisor.send(WriteEvent::Pull);
        let (credit, ready) = tokio::join!(credit, ready);
        credit.expect("credit should send");
        ready.expect("writer should become ready");
    }

    #[tokio::test]
    async fn read_frame_channels_construct_message_reader() {
        let stream_id = VarInt::from_u32(901);
        let (channels, mut hypervisor) = ReadFrameChannels::pair(stream_id);
        let mut reader = channels.into_message_stream(lifecycle());

        assert_eq!(reader.stream_id().await.expect("stream id"), stream_id);

        let read = reader.next();
        tokio::pin!(read);
        assert!(read.as_mut().now_or_never().is_none());
        assert_eq!(hypervisor.next().await.unwrap().unwrap(), ReadCommand::Pull);
        let send = hypervisor.send(ReadEvent::Push {
            data: Bytes::from_static(b"message read"),
        });
        let (send, received) = tokio::join!(send, read);
        send.expect("read event should send");
        assert_eq!(
            received.unwrap().expect("message read should succeed"),
            Bytes::from_static(b"message read")
        );
    }

    #[tokio::test]
    async fn write_frame_channels_construct_message_writer() {
        let stream_id = VarInt::from_u32(902);
        let (channels, mut hypervisor) = WriteFrameChannels::pair(stream_id);
        let mut writer = channels.into_message_stream(lifecycle());

        assert_eq!(writer.stream_id().await.expect("stream id"), stream_id);
        send_write_credit(&mut hypervisor, &mut writer).await;
        Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"message write"))
            .expect("start send should succeed");

        let flush = writer.flush();
        let drive = async {
            assert_eq!(
                hypervisor.next().await.unwrap().unwrap(),
                WriteCommand::Push {
                    data: Bytes::from_static(b"message write")
                }
            );
            assert_eq!(
                hypervisor.next().await.unwrap().unwrap(),
                WriteCommand::Flush
            );
            hypervisor
                .send(WriteEvent::FlushAck)
                .await
                .expect("flush ack should send");
        };
        let (flush, ()) = tokio::join!(flush, drive);
        flush.expect("message flush should succeed");
    }

    #[tokio::test]
    async fn read_message_stream_stop_is_first_wins_through_frames() {
        let stream_id = VarInt::from_u32(903);
        let first = VarInt::from_u32(11);
        let second = VarInt::from_u32(12);
        let (channels, mut hypervisor) = ReadFrameChannels::pair(stream_id);
        let mut reader = channels.into_message_stream(lifecycle());

        assert!(reader.stop(first).now_or_never().is_none());
        assert_eq!(
            hypervisor.next().await.unwrap().unwrap(),
            ReadCommand::Stop { code: first }
        );
        let second_stop = reader.stop(second);
        tokio::pin!(second_stop);
        let send = hypervisor.send(ReadEvent::StopAck { code: first });
        let (send, stop) = tokio::join!(send, second_stop);
        send.expect("stop ack should send");
        stop.expect("second stop should observe first committed stop");
    }

    #[tokio::test]
    async fn write_message_stream_reset_is_first_wins_through_frames() {
        let stream_id = VarInt::from_u32(904);
        let first = VarInt::from_u32(21);
        let second = VarInt::from_u32(22);
        let (channels, mut hypervisor) = WriteFrameChannels::pair(stream_id);
        let mut writer = channels.into_message_stream(lifecycle());

        assert!(writer.reset(first).now_or_never().is_none());
        assert_eq!(
            hypervisor.next().await.unwrap().unwrap(),
            WriteCommand::Reset { code: first }
        );
        let second_reset = writer.reset(second);
        tokio::pin!(second_reset);
        let send = hypervisor.send(WriteEvent::ResetAck { code: first });
        let (send, reset) = tokio::join!(send, second_reset);
        send.expect("reset ack should send");
        reset.expect("second reset should observe first committed reset");
    }

    #[tokio::test]
    async fn read_message_stream_maps_quic_errors_to_message_errors() {
        let stream_id = VarInt::from_u32(905);
        let code = VarInt::from_u32(31);
        let (channels, mut hypervisor) = ReadFrameChannels::pair(stream_id);
        let mut reader = channels.into_message_stream(lifecycle());

        let read = reader.next();
        tokio::pin!(read);
        assert!(read.as_mut().now_or_never().is_none());
        assert_eq!(hypervisor.next().await.unwrap().unwrap(), ReadCommand::Pull);
        let send = hypervisor.send(ReadEvent::ErrReset { code });
        let (send, received) = tokio::join!(send, read);
        send.expect("reset event should send");
        let error = received
            .expect("reset should produce an item")
            .expect_err("reset should map to message error");
        assert_message_reset(error, code);
    }

    #[tokio::test]
    async fn write_message_stream_maps_quic_errors_to_message_errors() {
        let stream_id = VarInt::from_u32(906);
        let code = VarInt::from_u32(41);
        let (channels, mut hypervisor) = WriteFrameChannels::pair(stream_id);
        let mut writer = channels.into_message_stream(lifecycle());

        let ready = poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx));
        let reset = hypervisor.send(WriteEvent::ErrReset { code });
        let (reset, ready) = tokio::join!(reset, ready);
        reset.expect("reset event should send");
        let error = ready.expect_err("reset should map to message error");
        assert_message_reset(error, code);
    }

    #[tokio::test]
    async fn read_message_box_adapters_use_frame_channels() {
        let stream_id = VarInt::from_u32(907);
        let (channels, mut hypervisor) = ReadFrameChannels::pair(stream_id);
        let mut stream = channels.into_boxed_message_stream(lifecycle());

        let read = stream.next();
        tokio::pin!(read);
        assert!(read.as_mut().now_or_never().is_none());
        assert_eq!(hypervisor.next().await.unwrap().unwrap(), ReadCommand::Pull);
        let send = hypervisor.send(ReadEvent::Push {
            data: Bytes::from_static(b"boxed"),
        });
        let (send, received) = tokio::join!(send, read);
        send.expect("boxed read event should send");
        assert_eq!(
            received.unwrap().expect("boxed read should succeed"),
            Bytes::from_static(b"boxed")
        );

        let stream_id = VarInt::from_u32(908);
        let (channels, mut hypervisor) = ReadFrameChannels::pair(stream_id);
        let reader = channels.into_box_reader(lifecycle());
        let read_all = async {
            let mut buf = Vec::new();
            StreamReader::new(reader)
                .read_to_end(&mut buf)
                .await
                .expect("box reader should read");
            buf
        };
        let drive = async {
            assert_eq!(hypervisor.next().await.unwrap().unwrap(), ReadCommand::Pull);
            hypervisor
                .send(ReadEvent::Push {
                    data: Bytes::from_static(b"reader"),
                })
                .await
                .expect("box reader chunk should send");
            assert_eq!(hypervisor.next().await.unwrap().unwrap(), ReadCommand::Pull);
            hypervisor
                .send(ReadEvent::Eos)
                .await
                .expect("box reader eos should send");
        };
        let (buf, ()) = tokio::join!(read_all, drive);
        assert_eq!(buf, b"reader");
    }

    #[tokio::test]
    async fn write_message_box_adapters_use_frame_channels() {
        let stream_id = VarInt::from_u32(909);
        let (channels, mut hypervisor) = WriteFrameChannels::pair(stream_id);
        let mut stream = channels.into_boxed_message_stream(lifecycle());
        send_write_credit(&mut hypervisor, &mut stream).await;

        Pin::new(&mut stream)
            .start_send(Bytes::from_static(b"boxed"))
            .expect("boxed start send should succeed");
        let flush = stream.flush();
        let drive = async {
            assert_eq!(
                hypervisor.next().await.unwrap().unwrap(),
                WriteCommand::Push {
                    data: Bytes::from_static(b"boxed")
                }
            );
            assert_eq!(
                hypervisor.next().await.unwrap().unwrap(),
                WriteCommand::Flush
            );
            hypervisor
                .send(WriteEvent::FlushAck)
                .await
                .expect("boxed flush ack should send");
        };
        let (flush, ()) = tokio::join!(flush, drive);
        flush.expect("boxed flush should succeed");

        let stream_id = VarInt::from_u32(910);
        let (channels, mut hypervisor) = WriteFrameChannels::pair(stream_id);
        let mut writer = SinkWriter::new(channels.into_box_writer(lifecycle()));
        let write_all = async {
            writer
                .write_all(b"writer")
                .await
                .expect("box writer should write");
            tokio::io::AsyncWriteExt::flush(&mut writer)
                .await
                .expect("box writer should flush");
        };
        let drive = async {
            let ready = hypervisor.send(WriteEvent::Pull);
            ready.await.expect("box writer credit should send");
            assert_eq!(
                hypervisor.next().await.unwrap().unwrap(),
                WriteCommand::Push {
                    data: Bytes::from_static(b"writer")
                }
            );
            assert_eq!(
                hypervisor.next().await.unwrap().unwrap(),
                WriteCommand::Flush
            );
            hypervisor
                .send(WriteEvent::FlushAck)
                .await
                .expect("box writer flush ack should send");
        };
        let ((), ()) = tokio::join!(write_all, drive);
    }
}
