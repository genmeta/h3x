//! Channel-backed RPC stream payloads.
//!
//! Raw QUIC stream data/control is transported over typed remoc MPSC frame
//! channels and reconstructed with the shared `rpc::stream` bridge drivers.

pub use crate::rpc::stream::remoc::{ReadFrameChannels, WriteFrameChannels};

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use futures::{FutureExt as _, SinkExt as _, StreamExt as _};

    use super::*;
    use crate::{
        quic::{ResetStreamExt as _, StopStreamExt as _},
        rpc::stream::{
            frame::{ReadCommand, WriteCommand},
            test_io::TestLifecycle,
        },
        varint::VarInt,
    };

    #[tokio::test]
    async fn read_frame_channels_construct_quic_reader() {
        let stream_id = VarInt::from_u32(801);
        let (channels, mut hypervisor) = ReadFrameChannels::pair(stream_id);
        let lifecycle = Arc::new(TestLifecycle::new());
        let mut reader = channels.into_quic(lifecycle);

        let read = Box::pin(reader.next());
        tokio::pin!(read);
        assert!(read.as_mut().now_or_never().is_none());
        assert_eq!(hypervisor.next().await.unwrap().unwrap(), ReadCommand::Pull);
        let send = hypervisor.send(crate::rpc::stream::frame::ReadEvent::Push {
            data: Bytes::from_static(b"rpc read"),
        });
        let (send, received) = tokio::join!(send, read);
        send.unwrap();
        assert_eq!(received.unwrap().unwrap(), Bytes::from_static(b"rpc read"));
    }

    #[tokio::test]
    async fn read_stream_stop_is_first_wins_through_frames() {
        let stream_id = VarInt::from_u32(802);
        let first = VarInt::from_u32(11);
        let second = VarInt::from_u32(12);
        let (channels, mut hypervisor) = ReadFrameChannels::pair(stream_id);
        let lifecycle = Arc::new(TestLifecycle::new());
        let mut reader = channels.into_quic(lifecycle);

        assert!(reader.stop(first).now_or_never().is_none());
        assert_eq!(
            hypervisor.next().await.unwrap().unwrap(),
            ReadCommand::Stop { code: first }
        );
        let second_stop = reader.stop(second);
        tokio::pin!(second_stop);
        let send = hypervisor.send(crate::rpc::stream::frame::ReadEvent::StopAck { code: first });
        let (send, stop) = tokio::join!(send, second_stop);
        send.unwrap();
        stop.unwrap();
    }

    #[tokio::test]
    async fn write_stream_reset_is_first_wins_through_frames() {
        let stream_id = VarInt::from_u32(803);
        let first = VarInt::from_u32(21);
        let second = VarInt::from_u32(22);
        let (channels, mut hypervisor) = WriteFrameChannels::pair(stream_id);
        let lifecycle = Arc::new(TestLifecycle::new());
        let mut writer = channels.into_quic(lifecycle);

        assert!(writer.reset(first).now_or_never().is_none());
        assert_eq!(
            hypervisor.next().await.unwrap().unwrap(),
            WriteCommand::Reset { code: first }
        );
        let second_reset = writer.reset(second);
        tokio::pin!(second_reset);
        let send = hypervisor.send(crate::rpc::stream::frame::WriteEvent::ResetAck { code: first });
        let (send, reset) = tokio::join!(send, second_reset);
        send.unwrap();
        reset.unwrap();
    }
}
