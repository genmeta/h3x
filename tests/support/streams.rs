//! Native dquic stream state for codec tests, without sockets or replacement stream traits.
#![cfg_attr(not(test), allow(dead_code))] // Fuzzing uses only the receive fixture.
use bytes::{BufMut, Bytes, BytesMut, buf::UninitSlice};
use dquic::{
    prelude::{StreamReader, StreamWriter},
    qconnection::{ArcReliableFrameDeque, DataStreams},
};
use qbase::{
    flow::ArcSendControler,
    frame::{Frame, ResetStreamFrame, StreamFrame, io::ReceiveFrame},
    packet::RecordFrame,
    param::{
        ArcParameters, Parameters,
        handy::{client_parameters, server_parameters},
    },
    role::Role,
    sid::{Dir, StreamId, handy::DemandConcurrency},
    util::ContinuousData,
    varint::VarInt,
};

use crate::{Code, transport};

pub(crate) struct Streams {
    pub(crate) data: DataStreams,
    params: ArcParameters,
    controls: ArcReliableFrameDeque,
    flow: ArcSendControler<ArcReliableFrameDeque>,
    pub(crate) sent: std::sync::Mutex<Vec<(StreamFrame, Bytes)>>,
    pub(crate) reset: std::sync::atomic::AtomicBool,
}
impl Streams {
    pub(crate) fn new() -> Self {
        Self::with_uni_credit(1 << 20)
    }
    pub(crate) fn with_uni_credit(credit: u64) -> Self {
        let mut client = client_parameters();
        client
            .set(
                qbase::param::ParameterId::InitialMaxStreamDataUni,
                VarInt::try_from(qbase::varint::VARINT_MAX).unwrap(),
            )
            .unwrap();
        let mut server = server_parameters();
        server
            .set(
                qbase::param::ParameterId::InitialMaxStreamDataUni,
                VarInt::try_from(credit).unwrap(),
            )
            .unwrap();
        let controls = ArcReliableFrameDeque::with_capacity_and_wakers(16, Default::default());
        Self {
            data: DataStreams::new(
                Role::Client,
                &client,
                &server,
                Box::new(DemandConcurrency),
                controls.clone(),
                Default::default(),
                None,
            ),
            params: Parameters::new_client(client, Some(server), Default::default()).into(),
            flow: ArcSendControler::new(1 << 24, controls.clone(), Default::default()),
            controls,
            sent: Default::default(),
            reset: Default::default(),
        }
    }
    pub(crate) fn writer(&self) -> (StreamId, StreamWriter) {
        futures::executor::block_on(self.data.open_uni(&self.params))
            .unwrap()
            .unwrap()
    }
    pub(crate) fn open_bi(&self) -> (StreamId, (StreamReader, StreamWriter)) {
        futures::executor::block_on(self.data.open_bi(&self.params))
            .unwrap()
            .unwrap()
    }
    pub(crate) fn feed(&self, id: StreamId, offset: u64, bytes: Bytes, fin: bool) {
        let mut frame = StreamFrame::new(id, offset, bytes.len());
        frame.set_eos_flag(fin);
        self.data.recv_frame((frame, bytes)).unwrap();
    }
    pub(crate) fn accept_reader(&self) -> StreamReader {
        futures::executor::block_on(self.data.accept_uni())
            .unwrap()
            .1
    }
    pub(crate) async fn drive<F: std::future::Future>(&self, future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        futures::future::poll_fn(|cx| {
            let result = future.as_mut().poll(cx);
            let (frames, _) = self.drain();
            if !frames.is_empty() {
                cx.waker().wake_by_ref();
            }
            result
        })
        .await
    }
    pub(crate) fn drain(&self) -> (Vec<(StreamFrame, Bytes)>, bool) {
        let mut packet = Packet {
            bytes: BytesMut::with_capacity(1 << 20),
            data: Vec::new(),
            reset: false,
        };
        let _ = self.data.try_load_data_into(&mut packet, &self.flow, false);
        let _ = self.controls.try_load_frames_into(&mut packet);
        for (frame, _) in &packet.data {
            self.data.on_data_acked(frame.clone());
        }
        self.sent
            .lock()
            .unwrap()
            .extend(packet.data.iter().cloned());
        self.reset
            .fetch_or(packet.reset, std::sync::atomic::Ordering::Relaxed);
        (packet.data, packet.reset)
    }
}

pub(crate) fn reader(
    chunks: impl IntoIterator<Item = Result<Bytes, transport::StreamError>>,
) -> StreamReader {
    let streams = Streams::new();
    let id = StreamId::new(Role::Server, Dir::Uni, 0);
    streams.feed(id, 0, Bytes::new(), false);
    let reader = streams.accept_reader();
    let mut offset = 0;
    for chunk in chunks {
        match chunk {
            Ok(bytes) => {
                let len = bytes.len() as u64;
                streams.feed(id, offset, bytes, false);
                offset += len;
            }
            Err(error) => {
                if error.is_connection() {
                    streams.data.on_conn_error(
                        &qbase::error::QuicError::with_default_fty(
                            qbase::error::ErrorKind::Internal,
                            "test connection failed",
                        )
                        .into(),
                    );
                } else {
                    streams
                        .data
                        .recv_stream_control(
                            ResetStreamFrame::new(
                                id,
                                VarInt::try_from(
                                    error.code().unwrap_or(Code::H3_REQUEST_CANCELLED).as_u64(),
                                )
                                .unwrap(),
                                VarInt::try_from(offset).unwrap(),
                            )
                            .into(),
                        )
                        .unwrap();
                }
                return reader;
            }
        }
    }
    streams.feed(id, offset, Bytes::new(), true);
    reader
}
pub(crate) fn writer() -> StreamWriter {
    Streams::new().writer().1
}

struct Packet {
    bytes: BytesMut,
    data: Vec<(StreamFrame, Bytes)>,
    reset: bool,
}
// SAFETY: buffer storage and initialized-length rules are delegated unchanged to BytesMut.
unsafe impl BufMut for Packet {
    fn remaining_mut(&self) -> usize {
        self.bytes.remaining_mut()
    }
    unsafe fn advance_mut(&mut self, count: usize) {
        unsafe {
            self.bytes.advance_mut(count);
        }
    }
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.bytes.chunk_mut()
    }
}
impl<D: ContinuousData> RecordFrame<Frame<D>, D> for Packet {
    fn record_frame(&mut self, frame: &Frame<D>) {
        match frame {
            Frame::Stream(frame, data) => self.data.push((frame.clone(), data.to_bytes())),
            Frame::StreamCtl(qbase::frame::StreamCtlFrame::ResetStream(_)) => self.reset = true,
            _ => {}
        }
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_frame(data: &[u8]) {
    use crate::wire::{self, frame};
    let _ = frame::be_complete_frame(&Bytes::copy_from_slice(data));
    let width = data.first().map_or(1, |byte| 1 + usize::from(*byte));
    let stream = reader(
        data.chunks(width)
            .map(|chunk| Ok(Bytes::copy_from_slice(chunk))),
    );
    let id = StreamId::new(Role::Server, Dir::Uni, 0);
    let mut frames = wire::FrameReader::new(wire::ChunkReader::new(id, stream));
    let _: Result<(), crate::Error> = futures::executor::block_on(async {
        while let Some(header) = frames.next_header().await? {
            match header.frame_type {
                frame::FrameType::Data | frame::FrameType::Unknown(_) => {
                    frames.discard_payload().await?
                }
                _ => {
                    frames.read(|input| frame::be_frame(input, header)).await?;
                }
            }
        }
        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{self, frame};

    #[tokio::test]
    async fn native_receive_preserves_data_pointers_across_pending_and_fin() {
        let streams = Streams::new();
        let id = StreamId::new(Role::Server, Dir::Uni, 0);
        let first = Bytes::from_static(&[0, 4, b'a', b'b']);
        let second = Bytes::from_static(&[b'c', b'd', 1, 2, 0, 0]);
        streams.feed(id, 0, first.clone(), false);
        let mut frames =
            wire::FrameReader::new(wire::ChunkReader::new(id, streams.accept_reader()));
        let header = frames.next_header().await.unwrap().unwrap();
        assert_eq!(header.frame_type, frame::FrameType::Data);
        let bytes = frames
            .read(|input| frame::be_payload_chunk(input, 16))
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"ab");
        assert_eq!(bytes.as_ptr(), first[2..].as_ptr());
        let mut next = Box::pin(frames.read(|input| frame::be_payload_chunk(input, 16)));
        assert!(futures::poll!(next.as_mut()).is_pending());
        streams.feed(id, first.len() as u64, second.clone(), true);
        let bytes = next.await.unwrap();
        assert_eq!(&bytes[..], b"cd");
        assert_eq!(bytes.as_ptr(), second.as_ptr());
        assert_eq!(
            frames.next_header().await.unwrap().unwrap().frame_type,
            frame::FrameType::Headers
        );
        frames.discard_payload().await.unwrap();
        assert!(frames.next_header().await.unwrap().is_none());
    }
}
