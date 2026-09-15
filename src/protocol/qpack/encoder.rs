//! Outgoing headers, encoder-stream instructions, and feedback from the peer decoder.
use bytes::Bytes;
use tokio::sync::mpsc;

use super::{
    Field, Settings,
    codec::instruction::{DecoderInstruction, EncoderInstruction},
};
use crate::{ErrorCode, Result};
mod state;
use state::State;
pub(in crate::protocol) type Batch = Vec<EncoderInstruction>;
pub(in crate::protocol) type Instructions = mpsc::Receiver<Batch>;
type OnInstruction = Box<dyn Fn(Batch) -> Result<()> + Send + Sync>;

pub(in crate::protocol) struct Encoder {
    state: State,
    completed: u64,
}
impl Encoder {
    pub(super) fn new(peer: Settings) -> Result<Self> {
        Ok(Self {
            state: State::new(
                peer,
                Box::new(|_| {
                    Err(ErrorCode::H3_INTERNAL_ERROR
                        .with_reason("instruction callback is not registered"))
                }),
            )?,
            completed: 0,
        })
    }

    pub(in crate::protocol) fn on_instruction(
        &mut self,
        callback: impl Fn(Batch) -> Result<()> + Send + Sync + 'static,
    ) {
        self.state.on_instruction = Box::new(callback);
    }

    pub(super) fn record_insert_written(&mut self) {
        self.completed += 1;
    }

    pub(super) fn configure(&mut self, peer: Settings, max_fields: u64) -> Result<()> {
        self.state.configure(peer, max_fields)
    }
    pub(super) fn encode(&mut self, id: u64, fields: Vec<Field>) -> Result<Bytes> {
        self.state.encode(id, fields)
    }
    pub(super) fn on_decoder_instruction(&mut self, instruction: DecoderInstruction) -> Result<()> {
        self.state
            .on_decoder_instruction(instruction, self.completed)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    use tokio::io::AsyncWrite;

    use super::*;
    use crate::protocol::qpack::{ArcQpack, Qpack};
    fn shared(encoder: Encoder) -> ArcQpack {
        ArcQpack(Arc::new(Mutex::new(Ok(Qpack {
            encoder,
            decoder: super::super::decoder::Decoder::new(Settings::default(), 0, u64::MAX).unwrap(),
            on_failure: None,
        }))))
    }
    fn feedback(qpack: &ArcQpack, instruction: DecoderInstruction) -> Result<()> {
        qpack
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .encoder
            .on_decoder_instruction(instruction)
    }

    struct Writer {
        fail: bool,
    }
    impl AsyncWrite for Writer {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fail {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            } else {
                Poll::Ready(Ok(bytes.len()))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("QPACK instructions must not wait for transport acknowledgments")
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn queued_insert() -> (ArcQpack, Instructions) {
        let (mut encoder, source) = Encoder::with_channel(Settings::default()).unwrap();
        encoder
            .configure(
                Settings {
                    max_table_capacity: 68,
                    blocked_streams: 1,
                },
                1024,
            )
            .unwrap();
        encoder
            .encode(
                0,
                vec![Field {
                    name: Bytes::from_static(b"x"),
                    value: Bytes::from_static(b"a"),
                    never_index: false,
                }],
            )
            .unwrap();
        (shared(encoder), source)
    }

    #[tokio::test]
    async fn completed_writes_allow_feedback_without_flushing() {
        let (encoder, source) = queued_insert();
        assert_eq!(
            (feedback(&encoder, DecoderInstruction::SectionAcknowledgment(0)))
                .map_err(ErrorCode::from),
            Err(ErrorCode::QPACK_DECODER_STREAM_ERROR)
        );
        let mut writer = Writer { fail: false };
        let mut writing = Box::pin(encoder.write_encoder(source, &mut writer));
        assert!(
            writing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(
            encoder.lock().unwrap().as_ref().unwrap().encoder.completed,
            1
        );
        assert_eq!(
            feedback(&encoder, DecoderInstruction::SectionAcknowledgment(0)),
            Ok(())
        );
        assert_eq!(
            (feedback(&encoder, DecoderInstruction::SectionAcknowledgment(0)))
                .map_err(ErrorCode::from),
            Err(ErrorCode::QPACK_DECODER_STREAM_ERROR)
        );
    }

    #[tokio::test]
    async fn completed_count_tracks_insertions_and_duplicates_across_batches() {
        let encoder = shared(Encoder::new(Settings::default()).unwrap());
        let (tx, rx) = mpsc::channel(2);
        tx.try_send(vec![
            EncoderInstruction::SetDynamicTableCapacity(128),
            EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from_static(b"a"),
            },
        ])
        .unwrap();
        tx.try_send(vec![
            EncoderInstruction::Duplicate(0),
            EncoderInstruction::InsertWithNameReference {
                static_table: false,
                index: 0,
                value: Bytes::from_static(b"b"),
            },
            EncoderInstruction::SetDynamicTableCapacity(128),
        ])
        .unwrap();
        drop(tx);
        assert_eq!(
            (encoder.write_encoder(rx, &mut Writer { fail: false }).await).map_err(ErrorCode::from),
            Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM),
        );
        assert_eq!(
            encoder.lock().unwrap().as_ref().unwrap().encoder.completed,
            3
        );
    }

    #[tokio::test]
    async fn failed_writes_do_not_advance_completion() {
        let (encoder, source) = queued_insert();
        assert_eq!(
            (encoder
                .write_encoder(source, &mut Writer { fail: true })
                .await)
                .map_err(ErrorCode::from),
            Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
        );
        assert_eq!(
            encoder.lock().unwrap().as_ref().unwrap().encoder.completed,
            0
        );
    }

    impl Encoder {
        pub(in crate::protocol::qpack) fn with_channel(
            peer: Settings,
        ) -> Result<(Self, Instructions)> {
            let mut encoder = Self::new(peer)?;
            let (tx, rx) = mpsc::channel(crate::protocol::qpack::MAX_PENDING_INSTRUCTION);
            encoder.on_instruction(move |batch| {
                tx.try_send(batch)
                    .map_err(crate::protocol::qpack::instruction_send_error)
            });
            Ok((encoder, rx))
        }
    }
}
