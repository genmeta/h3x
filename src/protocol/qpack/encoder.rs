//! Outgoing headers, encoder-stream instructions, and feedback from the peer decoder.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use super::{
    Field, Settings,
    codec::instruction::{
        DecoderInstruction, EncoderInstruction, WriteInstruction, be_decoder_instruction,
    },
};
use crate::{ErrorCode, Result, protocol::frame::StreamType};

mod state;
use state::State;

/// Instructions from one atomic encoder state update.
pub(in crate::protocol) type Batch = Vec<EncoderInstruction>;
pub(in crate::protocol) type Instructions = mpsc::Receiver<Batch>;
type OnInstruction = Box<dyn Fn(Batch) -> Result<()> + Send + Sync>;

pub(in crate::protocol) struct Encoder {
    state: Mutex<Result<State>>,
    completed: AtomicU64,
}

impl Encoder {
    pub(super) fn new(peer: Settings) -> Result<Self> {
        Ok(Self {
            state: Mutex::new(Ok(State::new(
                peer,
                Box::new(|_| Err(ErrorCode::H3_INTERNAL_ERROR)),
            )?)),
            completed: AtomicU64::new(0),
        })
    }

    /// Called synchronously under the state lock; the callback must not reenter QPACK.
    pub(in crate::protocol) fn on_instruction(
        &self,
        callback: impl Fn(Batch) -> Result<()> + Send + Sync + 'static,
    ) {
        self.state
            .lock()
            .unwrap()
            .as_mut()
            .expect("register before use")
            .on_instruction = Box::new(callback);
    }

    /// Simulate a successful insertion write in cross-direction codec tests.
    #[cfg(test)]
    pub(super) fn record_insert_written(&self) {
        self.completed.fetch_add(1, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn with_channel(peer: Settings) -> Result<(Self, Instructions)> {
        let encoder = Self::new(peer)?;
        let (tx, rx) = mpsc::channel(super::MAX_PENDING_INSTRUCTION);
        encoder.on_instruction(move |batch| {
            tx.try_send(batch)
                .map_err(crate::protocol::connection::instruction_send_error)
        });
        Ok((encoder, rx))
    }

    pub(super) fn configure(&self, peer: Settings, max_fields: u64) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .as_mut()
            .map_err(|error| *error)?
            .configure(peer, max_fields)
    }

    #[cfg(test)]
    pub(super) fn error(&self) -> Option<ErrorCode> {
        self.state.lock().unwrap().as_ref().err().copied()
    }

    pub(super) fn close(&self, error: ErrorCode) -> ErrorCode {
        let error = {
            let mut state = self.state.lock().unwrap();
            let error = state.as_ref().err().copied().unwrap_or(error);
            *state = Err(error);
            error
        };

        error
    }

    pub(super) fn encode(&self, id: u64, fields: Vec<Field>) -> Result<Bytes> {
        self.state
            .lock()
            .unwrap()
            .as_mut()
            .map_err(|error| *error)?
            .encode(id, fields)
    }

    /// Read and validate peer feedback against completed local writes.
    pub(super) async fn receive<R: AsyncRead + Unpin>(&self, recv: &mut R) -> Result<()> {
        loop {
            let instruction = be_decoder_instruction(recv).await?;
            self.on_decoder_instruction(instruction)?;
        }
    }

    pub(super) fn on_decoder_instruction(&self, instruction: DecoderInstruction) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .as_mut()
            .map_err(|error| *error)?
            .on_decoder_instruction(instruction, self.completed.load(Ordering::Acquire))
    }

    /// Own the state needed by the writer so its task does not borrow the connection.
    pub(in crate::protocol) fn sync<T: crate::Transport>(
        self: &Arc<Self>,
        transport: Arc<T>,
        instructions: Instructions,
    ) -> impl Future<Output = ()> + Send + 'static + use<T> {
        let encoder = self.clone();
        async move {
            super::drive(transport, async move |send: &mut T::StreamWriter| {
                encoder.write(instructions, send).await
            })
            .await;
        }
    }

    pub(in crate::protocol) async fn write<W: AsyncWrite + Unpin>(
        &self,
        mut instructions: Instructions,
        writer: &mut W,
    ) -> Result<()> {
        writer
            .write_all(&[StreamType::QpackEncoder as u8])
            .await
            .map_err(|_| ErrorCode::H3_CLOSED_CRITICAL_STREAM)?;
        let mut buf = Vec::new();
        while let Some(batch) = instructions.recv().await {
            for instruction in batch {
                buf.clear();
                buf.put_encoder_instruction(&instruction)?;
                writer
                    .write_all(&buf)
                    .await
                    .map_err(|_| ErrorCode::H3_CLOSED_CRITICAL_STREAM)?;
                if !matches!(instruction, EncoderInstruction::SetDynamicTableCapacity(_)) {
                    self.completed.fetch_add(1, Ordering::Release);
                }
            }
        }
        Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        io,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    use super::*;

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

    fn queued_insert() -> (Encoder, Instructions) {
        let (encoder, source) = Encoder::with_channel(Settings::default()).unwrap();
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
        (encoder, source)
    }

    #[tokio::test]
    async fn completed_writes_allow_feedback_without_flushing() {
        let (encoder, source) = queued_insert();
        assert_eq!(
            encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0)),
            Err(ErrorCode::QPACK_DECODER_STREAM_ERROR)
        );
        let mut writer = Writer { fail: false };
        let mut writing = Box::pin(encoder.write(source, &mut writer));
        assert!(
            writing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(encoder.completed.load(Ordering::Acquire), 1);
        assert_eq!(
            encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0)),
            Ok(())
        );
        assert_eq!(
            encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0)),
            Err(ErrorCode::QPACK_DECODER_STREAM_ERROR)
        );
    }

    #[tokio::test]
    async fn completed_count_tracks_insertions_and_duplicates_across_batches() {
        let encoder = Encoder::new(Settings::default()).unwrap();
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
            encoder.write(rx, &mut Writer { fail: false }).await,
            Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM),
        );
        assert_eq!(encoder.completed.load(Ordering::Acquire), 3);
    }

    #[tokio::test]
    async fn failed_writes_do_not_advance_completion() {
        let (encoder, source) = queued_insert();
        assert_eq!(
            encoder.write(source, &mut Writer { fail: true }).await,
            Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
        );
        assert_eq!(encoder.completed.load(Ordering::Acquire), 0);
    }
}
