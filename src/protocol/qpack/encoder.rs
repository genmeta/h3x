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

/// Each instruction carries the cumulative insert count after its table update.
type Instructions = mpsc::Receiver<Vec<(EncoderInstruction, u64)>>;

/// Queued instructions and their completed local write count.
///
/// ```text
/// Encoder::write()                         Encoder::receive()
///       |                                        |
/// write_all(instruction).await                   | peer feedback
///       |                                        v
///       +-- store(n) --> completed: AtomicU64 <-- load
///                                                |
///                                 validate and apply feedback
/// ```
///
/// Completion means the full instruction was accepted by the stream writer,
/// not acknowledged by the peer. There is no progress notification or wait.
pub(in crate::protocol) struct InstructionSource {
    pub(super) instructions: Instructions,
    completed: Arc<AtomicU64>,
}

// on_instruction
//
pub(in crate::protocol) struct Encoder {
    state: Mutex<Result<State>>,
    completed: Arc<AtomicU64>,
}

impl Encoder {
    pub(super) fn new(peer: Settings) -> Result<(Self, InstructionSource)> {
        let (sender, receiver) = mpsc::channel(16);
        let completed = Arc::new(AtomicU64::new(0));
        Ok((
            Self {
                state: Mutex::new(Ok(State::new(peer, sender)?)),
                completed: completed.clone(),
            },
            InstructionSource {
                instructions: receiver,
                completed,
            },
        ))
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

    pub(in crate::protocol) async fn write<W: AsyncWrite + Unpin>(
        instruction_source: InstructionSource,
        writer: &mut W,
    ) -> Result<()> {
        let InstructionSource {
            mut instructions,
            completed,
        } = instruction_source;
        writer
            .write_all(&[StreamType::QpackEncoder as u8])
            .await
            .map_err(|_| ErrorCode::H3_CLOSED_CRITICAL_STREAM)?;
        let mut buf = Vec::new();
        while let Some(batch) = instructions.recv().await {
            for (instruction, insert_count) in batch {
                buf.clear();
                buf.put_encoder_instruction(&instruction)?;
                writer
                    .write_all(&buf)
                    .await
                    .map_err(|_| ErrorCode::H3_CLOSED_CRITICAL_STREAM)?;
                completed.store(insert_count, Ordering::Release);
            }
        }
        Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
    }
}

/// Cross-direction codec tests simulate transport progress without exposing State.
#[cfg(test)]
impl Encoder {
    pub(super) fn on_instruction_sent(&self, insert_count: u64) -> Result<()> {
        if let Some(error) = self.error() {
            return Err(error);
        }
        self.completed.store(insert_count, Ordering::Release);
        Ok(())
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

    fn queued_insert() -> (Encoder, InstructionSource) {
        let (encoder, source) = Encoder::new(Settings::default()).unwrap();
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
        let mut writing = Box::pin(Encoder::write(source, &mut writer));
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
    async fn failed_writes_do_not_advance_completion() {
        let (encoder, source) = queued_insert();
        assert_eq!(
            Encoder::write(source, &mut Writer { fail: true }).await,
            Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
        );
        assert_eq!(encoder.completed.load(Ordering::Acquire), 0);
    }
}
