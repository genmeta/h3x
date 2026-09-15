//! Outgoing headers, encoder-stream instructions, and feedback from the peer decoder.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, watch},
    task::JoinHandle,
};

use super::{
    Field, Qpack, Settings,
    codec::instruction::{
        DecoderInstruction, EncoderInstruction, WriteInstruction, be_decoder_instruction,
    },
};
use crate::{
    Error, Result, Transport,
    protocol::{frame::StreamType, stream::bi::BiStreams},
};

mod state;
use state::State;

/// Each instruction carries the cumulative insert count after its table update.
type Instructions = mpsc::Receiver<Vec<(EncoderInstruction, u64)>>;

pub(super) struct Encoder {
    state: Mutex<Result<State>>,
    started: Arc<AtomicU64>,
    completed: watch::Receiver<u64>,
    write_task: Mutex<Option<JoinHandle<()>>>,
}

impl Encoder {
    pub(super) fn new(peer: Settings) -> Result<(Self, Instructions, watch::Sender<u64>)> {
        let (sender, receiver) = mpsc::channel(16);
        let (completed, completion) = watch::channel(0);
        Ok((
            Self {
                state: Mutex::new(Ok(State::new(peer, sender)?)),
                started: Arc::new(AtomicU64::new(0)),
                completed: completion,
                write_task: Mutex::new(None),
            },
            receiver,
            completed,
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

    pub(super) fn error(&self) -> Option<Error> {
        self.state.lock().unwrap().as_ref().err().copied()
    }

    pub(super) fn close(&self, error: Error) -> Error {
        let error = {
            let mut state = self.state.lock().unwrap();
            let error = state.as_ref().err().copied().unwrap_or(error);
            *state = Err(error);
            error
        };
        if let Some(writer) = self.write_task.lock().unwrap().take() {
            writer.abort();
        }
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

    /// The read task owns feedback; it keeps at most one instruction while waiting.
    pub(super) async fn receive<R: AsyncRead + Unpin>(&self, recv: &mut R) -> Result<()> {
        let mut progress = self.completed.clone();
        loop {
            let instruction = be_decoder_instruction(recv).await?;
            self.receive_feedback(instruction, &mut progress).await?;
        }
    }

    async fn receive_feedback(
        &self,
        instruction: DecoderInstruction,
        progress: &mut watch::Receiver<u64>,
    ) -> Result<()> {
        loop {
            let completed = *progress.borrow_and_update();
            {
                let mut state = self.state.lock().unwrap();
                let state = state.as_mut().map_err(|error| *error)?;
                let required = state.feedback_insert_count(&instruction)?;
                if required > self.started.load(Ordering::Acquire) {
                    return Err(Error::QPACK_DECODER_STREAM_ERROR);
                }
                if required <= completed {
                    return state.on_decoder_instruction(instruction, completed);
                }
            }
            // Only the writer can complete this instruction; do not hold the state lock.
            progress
                .changed()
                .await
                .map_err(|_| self.error().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM))?;
        }
    }

    pub(super) fn start<T: Transport>(
        &self,
        qpack: &Arc<Qpack<T>>,
        receiver: Instructions,
        completed: watch::Sender<u64>,
        bi: Arc<BiStreams<T::StreamReader, T::StreamWriter>>,
    ) {
        let mut write_task = self.write_task.lock().unwrap();
        if write_task.is_some() || self.error().is_some() {
            return;
        }
        let started = self.started.clone();
        let transport = qpack.transport.clone();
        let qpack = Arc::downgrade(qpack);

        *write_task = Some(tokio::spawn(async move {
            let stream = transport
                .open_uni()
                .await
                .and_then(|stream| stream.ok_or(Error::H3_STREAM_CREATION_ERROR));

            let (_, mut send) = match stream {
                Ok(stream) => stream,
                Err(error) => {
                    if let Some(qpack) = qpack.upgrade() {
                        qpack.fail(error, &bi);
                    }
                    return;
                }
            };

            if let Err(error) =
                Self::write_instructions(&started, &completed, receiver, &mut send).await
                && let Some(qpack) = qpack.upgrade()
            {
                qpack.fail(error, &bi);
            }
        }));
    }

    async fn write_instructions<W: AsyncWrite + Unpin>(
        started: &AtomicU64,
        completed: &watch::Sender<u64>,
        mut receiver: Instructions,
        writer: &mut W,
    ) -> Result<()> {
        writer
            .write_all(&[StreamType::QpackEncoder as u8])
            .await
            .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
        let mut buf = Vec::new();
        while let Some(batch) = receiver.recv().await {
            for (instruction, insert_count) in batch {
                buf.clear();
                buf.put_encoder_instruction(&instruction)?;
                started.store(insert_count, Ordering::Release);
                writer
                    .write_all(&buf)
                    .await
                    .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
                writer
                    .flush()
                    .await
                    .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
                completed.send_replace(insert_count);
            }
        }
        Err(Error::H3_CLOSED_CRITICAL_STREAM)
    }
}

/// Cross-direction codec tests simulate transport progress without exposing State.
#[cfg(test)]
impl Encoder {
    pub(super) fn on_instruction_sent(
        &self,
        completed: &watch::Sender<u64>,
        insert_count: u64,
    ) -> Result<()> {
        if let Some(error) = self.error() {
            return Err(error);
        }
        self.started.store(insert_count, Ordering::Release);
        completed.send_replace(insert_count);
        Ok(())
    }

    pub(super) fn on_decoder_instruction(&self, instruction: DecoderInstruction) -> Result<()> {
        let completed = *self.completed.borrow();
        self.state
            .lock()
            .unwrap()
            .as_mut()
            .map_err(|error| *error)?
            .on_decoder_instruction(instruction, completed)
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        if let Some(writer) = self.write_task.get_mut().unwrap().take() {
            writer.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    use super::*;

    #[tokio::test]
    async fn decoder_feedback_waits_for_the_current_encoder_write_to_commit() {
        let (encoder, mut receiver, completed) = Encoder::new(Settings::default()).unwrap();
        encoder
            .configure(
                Settings {
                    max_table_capacity: 68,
                    blocked_streams: 1,
                },
                1024,
            )
            .unwrap();
        receiver.try_recv().unwrap(); // Capacity does not advance the insertion count.
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
        let batch = receiver.try_recv().unwrap();
        assert_eq!(batch.len(), 1);
        let insert_count = batch[0].1;
        encoder.started.store(insert_count, Ordering::Release);
        let mut progress = encoder.completed.clone();
        let mut feedback = Box::pin(
            encoder.receive_feedback(DecoderInstruction::SectionAcknowledgment(0), &mut progress),
        );
        assert!(
            feedback
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        encoder
            .on_instruction_sent(&completed, insert_count)
            .unwrap();
        assert_eq!(
            feedback
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        );
        assert_eq!(
            encoder.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0)),
            Err(Error::QPACK_DECODER_STREAM_ERROR)
        );
    }
}
