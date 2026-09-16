//! Incoming headers, table updates from the peer encoder, and decoder-stream feedback.
use std::{future::poll_fn, sync::Mutex, task::Poll};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use super::{
    Field, Settings,
    codec::instruction::{DecoderInstruction, WriteInstruction, be_encoder_instruction},
};
use crate::{ErrorCode, Result, protocol::frame::StreamType};

mod state;
use state::State;

pub(in crate::protocol) type Batch = Vec<DecoderInstruction>;
type OnInstruction = Box<dyn Fn(Batch) -> Result<()> + Send + Sync>;

/// Insertions / decoded fields / cancellations -> feedback FIFO
/// -> Decoder::write() -> decoder stream -> peer encoder.
/// Enqueueing wakes the writer; increments precede dependent ACKs.
pub(in crate::protocol) type Instructions = mpsc::Receiver<Batch>;

pub(in crate::protocol) struct Decoder {
    state: Mutex<Result<State>>,
}

/// Only a registered decode owns cancellation; rejected and unpolled futures do not.
struct StreamDecoder<'a> {
    decoder: &'a Decoder,
    stream_id: u64,
}

impl Drop for StreamDecoder<'_> {
    fn drop(&mut self) {
        let wakes = {
            let mut state = self.decoder.state.lock().unwrap();
            let Ok(decoder) = state.as_mut() else {
                return;
            };
            if !decoder.decoding_stream.remove(&self.stream_id) {
                return;
            }
            decoder.cancel_stream(self.stream_id)
        };
        match wakes {
            Ok(wakes) => {
                for wake in wakes {
                    wake.wake();
                }
            }
            // The receiver is gone. The writer reports the connection failure;
            // release local waiters even if this decode future was abandoned.
            Err(error) => self.decoder.close(error),
        }
    }
}

impl Decoder {
    pub(super) fn new(local: Settings, max_blocked_bytes: usize, max_fields: u64) -> Result<Self> {
        Ok(Self {
            state: Mutex::new(Ok(State::new(
                local,
                max_blocked_bytes,
                max_fields,
                Box::new(|_| Err(ErrorCode::H3_INTERNAL_ERROR)),
            )?)),
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

    #[cfg(test)]
    pub(super) fn with_channel(
        local: Settings,
        max_blocked_bytes: usize,
        max_fields: u64,
    ) -> Result<(Self, Instructions)> {
        let decoder = Self::new(local, max_blocked_bytes, max_fields)?;
        let (tx, rx) = mpsc::channel(super::MAX_PENDING_INSTRUCTION);
        decoder.on_instruction(move |batch| {
            tx.try_send(batch)
                .map_err(crate::protocol::connection::instruction_send_error)
        });
        Ok((decoder, rx))
    }

    pub(super) fn close(&self, error: ErrorCode) {
        let wakes = {
            let mut state = self.state.lock().unwrap();
            let wakes = match state.as_mut() {
                Ok(decoder) => decoder.take_waiters(),
                Err(_) => Vec::new(),
            };
            *state = Err(error);
            wakes
        };

        for wake in wakes {
            wake.wake();
        }
    }

    pub(super) async fn decode(&self, id: u64, payload: Bytes) -> Result<Vec<Field>> {
        if id > qbase::varint::VARINT_MAX {
            return Err(ErrorCode::H3_INTERNAL_ERROR);
        }
        let (offset, prefix) = {
            let mut state = self.state.lock().unwrap();
            let decoder = state.as_mut().map_err(|error| *error)?;
            if decoder.decoding_stream.contains(&id) {
                return Err(ErrorCode::H3_REQUEST_CANCELLED);
            }
            let (rest, prefix) = decoder.read_prefix(&payload)?;
            let offset = payload.len() - rest.len();
            decoder.decoding_stream.insert(id);
            (offset, prefix)
        };
        let _stream_decoder = StreamDecoder {
            decoder: self,
            stream_id: id,
        };
        poll_fn(|cx| {
            let mut state = self.state.lock().unwrap();
            let decoder = match state.as_mut() {
                Ok(decoder) => decoder,
                Err(error) => return Poll::Ready(Err(*error)),
            };
            if !decoder.decoding_stream.contains(&id) {
                return Poll::Ready(Err(ErrorCode::H3_REQUEST_CANCELLED));
            }
            let result = decoder.poll_decode(id, prefix, &payload[offset..], cx);
            if result.is_ready() {
                decoder.decoding_stream.remove(&id);
            }
            result
        })
        .await
    }

    pub(super) fn cancel(&self, id: u64) -> Result<()> {
        let wakes = self
            .state
            .lock()
            .unwrap()
            .as_mut()
            .map_err(|error| *error)?
            .cancel_stream(id)?;
        for wake in wakes {
            wake.wake();
        }
        Ok(())
    }

    /// Table updates and application decoding share this direction's dynamic table.
    pub(super) async fn receive<R: AsyncRead + Unpin>(&self, recv: &mut R) -> Result<()> {
        loop {
            let instruction = be_encoder_instruction(recv).await?;
            let wakes = self
                .state
                .lock()
                .unwrap()
                .as_mut()
                .map_err(|error| *error)?
                .on_encoder_instruction(instruction)?;
            for wake in wakes {
                wake.wake();
            }
        }
    }

    /// The feedback writer only needs the receiver and transport.
    pub(in crate::protocol) fn sync<T: crate::Transport>(
        &self,
        transport: std::sync::Arc<T>,
        instructions: Instructions,
    ) -> impl Future<Output = ()> + Send + 'static + use<T> {
        async move {
            super::drive(transport, async move |send: &mut T::StreamWriter| {
                Self::write(instructions, send).await
            })
            .await;
        }
    }

    pub(in crate::protocol) async fn write<W: AsyncWrite + Unpin>(
        mut receiver: Instructions,
        writer: &mut W,
    ) -> Result<()> {
        writer
            .write_all(&[StreamType::QpackDecoder as u8])
            .await
            .map_err(|_| ErrorCode::H3_CLOSED_CRITICAL_STREAM)?;
        let mut buf = Vec::new();
        while let Some(batch) = receiver.recv().await {
            for instruction in batch {
                buf.clear();
                buf.put_decoder_instruction(&instruction)?;
                writer
                    .write_all(&buf)
                    .await
                    .map_err(|_| ErrorCode::H3_CLOSED_CRITICAL_STREAM)?;
            }
        }
        Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
    }
}

/// Synchronous codec operations for cross-direction tests; State stays private.
#[cfg(test)]
impl Decoder {
    pub(super) fn on_encoder_instruction(
        &self,
        instruction: super::codec::instruction::EncoderInstruction,
    ) -> Result<Vec<std::task::Waker>> {
        self.state
            .lock()
            .unwrap()
            .as_mut()
            .map_err(|error| *error)?
            .on_encoder_instruction(instruction)
    }

    pub(super) fn poll_feedback(
        receiver: &mut Instructions,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Batch>> {
        receiver
            .poll_recv(cx)
            .map(|instruction| instruction.ok_or(ErrorCode::H3_CLOSED_CRITICAL_STREAM))
    }

    pub(super) fn read_prefix<'a>(
        &self,
        payload: &'a [u8],
    ) -> Result<(&'a [u8], super::codec::field::FieldSectionPrefix)> {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .map_err(|error| *error)?
            .read_prefix(payload)
    }

    pub(super) fn poll_decode(
        &self,
        id: u64,
        prefix: super::codec::field::FieldSectionPrefix,
        bytes: &[u8],
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Vec<Field>>> {
        self.state
            .lock()
            .unwrap()
            .as_mut()
            .map_err(|error| *error)?
            .poll_decode(id, prefix, bytes, cx)
    }
}
