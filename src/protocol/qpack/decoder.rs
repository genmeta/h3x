//! Incoming headers, table updates from the peer encoder, and decoder-stream feedback.
use std::{
    future::poll_fn,
    sync::{Arc, Mutex},
    task::Poll,
};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, watch},
    task::JoinHandle,
};

use super::{
    Field, Qpack, Settings,
    codec::instruction::{DecoderInstruction, WriteInstruction, be_encoder_instruction},
};
use crate::{
    Error, Result, Transport,
    protocol::{frame::StreamType, stream::bi::BiStreams},
};

mod state;
use state::State;

// ACKs retain their required insert count; cancellations carry zero.
type Instructions = mpsc::UnboundedReceiver<(DecoderInstruction, u64)>;

pub(super) struct Decoder {
    state: Mutex<Result<State>>,
    write_task: Mutex<Option<JoinHandle<()>>>,
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
    pub(super) fn new(
        local: Settings,
        max_blocked_bytes: usize,
        max_fields: u64,
    ) -> Result<(Self, Instructions, watch::Receiver<u64>)> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let (inserted, insert_count) = watch::channel(0);
        let state = State::new(local, max_blocked_bytes, max_fields, sender, inserted)?;
        Ok((
            Self {
                state: Mutex::new(Ok(state)),
                write_task: Mutex::new(None),
            },
            receiver,
            insert_count,
        ))
    }

    pub(super) fn close(&self, error: Error) {
        let wakes = {
            let mut state = self.state.lock().unwrap();
            let wakes = match state.as_mut() {
                Ok(decoder) => decoder.take_waiters(),
                Err(_) => Vec::new(),
            };
            *state = Err(error);
            wakes
        };
        if let Some(writer) = self.write_task.lock().unwrap().take() {
            writer.abort();
        }
        for wake in wakes {
            wake.wake();
        }
    }

    pub(super) async fn decode(&self, id: u64, payload: Bytes) -> Result<Vec<Field>> {
        if id > qbase::varint::VARINT_MAX {
            return Err(Error::H3_INTERNAL_ERROR);
        }
        let (offset, prefix) = {
            let mut state = self.state.lock().unwrap();
            let decoder = state.as_mut().map_err(|error| *error)?;
            if decoder.decoding_stream.contains(&id) {
                return Err(Error::H3_REQUEST_CANCELLED);
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
                return Poll::Ready(Err(Error::H3_REQUEST_CANCELLED));
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

    pub(super) fn start<T: Transport>(
        &self,
        qpack: &Arc<Qpack<T>>,
        receiver: Instructions,
        insert_count: watch::Receiver<u64>,
        bi: Arc<BiStreams<T::StreamReader, T::StreamWriter>>,
    ) {
        // Serialize handle installation with close; a closed direction cannot restart.
        let mut writer = self.write_task.lock().unwrap();
        if writer.is_some() || self.state.lock().unwrap().is_err() {
            return;
        }
        let transport = qpack.transport.clone();
        let qpack = Arc::downgrade(qpack);
        *writer = Some(tokio::spawn(async move {
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

            if let Err(error) = Self::write_instructions(receiver, insert_count, &mut send).await
                && let Some(qpack) = qpack.upgrade()
            {
                qpack.fail(error, &bi);
            }
        }));
    }

    async fn write_instructions<W: AsyncWrite + Unpin>(
        mut receiver: Instructions,
        mut insert_count: watch::Receiver<u64>,
        writer: &mut W,
    ) -> Result<()> {
        writer
            .write_all(&[StreamType::QpackDecoder as u8])
            .await
            .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
        let mut reported = 0;
        let mut buf = Vec::new();
        loop {
            let instruction =
                Self::next_instruction(&mut receiver, &mut insert_count, &mut reported).await?;
            buf.clear();
            buf.put_decoder_instruction(&instruction)?;
            writer
                .write_all(&buf)
                .await
                .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
            writer
                .flush()
                .await
                .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
        }
    }

    /// ACKs cover their required insert count; only report insertion progress beyond that.
    async fn next_instruction(
        receiver: &mut Instructions,
        insert_count: &mut watch::Receiver<u64>,
        reported: &mut u64,
    ) -> Result<DecoderInstruction> {
        let (instruction, count) = tokio::select! {
            biased;
            feedback = receiver.recv() => feedback.ok_or(Error::H3_CLOSED_CRITICAL_STREAM)?,
            count = insert_count.wait_for(|count| *count > *reported) => {
                let count = *count.map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
                (DecoderInstruction::InsertCountIncrement(count - *reported), count)
            }
        };
        *reported = (*reported).max(count);
        Ok(instruction)
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
        inserted: &mut watch::Receiver<u64>,
        reported: &mut u64,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<DecoderInstruction>> {
        use std::future::Future;
        Box::pin(Self::next_instruction(receiver, inserted, reported))
            .as_mut()
            .poll(cx)
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

impl Drop for Decoder {
    fn drop(&mut self) {
        if let Some(writer) = self.write_task.get_mut().unwrap().take() {
            writer.abort();
        }
    }
}
