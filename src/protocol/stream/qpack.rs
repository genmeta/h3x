//! QPACK encoder and decoder stream I/O, owned by the compression component.
use std::future::poll_fn;

use tokio::{
    io::{AsyncRead, AsyncWriteExt},
    sync::mpsc,
};

use super::bi::BiStreams;
use crate::{
    Error, Result, Transport,
    protocol::qpack::{
        Qpack,
        instruction::{DecoderInstruction, EncoderInstruction},
    },
};

impl<T: Transport> Qpack<T> {
    pub(crate) async fn receive_encoder<R: AsyncRead + Unpin>(&self, recv: &mut R) -> Result<()> {
        loop {
            let instruction = EncoderInstruction::read(recv).await?;
            let wakes = {
                let mut state = self.decoder.lock().unwrap();
                state
                    .as_mut()
                    .map_err(|error| *error)?
                    .on_encoder_instruction(instruction)?
            };
            for wake in wakes {
                wake.wake();
            }
        }
    }

    pub(crate) async fn receive_decoder<R: AsyncRead + Unpin>(&self, recv: &mut R) -> Result<()> {
        loop {
            let instruction = DecoderInstruction::read(recv).await?;
            self.encoder
                .lock()
                .unwrap()
                .as_mut()
                .map_err(|error| *error)?
                .receive_feedback(instruction)?;
        }
    }

    pub(crate) async fn send_encoder(
        &self,
        mut receiver: mpsc::Receiver<Vec<EncoderInstruction>>,
        bi: &BiStreams<T::StreamReader, T::StreamWriter>,
    ) {
        // Keep the half alive until this task has handled its result.
        let mut send = None;
        let result: Result<()> = async {
            send = Some(
                self.transport
                    .open_uni()
                    .await?
                    .ok_or(Error::H3_STREAM_CREATION_ERROR)?
                    .1,
            );
            let send = send.as_mut().unwrap();
            send.write_all(&[2])
                .await
                .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
            loop {
                let batch = receiver.recv().await.ok_or_else(|| {
                    self.encoder
                        .lock()
                        .unwrap()
                        .as_ref()
                        .err()
                        .copied()
                        .unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM)
                })?;
                for instruction in batch {
                    self.encoder
                        .lock()
                        .unwrap()
                        .as_mut()
                        .map_err(|error| *error)?
                        .start_instruction();
                    send.write_all(&instruction.encode()?)
                        .await
                        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
                    send.flush()
                        .await
                        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
                    self.encoder
                        .lock()
                        .unwrap()
                        .as_mut()
                        .map_err(|error| *error)?
                        .finish_instruction(&instruction)?;
                }
            }
        }
        .await;
        if let Err(error) = result {
            let error = self.close(error);
            let _ = self.transport.close(error.to_string(), error.as_u64());
            bi.close(error);
        }
    }

    pub(crate) async fn send_decoder(&self, bi: &BiStreams<T::StreamReader, T::StreamWriter>) {
        let mut send = None;
        let result: Result<()> = async {
            send = Some(
                self.transport
                    .open_uni()
                    .await?
                    .ok_or(Error::H3_STREAM_CREATION_ERROR)?
                    .1,
            );
            let send = send.as_mut().unwrap();
            send.write_all(&[3])
                .await
                .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
            loop {
                let instruction = poll_fn(|cx| {
                    self.decoder
                        .lock()
                        .unwrap()
                        .as_mut()
                        .map_err(|error| *error)?
                        .poll_instruction(cx)
                        .map(Ok::<_, Error>)
                })
                .await?;
                send.write_all(&instruction.encode()?)
                    .await
                    .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
                send.flush()
                    .await
                    .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
            }
        }
        .await;
        if let Err(error) = result {
            let error = self.close(error);
            let _ = self.transport.close(error.to_string(), error.as_u64());
            bi.close(error);
        }
    }
}
