use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use futures::SinkExt;
use http_body_util::BodyExt;
use tokio::sync::mpsc;

use super::{Close, ControlCommand, SessionState};
use crate::{ChunkBody, Code, Error, transport, wire};

const WT_CLOSE_SESSION: u64 = 0x2843;
const WT_DRAIN_SESSION: u64 = 0x78ae;

enum Capsule {
    Close(Close),
    Drain,
    Unknown,
}

struct CapsuleReader {
    body: ChunkBody,
    buffered: BytesMut,
    ended: bool,
}

impl CapsuleReader {
    fn new(body: ChunkBody) -> Self {
        Self {
            body,
            buffered: BytesMut::new(),
            ended: false,
        }
    }

    async fn next(&mut self) -> Result<Option<Capsule>, Error> {
        let Some(capsule_type) = self.read_varint(true).await? else {
            return Ok(None);
        };
        let length = self
            .read_varint(false)
            .await?
            .expect("EOF is rejected for a required capsule length");
        match capsule_type {
            WT_CLOSE_SESSION => {
                if !(4..=1028).contains(&length) {
                    return Err(message_error(
                        "WT_CLOSE_SESSION payload must contain a u32 code and at most 1024 message bytes",
                    ));
                }
                let payload = self.read_exact(length as usize).await?;
                let code =
                    u32::from_be_bytes(payload[..4].try_into().expect("length is at least 4"));
                let message = std::str::from_utf8(&payload[4..])
                    .map_err(|source| {
                        Error::stream_with_source(
                            Some(Code::H3_MESSAGE_ERROR),
                            "WT_CLOSE_SESSION message is not UTF-8",
                            source,
                        )
                    })?
                    .to_owned();
                Ok(Some(Capsule::Close(Close::new(code, message)?)))
            }
            WT_DRAIN_SESSION => {
                if length != 0 {
                    return Err(message_error("WT_DRAIN_SESSION payload must be empty"));
                }
                Ok(Some(Capsule::Drain))
            }
            _ => {
                self.discard(length).await?;
                Ok(Some(Capsule::Unknown))
            }
        }
    }

    async fn read_varint(&mut self, allow_clean_eof: bool) -> Result<Option<u64>, Error> {
        self.fill(1).await?;
        if self.buffered.is_empty() {
            return if allow_clean_eof {
                Ok(None)
            } else {
                Err(message_error("capsule ended before its length"))
            };
        }
        let len = 1usize << (self.buffered[0] >> 6);
        self.fill(len).await?;
        if self.buffered.len() < len {
            return Err(message_error("capsule contains an incomplete varint"));
        }
        let (value, consumed) = wire::decode_varint(&self.buffered[..len]).map_err(|source| {
            Error::stream_with_source(
                Some(Code::H3_MESSAGE_ERROR),
                "capsule contains an invalid varint",
                source,
            )
        })?;
        self.buffered.advance(consumed);
        Ok(Some(value))
    }

    async fn read_exact(&mut self, len: usize) -> Result<Bytes, Error> {
        self.fill(len).await?;
        if self.buffered.len() < len {
            return Err(message_error("capsule payload ended early"));
        }
        Ok(self.buffered.split_to(len).freeze())
    }

    async fn discard(&mut self, mut remaining: u64) -> Result<(), Error> {
        while remaining != 0 {
            if self.buffered.is_empty() {
                self.fill(1).await?;
                if self.buffered.is_empty() {
                    return Err(message_error("capsule payload ended early"));
                }
            }
            let consumed = remaining.min(self.buffered.len() as u64) as usize;
            self.buffered.advance(consumed);
            remaining -= consumed as u64;
        }
        Ok(())
    }

    async fn fill(&mut self, required: usize) -> Result<(), Error> {
        while self.buffered.len() < required && !self.ended {
            let Some(frame) = self.body.frame().await else {
                self.ended = true;
                break;
            };
            let frame = frame?;
            match frame.into_data() {
                Ok(data) => self.buffered.extend_from_slice(&data),
                Err(_non_data) => {
                    return Err(message_error(
                        "WebTransport CONNECT stream contains non-DATA body metadata",
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(super) async fn run(
    state: Arc<SessionState>,
    body: ChunkBody,
    mut writer: Box<dyn transport::SendStream>,
    mut commands: mpsc::Receiver<ControlCommand>,
) {
    let mut reader = CapsuleReader::new(body);
    let mut peer_close = None;
    let mut writer_closed = false;

    loop {
        enum Event {
            Capsule(Result<Option<Capsule>, Error>),
            Command(Option<ControlCommand>),
        }

        let event = if peer_close.is_some() {
            Event::Capsule(reader.next().await)
        } else {
            tokio::select! {
                capsule = reader.next() => Event::Capsule(capsule),
                command = commands.recv() => Event::Command(command),
            }
        };

        match event {
            Event::Capsule(Ok(Some(_))) if peer_close.is_some() => {
                fail(
                    &state,
                    &mut writer,
                    message_error("data followed WT_CLOSE_SESSION on the CONNECT stream"),
                );
                return;
            }
            Event::Capsule(Ok(Some(Capsule::Close(close)))) if peer_close.is_none() => {
                state.terminate(Ok(close.clone()));
                commands.close();
                while commands.try_recv().is_ok() {}
                let result = close_writer(&mut writer).await;
                writer_closed = result.is_ok();
                if result.is_err() {
                    return;
                }
                peer_close = Some(close);
            }
            Event::Capsule(Ok(Some(Capsule::Close(_)))) => unreachable!("handled by guards above"),
            Event::Capsule(Ok(Some(Capsule::Drain))) => state.mark_drained(),
            Event::Capsule(Ok(Some(Capsule::Unknown))) => {}
            Event::Capsule(Ok(None)) => {
                if !writer_closed && let Err(error) = close_writer(&mut writer).await {
                    state.terminate(Err(error));
                    return;
                }
                state.terminate(Ok(peer_close.unwrap_or_default()));
                return;
            }
            Event::Capsule(Err(error)) => {
                fail(&state, &mut writer, error);
                return;
            }
            Event::Command(Some(ControlCommand::Drain(reply))) => {
                let result = send_capsule(&mut writer, WT_DRAIN_SESSION, &[]).await;
                let _ = reply.send(result.clone());
                if let Err(error) = result {
                    state.terminate(Err(error));
                    return;
                }
            }
            Event::Command(Some(ControlCommand::Close(close, reply))) => {
                let result = if let Err(error) = send_close(&mut writer, &close).await {
                    Err(error)
                } else {
                    state.terminate(Ok(close.clone()));
                    close_writer(&mut writer).await
                };
                let _ = reply.send(result.clone());
                if let Err(error) = result {
                    state.terminate(Err(error));
                }
                return;
            }
            Event::Command(None) => {
                match close_writer(&mut writer).await {
                    Ok(()) => state.terminate(Ok(Close::default())),
                    Err(error) => state.terminate(Err(error)),
                }
                return;
            }
        }
    }
}

async fn send_close(
    writer: &mut Box<dyn transport::SendStream>,
    close: &Close,
) -> Result<(), Error> {
    let mut payload = Vec::with_capacity(4 + close.message.len());
    payload.extend_from_slice(&close.code.to_be_bytes());
    payload.extend_from_slice(close.message.as_bytes());
    send_capsule(writer, WT_CLOSE_SESSION, &payload).await
}

async fn send_capsule(
    writer: &mut Box<dyn transport::SendStream>,
    capsule_type: u64,
    payload: &[u8],
) -> Result<(), Error> {
    let mut capsule = Vec::with_capacity(16 + payload.len());
    wire::encode_varint(capsule_type, &mut capsule)?;
    wire::encode_varint(payload.len() as u64, &mut capsule)?;
    capsule.extend_from_slice(payload);
    writer
        .send(wire::encode_frame(wire::DATA_FRAME_TYPE, &capsule)?)
        .await
        .map_err(wire::map_stream_error)
}

async fn close_writer(writer: &mut Box<dyn transport::SendStream>) -> Result<(), Error> {
    writer.close().await.map_err(wire::map_stream_error)
}

fn fail(state: &SessionState, writer: &mut Box<dyn transport::SendStream>, error: Error) {
    let _ = writer.reset(error.code().unwrap_or(Code::H3_MESSAGE_ERROR));
    state.terminate(Err(error));
}

fn message_error(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::stream(Some(Code::H3_MESSAGE_ERROR), message)
}

#[cfg(test)]
mod tests {
    #[test]
    fn close_capsule_code_is_network_byte_order() {
        let code = 0x0102_0304_u32;
        assert_eq!(code.to_be_bytes(), [1, 2, 3, 4]);
    }
}
