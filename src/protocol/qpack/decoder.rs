//! Incoming headers, table updates from the peer encoder, and decoder-stream feedback.
use std::task::{Context, Poll, Waker};

use tokio::sync::mpsc;

use super::{
    Field, Settings,
    codec::{
        field::FieldSectionPrefix,
        instruction::{DecoderInstruction, EncoderInstruction},
    },
};
use crate::{ErrorCode, Result};
mod state;
use state::State;
pub(in crate::protocol) type Batch = Vec<DecoderInstruction>;
type OnInstruction = Box<dyn Fn(Batch) -> Result<()> + Send + Sync>;
pub(in crate::protocol) type Instructions = mpsc::Receiver<Batch>;

pub(in crate::protocol) struct Decoder {
    state: State,
}
impl Decoder {
    pub(super) fn new(local: Settings, max_blocked_bytes: usize, max_fields: u64) -> Result<Self> {
        Ok(Self {
            state: State::new(
                local,
                max_blocked_bytes,
                max_fields,
                Box::new(|_| {
                    Err(ErrorCode::H3_INTERNAL_ERROR
                        .reason("instruction callback is not registered"))
                }),
            )?,
        })
    }
    pub(in crate::protocol) fn on_instruction(
        &mut self,
        callback: impl Fn(Batch) -> Result<()> + Send + Sync + 'static,
    ) {
        self.state.on_instruction = Box::new(callback);
    }

    pub(super) fn take_waiters(&mut self) -> Vec<Waker> {
        self.state.take_waiters()
    }
    pub(super) fn begin_decode(
        &mut self,
        id: u64,
        payload: &[u8],
    ) -> Result<(usize, FieldSectionPrefix)> {
        if id > qbase::varint::VARINT_MAX {
            return Err(ErrorCode::H3_INTERNAL_ERROR.reason("invalid stream ID"));
        }
        if self.state.decoding_stream.contains(&id) {
            return Err(ErrorCode::H3_REQUEST_CANCELLED.reason("request cancelled"));
        }
        let (rest, prefix) = self.state.read_prefix(payload)?;
        let offset = payload.len() - rest.len();
        self.state.decoding_stream.insert(id);
        Ok((offset, prefix))
    }
    pub(super) fn poll_registered_decode(
        &mut self,
        id: u64,
        prefix: FieldSectionPrefix,
        payload: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<Vec<Field>>> {
        if !self.state.decoding_stream.contains(&id) {
            return Poll::Ready(Err(
                ErrorCode::H3_REQUEST_CANCELLED.reason("request cancelled")
            ));
        }
        let result = self.state.poll_decode(id, prefix, payload, cx);
        if result.is_ready() {
            self.state.decoding_stream.remove(&id);
        }
        result
    }
    pub(super) fn cancel(&mut self, id: u64) -> Result<Vec<Waker>> {
        self.state.cancel_stream(id)
    }

    pub(super) fn cancel_registered(&mut self, id: u64) -> Result<Vec<Waker>> {
        if !self.state.decoding_stream.remove(&id) {
            return Ok(Vec::new());
        }
        self.state.cancel_stream(id)
    }

    pub(super) fn on_encoder_instruction(
        &mut self,
        instruction: EncoderInstruction,
    ) -> Result<Vec<Waker>> {
        self.state.on_encoder_instruction(instruction)
    }
}
