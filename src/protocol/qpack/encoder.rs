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
                        .reason("instruction callback is not registered"))
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
