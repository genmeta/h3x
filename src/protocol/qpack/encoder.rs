use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use super::{
    Field, encode_prefixed_integer, encode_string,
    instruction::{self, DecoderInstruction, EncoderInstruction},
    is_sensitive, static_table,
    table::{Table, TableError},
};
use crate::{Code, Error, StreamId};

#[derive(Debug)]
pub(super) struct Encoded {
    pub(super) field_section: Bytes,
    pub(super) instructions: Bytes,
}

#[derive(Debug)]
struct Section {
    required_insert_count: u64,
    references: Vec<u64>,
}

/// Connection-scoped QPACK encoder state.
///
/// It inserts fields speculatively, but only references entries covered by
/// the peer's Known Received Count. That keeps the peer's blocked-stream
/// count at zero without giving up dynamic compression on later sections.
#[derive(Debug)]
pub(super) struct Encoder {
    table: Table,
    known_received_count: u64,
    sections: BTreeMap<StreamId, VecDeque<Section>>,
    configured: bool,
}

impl Encoder {
    pub(super) const fn new() -> Self {
        Self {
            table: Table::new(0),
            known_received_count: 0,
            sections: BTreeMap::new(),
            configured: false,
        }
    }

    pub(super) fn configure(&mut self, max_capacity: u64) -> Result<Bytes, Error> {
        if self.configured {
            return Err(decoder_stream_error(
                "peer SETTINGS were applied more than once",
            ));
        }
        self.configured = true;
        self.table
            .set_max_capacity(max_capacity)
            .map_err(table_state_error)?;
        self.table
            .set_capacity(max_capacity)
            .map_err(table_state_error)?;
        if max_capacity == 0 {
            return Ok(Bytes::new());
        }
        instruction::encode_encoder(&EncoderInstruction::SetCapacity(max_capacity))
    }

    pub(super) fn encode(
        &mut self,
        stream_id: StreamId,
        fields: impl IntoIterator<Item = Field>,
    ) -> Result<Encoded, Error> {
        let base = self.table.insert_count();
        let mut representations = Vec::new();
        let mut instructions = Vec::new();
        let mut references = Vec::new();
        let mut max_reference = None;

        for field in fields {
            let (static_name, static_value) = static_table::find(&field.name, &field.value);
            let static_exact = static_value.filter(|index| static_name == Some(*index));
            if let Some(index) = static_exact {
                encode_prefixed_integer(index as u64, 6, 0xc0, &mut representations)?;
                continue;
            }

            let existing_exact = self.table.newest_exact(&field);
            if let Some(absolute) = self
                .table
                .newest_exact_before(&field, self.known_received_count.min(base))
            {
                self.reference(absolute, &mut references, &mut max_reference)?;
                encode_prefixed_integer(base - absolute - 1, 6, 0x80, &mut representations)?;
                continue;
            }

            let known_dynamic_name = self
                .table
                .newest_name_before(&field.name, self.known_received_count.min(base));

            if !is_sensitive(&field.name) && existing_exact.is_none() && self.table.capacity() != 0
            {
                let insert = if let Some(index) = static_name {
                    EncoderInstruction::InsertNameReference {
                        is_static: true,
                        index: index as u64,
                        value: field.value.clone(),
                    }
                } else if let Some(absolute) = self.table.newest_name(&field.name) {
                    EncoderInstruction::InsertNameReference {
                        is_static: false,
                        index: self
                            .table
                            .encoder_relative(absolute)
                            .map_err(table_state_error)?,
                        value: field.value.clone(),
                    }
                } else {
                    EncoderInstruction::InsertLiteral {
                        name: field.name.clone(),
                        value: field.value.clone(),
                    }
                };

                if self
                    .table
                    .insert_encoder(field.clone(), self.known_received_count)
                    .is_some()
                {
                    let bytes = instruction::encode_encoder(&insert)?;
                    instructions.extend_from_slice(&bytes);
                }
            }

            let never_dynamic = is_sensitive(&field.name);
            if let Some(index) = static_name {
                let prefix = 0x50 | if never_dynamic { 0x20 } else { 0 };
                encode_prefixed_integer(index as u64, 4, prefix, &mut representations)?;
                encode_string(&field.value, 7, 0, &mut representations)?;
            } else if let Some(absolute) = known_dynamic_name {
                self.reference(absolute, &mut references, &mut max_reference)?;
                let prefix = 0x40 | if never_dynamic { 0x20 } else { 0 };
                encode_prefixed_integer(base - absolute - 1, 4, prefix, &mut representations)?;
                encode_string(&field.value, 7, 0, &mut representations)?;
            } else {
                let prefix = 0x20 | if never_dynamic { 0x10 } else { 0 };
                encode_prefixed_integer(field.name.len() as u64, 3, prefix, &mut representations)?;
                representations.extend_from_slice(&field.name);
                encode_string(&field.value, 7, 0, &mut representations)?;
            }
        }

        let mut field_section = Vec::new();
        let required_insert_count = max_reference.map_or(0, |absolute| absolute + 1);
        let encoded_insert_count =
            encode_required_insert_count(required_insert_count, self.table.max_entries())?;
        encode_prefixed_integer(encoded_insert_count, 8, 0, &mut field_section)?;
        let delta_base = if required_insert_count == 0 {
            0
        } else {
            base.saturating_sub(required_insert_count)
        };
        encode_prefixed_integer(delta_base, 7, 0, &mut field_section)?;
        field_section.extend_from_slice(&representations);

        if required_insert_count != 0 {
            self.sections
                .entry(stream_id)
                .or_default()
                .push_back(Section {
                    required_insert_count,
                    references,
                });
        }

        Ok(Encoded {
            field_section: Bytes::from(field_section),
            instructions: Bytes::from(instructions),
        })
    }

    pub(super) fn apply(&mut self, instruction: DecoderInstruction) -> Result<(), Error> {
        match instruction {
            DecoderInstruction::SectionAcknowledgement(stream_id) => {
                let stream_id = qbase::varint::VarInt::try_from(stream_id)
                    .map(StreamId::from)
                    .map_err(|_| {
                        decoder_stream_error("invalid stream ID in QPACK acknowledgement")
                    })?;
                let sections = self.sections.get_mut(&stream_id).ok_or_else(|| {
                    decoder_stream_error("QPACK acknowledgement has no outstanding field section")
                })?;
                let section = sections.pop_front().ok_or_else(|| {
                    decoder_stream_error("QPACK acknowledgement has no outstanding field section")
                })?;
                if sections.is_empty() {
                    self.sections.remove(&stream_id);
                }
                self.known_received_count =
                    self.known_received_count.max(section.required_insert_count);
                self.release(section.references)?;
            }
            DecoderInstruction::StreamCancellation(stream_id) => {
                let stream_id = qbase::varint::VarInt::try_from(stream_id)
                    .map(StreamId::from)
                    .map_err(|_| decoder_stream_error("invalid stream ID in QPACK cancellation"))?;
                if let Some(sections) = self.sections.remove(&stream_id) {
                    for section in sections {
                        self.release(section.references)?;
                    }
                }
            }
            DecoderInstruction::InsertCountIncrement(increment) => {
                let known = self
                    .known_received_count
                    .checked_add(increment)
                    .ok_or_else(|| decoder_stream_error("QPACK Known Received Count overflow"))?;
                if known > self.table.insert_count() {
                    return Err(decoder_stream_error(
                        "QPACK Known Received Count exceeds the number of insertions",
                    ));
                }
                self.known_received_count = known;
            }
        }
        Ok(())
    }

    fn reference(
        &mut self,
        absolute: u64,
        references: &mut Vec<u64>,
        max_reference: &mut Option<u64>,
    ) -> Result<(), Error> {
        self.table
            .add_reference(absolute)
            .map_err(table_state_error)?;
        references.push(absolute);
        *max_reference = Some(max_reference.map_or(absolute, |current| current.max(absolute)));
        Ok(())
    }

    fn release(&mut self, references: Vec<u64>) -> Result<(), Error> {
        for absolute in references {
            self.table
                .remove_reference(absolute)
                .map_err(table_state_error)?;
        }
        Ok(())
    }
}

fn encode_required_insert_count(required: u64, max_entries: u64) -> Result<u64, Error> {
    if required == 0 {
        return Ok(0);
    }
    let full_range = max_entries
        .checked_mul(2)
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            Error::connection_protocol(
                Code::QPACK_DECODER_STREAM_ERROR,
                "dynamic reference used with zero QPACK table capacity",
            )
        })?;
    Ok((required % full_range) + 1)
}

fn decoder_stream_error(message: &'static str) -> Error {
    Error::connection_protocol(Code::QPACK_DECODER_STREAM_ERROR, message)
}

fn table_state_error(_error: TableError) -> Error {
    decoder_stream_error("QPACK encoder dynamic table state is inconsistent")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::instruction::decode_encoder;

    fn field(name: &'static [u8], value: &'static [u8]) -> Field {
        Field {
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
        }
    }

    #[test]
    fn encoder_inserts_then_waits_for_confirmation_before_referencing() {
        let stream = crate::StreamId::from(qbase::varint::VarInt::from_u32(0));
        let mut encoder = Encoder::new();
        let capacity = encoder.configure(256).unwrap();
        assert!(matches!(
            decode_encoder(&capacity).unwrap(),
            Some((EncoderInstruction::SetCapacity(256), _))
        ));

        let first = encoder.encode(stream, [field(b"x-test", b"same")]).unwrap();
        assert!(!first.instructions.is_empty());
        assert_eq!(first.field_section[0], 0);

        let second = encoder
            .encode(
                crate::StreamId::from(qbase::varint::VarInt::from_u32(4)),
                [field(b"x-test", b"same")],
            )
            .unwrap();
        assert_eq!(second.field_section[0], 0);

        encoder
            .apply(DecoderInstruction::InsertCountIncrement(1))
            .unwrap();
        let third = encoder
            .encode(
                crate::StreamId::from(qbase::varint::VarInt::from_u32(8)),
                [field(b"x-test", b"same")],
            )
            .unwrap();
        assert_ne!(third.field_section[0], 0);
        assert!(third.instructions.is_empty());
    }

    #[test]
    fn sensitive_fields_are_never_inserted() {
        let mut encoder = Encoder::new();
        encoder.configure(256).unwrap();
        let encoded = encoder
            .encode(
                crate::StreamId::from(qbase::varint::VarInt::from_u32(0)),
                [field(b"authorization", b"secret")],
            )
            .unwrap();

        assert!(encoded.instructions.is_empty());
        assert_eq!(encoded.field_section[2] & 0x20, 0x20);
    }

    #[test]
    fn invalid_acknowledgement_is_a_decoder_stream_error() {
        let error = Encoder::new()
            .apply(DecoderInstruction::SectionAcknowledgement(0))
            .unwrap_err();
        assert_eq!(error.code(), Some(Code::QPACK_DECODER_STREAM_ERROR));
    }

    #[test]
    fn acknowledgement_and_cancellation_release_dynamic_references() {
        let first_stream = crate::StreamId::from(qbase::varint::VarInt::from_u32(0));
        let second_stream = crate::StreamId::from(qbase::varint::VarInt::from_u32(4));
        let mut encoder = Encoder::new();
        encoder.configure(38).unwrap();

        encoder
            .encode(first_stream, [field(b"x", b"same")])
            .unwrap();
        encoder
            .apply(DecoderInstruction::InsertCountIncrement(1))
            .unwrap();

        let referenced = encoder
            .encode(first_stream, [field(b"x", b"same")])
            .unwrap();
        assert_ne!(referenced.field_section[0], 0);
        let retained = encoder
            .encode(second_stream, [field(b"y", b"next")])
            .unwrap();
        assert!(retained.instructions.is_empty());

        encoder
            .apply(DecoderInstruction::SectionAcknowledgement(u64::from(
                first_stream,
            )))
            .unwrap();
        let inserted = encoder
            .encode(second_stream, [field(b"y", b"next")])
            .unwrap();
        assert!(!inserted.instructions.is_empty());
        encoder
            .apply(DecoderInstruction::InsertCountIncrement(1))
            .unwrap();
        encoder
            .encode(second_stream, [field(b"y", b"next")])
            .unwrap();

        encoder
            .apply(DecoderInstruction::StreamCancellation(u64::from(
                second_stream,
            )))
            .unwrap();
        let inserted = encoder
            .encode(first_stream, [field(b"z", b"later")])
            .unwrap();
        assert!(!inserted.instructions.is_empty());
    }
}
