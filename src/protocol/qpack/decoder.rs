use std::collections::BTreeMap;

use bytes::Bytes;

use super::{
    Field, decode_prefixed_integer, decode_string,
    instruction::EncoderInstruction,
    qpack_error, static_table,
    table::{Table, TableError},
};
use crate::{Code, Error, StreamId};

#[derive(Debug)]
pub(super) enum Decode {
    Ready {
        fields: Vec<Field>,
        used_dynamic_table: bool,
    },
    Blocked,
}

/// Connection-scoped QPACK decoder state.
#[derive(Debug)]
pub(super) struct Decoder {
    table: Table,
    max_blocked_streams: u64,
    max_field_section_size: Option<u64>,
    blocked: BTreeMap<StreamId, u64>,
}

impl Decoder {
    pub(super) const fn new(
        max_capacity: u64,
        max_blocked_streams: u64,
        max_field_section_size: Option<u64>,
    ) -> Self {
        Self {
            table: Table::new(max_capacity),
            max_blocked_streams,
            max_field_section_size,
            blocked: BTreeMap::new(),
        }
    }

    pub(super) fn apply(&mut self, instruction: EncoderInstruction) -> Result<bool, Error> {
        match instruction {
            EncoderInstruction::SetCapacity(capacity) => {
                self.table
                    .set_capacity(capacity)
                    .map_err(encoder_table_error)?;
                Ok(false)
            }
            EncoderInstruction::InsertNameReference {
                is_static,
                index,
                value,
            } => {
                let name = if is_static {
                    Bytes::from_static(
                        static_table::get_name(index)
                            .ok_or_else(|| {
                                encoder_stream_error(
                                    "QPACK encoder instruction references an unknown static name",
                                )
                            })?
                            .as_bytes(),
                    )
                } else {
                    let absolute = self
                        .table
                        .resolve_encoder_relative(index)
                        .map_err(encoder_table_error)?;
                    self.table
                        .get(absolute)
                        .ok_or_else(|| {
                            encoder_stream_error(
                                "QPACK encoder instruction references an evicted dynamic name",
                            )
                        })?
                        .name
                        .clone()
                };
                self.table
                    .insert_decoder(Field { name, value })
                    .map_err(encoder_table_error)?;
                Ok(true)
            }
            EncoderInstruction::InsertLiteral { name, value } => {
                self.table
                    .insert_decoder(Field { name, value })
                    .map_err(encoder_table_error)?;
                Ok(true)
            }
            EncoderInstruction::Duplicate(index) => {
                let absolute = self
                    .table
                    .resolve_encoder_relative(index)
                    .map_err(encoder_table_error)?;
                let field = self.table.get(absolute).cloned().ok_or_else(|| {
                    encoder_stream_error("QPACK duplicate instruction references an evicted entry")
                })?;
                self.table
                    .insert_decoder(field)
                    .map_err(encoder_table_error)?;
                Ok(true)
            }
        }
    }

    pub(super) fn decode(
        &mut self,
        stream_id: StreamId,
        mut encoded: &[u8],
    ) -> Result<Decode, Error> {
        let (wire_insert_count, consumed) = decode_prefixed_integer(encoded, 8)?;
        encoded = &encoded[consumed..];
        let sign = encoded
            .first()
            .copied()
            .ok_or_else(|| qpack_error("missing QPACK delta-base prefix"))?
            & 0x80
            != 0;
        let (delta_base, consumed) = decode_prefixed_integer(encoded, 7)?;
        encoded = &encoded[consumed..];

        let required_insert_count = decode_required_insert_count(
            wire_insert_count,
            self.table.max_entries(),
            self.table.insert_count(),
        )?;
        let base = if sign {
            required_insert_count
                .checked_sub(delta_base)
                .and_then(|base| base.checked_sub(1))
                .ok_or_else(|| qpack_error("QPACK delta base makes the base negative"))?
        } else {
            required_insert_count
                .checked_add(delta_base)
                .ok_or_else(|| qpack_error("QPACK base overflow"))?
        };

        if required_insert_count > self.table.insert_count() {
            if !self.blocked.contains_key(&stream_id) {
                if self.blocked.len() as u64 >= self.max_blocked_streams {
                    return Err(Error::connection_protocol(
                        Code::QPACK_DECOMPRESSION_FAILED,
                        "peer exceeded SETTINGS_QPACK_BLOCKED_STREAMS",
                    ));
                }
                self.blocked.insert(stream_id, required_insert_count);
            }
            return Ok(Decode::Blocked);
        }
        self.blocked.remove(&stream_id);

        let mut fields = Vec::new();
        let mut largest_reference = None;
        let mut decoded_size = 0u64;
        while let Some(first) = encoded.first().copied() {
            let field = if first & 0x80 != 0 {
                let is_static = first & 0x40 != 0;
                let (index, consumed) = decode_prefixed_integer(encoded, 6)?;
                encoded = &encoded[consumed..];
                if is_static {
                    let (name, value) = static_table::get(index).ok_or_else(|| {
                        qpack_error(format!("unknown QPACK static index {index}"))
                    })?;
                    Field {
                        name: Bytes::from_static(name.as_bytes()),
                        value: Bytes::from_static(value.as_bytes()),
                    }
                } else {
                    let absolute = resolve_relative(base, index)?;
                    self.dynamic_field(absolute, required_insert_count, &mut largest_reference)?
                }
            } else if first & 0xf0 == 0x10 {
                let (index, consumed) = decode_prefixed_integer(encoded, 4)?;
                encoded = &encoded[consumed..];
                let absolute = base
                    .checked_add(index)
                    .ok_or_else(|| qpack_error("QPACK post-base index overflow"))?;
                self.dynamic_field(absolute, required_insert_count, &mut largest_reference)?
            } else if first & 0xc0 == 0x40 {
                let is_static = first & 0x10 != 0;
                let (name_index, consumed) = decode_prefixed_integer(encoded, 4)?;
                encoded = &encoded[consumed..];
                let (value, consumed) = decode_string(encoded, 7)?;
                encoded = &encoded[consumed..];
                let name = if is_static {
                    Bytes::from_static(
                        static_table::get_name(name_index)
                            .ok_or_else(|| {
                                qpack_error(format!("unknown QPACK static name index {name_index}"))
                            })?
                            .as_bytes(),
                    )
                } else {
                    let absolute = resolve_relative(base, name_index)?;
                    self.dynamic_name(absolute, required_insert_count, &mut largest_reference)?
                };
                Field { name, value }
            } else if first & 0xf0 == 0 {
                let (name_index, consumed) = decode_prefixed_integer(encoded, 3)?;
                encoded = &encoded[consumed..];
                let (value, consumed) = decode_string(encoded, 7)?;
                encoded = &encoded[consumed..];
                let absolute = base
                    .checked_add(name_index)
                    .ok_or_else(|| qpack_error("QPACK post-base name index overflow"))?;
                let name =
                    self.dynamic_name(absolute, required_insert_count, &mut largest_reference)?;
                Field { name, value }
            } else if first & 0xe0 == 0x20 {
                let name_huffman = first & 0x08 != 0;
                let (name_len, consumed) = decode_prefixed_integer(encoded, 3)?;
                encoded = &encoded[consumed..];
                let name_len = usize::try_from(name_len)
                    .map_err(|_| qpack_error("QPACK field name is too large"))?;
                if encoded.len() < name_len {
                    return Err(qpack_error("incomplete QPACK field name"));
                }
                let name = super::decode_octets(&encoded[..name_len], name_huffman)?;
                encoded = &encoded[name_len..];
                let (value, consumed) = decode_string(encoded, 7)?;
                encoded = &encoded[consumed..];
                Field { name, value }
            } else {
                return Err(qpack_error("unknown QPACK field-line representation"));
            };

            decoded_size = decoded_size
                .checked_add(field.name.len() as u64 + field.value.len() as u64 + 32)
                .ok_or_else(|| qpack_error("decoded QPACK field section size overflow"))?;
            if self
                .max_field_section_size
                .is_some_and(|limit| decoded_size > limit)
            {
                return Err(Error::stream(
                    Some(Code::H3_EXCESSIVE_LOAD),
                    "decoded field section exceeds SETTINGS_MAX_FIELD_SECTION_SIZE",
                ));
            }
            fields.push(field);
        }

        let actual_required = largest_reference.map_or(0, |absolute| absolute + 1);
        if actual_required != required_insert_count {
            return Err(qpack_error(
                "QPACK Required Insert Count is not the minimum needed by the field section",
            ));
        }

        Ok(Decode::Ready {
            fields,
            used_dynamic_table: required_insert_count != 0,
        })
    }

    pub(super) fn cancel(&mut self, stream_id: StreamId) -> bool {
        self.blocked.remove(&stream_id);
        self.table.max_capacity() != 0
    }

    fn dynamic_field(
        &self,
        absolute: u64,
        required_insert_count: u64,
        largest_reference: &mut Option<u64>,
    ) -> Result<Field, Error> {
        self.track_dynamic(absolute, required_insert_count, largest_reference)?;
        self.table
            .get(absolute)
            .cloned()
            .ok_or_else(|| qpack_error("QPACK field references an evicted dynamic entry"))
    }

    fn dynamic_name(
        &self,
        absolute: u64,
        required_insert_count: u64,
        largest_reference: &mut Option<u64>,
    ) -> Result<Bytes, Error> {
        self.track_dynamic(absolute, required_insert_count, largest_reference)?;
        self.table
            .get(absolute)
            .map(|field| field.name.clone())
            .ok_or_else(|| qpack_error("QPACK field references an evicted dynamic name"))
    }

    fn track_dynamic(
        &self,
        absolute: u64,
        required_insert_count: u64,
        largest_reference: &mut Option<u64>,
    ) -> Result<(), Error> {
        if absolute >= required_insert_count {
            return Err(qpack_error(
                "QPACK dynamic reference is not below Required Insert Count",
            ));
        }
        *largest_reference =
            Some(largest_reference.map_or(absolute, |current| current.max(absolute)));
        Ok(())
    }
}

fn resolve_relative(base: u64, relative: u64) -> Result<u64, Error> {
    base.checked_sub(relative)
        .and_then(|absolute| absolute.checked_sub(1))
        .ok_or_else(|| qpack_error("QPACK relative index precedes the dynamic table"))
}

fn decode_required_insert_count(
    encoded: u64,
    max_entries: u64,
    total_inserts: u64,
) -> Result<u64, Error> {
    if encoded == 0 {
        return Ok(0);
    }
    let full_range = max_entries
        .checked_mul(2)
        .filter(|value| *value != 0)
        .ok_or_else(|| qpack_error("non-zero QPACK insert count with zero table capacity"))?;
    if encoded > full_range {
        return Err(qpack_error(
            "encoded QPACK insert count exceeds its full range",
        ));
    }
    let max_value = total_inserts
        .checked_add(max_entries)
        .ok_or_else(|| qpack_error("QPACK insert count overflow"))?;
    let max_wrapped = (max_value / full_range) * full_range;
    let mut required = max_wrapped
        .checked_add(encoded - 1)
        .ok_or_else(|| qpack_error("QPACK required insert count overflow"))?;
    if required > max_value {
        if required <= full_range {
            return Err(qpack_error("invalid wrapped QPACK insert count"));
        }
        required -= full_range;
    }
    if required == 0 {
        return Err(qpack_error(
            "QPACK insert count zero was not encoded as zero",
        ));
    }
    Ok(required)
}

fn encoder_stream_error(message: &'static str) -> Error {
    Error::connection_protocol(Code::QPACK_ENCODER_STREAM_ERROR, message)
}

fn encoder_table_error(error: TableError) -> Error {
    match error {
        TableError::CapacityExceeded => encoder_stream_error(
            "QPACK encoder set a dynamic table capacity above the advertised limit",
        ),
        TableError::EntryTooLarge => {
            encoder_stream_error("QPACK encoder inserted an entry larger than table capacity")
        }
        TableError::InvalidIndex => {
            encoder_stream_error("QPACK encoder instruction has an invalid dynamic index")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(name: &'static [u8], value: &'static [u8]) -> EncoderInstruction {
        EncoderInstruction::InsertLiteral {
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
        }
    }

    #[test]
    fn blocked_field_section_resolves_after_the_encoder_instruction() {
        let stream_id = crate::StreamId::from(qbase::varint::VarInt::from_u32(0));
        let encoded = [2, 0, 0x80];
        let mut decoder = Decoder::new(256, 1, None);
        decoder.apply(EncoderInstruction::SetCapacity(256)).unwrap();

        assert!(matches!(
            decoder.decode(stream_id, &encoded).unwrap(),
            Decode::Blocked
        ));
        assert!(decoder.apply(insert(b"x-test", b"value")).unwrap());
        let Decode::Ready {
            fields,
            used_dynamic_table,
        } = decoder.decode(stream_id, &encoded).unwrap()
        else {
            panic!("field section should be ready");
        };
        assert!(used_dynamic_table);
        assert_eq!(
            fields,
            vec![Field {
                name: Bytes::from_static(b"x-test"),
                value: Bytes::from_static(b"value"),
            }]
        );
    }

    #[test]
    fn post_base_reference_decodes() {
        let stream_id = crate::StreamId::from(qbase::varint::VarInt::from_u32(0));
        let mut decoder = Decoder::new(256, 1, None);
        decoder.apply(EncoderInstruction::SetCapacity(256)).unwrap();
        decoder.apply(insert(b"x-test", b"value")).unwrap();

        let Decode::Ready { fields, .. } = decoder.decode(stream_id, &[2, 0x80, 0x10]).unwrap()
        else {
            panic!("field section should be ready");
        };
        assert_eq!(fields[0].name, Bytes::from_static(b"x-test"));
    }

    #[test]
    fn decodes_rfc_9204_appendix_b_dynamic_field_section() {
        let mut decoder = Decoder::new(220, 1, None);
        decoder.apply(EncoderInstruction::SetCapacity(220)).unwrap();
        decoder
            .apply(EncoderInstruction::InsertNameReference {
                is_static: true,
                index: 0,
                value: Bytes::from_static(b"www.example.com"),
            })
            .unwrap();
        decoder
            .apply(EncoderInstruction::InsertNameReference {
                is_static: true,
                index: 1,
                value: Bytes::from_static(b"/sample/path"),
            })
            .unwrap();

        let Decode::Ready { fields, .. } = decoder
            .decode(
                crate::StreamId::from(qbase::varint::VarInt::from_u32(4)),
                &[0x03, 0x81, 0x10, 0x11],
            )
            .unwrap()
        else {
            panic!("RFC field section should decode immediately");
        };
        assert_eq!(
            fields,
            vec![
                Field {
                    name: Bytes::from_static(b":authority"),
                    value: Bytes::from_static(b"www.example.com"),
                },
                Field {
                    name: Bytes::from_static(b":path"),
                    value: Bytes::from_static(b"/sample/path"),
                },
            ]
        );
    }

    #[test]
    fn peer_cannot_exceed_the_advertised_blocked_stream_limit() {
        let mut decoder = Decoder::new(256, 1, None);
        decoder.apply(EncoderInstruction::SetCapacity(256)).unwrap();
        assert!(matches!(
            decoder
                .decode(
                    crate::StreamId::from(qbase::varint::VarInt::from_u32(0)),
                    &[2, 0, 0x80]
                )
                .unwrap(),
            Decode::Blocked
        ));
        let error = decoder
            .decode(
                crate::StreamId::from(qbase::varint::VarInt::from_u32(4)),
                &[2, 0, 0x80],
            )
            .unwrap_err();
        assert!(matches!(&error, crate::Error::Connection { .. }));
        assert_eq!(error.code(), Some(Code::QPACK_DECOMPRESSION_FAILED));
    }

    #[test]
    fn capacity_above_settings_is_an_encoder_stream_error() {
        let error = Decoder::new(128, 0, None)
            .apply(EncoderInstruction::SetCapacity(129))
            .unwrap_err();
        assert_eq!(error.code(), Some(Code::QPACK_ENCODER_STREAM_ERROR));
    }
}
