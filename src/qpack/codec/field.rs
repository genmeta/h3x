//! Fields and field-section wire format (RFC 9204 section 4.5).
use bytes::{BufMut, Bytes};
use qbase::varint::VARINT_MAX;

use super::{
    integer::{WritePrefixedInteger, be_prefixed_integer},
    string_literal::{WriteStringLiteral, be_string_literal_slice},
};
use crate::{
    ErrorCode, Result,
    qpack::table::{self, DynamicTable},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Field {
    pub(crate) name: Bytes,
    pub(crate) value: Bytes,
    /// RFC 9204 section 7.1.3: preserve N when re-encoding this field line.
    pub(crate) never_index: bool,
}

/// Values used for dependency checks and indexing. be_field_section_prefix reconstructs them from
/// the wire's modulo-encoded insert count and signed Delta Base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FieldSectionPrefix {
    /// Minimum cumulative insertions needed to decode this section: zero without
    /// dynamic references, otherwise the largest referenced absolute index plus one.
    pub(crate) required_insert_count: u64,
    /// Reference point for this section's dynamic indices: relative i resolves to
    /// base - 1 - i, and post-Base i resolves to base + i.
    pub(crate) base: u64,
}

impl FieldSectionPrefix {
    /// absolute = Base - 1 - index; reject underflow and absolute >= RIC.
    fn relative_index(&self, index: u64) -> Result<u64> {
        self.base
            .checked_sub(index)
            .and_then(|absolute| absolute.checked_sub(1))
            .filter(|&absolute| absolute < self.required_insert_count)
            .ok_or_else(|| {
                ErrorCode::QPACK_DECOMPRESSION_FAILED
                    .reason("dynamic relative index is outside Required Insert Count")
            })
    }

    /// absolute = Base + index; reject overflow and absolute >= RIC.
    fn post_base_index(&self, index: u64) -> Result<u64> {
        self.base
            .checked_add(index)
            .filter(|&absolute| absolute < self.required_insert_count)
            .ok_or_else(|| {
                ErrorCode::QPACK_DECOMPRESSION_FAILED
                    .reason("post-Base index is outside Required Insert Count")
            })
    }
}

/// The five field-line representations, in RFC section order. Dynamic `index` values
/// are relative to the section's Base; encoder-instruction indices use a different origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FieldLine {
    /// 4.5.2: 1 T Index(6+); T=1 static, T=0 dynamic relative.
    Indexed { static_table: bool, index: u64 },
    /// 4.5.3: 0001 Index(4+), always dynamic post-Base.
    IndexedPostBase { index: u64 },
    /// 4.5.4: 01 N T NameIndex(4+), followed by a value string.
    LiteralWithNameReference {
        never_index: bool,
        static_table: bool,
        index: u64,
        value: Bytes,
    },
    /// 4.5.5: 0000 N NameIndex(3+), followed by a value string.
    LiteralWithPostBaseNameReference {
        never_index: bool,
        index: u64,
        value: Bytes,
    },
    /// 4.5.6: 001 N H NameLength(3+), name bytes, then a value string.
    Literal(Field),
}

impl FieldLine {
    /// Return the referenced dynamic absolute index, including name-only references.
    /// Used to calculate/check RIC and retain encoder references; None means no dependency.
    pub(crate) fn dynamic_index(&self, prefix: FieldSectionPrefix) -> Result<Option<u64>> {
        match self {
            Self::Indexed {
                static_table: false,
                index,
            }
            | Self::LiteralWithNameReference {
                static_table: false,
                index,
                ..
            } => prefix.relative_index(*index).map(Some),
            Self::IndexedPostBase { index }
            | Self::LiteralWithPostBaseNameReference { index, .. } => {
                prefix.post_base_index(*index).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Resolve name/value through the static or dynamic table; reject invalid or evicted
    /// indices as QPACK_DECOMPRESSION_FAILED. Pure lookup: no ACKs or table mutations.
    pub(crate) fn resolve(
        &self,
        prefix: FieldSectionPrefix,
        table: &DynamicTable,
    ) -> Result<Field> {
        if let Self::Literal(field) = self {
            return Ok(field.clone());
        }
        let mut field = if let Some(absolute) = self.dynamic_index(prefix)? {
            table.get(absolute).cloned().ok_or_else(|| {
                ErrorCode::QPACK_DECOMPRESSION_FAILED
                    .reason("dynamic table entry is missing or has been evicted")
            })?
        } else {
            let index = match self {
                Self::Indexed { index, .. } | Self::LiteralWithNameReference { index, .. } => {
                    *index
                }
                _ => unreachable!("only static references have no dynamic dependency here"),
            };
            let (name, value) = table::get(index).ok_or_else(|| {
                ErrorCode::QPACK_DECOMPRESSION_FAILED.reason("static table index is out of range")
            })?;
            Field {
                name: Bytes::from_static(name.as_bytes()),
                value: Bytes::from_static(value.as_bytes()),
                never_index: false,
            }
        };
        if let Self::LiteralWithNameReference {
            never_index, value, ..
        }
        | Self::LiteralWithPostBaseNameReference {
            never_index, value, ..
        } = self
        {
            field.never_index = *never_index;
            field.value = value.clone();
        }
        Ok(field)
    }
}

/// Append field-section wire representations to a caller-owned buffer.
pub(crate) trait WriteField {
    fn put_field_section_prefix(
        &mut self,
        prefix: &FieldSectionPrefix,
        max_capacity: u64,
    ) -> Result<()>;
    fn put_field_line(&mut self, line: &FieldLine) -> Result<()>;
}

impl<B: BufMut> WriteField for B {
    fn put_field_section_prefix(
        &mut self,
        prefix: &FieldSectionPrefix,
        max_capacity: u64,
    ) -> Result<()> {
        if max_capacity > VARINT_MAX
            || prefix.required_insert_count > VARINT_MAX
            || prefix.base > VARINT_MAX
        {
            return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
                .reason("field section prefix exceeds the QUIC variable-integer range"));
        }
        let encoded_insert_count = if prefix.required_insert_count == 0 {
            0
        } else {
            let full_range = 2 * (max_capacity / 32);
            if full_range == 0 {
                return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
                    .reason("nonzero Required Insert Count with a table too small for entries"));
            }
            prefix.required_insert_count % full_range + 1
        };
        let (sign, delta_base) = if prefix.base >= prefix.required_insert_count {
            (0, prefix.base - prefix.required_insert_count)
        } else {
            (0x80, prefix.required_insert_count - prefix.base - 1)
        };
        self.put_prefixed_integer(encoded_insert_count, 8, 0)?;
        self.put_prefixed_integer(delta_base, 7, sign)
    }

    fn put_field_line(&mut self, line: &FieldLine) -> Result<()> {
        match line {
            FieldLine::Indexed {
                static_table,
                index,
            } => self.put_prefixed_integer(*index, 6, 0x80 | (u8::from(*static_table) << 6)),
            FieldLine::IndexedPostBase { index } => self.put_prefixed_integer(*index, 4, 0x10),
            FieldLine::LiteralWithNameReference {
                never_index,
                static_table,
                index,
                value,
            } => {
                self.put_prefixed_integer(
                    *index,
                    4,
                    0x40 | (u8::from(*never_index) << 5) | (u8::from(*static_table) << 4),
                )?;
                self.put_string_literal(value, 8, 0)
            }
            FieldLine::LiteralWithPostBaseNameReference {
                never_index,
                index,
                value,
            } => {
                self.put_prefixed_integer(*index, 3, u8::from(*never_index) << 3)?;
                self.put_string_literal(value, 8, 0)
            }
            FieldLine::Literal(field) => {
                self.put_string_literal(&field.name, 4, 0x20 | (u8::from(field.never_index) << 4))?;
                self.put_string_literal(&field.value, 8, 0)
            }
        }
    }
}

/// Reconstruct RIC/Base from the wire using the decoder table capacity and insert count.
pub(crate) fn be_field_section_prefix(
    input: &[u8],
    max_capacity: u64,
    insert_count: u64,
) -> Result<(&[u8], FieldSectionPrefix)> {
    if max_capacity > VARINT_MAX || insert_count > VARINT_MAX {
        return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
            .reason("table capacity or insert count exceeds the QUIC variable-integer range"));
    }
    let (input, encoded_insert_count) = be_prefixed_integer(input, 8)?;
    let required_insert_count = if encoded_insert_count == 0 {
        0
    } else {
        // RFC 9204 section 4.5.1.1: choose the wrap nearest the decoder's progress.
        let max_entries = max_capacity / 32;
        let full_range = 2 * max_entries;
        if encoded_insert_count > full_range {
            return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
                .reason("encoded Required Insert Count exceeds the table wrap range"));
        }
        let max_value = insert_count + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut count = max_wrapped + encoded_insert_count - 1;
        if count > max_value {
            if count <= full_range {
                return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED
                    .reason("Required Insert Count cannot be reconstructed from the table state"));
            }
            count -= full_range;
        }
        if count == 0 || count > VARINT_MAX {
            return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED.reason(
                "reconstructed Required Insert Count is zero or exceeds the allowed range",
            ));
        }
        count
    };
    let sign = *input.first().ok_or_else(|| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED.reason("field section is missing Delta Base")
    })? & 0x80
        != 0;
    let (input, delta_base) = be_prefixed_integer(input, 7)?;
    let base = if sign {
        required_insert_count
            .checked_sub(delta_base)
            .and_then(|base| base.checked_sub(1))
    } else {
        required_insert_count.checked_add(delta_base)
    }
    .filter(|&base| base <= VARINT_MAX)
    .ok_or_else(|| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED.reason("Delta Base produces an invalid Base")
    })?;
    Ok((
        input,
        FieldSectionPrefix {
            required_insert_count,
            base,
        },
    ))
}

/// Parse one field-line representation and retain the unconsumed suffix.
pub(crate) fn be_field_line(input: &[u8]) -> Result<(&[u8], FieldLine)> {
    let first = *input.first().ok_or_else(|| {
        ErrorCode::QPACK_DECOMPRESSION_FAILED.reason("field line is missing its first byte")
    })?;
    if first & 0x80 != 0 {
        let (input, index) = be_prefixed_integer(input, 6)?;
        Ok((
            input,
            FieldLine::Indexed {
                static_table: first & 0x40 != 0,
                index,
            },
        ))
    } else if first & 0x40 != 0 {
        let (input, index) = be_prefixed_integer(input, 4)?;
        let (input, value) = be_string_literal_slice(input, 8)?;
        Ok((
            input,
            FieldLine::LiteralWithNameReference {
                never_index: first & 0x20 != 0,
                static_table: first & 0x10 != 0,
                index,
                value,
            },
        ))
    } else if first & 0x20 != 0 {
        let (input, name) = be_string_literal_slice(input, 4)?;
        let (input, value) = be_string_literal_slice(input, 8)?;
        Ok((
            input,
            FieldLine::Literal(Field {
                never_index: first & 0x10 != 0,
                name,
                value,
            }),
        ))
    } else if first & 0x10 != 0 {
        let (input, index) = be_prefixed_integer(input, 4)?;
        Ok((input, FieldLine::IndexedPostBase { index }))
    } else {
        let (input, index) = be_prefixed_integer(input, 3)?;
        let (input, value) = be_string_literal_slice(input, 8)?;
        Ok((
            input,
            FieldLine::LiteralWithPostBaseNameReference {
                never_index: first & 0x08 != 0,
                index,
                value,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_field_line_representation_round_trips() {
        let lines = [
            FieldLine::Indexed {
                static_table: true,
                index: 17,
            },
            FieldLine::Indexed {
                static_table: false,
                index: 1337,
            },
            FieldLine::IndexedPostBase { index: 42 },
            FieldLine::LiteralWithNameReference {
                never_index: true,
                static_table: true,
                index: 1,
                value: Bytes::from_static(b"/other"),
            },
            FieldLine::LiteralWithPostBaseNameReference {
                never_index: true,
                index: 9,
                value: Bytes::from_static(b"value"),
            },
            FieldLine::Literal(Field {
                name: Bytes::from_static(b"x-name"),
                value: Bytes::from_static(b"x-value"),
                never_index: true,
            }),
        ];

        for line in lines {
            let mut wire = Vec::new();
            wire.put_field_line(&line).unwrap();
            wire.push(0xff);
            let (rest, decoded) = be_field_line(&wire).unwrap();
            assert_eq!(decoded, line);
            assert_eq!(rest, &[0xff]);
        }
    }

    #[test]
    fn field_section_prefix_round_trips_both_delta_base_directions() {
        for prefix in [
            FieldSectionPrefix {
                required_insert_count: 0,
                base: 0,
            },
            FieldSectionPrefix {
                required_insert_count: 10,
                base: 14,
            },
            FieldSectionPrefix {
                required_insert_count: 10,
                base: 7,
            },
        ] {
            let mut wire = Vec::new();
            wire.put_field_section_prefix(&prefix, 4096).unwrap();
            wire.push(0xff);
            let (rest, decoded) = be_field_section_prefix(&wire, 4096, 10).unwrap();
            assert_eq!(decoded, prefix);
            assert_eq!(rest, &[0xff]);
        }
    }

    #[test]
    fn field_resolution_preserves_never_index_and_checks_dynamic_bounds() {
        let table = DynamicTable::new(0).unwrap();
        let prefix = FieldSectionPrefix {
            required_insert_count: 0,
            base: 0,
        };
        let resolved = FieldLine::LiteralWithNameReference {
            never_index: true,
            static_table: true,
            index: 1,
            value: Bytes::from_static(b"/private"),
        }
        .resolve(prefix, &table)
        .unwrap();
        assert_eq!(resolved.name, Bytes::from_static(b":path"));
        assert_eq!(resolved.value, Bytes::from_static(b"/private"));
        assert!(resolved.never_index);

        let invalid = FieldLine::Indexed {
            static_table: false,
            index: 0,
        };
        assert_eq!(
            invalid.dynamic_index(prefix).unwrap_err().code,
            ErrorCode::QPACK_DECOMPRESSION_FAILED
        );
    }
}
