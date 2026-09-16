//! Fields and field-section wire format (RFC 9204 section 4.5).
use bytes::{BufMut, Bytes};
use qbase::varint::VARINT_MAX;

use super::{
    integer::{WritePrefixedInteger, be_prefixed_integer},
    string_literal::{WriteStringLiteral, be_string_literal_slice},
};
use crate::{
    ErrorCode, Result,
    protocol::qpack::table::{self, DynamicTable},
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
                ErrorCode::QPACK_DECOMPRESSION_FAILED
                    .reason("static table index is out of range")
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
                return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED.reason(
                    "nonzero Required Insert Count with a table too small for entries",
                ));
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
        return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED.reason(
            "table capacity or insert count exceeds the QUIC variable-integer range",
        ));
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
                return Err(ErrorCode::QPACK_DECOMPRESSION_FAILED.reason(
                    "Required Insert Count cannot be reconstructed from the table state",
                ));
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

/// Append a field section without dynamic-table references.
#[cfg(test)]
pub(crate) use tests::{WriteFieldSection, be_field_section};

#[cfg(test)]
mod tests {
    use super::{super::instruction::EncoderInstruction, *};
    use crate::protocol::qpack::should_never_index;

    #[test]
    fn rfc_appendix_b_field_sections() {
        let mut table = DynamicTable::new(220).unwrap();
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(220))
            .unwrap();
        for (index, value) in [(0, "www.example.com"), (1, "/sample/path")] {
            table
                .apply(EncoderInstruction::InsertWithNameReference {
                    static_table: true,
                    index,
                    value: Bytes::from_static(value.as_bytes()),
                })
                .unwrap();
        }
        // Independent RFC 9204 Appendix B.1 and B.2 wire bytes.
        for (wire, insert_count, expected) in [
            (
                &b"\x00\x00\x51\x0b/index.html"[..],
                0,
                vec![(":path", "/index.html")],
            ),
            (
                &b"\x03\x81\x10\x11"[..],
                2,
                vec![(":authority", "www.example.com"), (":path", "/sample/path")],
            ),
        ] {
            let (mut input, prefix) = be_field_section_prefix(wire, 220, insert_count).unwrap();
            let mut output = Vec::new();
            output.put_field_section_prefix(&prefix, 220).unwrap();
            for (name, value) in expected {
                let (rest, line) = be_field_line(input).unwrap();
                assert_eq!(
                    line.resolve(prefix, &table).unwrap(),
                    Field {
                        name: Bytes::from_static(name.as_bytes()),
                        value: Bytes::from_static(value.as_bytes()),
                        never_index: false,
                    }
                );
                output.put_field_line(&line).unwrap();
                input = rest;
            }
            assert!(input.is_empty());
            assert_eq!(output, wire);
        }
    }

    #[test]
    fn prefix_wraparound_bounds_and_index_coordinates() {
        // RFC section 4.5.1: 100-byte maximum, ten inserts, encoded RIC=4 -> RIC=9.
        let (rest, prefix) = be_field_section_prefix(&[4, 0x82, 42], 100, 10).unwrap();
        assert_eq!(rest, &[42]);
        assert_eq!(
            prefix,
            FieldSectionPrefix {
                required_insert_count: 9,
                base: 6
            }
        );
        assert_eq!(prefix.relative_index(1).unwrap(), 4);
        assert_eq!(prefix.post_base_index(1).unwrap(), 7);
        assert!(prefix.relative_index(6).is_err());
        assert!(prefix.post_base_index(3).is_err());
        assert!(prefix.post_base_index(u64::MAX).is_err());
        assert!(
            FieldSectionPrefix {
                required_insert_count: 2,
                base: 3
            }
            .relative_index(0)
            .is_err()
        );
        // One wrap fewer than the largest candidate: 10 + 3 = 13, candidate 17 -> 11.
        assert_eq!(
            be_field_section_prefix(&[6, 0], 100, 10)
                .unwrap()
                .1
                .required_insert_count,
            11
        );
        for max_capacity in [32, 100, 4096, VARINT_MAX] {
            for required_insert_count in [0, 1, 10, 255, 256, 258, VARINT_MAX] {
                for base in [0, required_insert_count, VARINT_MAX] {
                    let prefix = FieldSectionPrefix {
                        required_insert_count,
                        base,
                    };
                    let mut wire = Vec::new();
                    wire.put_field_section_prefix(&prefix, max_capacity)
                        .unwrap();
                    assert_eq!(
                        be_field_section_prefix(&wire, max_capacity, required_insert_count)
                            .unwrap()
                            .1,
                        prefix
                    );
                }
            }
        }
        // Zero dynamic references permit any nonnegative Base, even at zero capacity.
        let unused = FieldSectionPrefix {
            required_insert_count: 0,
            base: VARINT_MAX,
        };
        let mut wire = Vec::new();
        wire.put_field_section_prefix(&unused, 0).unwrap();
        assert_eq!(be_field_section_prefix(&wire, 0, 0).unwrap().1, unused);
        for (wire, capacity, count) in [
            (&[][..], 0, 0),
            (&[0][..], 0, 0),
            (&[1, 0][..], 0, 0), // Dynamic references with no table space.
            (&[1, 0][..], 31, 0),
            (&[3, 0][..], 32, 0),     // Encoded count exceeds FullRange.
            (&[1, 0][..], 100, 0),    // Zero count must use encoded zero.
            (&[6, 0][..], 100, 0),    // Cannot wrap to an earlier positive count.
            (&[0, 0x80][..], 100, 0), // Negative Base.
            (&[2, 0x81][..], 100, 0),
            (&[1, 0][..], 64, VARINT_MAX), // Reconstructed count exceeds 62 bits.
            (&[0, 0][..], VARINT_MAX + 1, 0),
            (&[0, 0][..], 0, VARINT_MAX + 1),
        ] {
            assert_eq!(
                ErrorCode::from(be_field_section_prefix(wire, capacity, count).unwrap_err()),
                ErrorCode::QPACK_DECOMPRESSION_FAILED
            );
        }
        // Both wire integers fit in 62 bits, but their reconstructed Base does not.
        let mut wire = vec![2]; // RIC=1 with a 100-byte maximum.
        wire.put_prefixed_integer(VARINT_MAX, 7, 0).unwrap();
        assert!(be_field_section_prefix(&wire, 100, 0).is_err());
        for (prefix, capacity) in [
            (
                FieldSectionPrefix {
                    required_insert_count: 1,
                    base: 0,
                },
                31,
            ),
            (
                FieldSectionPrefix {
                    required_insert_count: VARINT_MAX + 1,
                    base: 0,
                },
                100,
            ),
            (
                FieldSectionPrefix {
                    required_insert_count: 0,
                    base: VARINT_MAX + 1,
                },
                100,
            ),
        ] {
            let mut output = vec![42];
            assert!(output.put_field_section_prefix(&prefix, capacity).is_err());
            assert_eq!(output, [42]);
        }
    }

    #[test]
    fn five_line_forms_preserve_names_values_and_never_index() {
        let mut table = DynamicTable::new(68).unwrap();
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(68))
            .unwrap();
        for (name, value) in [("x", "a"), ("y", "b")] {
            table
                .apply(EncoderInstruction::InsertWithLiteralName {
                    name: Bytes::from_static(name.as_bytes()),
                    value: Bytes::from_static(value.as_bytes()),
                })
                .unwrap();
        }
        let prefix = FieldSectionPrefix {
            required_insert_count: 2,
            base: 1,
        };
        for (wire, name, value, never_index, dependency) in [
            (&b"\xd1"[..], ":method", "GET", false, None),
            (&b"\x80"[..], "x", "a", false, Some(0)),
            (&b"\x10"[..], "y", "b", false, Some(1)),
            (&b"\x50\x01v"[..], ":authority", "v", false, None),
            (&b"\x70\x01v"[..], ":authority", "v", true, None),
            (&b"\x40\x01v"[..], "x", "v", false, Some(0)),
            (&b"\x60\x01v"[..], "x", "v", true, Some(0)),
            (&b"\x00\x01v"[..], "y", "v", false, Some(1)),
            (&b"\x08\x01v"[..], "y", "v", true, Some(1)),
            (&b"\x21x\x01v"[..], "x", "v", false, None),
            (&b"\x31x\x01v"[..], "x", "v", true, None),
        ] {
            let mut with_suffix = wire.to_vec();
            with_suffix.push(42);
            let (rest, line) = be_field_line(&with_suffix).unwrap();
            assert_eq!(rest, &[42]);
            assert_eq!(line.dynamic_index(prefix).unwrap(), dependency);
            assert_eq!(
                line.resolve(prefix, &table).unwrap(),
                Field {
                    name: Bytes::from_static(name.as_bytes()),
                    value: Bytes::from_static(value.as_bytes()),
                    never_index,
                }
            );
            let mut output = Vec::new();
            output.put_field_line(&line).unwrap();
            assert_eq!(output, wire);
            for end in 0..wire.len() {
                assert!(be_field_line(&wire[..end]).is_err());
            }
        }
        // Literal N=1 and Huffman-encoded name and value, independently encoded bytes.
        let huffman = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let mut wire = vec![0x3f, 5];
        wire.extend(huffman);
        wire.push(0x8c);
        wire.extend(huffman);
        let line = be_field_line(&wire).unwrap().1;
        assert_eq!(
            line.resolve(prefix, &table).unwrap(),
            Field {
                name: Bytes::from_static(b"www.example.com"),
                value: Bytes::from_static(b"www.example.com"),
                never_index: true,
            }
        );
        for wire in [&[0xff, 36][..], &[0x81][..], &[0x11][..]] {
            assert!(
                be_field_line(wire)
                    .unwrap()
                    .1
                    .resolve(prefix, &table)
                    .is_err()
            );
        }
        for wire in [&[0x50, 0x81, 0xff][..], &[0xff; 12][..]] {
            assert!(be_field_line(wire).is_err());
        }
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(34))
            .unwrap();
        assert!(
            be_field_line(&[0x80])
                .unwrap()
                .1
                .resolve(prefix, &table)
                .is_err()
        );
        assert!(
            be_field_line(&[0x60, 0])
                .unwrap()
                .1
                .resolve(prefix, &table)
                .is_err()
        );
    }

    #[test]
    fn parsers_return_the_unconsumed_suffix() {
        let table = DynamicTable::default();
        let prefix = FieldSectionPrefix {
            required_insert_count: 0,
            base: 0,
        };
        let input = [0xd1, 0x50, 1, b'a', 0x21, b'x', 1, b'y', 0xff];
        let (rest, method) = be_field_line(&input).unwrap();
        assert_eq!(method.resolve(prefix, &table).unwrap().value, "GET");
        assert_eq!(rest, &input[1..]);
        let (rest, authority) = be_field_line(rest).unwrap();
        assert_eq!(authority.resolve(prefix, &table).unwrap().value, "a");
        assert_eq!(rest, &input[4..]);
        let (rest, custom) = be_field_line(rest).unwrap();
        let custom = custom.resolve(prefix, &table).unwrap();
        assert_eq!(custom.name, "x");
        assert_eq!(custom.value, "y");
        assert_eq!(rest, &[0xff]);
        // A complete section must reject a malformed suffix, not silently stop.
        assert!(be_field_section(&[0, 0, 0xd1, 0xff]).is_err());
        assert!(be_field_line(&[]).is_err());
    }

    #[test]
    fn accepts_unused_base_and_preserves_never_index() {
        for delta_base in [0, 1, 127, VARINT_MAX] {
            let mut wire = vec![0];
            wire.put_prefixed_integer(delta_base, 7, 0).unwrap();
            wire.push(0xd1); // :method = GET
            assert_eq!(be_field_section(wire.as_slice()).unwrap().1[0].value, "GET");
        }
        // N=1 with a custom literal name, and with an exact static-table match.
        for wire in [
            vec![0, 0, 0x31, b'x', 1, b'y'],
            vec![0, 0, 0x7f, 2, 3, b'G', b'E', b'T'],
        ] {
            let fields = be_field_section(wire.as_slice()).unwrap().1;
            assert!(fields[0].never_index);
            let mut encoded = Vec::new();
            encoded.put_field_section(fields.clone()).unwrap();
            assert_eq!(be_field_section(encoded.as_slice()).unwrap().1, fields);
        }
        let wire = [0, 0, 0x31, b'x', 1, b'y'];
        let fields = be_field_section(&wire[..]).unwrap().1;
        let headers = crate::common::headers::be_trailers(fields).unwrap();
        assert!(headers["x"].is_sensitive());
        let mut encoded = Vec::new();
        encoded
            .put_field_section(headers.iter().map(|(name, value)| Field {
                name: Bytes::copy_from_slice(name.as_str().as_bytes()),
                value: Bytes::copy_from_slice(value.as_bytes()),
                never_index: value.is_sensitive(),
            }))
            .unwrap();
        assert_eq!(encoded, wire);
        // Cookie concatenation must retain N from either input field.
        let wire = [0, 0, 0x55, 1, b'a', 0x75, 1, b'b'];
        let fields = be_field_section(&wire[..]).unwrap().1;
        let headers = crate::common::headers::be_trailers(fields).unwrap();
        assert_eq!(headers["cookie"], "a; b");
        assert!(headers["cookie"].is_sensitive());
    }

    #[test]
    fn field_sections_cover_static_literals_huffman_and_invalid_input() {
        for &(name, value) in &table::STATIC_TABLE {
            let fields = vec![Field {
                never_index: should_never_index(name.as_bytes()),
                name: Bytes::from_static(name.as_bytes()),
                value: Bytes::from_static(value.as_bytes()),
            }];
            let mut output = bytes::BytesMut::new();
            output.put_field_section(fields.clone()).unwrap();
            let (input, decoded) = be_field_section(output.as_ref()).unwrap();
            assert_eq!(decoded, fields);
            assert!(input.is_empty());
        }
        // Independent wire bytes: indexed, name reference, literal, and N bit.
        for (name, value, wire) in [
            (":method", "GET", vec![0, 0, 0xd1]),
            (":authority", "", vec![0, 0, 0xc0]),
            (":authority", "a", vec![0, 0, 0x50, 1, b'a']),
            ("x", "y", vec![0, 0, 0x21, b'x', 1, b'y']),
            ("cookie", "", vec![0, 0, 0x75, 0]),
        ] {
            let fields = vec![Field {
                never_index: should_never_index(name.as_bytes()),
                name: Bytes::from_static(name.as_bytes()),
                value: Bytes::from_static(value.as_bytes()),
            }];
            let mut output = vec![0xff];
            output.put_field_section(fields.clone()).unwrap();
            assert_eq!(&output[1..], wire);
            assert_eq!(be_field_section(wire.as_slice()).unwrap().1, fields);
        }
        // HPACK/QPACK Huffman encoding of "www.example.com", in name and value.
        let huffman = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let mut wire = vec![0, 0, 0x2f, 5];
        wire.extend_from_slice(&huffman);
        wire.push(0x8c);
        wire.extend_from_slice(&huffman);
        let fields = be_field_section(wire.as_slice()).unwrap().1;
        assert_eq!(fields[0].name, "www.example.com");
        assert_eq!(fields[0].value, "www.example.com");
        for end in 3..wire.len() {
            assert!(be_field_section(&wire[..end]).is_err());
        }
        for wire in [
            &[][..],
            &[0],
            &[1, 0],
            &[0, 0x80],
            &[0, 0, 0x80],
            &[0, 0, 0x40],
            &[0, 0, 0x10],
            &[0, 0, 0],
            &[0, 0, 0xff, 36],
            &[0, 0, 0x50, 0x81, 0xff],
        ] {
            assert_eq!(
                ErrorCode::from(be_field_section(wire).unwrap_err()),
                ErrorCode::QPACK_DECOMPRESSION_FAILED
            );
        }
        assert_eq!(table::find_index(b"custom", b"GET"), None);
        assert_eq!(table::get(u64::MAX), None);
    }

    pub(crate) trait WriteFieldSection: BufMut {
        fn put_field_section(&mut self, fields: impl IntoIterator<Item = Field>) -> Result<()>;
    }

    impl<B: BufMut> WriteFieldSection for B {
        fn put_field_section(&mut self, fields: impl IntoIterator<Item = Field>) -> Result<()> {
            self.put_slice(&[0, 0]); // Required Insert Count = 0, S = 0, Delta Base = 0.
            for mut field in fields {
                field.never_index |= should_never_index(&field.name);
                if !field.never_index
                    && let Some(static_index) = table::find_index(&field.name, &field.value)
                {
                    self.put_field_line(&FieldLine::Indexed {
                        static_table: true,
                        index: static_index as u64,
                    })?;
                    continue;
                }
                let line = if let Some(index) = table::find_name(&field.name) {
                    FieldLine::LiteralWithNameReference {
                        never_index: field.never_index,
                        static_table: true,
                        index: index as u64,
                        value: field.value,
                    }
                } else {
                    FieldLine::Literal(field)
                };
                self.put_field_line(&line)?;
            }
            Ok(())
        }
    }

    /// Parse a complete, bounded HEADERS payload without dynamic-table references.
    /// Success leaves no remaining input; use Decoder::decode for the stateful path.
    pub(crate) fn be_field_section(input: &[u8]) -> Result<(&[u8], Vec<Field>)> {
        let (mut input, prefix) = be_field_section_prefix(input, 0, 0)?;
        let table = DynamicTable::default();
        let mut fields = Vec::new();
        while !input.is_empty() {
            let (rest, line) = be_field_line(input)?;
            fields.push(line.resolve(prefix, &table)?);
            input = rest;
        }
        Ok((input, fields))
    }
}
