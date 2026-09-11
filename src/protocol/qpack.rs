use bytes::{BufMut, Bytes};
use httlib_huffman::DecoderSpeed;
use qbase::varint::VARINT_MAX;

use crate::{Error, Result};

#[path = "qpack/static.rs"]
mod static_table;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Field {
    pub(crate) name: Bytes,
    pub(crate) value: Bytes,
    /// RFC 9204 section 7.1.3: preserve N when re-encoding this field line.
    pub(crate) never_index: bool,
}

/// Append a field section without dynamic-table references.
pub(crate) trait WriteFieldSection: BufMut {
    fn put_field_section(&mut self, fields: impl IntoIterator<Item = Field>) -> Result<()>;
}

impl<B: BufMut> WriteFieldSection for B {
    fn put_field_section(&mut self, fields: impl IntoIterator<Item = Field>) -> Result<()> {
        // RFC 9204 Appendix C, specialized for a zero-capacity dynamic table.
        // The prefix is known in advance, so no separate prefix buffer is needed.
        self.put_slice(&[0, 0]); // Required Insert Count = 0, S = 0, Delta Base = 0.
        for mut field in fields {
            field.never_index |= should_never_index(&field.name);
            if !field.never_index
                && let Some(static_index) = static_table::find_index(&field.name, &field.value)
            {
                put_static_index_reference(self, static_index)?;
                continue;
            }
            let static_name_index = static_table::find_name(&field.name);
            put_literal(self, static_name_index, &field)?;
        }
        Ok(())
    }
}

/// RFC 9204 section 4.5.2: Indexed Field Line with T = 1.
fn put_static_index_reference(output: &mut impl BufMut, index: usize) -> Result<()> {
    put_prefixed_integer(output, index as u64, 6, 0xc0)
}

/// Appendix C encodeLiteral: static name reference or literal name (4.5.4/4.5.6).
fn put_literal(
    output: &mut impl BufMut,
    static_name_index: Option<usize>,
    field: &Field,
) -> Result<()> {
    if let Some(index) = static_name_index {
        put_prefixed_integer(
            output,
            index as u64,
            4,
            0x50 | (u8::from(field.never_index) << 5),
        )?;
    } else {
        put_string_literal(
            output,
            &field.name,
            4,
            0x20 | (u8::from(field.never_index) << 4),
        )?;
    }
    put_string_literal(output, &field.value, 8, 0)
}

/// Parse a complete, bounded HEADERS payload; success leaves no remaining input.
pub(crate) fn be_field_section(input: &[u8]) -> Result<(&[u8], Vec<Field>)> {
    // Section 4.5.1: at zero capacity, only Encoded Insert Count = 0 is valid.
    let (input, encoded_insert_count) = be_prefixed_integer(input, 8)?;
    let sign = *input.first().ok_or(Error::QPACK_DECOMPRESSION_FAILED)? & 0x80 != 0;
    let (mut input, _delta_base) = be_prefixed_integer(input, 7)?;
    // Section 4.5.1.2: Base is unused without dynamic references; S=1 would make it negative.
    if encoded_insert_count != 0 || sign {
        return Err(Error::QPACK_DECOMPRESSION_FAILED);
    }
    let mut fields = Vec::new();
    while !input.is_empty() {
        let (rest, field) = be_field_line(input)?;
        fields.push(field);
        input = rest;
    }
    Ok((input, fields))
}

/// RFC 9204 section 4.5: parse one static reference or literal field line.
fn be_field_line(input: &[u8]) -> Result<(&[u8], Field)> {
    let first = *input.first().ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
    if first & 0xc0 == 0xc0 {
        let (input, index) = be_prefixed_integer(input, 6)?;
        let (name, value) = static_table::get(index).ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
        Ok((
            input,
            Field {
                never_index: false,
                name: Bytes::from_static(name.as_bytes()),
                value: Bytes::from_static(value.as_bytes()),
            },
        ))
    } else if first & 0xd0 == 0x50 {
        let (input, index) = be_prefixed_integer(input, 4)?;
        let (name, _) = static_table::get(index).ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
        let (input, value) = be_string_literal(input, 8)?;
        Ok((
            input,
            Field {
                never_index: first & 0x20 != 0,
                name: Bytes::from_static(name.as_bytes()),
                value,
            },
        ))
    } else if first & 0xe0 == 0x20 {
        let (input, name) = be_string_literal(input, 4)?;
        let (input, value) = be_string_literal(input, 8)?;
        Ok((
            input,
            Field {
                never_index: first & 0x10 != 0,
                name,
                value,
            },
        ))
    } else {
        Err(Error::QPACK_DECOMPRESSION_FAILED)
    }
}

/// RFC 9204 section 4.1.1; RFC 7541 section 5.1. Not a QUIC varint.
fn put_prefixed_integer(
    output: &mut impl BufMut,
    mut value: u64,
    prefix_bits: u8,
    high_bits: u8,
) -> Result<()> {
    if value > VARINT_MAX {
        return Err(Error::QPACK_DECOMPRESSION_FAILED);
    }
    let limit = (1u64 << prefix_bits) - 1;
    if value < limit {
        output.put_u8(high_bits | value as u8);
        return Ok(());
    }
    output.put_u8(high_bits | limit as u8);
    value -= limit;
    while value >= 128 {
        output.put_u8((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.put_u8(value as u8);
    Ok(())
}

/// RFC 9204 section 4.1.1: decode a prefixed integer, limited to 62 bits.
fn be_prefixed_integer(mut input: &[u8], prefix_bits: u8) -> Result<(&[u8], u64)> {
    let (&first, rest) = input
        .split_first()
        .ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
    input = rest;
    let limit = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first) & limit;
    if value < limit {
        return Ok((input, value));
    }
    for shift in (0..63).step_by(7) {
        let (&byte, rest) = input
            .split_first()
            .ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
        input = rest;
        value = value
            .checked_add(u64::from(byte & 0x7f) << shift)
            .filter(|&value| value <= VARINT_MAX)
            .ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
        if byte & 0x80 == 0 {
            return Ok((input, value));
        }
    }
    Err(Error::QPACK_DECOMPRESSION_FAILED)
}

/// RFC 9204 section 4.1.2: prefix_bits includes H; this encoder writes H = 0.
fn put_string_literal(
    output: &mut impl BufMut,
    value: &[u8],
    prefix_bits: u8,
    high_bits: u8,
) -> Result<()> {
    put_prefixed_integer(output, value.len() as u64, prefix_bits - 1, high_bits)?;
    output.put_slice(value);
    Ok(())
}

/// RFC 9204 section 4.1.2: prefix_bits includes the Huffman flag.
fn be_string_literal(input: &[u8], prefix_bits: u8) -> Result<(&[u8], Bytes)> {
    let first = *input.first().ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
    let huffman = first & (1 << (prefix_bits - 1)) != 0;
    let (input, len) = be_prefixed_integer(input, prefix_bits - 1)?;
    let len = usize::try_from(len).map_err(|_| Error::QPACK_DECOMPRESSION_FAILED)?;
    let (encoded, rest) = input
        .split_at_checked(len)
        .ok_or(Error::QPACK_DECOMPRESSION_FAILED)?;
    if !huffman {
        return Ok((rest, Bytes::copy_from_slice(encoded)));
    }
    let mut decoded = Vec::new();
    httlib_huffman::decode(encoded, &mut decoded, DecoderSpeed::FourBits)
        .map_err(|_| Error::QPACK_DECOMPRESSION_FAILED)?;
    Ok((rest, Bytes::from(decoded)))
}

/// Local policy permitted by RFC 9204 section 7.1.3; not an RFC-mandated list.
fn should_never_index(name: &[u8]) -> bool {
    matches!(
        name,
        b"authorization" | b"proxy-authorization" | b"cookie" | b"set-cookie"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers_return_the_unconsumed_suffix() {
        let input = [0xd1, 0x50, 1, b'a', 0x21, b'x', 1, b'y', 0xff];
        let (rest, method) = be_field_line(&input).unwrap();
        assert_eq!(method.value, "GET");
        assert_eq!(rest, &input[1..]);
        let (rest, authority) = be_field_line(rest).unwrap();
        assert_eq!(authority.value, "a");
        assert_eq!(rest, &input[4..]);
        let (rest, custom) = be_field_line(rest).unwrap();
        assert_eq!(custom.name, "x");
        assert_eq!(custom.value, "y");
        assert_eq!(rest, &[0xff]);
        let (rest, value) = be_string_literal(&[1, b'a', 42], 8).unwrap();
        assert_eq!(value, "a");
        assert_eq!(rest, &[42]);
        // A complete section must reject a malformed suffix, not silently stop.
        assert!(be_field_section(&[0, 0, 0xd1, 0xff]).is_err());
        assert!(be_field_line(&[]).is_err());
    }

    #[test]
    fn accepts_unused_base_and_preserves_never_index() {
        for delta_base in [0, 1, 127, VARINT_MAX] {
            let mut wire = vec![0];
            put_prefixed_integer(&mut wire, delta_base, 7, 0).unwrap();
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
        let headers = super::super::headers::trailer_fields(fields).unwrap();
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
        let headers = super::super::headers::trailer_fields(fields).unwrap();
        assert_eq!(headers["cookie"], "a; b");
        assert!(headers["cookie"].is_sensitive());
    }

    #[test]
    fn field_sections_cover_static_literals_huffman_and_invalid_input() {
        for &(name, value) in &static_table::STATIC_TABLE {
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
                be_field_section(wire).unwrap_err(),
                Error::QPACK_DECOMPRESSION_FAILED
            );
        }
        for bits in [3, 4, 6, 7, 8] {
            for value in [0, (1 << bits) - 1, 127, 128, VARINT_MAX] {
                let mut output = Vec::new();
                put_prefixed_integer(&mut output, value, bits, 0).unwrap();
                output.push(42);
                let (input, decoded) = be_prefixed_integer(output.as_slice(), bits).unwrap();
                assert_eq!(decoded, value);
                assert_eq!(input, &[42]);
            }
        }
        assert!(be_prefixed_integer(&[0xff; 12][..], 8).is_err());
        assert!(put_prefixed_integer(&mut Vec::new(), VARINT_MAX + 1, 8, 0).is_err());
        assert_eq!(static_table::find_index(b"custom", b"GET"), None);
        assert_eq!(static_table::get(u64::MAX), None);
    }
}
