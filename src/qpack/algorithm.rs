use bytes::Bytes;

use crate::qpack::{
    encoder::EncoderState,
    field::{EncodedFieldSectionPrefix, FieldLine, FieldLineRepresentation},
    r#static,
};

// TODO: implement heuristic encoder in RFC(https://datatracker.ietf.org/doc/html/rfc9204#section-2.1.1.1-2)

pub trait HuffmanStrategize {
    fn encode_with_huffman(&self, is_name: bool, bytes: &Bytes) -> bool;
}

pub struct HuffmanAlways;

impl HuffmanStrategize for HuffmanAlways {
    fn encode_with_huffman(&self, _is_name: bool, _bytes: &Bytes) -> bool {
        true
    }
}

pub struct HuffmanNever;

impl HuffmanStrategize for HuffmanNever {
    fn encode_with_huffman(&self, _is_name: bool, _bytes: &Bytes) -> bool {
        false
    }
}

/// Compresses HTTP field lines into QPACK representations.
///
/// This trait defines the interface for field line compression algorithms that convert
/// HTTP field lines into QPACK-encoded representations suitable for transmission.
///
/// # The `never_dynamic` Contract
///
/// Implementations **MUST** respect the `never_dynamic` (N-bit) constraint per RFC 9204 §7.1.
/// When compressing a field line, if the resulting representation has `never_dynamic: true`,
/// the field **MUST NOT** be inserted into the dynamic table. Fields marked with the N-bit
/// are intended for protecting field values that should not be put at risk by compression.
///
/// The `never_dynamic` flag appears in these representation types:
/// - [`FieldLineRepresentation::LiteralFieldLineWithNameReference`]: `never_dynamic: bool`
/// - [`FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference`]: `never_dynamic: bool`
/// - [`FieldLineRepresentation::LiteralFieldLineWithLiteralName`]: `never_dynamic: bool`
///
/// # RFC Reference
/// // RFC 9204 §7.1: Fields marked with N-bit MUST NOT be inserted into dynamic table
pub trait Algorithm {
    fn compress(
        &self,
        state: &mut EncoderState,
        entries: impl IntoIterator<Item = FieldLine> + Send,
    ) -> impl Future<Output = (EncodedFieldSectionPrefix, Vec<FieldLineRepresentation>)> + Send;
}

pub struct StaticCompressAlgo<HS> {
    huffman_strategize: HS,
}

impl<HS> StaticCompressAlgo<HS> {
    pub const fn new(huffman_strategize: HS) -> Self {
        Self { huffman_strategize }
    }
}

impl<HS> Algorithm for StaticCompressAlgo<HS>
where
    HS: HuffmanStrategize + Send + Sync,
{
    /// Compresses field lines using only the static table and literal representations,
    /// ensuring compliance with the `never_dynamic` contract.
    ///
    /// This implementation always sets `never_dynamic: true` on all field line representations
    /// and never inserts field lines into the dynamic table. It either:
    /// - Returns an indexed field line (both static and dynamic table lookups point to static table)
    /// - Returns a literal field line with a static name reference (`never_dynamic: true`)
    /// - Returns a literal field line with a literal name (`never_dynamic: true`)
    ///
    /// By design, this algorithm cannot violate the RFC 9204 §7.1 constraint.
    async fn compress(
        &self,
        _state: &mut EncoderState,
        entries: impl IntoIterator<Item = FieldLine> + Send,
    ) -> (EncodedFieldSectionPrefix, Vec<FieldLineRepresentation>) {
        let prefix = EncodedFieldSectionPrefix {
            encoded_insert_count: 0,
            sign: false,
            delta_base: 0,
        };
        let mut representations = Vec::new();
        for FieldLine { name, value } in entries {
            if let (Some(name_index), value_index) = r#static::find(&name, &value) {
                if value_index == Some(name_index) {
                    representations.push(FieldLineRepresentation::IndexedFieldLine {
                        is_static: true,
                        index: name_index as u64,
                    })
                } else {
                    representations.push(
                        FieldLineRepresentation::LiteralFieldLineWithNameReference {
                            // TODO: implement this
                            never_dynamic: true,
                            is_static: true,
                            name_index: name_index as u64,
                            huffman: self.huffman_strategize.encode_with_huffman(false, &value),
                            value: value.clone(),
                        },
                    )
                }
            } else {
                representations.push(FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                    never_dynamic: true,
                    name_huffman: self.huffman_strategize.encode_with_huffman(true, &name),
                    name: name.clone(),
                    value_huffman: self.huffman_strategize.encode_with_huffman(false, &value),
                    value: value.clone(),
                })
            }
        }
        (prefix, representations)
    }
}
