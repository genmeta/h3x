use bytes::Bytes;

use crate::qpack::{
    encoder::EncoderState,
    field::{EncodedFieldSectionPrefix, FieldLine, FieldLineRepresentation},
    r#static,
};

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

/// Output of a compression algorithm.
pub struct CompressOutput {
    pub prefix: EncodedFieldSectionPrefix,
    pub representations: Vec<FieldLineRepresentation>,
    /// Maximum absolute index of a dynamic table entry referenced by this field section.
    /// Used for blocked stream tracking. `None` if no dynamic table entries are referenced.
    pub max_referenced_index: Option<u64>,
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
/// # The `may_block` Parameter
///
/// When `may_block` is `true`, the algorithm may reference unacknowledged dynamic table entries,
/// which would block the stream at the decoder until those entries are received.
/// When `false`, only acknowledged entries (absolute index < known_received_count) and the
/// static table may be referenced. The caller (`Encoder::encode`) computes this based on
/// SETTINGS_QPACK_BLOCKED_STREAMS.
pub trait Algorithm {
    fn compress(
        &self,
        state: &mut EncoderState,
        entries: impl IntoIterator<Item = FieldLine> + Send,
        may_block: bool,
    ) -> impl Future<Output = CompressOutput> + Send;
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
    /// Compresses field lines using only the static table and literal representations.
    ///
    /// Never uses the dynamic table. Always sets `never_dynamic: true`.
    async fn compress(
        &self,
        _state: &mut EncoderState,
        entries: impl IntoIterator<Item = FieldLine> + Send,
        _may_block: bool,
    ) -> CompressOutput {
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
        CompressOutput {
            prefix,
            representations,
            max_referenced_index: None,
        }
    }
}

/// RFC 9204 §7.1: Headers whose values MUST NOT be inserted into the dynamic table.
const SENSITIVE_HEADER_NAMES: &[&[u8]] = &[
    b"authorization",
    b"proxy-authorization",
    b"cookie",
    b"set-cookie",
];

fn is_sensitive(name: &[u8]) -> bool {
    SENSITIVE_HEADER_NAMES
        .iter()
        .any(|s| name.eq_ignore_ascii_case(s))
}

/// Compression algorithm that utilizes the QPACK dynamic table.
///
/// Implements the single-pass encoding algorithm from RFC 9204 Appendix C.
/// For each field line, the decision tree is:
///
/// 1. Static table exact match → indexed field line (static)
/// 2. Dynamic table exact match → indexed field line (dynamic or post-base)
/// 3. No exact match → attempt insertion with best name reference, then post-base index
/// 4. Insertion failed or not allowed → literal with name reference or literal name
pub struct DynamicCompressAlgo<HS> {
    huffman_strategize: HS,
}

impl<HS> DynamicCompressAlgo<HS> {
    pub const fn new(huffman_strategize: HS) -> Self {
        Self { huffman_strategize }
    }
}

impl<HS> Algorithm for DynamicCompressAlgo<HS>
where
    HS: HuffmanStrategize + Send + Sync,
{
    async fn compress(
        &self,
        state: &mut EncoderState,
        entries: impl IntoIterator<Item = FieldLine> + Send,
        may_block: bool,
    ) -> CompressOutput {
        // RFC 9204 Appendix C: base = dynamicTable.getInsertCount()
        let base = state.table_inserted_count();
        let max_table_capacity = state.table_capacity();
        let known_received_count = state.table_known_received_count();

        let mut representations = Vec::new();
        let mut max_ref: Option<u64> = None;

        for FieldLine { name, value } in entries {
            let never_dynamic = is_sensitive(&name);

            // Step 1: Static table exact match
            let (static_name_idx, static_value_idx) = r#static::find(&name, &value);
            if let Some(val_idx) = static_value_idx
                && static_name_idx == Some(val_idx)
            {
                representations.push(FieldLineRepresentation::IndexedFieldLine {
                    is_static: true,
                    index: val_idx as u64,
                });
                continue;
            }

            // Step 2: Dynamic table exact match (name + value)
            if let Some(abs) = find_dynamic_exact(state, &name, &value)
                && can_reference(abs, known_received_count, may_block)
            {
                track_ref(&mut max_ref, abs);
                push_dynamic_index(&mut representations, abs, base);
                continue;
            }

            // Step 3: Try insertion (if not sensitive, may_block allows, and entry fits)
            let dynamic_name_abs = find_dynamic_name(state, &name);

            if !never_dynamic && may_block && entry_fits_capacity(state, &name, &value) {
                let insert_result = if let Some(static_idx) = static_name_idx {
                    state.insert_with_name_reference(
                        true,
                        static_idx as u64,
                        self.huffman_strategize.encode_with_huffman(false, &value),
                        value.clone(),
                    )
                } else if let Some(dyn_abs) = dynamic_name_abs {
                    state.insert_with_name_reference(
                        false,
                        dyn_abs,
                        self.huffman_strategize.encode_with_huffman(false, &value),
                        value.clone(),
                    )
                } else {
                    state.insert_with_literal_name(
                        self.huffman_strategize.encode_with_huffman(true, &name),
                        name.clone(),
                        self.huffman_strategize.encode_with_huffman(false, &value),
                        value.clone(),
                    )
                };

                if let Ok(new_abs) = insert_result {
                    track_ref(&mut max_ref, new_abs);
                    representations.push(
                        FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex {
                            index: new_abs - base,
                        },
                    );
                    continue;
                }
                // Insert failed (CannotEvict) — fall through to literal encoding
            }

            // Step 4: Literal encoding with best available name reference
            if let Some(static_idx) = static_name_idx {
                representations.push(FieldLineRepresentation::LiteralFieldLineWithNameReference {
                    never_dynamic,
                    is_static: true,
                    name_index: static_idx as u64,
                    huffman: self.huffman_strategize.encode_with_huffman(false, &value),
                    value: value.clone(),
                });
            } else if let Some(dyn_abs) = dynamic_name_abs {
                if can_reference(dyn_abs, known_received_count, may_block) {
                    track_ref(&mut max_ref, dyn_abs);
                    push_dynamic_name_ref(
                        &mut representations,
                        dyn_abs,
                        base,
                        never_dynamic,
                        self.huffman_strategize.encode_with_huffman(false, &value),
                        value.clone(),
                    );
                } else {
                    push_literal_name(
                        &mut representations,
                        &self.huffman_strategize,
                        never_dynamic,
                        name.clone(),
                        value.clone(),
                    );
                }
            } else {
                push_literal_name(
                    &mut representations,
                    &self.huffman_strategize,
                    never_dynamic,
                    name.clone(),
                    value.clone(),
                );
            }
        }

        // Compute prefix per RFC 9204 Appendix C
        let prefix = compute_prefix(max_ref, base, max_table_capacity);

        CompressOutput {
            prefix,
            representations,
            max_referenced_index: max_ref,
        }
    }
}

fn find_dynamic_exact(state: &EncoderState, name: &Bytes, value: &Bytes) -> Option<u64> {
    let name_indices = state.find_name(name)?;
    let value_indices = state.find_value(value)?;
    // Most recent entry matching both name and value (highest absolute index)
    name_indices.intersection(value_indices).last().copied()
}

fn find_dynamic_name(state: &EncoderState, name: &Bytes) -> Option<u64> {
    // Most recent entry matching this name (highest absolute index)
    state.find_name(name)?.iter().next_back().copied()
}

/// Quick pre-check: entry size must not exceed table capacity.
/// The actual insert methods handle eviction and return `Err(CannotEvict)` if needed.
fn entry_fits_capacity(state: &EncoderState, name: &Bytes, value: &Bytes) -> bool {
    let entry_size = name.len() as u64 + value.len() as u64 + 32;
    entry_size <= state.table_capacity()
}

/// Whether an entry at the given absolute index can be referenced.
/// Acknowledged entries (index < known_received_count) are always safe.
/// Unacknowledged entries require `may_block` to be true.
fn can_reference(abs_index: u64, known_received_count: u64, may_block: bool) -> bool {
    abs_index < known_received_count || may_block
}

fn track_ref(max_ref: &mut Option<u64>, index: u64) {
    *max_ref = Some(max_ref.map_or(index, |m| m.max(index)));
}

/// Emit an indexed dynamic reference — pre-base (relative) or post-base.
fn push_dynamic_index(representations: &mut Vec<FieldLineRepresentation>, abs: u64, base: u64) {
    if abs >= base {
        representations
            .push(FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index: abs - base });
    } else {
        representations.push(FieldLineRepresentation::IndexedFieldLine {
            is_static: false,
            index: base - abs - 1,
        });
    }
}

/// Emit a literal with dynamic name reference — pre-base or post-base.
fn push_dynamic_name_ref(
    representations: &mut Vec<FieldLineRepresentation>,
    dyn_abs: u64,
    base: u64,
    never_dynamic: bool,
    huffman: bool,
    value: Bytes,
) {
    if dyn_abs >= base {
        representations.push(
            FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                never_dynamic,
                name_index: dyn_abs - base,
                huffman,
                value,
            },
        );
    } else {
        representations.push(FieldLineRepresentation::LiteralFieldLineWithNameReference {
            never_dynamic,
            is_static: false,
            name_index: base - dyn_abs - 1,
            huffman,
            value,
        });
    }
}

fn push_literal_name(
    representations: &mut Vec<FieldLineRepresentation>,
    hs: &impl HuffmanStrategize,
    never_dynamic: bool,
    name: Bytes,
    value: Bytes,
) {
    representations.push(FieldLineRepresentation::LiteralFieldLineWithLiteralName {
        never_dynamic,
        name_huffman: hs.encode_with_huffman(true, &name),
        name,
        value_huffman: hs.encode_with_huffman(false, &value),
        value,
    });
}

fn compute_prefix(
    max_ref: Option<u64>,
    base: u64,
    max_table_capacity: u64,
) -> EncodedFieldSectionPrefix {
    match max_ref {
        Some(max) => {
            let required_insert_count = max + 1;
            let encoded_insert_count =
                EncodedFieldSectionPrefix::encode_ric(required_insert_count, max_table_capacity);
            if base >= required_insert_count {
                EncodedFieldSectionPrefix {
                    encoded_insert_count,
                    sign: false,
                    delta_base: base - required_insert_count,
                }
            } else {
                EncodedFieldSectionPrefix {
                    encoded_insert_count,
                    sign: true,
                    delta_base: required_insert_count - base - 1,
                }
            }
        }
        None => EncodedFieldSectionPrefix {
            encoded_insert_count: 0,
            sign: false,
            delta_base: 0,
        },
    }
}
