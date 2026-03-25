use bytes::Bytes;

use crate::qpack::{
    encoder::EncoderState,
    field::{EncodedFieldSectionPrefix, FieldLine, FieldLineRepresentation},
    r#static,
};

pub trait HuffmanStrategize {
    fn should_encode_name_with_huffman(&self, name: &Bytes) -> bool;
    fn should_encode_value_with_huffman(&self, value: &Bytes) -> bool;
}

pub struct HuffmanAlways;

impl HuffmanStrategize for HuffmanAlways {
    fn should_encode_name_with_huffman(&self, _name: &Bytes) -> bool {
        true
    }
    fn should_encode_value_with_huffman(&self, _value: &Bytes) -> bool {
        true
    }
}

pub struct HuffmanNever;

impl HuffmanStrategize for HuffmanNever {
    fn should_encode_name_with_huffman(&self, _name: &Bytes) -> bool {
        false
    }
    fn should_encode_value_with_huffman(&self, _value: &Bytes) -> bool {
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
                            huffman: self
                                .huffman_strategize
                                .should_encode_value_with_huffman(&value),
                            value: value.clone(),
                        },
                    )
                }
            } else {
                representations.push(FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                    never_dynamic: true,
                    name_huffman: self
                        .huffman_strategize
                        .should_encode_name_with_huffman(&name),
                    name: name.clone(),
                    value_huffman: self
                        .huffman_strategize
                        .should_encode_value_with_huffman(&value),
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
                        self.huffman_strategize
                            .should_encode_value_with_huffman(&value),
                        value.clone(),
                    )
                } else if let Some(dyn_abs) = dynamic_name_abs {
                    state.insert_with_name_reference(
                        false,
                        dyn_abs,
                        self.huffman_strategize
                            .should_encode_value_with_huffman(&value),
                        value.clone(),
                    )
                } else {
                    state.insert_with_literal_name(
                        self.huffman_strategize
                            .should_encode_name_with_huffman(&name),
                        name.clone(),
                        self.huffman_strategize
                            .should_encode_value_with_huffman(&value),
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
                    huffman: self
                        .huffman_strategize
                        .should_encode_value_with_huffman(&value),
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
                        self.huffman_strategize
                            .should_encode_value_with_huffman(&value),
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
        name_huffman: hs.should_encode_name_with_huffman(&name),
        name,
        value_huffman: hs.should_encode_value_with_huffman(&value),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;

    use crate::{
        dhttp::settings::{QpackBlockedStreams, QpackMaxTableCapacity, Settings},
        qpack::{
            algorithm::{Algorithm, CompressOutput, DynamicCompressAlgo, HuffmanNever},
            encoder::EncoderState,
            field::{EncodedFieldSectionPrefix, FieldLine, FieldLineRepresentation},
        },
        varint::VarInt,
    };

    fn state_with_capacity(table_capacity: u32) -> EncoderState {
        let mut settings = Settings::default();
        settings.set(QpackMaxTableCapacity::setting(VarInt::from_u32(
            table_capacity,
        )));
        settings.set(QpackBlockedStreams::setting(VarInt::from_u32(100)));
        let mut state = EncoderState::new(Arc::new(settings));
        if table_capacity > 0 {
            state
                .set_max_table_capacity(table_capacity as u64)
                .expect("set capacity failed");
        }
        state
    }

    fn field_line(name: &str, value: &str) -> FieldLine {
        FieldLine {
            name: Bytes::from(name.to_owned()),
            value: Bytes::from(value.to_owned()),
        }
    }

    fn algo() -> DynamicCompressAlgo<HuffmanNever> {
        DynamicCompressAlgo::new(HuffmanNever)
    }

    async fn do_compress(
        state: &mut EncoderState,
        entries: Vec<FieldLine>,
        may_block: bool,
    ) -> CompressOutput {
        algo().compress(state, entries, may_block).await
    }

    // --- Static table tests ---

    #[tokio::test]
    async fn static_exact_match() {
        let mut state = state_with_capacity(256);
        // ":method GET" is static table entry 17
        let output = do_compress(&mut state, vec![field_line(":method", "GET")], true).await;
        assert_eq!(output.representations.len(), 1);
        assert!(matches!(
            output.representations[0],
            FieldLineRepresentation::IndexedFieldLine {
                is_static: true,
                index: 17
            }
        ));
        assert!(output.max_referenced_index.is_none());
        assert_eq!(output.prefix.encoded_insert_count, 0);
    }

    // --- Dynamic table insertion ---

    #[tokio::test]
    async fn insert_and_post_base_reference() {
        let mut state = state_with_capacity(256);
        let output = do_compress(&mut state, vec![field_line("x-custom", "hello")], true).await;

        assert_eq!(output.representations.len(), 1);
        assert!(matches!(
            output.representations[0],
            FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index: 0 }
        ));
        assert_eq!(output.max_referenced_index, Some(0));
        assert_ne!(output.prefix.encoded_insert_count, 0);
        // New insertion: base(0) < RIC(1), so sign=true
        assert!(output.prefix.sign);
    }

    #[tokio::test]
    async fn second_request_uses_pre_base_dynamic_ref() {
        let mut state = state_with_capacity(256);

        // First request: insert entry
        let _ = do_compress(&mut state, vec![field_line("x-custom", "hello")], true).await;
        // Simulate decoder acknowledging the entry
        state.dynamic_table.known_received_count = state.dynamic_table.inserted_count;

        // Second request: same header should use pre-base indexed reference
        let output = do_compress(&mut state, vec![field_line("x-custom", "hello")], true).await;

        assert_eq!(output.representations.len(), 1);
        // base = 1, absolute = 0, wire index = base - abs - 1 = 0
        assert!(matches!(
            output.representations[0],
            FieldLineRepresentation::IndexedFieldLine {
                is_static: false,
                index: 0
            }
        ));
        assert_eq!(output.max_referenced_index, Some(0));
        // base(1) >= RIC(1), so sign=false
        assert!(!output.prefix.sign);
    }

    // --- Sensitive headers ---

    #[tokio::test]
    async fn sensitive_headers_never_inserted() {
        let mut state = state_with_capacity(256);
        let output = do_compress(
            &mut state,
            vec![field_line("authorization", "Bearer secret")],
            true,
        )
        .await;

        assert_eq!(output.representations.len(), 1);
        // "authorization" exists in static table as name — uses static name ref with N-bit
        match &output.representations[0] {
            FieldLineRepresentation::LiteralFieldLineWithNameReference {
                never_dynamic,
                is_static,
                ..
            } => {
                assert!(
                    never_dynamic,
                    "sensitive header should have never_dynamic=true"
                );
                assert!(is_static, "should use static name reference");
            }
            FieldLineRepresentation::LiteralFieldLineWithLiteralName { never_dynamic, .. } => {
                assert!(
                    never_dynamic,
                    "sensitive header should have never_dynamic=true"
                );
            }
            other => panic!("expected literal representation, got {other:?}"),
        }
        assert!(output.max_referenced_index.is_none());
        assert_eq!(state.table_inserted_count(), 0);
    }

    #[tokio::test]
    async fn cookie_header_never_inserted() {
        let mut state = state_with_capacity(256);
        let output = do_compress(&mut state, vec![field_line("cookie", "session=abc")], true).await;

        // "cookie" is static table entry 5 — should use name reference, never_dynamic=true
        assert!(matches!(
            output.representations[0],
            FieldLineRepresentation::LiteralFieldLineWithNameReference {
                never_dynamic: true,
                is_static: true,
                ..
            }
        ));
        assert_eq!(state.table_inserted_count(), 0);
    }

    // --- may_block=false ---

    #[tokio::test]
    async fn may_block_false_skips_insertion() {
        let mut state = state_with_capacity(256);
        let output = do_compress(&mut state, vec![field_line("x-custom", "hello")], false).await;

        assert!(output.max_referenced_index.is_none());
        // SetDynamicTableCapacity was inserted by state_with_capacity, but no field insertion
        assert_eq!(state.table_inserted_count(), 0);
        assert!(matches!(
            output.representations[0],
            FieldLineRepresentation::LiteralFieldLineWithLiteralName { .. }
        ));
    }

    #[tokio::test]
    async fn may_block_false_can_reference_acknowledged() {
        let mut state = state_with_capacity(256);

        // Insert with may_block=true, then acknowledge
        let _ = do_compress(&mut state, vec![field_line("x-custom", "hello")], true).await;
        state.dynamic_table.known_received_count = state.dynamic_table.inserted_count;

        // may_block=false should still reference the acknowledged entry
        let output = do_compress(&mut state, vec![field_line("x-custom", "hello")], false).await;

        assert_eq!(output.representations.len(), 1);
        assert!(matches!(
            output.representations[0],
            FieldLineRepresentation::IndexedFieldLine {
                is_static: false,
                ..
            }
        ));
        assert!(output.max_referenced_index.is_some());
    }

    // --- Name reference fallback ---

    #[tokio::test]
    async fn static_name_reference_with_literal_value() {
        let mut state = state_with_capacity(0);
        let output = do_compress(
            &mut state,
            vec![field_line(":path", "/my/custom/path")],
            true,
        )
        .await;

        assert_eq!(output.representations.len(), 1);
        assert!(matches!(
            output.representations[0],
            FieldLineRepresentation::LiteralFieldLineWithNameReference {
                is_static: true,
                ..
            }
        ));
    }

    // --- Multiple entries ---

    #[tokio::test]
    async fn multiple_insertions_correct_post_base_indices() {
        let mut state = state_with_capacity(4096);
        let output = do_compress(
            &mut state,
            vec![
                field_line("x-header-a", "value-a"),
                field_line("x-header-b", "value-b"),
                field_line("x-header-c", "value-c"),
            ],
            true,
        )
        .await;

        assert_eq!(output.representations.len(), 3);
        for (i, repr) in output.representations.iter().enumerate() {
            assert!(
                matches!(
                    repr,
                    FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index }
                    if *index == i as u64
                ),
                "entry {i}: expected PostBaseIndex({i}), got {repr:?}"
            );
        }
        assert_eq!(state.table_inserted_count(), 3);
        assert_eq!(output.max_referenced_index, Some(2));
    }

    // --- Duplicate name with different value ---

    #[tokio::test]
    async fn same_name_different_value_inserts_new_entry() {
        let mut state = state_with_capacity(4096);

        let _ = do_compress(&mut state, vec![field_line("x-custom", "hello")], true).await;
        state.dynamic_table.known_received_count = state.dynamic_table.inserted_count;

        // Same name, different value — should insert new entry
        let output = do_compress(&mut state, vec![field_line("x-custom", "world")], true).await;

        assert_eq!(state.table_inserted_count(), 2);
        assert!(matches!(
            output.representations[0],
            FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index: 0 }
        ));
    }

    // --- Prefix computation ---

    #[tokio::test]
    async fn prefix_no_dynamic_refs() {
        let mut state = state_with_capacity(0);
        let output = do_compress(&mut state, vec![field_line(":method", "GET")], true).await;

        assert_eq!(
            output.prefix,
            EncodedFieldSectionPrefix {
                encoded_insert_count: 0,
                sign: false,
                delta_base: 0,
            }
        );
    }

    #[tokio::test]
    async fn prefix_with_post_base_sign_true() {
        let mut state = state_with_capacity(256);
        let output = do_compress(&mut state, vec![field_line("x-custom", "hello")], true).await;

        // base=0, RIC=1, sign=true (base < RIC), delta_base = RIC - base - 1 = 0
        assert!(output.prefix.sign);
        assert_eq!(output.prefix.delta_base, 0);
    }

    #[tokio::test]
    async fn prefix_with_pre_base_sign_false() {
        let mut state = state_with_capacity(256);

        let _ = do_compress(&mut state, vec![field_line("x-custom", "hello")], true).await;
        state.dynamic_table.known_received_count = state.dynamic_table.inserted_count;

        let output = do_compress(&mut state, vec![field_line("x-custom", "hello")], true).await;

        // base=1, RIC=1, sign=false (base >= RIC), delta_base = base - RIC = 0
        assert!(!output.prefix.sign);
        assert_eq!(output.prefix.delta_base, 0);
    }

    // --- Encoder instructions ---

    #[tokio::test]
    async fn insert_emits_encoder_instructions() {
        let mut state = state_with_capacity(256);
        let _ = do_compress(&mut state, vec![field_line("x-custom", "hello")], true).await;

        // SetDynamicTableCapacity (from state_with_capacity) + InsertWithLiteralName
        assert_eq!(state.pending_instructions.len(), 2);
    }

    #[tokio::test]
    async fn insert_with_static_name_emits_name_reference() {
        let mut state = state_with_capacity(256);
        let _ = do_compress(
            &mut state,
            vec![field_line(":path", "/my/custom/path")],
            true,
        )
        .await;

        assert_eq!(state.table_inserted_count(), 1);
        assert!(state.pending_instructions.iter().any(|inst| matches!(
            inst,
            crate::qpack::encoder::EncoderInstruction::InsertWithNameReference {
                is_static: true,
                ..
            }
        )));
    }

    // --- Capacity edge case ---

    #[tokio::test]
    async fn entry_too_large_for_table_falls_to_literal() {
        let mut state = state_with_capacity(64);
        // entry size = 8 + 32 + 32 = 72 > 64
        let output = do_compress(
            &mut state,
            vec![field_line("x-custom", "a-very-long-value-that-wont-fit-")],
            true,
        )
        .await;

        assert_eq!(state.table_inserted_count(), 0);
        assert!(matches!(
            output.representations[0],
            FieldLineRepresentation::LiteralFieldLineWithLiteralName { .. }
        ));
    }
}
