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
    async fn compress(
        &self,
        _state: &mut EncoderState,
        entries: impl IntoIterator<Item = FieldLine> + Send,
    ) -> (EncodedFieldSectionPrefix, Vec<FieldLineRepresentation>) {
        let prefix = EncodedFieldSectionPrefix {
            required_insert_count: 0,
            base: 0,
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
