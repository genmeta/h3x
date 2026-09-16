//! Table storage and received updates, RFC 9204 section 3.2.
//! Each codec direction owns its own table. apply() enforces storage/wire validity;
//! Encoder additionally validates pinned entries before any mutation.
use std::collections::VecDeque;

use bytes::Bytes;
use qbase::varint::VARINT_MAX;

use super::{Field, codec::instruction::EncoderInstruction};
use crate::{ErrorCode, Result};

#[derive(Clone, Default)]
pub(super) struct DynamicTable {
    entries: VecDeque<Field>,
    /// Current table size in bytes: sum of each entry's uncompressed name/value
    /// lengths plus 32 bytes. Protocol accounting, not heap usage (section 3.2.1).
    size: u64,
    /// Current byte limit selected by the encoder via Set Dynamic Table Capacity;
    /// initially 0. Always size <= capacity <= max_capacity (section 3.2.2).
    capacity: u64,
    /// Byte ceiling advertised by the decoder in SETTINGS_QPACK_MAX_TABLE_CAPACITY;
    /// limits the capacity the encoder may select (section 3.2.3).
    max_capacity: u64,
    /// Cumulative insertions, including Duplicate; never decreases on eviction.
    /// Also the next entry's absolute index, not the current entry count (section 3.2.4).
    insert_count: u64,
}

impl DynamicTable {
    pub(super) fn new(max_capacity: u64) -> Result<Self> {
        if max_capacity > VARINT_MAX {
            return Err(ErrorCode::H3_SETTINGS_ERROR
                .with_reason("QPACK table capacity exceeds the QUIC variable-integer range"));
        }
        Ok(Self {
            max_capacity,
            ..Self::default()
        })
    }

    pub(super) fn insert_count(&self) -> u64 {
        self.insert_count
    }

    pub(super) fn capacity(&self) -> u64 {
        self.capacity
    }

    pub(super) fn max_capacity(&self) -> u64 {
        self.max_capacity
    }

    /// Update the peer-advertised maximum without eviction or resetting insert_count.
    /// Reject values outside 62 bits or below the current capacity.
    pub(super) fn set_max_capacity(&mut self, max_capacity: u64) -> Result<()> {
        if max_capacity > VARINT_MAX || max_capacity < self.capacity {
            return Err(ErrorCode::H3_SETTINGS_ERROR.with_reason(
                "QPACK maximum capacity is out of range or below the current capacity",
            ));
        }
        self.max_capacity = max_capacity;
        Ok(())
    }

    /// First retained absolute index; equals insert_count when the table is empty.
    pub(super) fn oldest_index(&self) -> u64 {
        self.insert_count - self.entries.len() as u64
    }

    /// Newest exact match's absolute index; caller still checks can_reference.
    pub(super) fn find_index(&self, name: &[u8], value: &[u8]) -> Option<u64> {
        self.entries
            .iter()
            .rposition(|entry| entry.name == name && entry.value == value)
            .map(|index| self.oldest_index() + index as u64)
    }

    /// Newest name match's absolute index; caller still checks can_reference.
    pub(super) fn find_name(&self, name: &[u8]) -> Option<u64> {
        self.entries
            .iter()
            .rposition(|entry| entry.name == name)
            .map(|index| self.oldest_index() + index as u64)
    }

    fn evict_to(&mut self, size: u64) {
        while self.size > size {
            let entry = self.entries.pop_front().unwrap();
            self.size -= entry.name.len() as u64 + entry.value.len() as u64 + 32;
        }
    }

    pub(super) fn get(&self, absolute: u64) -> Option<&Field> {
        let oldest = self.oldest_index();
        self.entries
            .get(usize::try_from(absolute.checked_sub(oldest)?).ok()?)
    }

    fn relative(&self, index: u64) -> Result<Field> {
        self.insert_count
            .checked_sub(index)
            .and_then(|v| v.checked_sub(1))
            .and_then(|id| self.get(id))
            .cloned()
            .ok_or_else(|| {
                ErrorCode::QPACK_ENCODER_STREAM_ERROR
                    .with_reason("dynamic table index is missing or has been evicted")
            })
    }

    pub(super) fn apply(&mut self, instruction: EncoderInstruction) -> Result<()> {
        let entry = match instruction {
            EncoderInstruction::SetDynamicTableCapacity(capacity) => {
                if capacity > self.max_capacity {
                    return Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR
                        .with_reason("dynamic table capacity exceeds the advertised maximum"));
                }
                self.evict_to(capacity);
                self.capacity = capacity;
                return Ok(());
            }
            EncoderInstruction::InsertWithLiteralName { name, value } => Field {
                name,
                value,
                never_index: false,
            },
            EncoderInstruction::InsertWithNameReference {
                static_table: is_static,
                index,
                value,
            } => {
                let name = if is_static {
                    Bytes::from_static(
                        get(index)
                            .ok_or_else(|| {
                                ErrorCode::QPACK_ENCODER_STREAM_ERROR
                                    .with_reason("static name index is out of range")
                            })?
                            .0
                            .as_bytes(),
                    )
                } else {
                    self.relative(index)?.name
                };
                Field {
                    name,
                    value,
                    never_index: false,
                }
            }
            EncoderInstruction::Duplicate(index) => self.relative(index)?,
        };
        let size = entry.name.len() as u64 + entry.value.len() as u64 + 32;
        if size > self.capacity || self.insert_count == VARINT_MAX {
            return Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR
                .with_reason("entry exceeds table capacity or insert count is exhausted"));
        }
        self.evict_to(self.capacity - size);
        self.entries.push_back(entry);
        self.size += size;
        self.insert_count += 1;
        Ok(())
    }
}

// RFC 9204 Appendix A. Array positions are wire indices.
pub(super) const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

// Appendix C: staticTable.findIndex and staticTable.findName.
//  scan 99 entries; add an index only if profiling warrants it.
pub(super) fn find_index(name: &[u8], value: &[u8]) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|&(n, v)| n.as_bytes() == name && v.as_bytes() == value)
}

pub(super) fn find_name(name: &[u8]) -> Option<usize> {
    STATIC_TABLE.iter().position(|&(n, _)| n.as_bytes() == name)
}

pub(super) fn get(index: u64) -> Option<(&'static str, &'static str)> {
    STATIC_TABLE.get(usize::try_from(index).ok()?).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_insert_duplicate_and_eviction() {
        let mut table = DynamicTable::new(68).unwrap();
        let insert = EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x"),
            value: Bytes::from_static(b"y"),
        };
        assert_eq!(table.capacity, 0);
        assert_eq!(
            (table.apply(insert.clone())).map_err(ErrorCode::from),
            Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
        );
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(68))
            .unwrap();
        table.apply(insert).unwrap();
        table.apply(EncoderInstruction::Duplicate(0)).unwrap();
        assert_eq!(
            (table.size, table.insert_count, table.entries.len()),
            (68, 2, 2)
        );
        table
            .apply(EncoderInstruction::InsertWithNameReference {
                static_table: false,
                index: 0,
                value: Bytes::from_static(b"z"),
            })
            .unwrap();
        assert!(table.get(0).is_none());
        assert_eq!(table.get(2).unwrap().value, "z");
        assert_eq!((table.size, table.insert_count), (68, 3));
        assert_eq!(
            (table.apply(EncoderInstruction::Duplicate(2))).map_err(ErrorCode::from),
            Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
        );
        assert_eq!(
            (table.apply(EncoderInstruction::SetDynamicTableCapacity(69))).map_err(ErrorCode::from),
            Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
        );
        assert_eq!(
            (table.capacity, table.size, table.insert_count),
            (68, 68, 3)
        );
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(34))
            .unwrap();
        assert!(table.get(1).is_none());
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(0))
            .unwrap();
        assert!(table.entries.is_empty());
        assert_eq!(
            (table.size, table.insert_count, table.max_capacity),
            (0, 3, 68)
        );
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(68))
            .unwrap();
        table
            .apply(EncoderInstruction::InsertWithNameReference {
                static_table: true,
                index: 0,
                value: Bytes::new(),
            })
            .unwrap();
        assert_eq!(table.get(3).unwrap().name, ":authority");
        assert_eq!(table.size, 42);
        assert!(DynamicTable::new(VARINT_MAX + 1).is_err());
    }

    #[test]
    fn rejected_updates_preserve_entries_and_capacity() {
        let mut table = DynamicTable::new(68).unwrap();
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(68))
            .unwrap();
        table
            .apply(EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from_static(b"y"),
            })
            .unwrap();
        for instruction in [
            EncoderInstruction::SetDynamicTableCapacity(69),
            EncoderInstruction::Duplicate(1),
            EncoderInstruction::InsertWithNameReference {
                static_table: true,
                index: 99,
                value: Bytes::new(),
            },
            EncoderInstruction::InsertWithNameReference {
                static_table: false,
                index: 1,
                value: Bytes::new(),
            },
            EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from(vec![0; 36]),
            },
        ] {
            assert_eq!(
                (table.apply(instruction)).map_err(ErrorCode::from),
                Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
            );
            assert_eq!(
                (table.capacity(), table.size(), table.insert_count()),
                (68, 34, 1)
            );
            assert_eq!(table.get(0).unwrap().value, "y");
        }
        for maximum in [67, VARINT_MAX + 1] {
            assert_eq!(
                (table.set_max_capacity(maximum)).map_err(ErrorCode::from),
                Err(ErrorCode::H3_SETTINGS_ERROR)
            );
            assert_eq!(table.max_capacity(), 68);
        }
        table.set_max_capacity(128).unwrap();
        assert_eq!(
            (table.capacity(), table.size(), table.insert_count()),
            (68, 34, 1)
        );
        assert_eq!(table.max_capacity(), 128);
    }

    #[test]
    fn lookups_prefer_newest_retained_match_and_survive_clear() {
        let mut table = DynamicTable::new(68).unwrap();
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(68))
            .unwrap();
        for value in [b"a", b"a", b"b"] {
            table
                .apply(EncoderInstruction::InsertWithLiteralName {
                    name: Bytes::from_static(b"x"),
                    value: Bytes::from_static(value),
                })
                .unwrap();
        }
        assert_eq!(table.oldest_index(), 1);
        assert_eq!(table.find_index(b"x", b"a"), Some(1));
        assert_eq!(table.find_name(b"x"), Some(2));
        assert_eq!(table.find_name(b"missing"), None);
        assert!(table.get(0).is_none());
        assert!(table.get(3).is_none());
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(0))
            .unwrap();
        assert_eq!(table.oldest_index(), 3);
        assert_eq!(table.find_name(b"x"), None);
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(68))
            .unwrap();
        table
            .apply(EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from_static(b"c"),
            })
            .unwrap();
        assert_eq!(table.find_index(b"x", b"c"), Some(3));
    }

    #[test]
    fn insertion_count_overflow_does_not_evict_existing_entry() {
        let mut table = DynamicTable::new(34).unwrap();
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(34))
            .unwrap();
        table
            .apply(EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from_static(b"y"),
            })
            .unwrap();
        table.insert_count = VARINT_MAX;
        assert_eq!(
            (table.apply(EncoderInstruction::Duplicate(0))).map_err(ErrorCode::from),
            Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
        );
        assert_eq!(table.insert_count(), VARINT_MAX);
        assert_eq!(table.size(), 34);
        assert_eq!(table.get(VARINT_MAX - 1).unwrap().value, "y");
    }

    impl DynamicTable {
        pub(in crate::protocol::qpack) fn size(&self) -> u64 {
            self.size
        }
    }
}
