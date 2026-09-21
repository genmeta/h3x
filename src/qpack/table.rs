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
            return Err(ErrorCode::SettingsError
                .reason("QPACK table capacity exceeds the QUIC variable-integer range"));
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
            return Err(ErrorCode::SettingsError
                .reason("QPACK maximum capacity is out of range or below the current capacity"));
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
                ErrorCode::QpackEncoderStreamError
                    .reason("dynamic table index is missing or has been evicted")
            })
    }

    pub(super) fn apply(&mut self, instruction: EncoderInstruction) -> Result<()> {
        let entry = match instruction {
            EncoderInstruction::SetDynamicTableCapacity(capacity) => {
                if capacity > self.max_capacity {
                    return Err(ErrorCode::QpackEncoderStreamError
                        .reason("dynamic table capacity exceeds the advertised maximum"));
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
                                ErrorCode::QpackEncoderStreamError
                                    .reason("static name index is out of range")
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
            return Err(ErrorCode::QpackEncoderStreamError
                .reason("entry exceeds table capacity or insert count is exhausted"));
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

    fn insert(name: &'static [u8], value: &'static [u8]) -> EncoderInstruction {
        EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
        }
    }

    #[test]
    fn dynamic_table_inserts_evicts_and_keeps_absolute_indices() {
        let mut table = DynamicTable::new(69).unwrap();
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(69))
            .unwrap();
        table.apply(insert(b"a", b"1")).unwrap();
        assert_eq!(table.insert_count(), 1);
        assert_eq!(table.oldest_index(), 0);
        assert_eq!(table.find_index(b"a", b"1"), Some(0));

        table.apply(insert(b"bb", b"22")).unwrap();
        assert_eq!(table.insert_count(), 2);
        assert_eq!(table.oldest_index(), 1);
        assert!(table.get(0).is_none());
        assert_eq!(table.find_name(b"bb"), Some(1));
    }

    #[test]
    fn duplicate_uses_relative_index_and_capacity_limits_are_enforced() {
        let mut table = DynamicTable::new(128).unwrap();
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(128))
            .unwrap();
        table.apply(insert(b"name", b"value")).unwrap();
        table.apply(EncoderInstruction::Duplicate(0)).unwrap();
        assert_eq!(table.insert_count(), 2);
        assert_eq!(table.find_index(b"name", b"value"), Some(1));

        assert_eq!(
            table
                .apply(EncoderInstruction::Duplicate(2))
                .unwrap_err()
                .code,
            ErrorCode::QpackEncoderStreamError
        );
        assert_eq!(
            table
                .apply(EncoderInstruction::SetDynamicTableCapacity(129))
                .unwrap_err()
                .code,
            ErrorCode::QpackEncoderStreamError
        );
        assert_eq!(table.capacity(), 128);
    }

    #[test]
    fn static_table_lookup_prefers_first_wire_index() {
        assert_eq!(find_index(b":method", b"GET"), Some(17));
        assert_eq!(find_name(b"content-type"), Some(44));
        assert_eq!(get(98), Some(("x-frame-options", "sameorigin")));
        assert_eq!(get(99), None);
    }

    #[test]
    fn rejects_invalid_capacities_and_references() {
        let Err(error) = DynamicTable::new(VARINT_MAX + 1) else {
            panic!("capacity beyond the variable-integer range must fail")
        };
        assert_eq!(error.code, ErrorCode::SettingsError);

        let mut table = DynamicTable::new(64).unwrap();
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(40))
            .unwrap();
        assert_eq!(
            table.set_max_capacity(39).unwrap_err().code,
            ErrorCode::SettingsError
        );
        assert_eq!(
            table.set_max_capacity(VARINT_MAX + 1).unwrap_err().code,
            ErrorCode::SettingsError
        );
        table.set_max_capacity(80).unwrap();
        assert_eq!(table.max_capacity(), 80);

        assert_eq!(
            table
                .apply(insert(b"too-large", b"value"))
                .unwrap_err()
                .code,
            ErrorCode::QpackEncoderStreamError
        );
        assert_eq!(
            table
                .apply(EncoderInstruction::InsertWithNameReference {
                    static_table: true,
                    index: 99,
                    value: Bytes::new(),
                })
                .unwrap_err()
                .code,
            ErrorCode::QpackEncoderStreamError
        );
        assert_eq!(get(u64::MAX), None);
    }
}
