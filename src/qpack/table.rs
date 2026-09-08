use std::collections::VecDeque;

use super::Field;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TableError {
    CapacityExceeded,
    EntryTooLarge,
    InvalidIndex,
}

#[derive(Debug, Clone)]
struct Entry {
    field: Field,
    references: usize,
}

impl Entry {
    fn size(&self) -> u64 {
        self.field.name.len() as u64 + self.field.value.len() as u64 + 32
    }
}

/// A QPACK dynamic table indexed by the absolute insertion index from RFC 9204.
#[derive(Debug)]
pub(super) struct Table {
    max_capacity: u64,
    capacity: u64,
    size: u64,
    insert_count: u64,
    dropped_count: u64,
    entries: VecDeque<Entry>,
}

impl Table {
    pub(super) const fn new(max_capacity: u64) -> Self {
        Self {
            max_capacity,
            capacity: 0,
            size: 0,
            insert_count: 0,
            dropped_count: 0,
            entries: VecDeque::new(),
        }
    }

    pub(super) const fn max_capacity(&self) -> u64 {
        self.max_capacity
    }

    pub(super) fn set_max_capacity(&mut self, max_capacity: u64) -> Result<(), TableError> {
        if self.capacity > max_capacity {
            return Err(TableError::CapacityExceeded);
        }
        self.max_capacity = max_capacity;
        Ok(())
    }

    pub(super) const fn capacity(&self) -> u64 {
        self.capacity
    }

    pub(super) const fn insert_count(&self) -> u64 {
        self.insert_count
    }

    pub(super) const fn max_entries(&self) -> u64 {
        self.max_capacity / 32
    }

    pub(super) fn set_capacity(&mut self, capacity: u64) -> Result<(), TableError> {
        if capacity > self.max_capacity {
            return Err(TableError::CapacityExceeded);
        }
        self.capacity = capacity;
        while self.size > capacity {
            self.evict_oldest();
        }
        Ok(())
    }

    pub(super) fn get(&self, absolute: u64) -> Option<&Field> {
        let offset = absolute.checked_sub(self.dropped_count)?;
        self.entries
            .get(usize::try_from(offset).ok()?)
            .map(|entry| &entry.field)
    }

    pub(super) fn newest_exact(&self, field: &Field) -> Option<u64> {
        self.entries
            .iter()
            .enumerate()
            .rev()
            .find(|(_, entry)| entry.field == *field)
            .map(|(offset, _)| self.dropped_count + offset as u64)
    }

    pub(super) fn newest_exact_before(&self, field: &Field, exclusive: u64) -> Option<u64> {
        self.entries
            .iter()
            .enumerate()
            .rev()
            .map(|(offset, entry)| (self.dropped_count + offset as u64, entry))
            .find(|(absolute, entry)| *absolute < exclusive && entry.field == *field)
            .map(|(absolute, _)| absolute)
    }

    pub(super) fn newest_name(&self, name: &[u8]) -> Option<u64> {
        self.entries
            .iter()
            .enumerate()
            .rev()
            .find(|(_, entry)| entry.field.name.as_ref() == name)
            .map(|(offset, _)| self.dropped_count + offset as u64)
    }

    pub(super) fn newest_name_before(&self, name: &[u8], exclusive: u64) -> Option<u64> {
        self.entries
            .iter()
            .enumerate()
            .rev()
            .map(|(offset, entry)| (self.dropped_count + offset as u64, entry))
            .find(|(absolute, entry)| *absolute < exclusive && entry.field.name.as_ref() == name)
            .map(|(absolute, _)| absolute)
    }

    pub(super) fn insert_decoder(&mut self, field: Field) -> Result<u64, TableError> {
        let size = field_size(&field);
        if size > self.capacity {
            return Err(TableError::EntryTooLarge);
        }
        while self.size > self.capacity - size {
            self.evict_oldest();
        }
        Ok(self.insert(field))
    }

    /// Inserts without evicting an unacknowledged or referenced entry.
    ///
    /// Returning `None` is an encoding choice, not a protocol failure; the
    /// caller falls back to a literal field representation.
    pub(super) fn insert_encoder(
        &mut self,
        field: Field,
        known_received_count: u64,
    ) -> Option<u64> {
        let size = field_size(&field);
        if size > self.capacity {
            return None;
        }
        while self.size > self.capacity - size {
            let oldest_absolute = self.dropped_count;
            let oldest = self.entries.front()?;
            if oldest_absolute >= known_received_count || oldest.references != 0 {
                return None;
            }
            self.evict_oldest();
        }
        Some(self.insert(field))
    }

    pub(super) fn add_reference(&mut self, absolute: u64) -> Result<(), TableError> {
        let entry = self
            .get_entry_mut(absolute)
            .ok_or(TableError::InvalidIndex)?;
        entry.references = entry
            .references
            .checked_add(1)
            .ok_or(TableError::InvalidIndex)?;
        Ok(())
    }

    pub(super) fn remove_reference(&mut self, absolute: u64) -> Result<(), TableError> {
        let entry = self
            .get_entry_mut(absolute)
            .ok_or(TableError::InvalidIndex)?;
        entry.references = entry
            .references
            .checked_sub(1)
            .ok_or(TableError::InvalidIndex)?;
        Ok(())
    }

    pub(super) fn encoder_relative(&self, absolute: u64) -> Result<u64, TableError> {
        self.insert_count
            .checked_sub(absolute)
            .and_then(|distance| distance.checked_sub(1))
            .ok_or(TableError::InvalidIndex)
    }

    pub(super) fn resolve_encoder_relative(&self, relative: u64) -> Result<u64, TableError> {
        self.insert_count
            .checked_sub(relative)
            .and_then(|absolute| absolute.checked_sub(1))
            .filter(|absolute| self.get(*absolute).is_some())
            .ok_or(TableError::InvalidIndex)
    }

    fn insert(&mut self, field: Field) -> u64 {
        let absolute = self.insert_count;
        let entry = Entry {
            field,
            references: 0,
        };
        self.size += entry.size();
        self.entries.push_back(entry);
        self.insert_count += 1;
        absolute
    }

    fn get_entry_mut(&mut self, absolute: u64) -> Option<&mut Entry> {
        let offset = absolute.checked_sub(self.dropped_count)?;
        self.entries.get_mut(usize::try_from(offset).ok()?)
    }

    fn evict_oldest(&mut self) {
        if let Some(entry) = self.entries.pop_front() {
            self.size -= entry.size();
            self.dropped_count += 1;
        }
    }
}

fn field_size(field: &Field) -> u64 {
    field.name.len() as u64 + field.value.len() as u64 + 32
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn field(name: &'static [u8], value: &'static [u8]) -> Field {
        Field {
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
        }
    }

    #[test]
    fn decoder_table_evicts_in_fifo_order() {
        let mut table = Table::new(96);
        table.set_capacity(96).unwrap();
        let first = table.insert_decoder(field(b"a", b"1")).unwrap();
        let second = table.insert_decoder(field(b"b", b"2")).unwrap();
        table.insert_decoder(field(b"c", b"3")).unwrap();

        assert!(table.get(first).is_none());
        assert_eq!(table.get(second), Some(&field(b"b", b"2")));
    }

    #[test]
    fn encoder_does_not_evict_unacknowledged_or_referenced_entries() {
        let mut table = Table::new(34);
        table.set_capacity(34).unwrap();
        let first = table.insert_encoder(field(b"a", b"1"), 0).unwrap();

        assert!(table.insert_encoder(field(b"b", b"2"), 0).is_none());
        table.add_reference(first).unwrap();
        assert!(table.insert_encoder(field(b"b", b"2"), 1).is_none());
        table.remove_reference(first).unwrap();
        assert!(table.insert_encoder(field(b"b", b"2"), 1).is_some());
    }

    #[test]
    fn encoder_relative_indices_follow_the_current_insert_count() {
        let mut table = Table::new(256);
        table.set_capacity(256).unwrap();
        let first = table.insert_decoder(field(b"a", b"1")).unwrap();
        let second = table.insert_decoder(field(b"b", b"2")).unwrap();

        assert_eq!(table.encoder_relative(second), Ok(0));
        assert_eq!(table.encoder_relative(first), Ok(1));
        assert_eq!(table.resolve_encoder_relative(0), Ok(second));
        assert_eq!(table.resolve_encoder_relative(1), Ok(first));
    }
}
