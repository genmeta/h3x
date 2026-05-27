use std::collections::VecDeque;

use crate::qpack::field::FieldLine;

#[derive(Debug)]
pub struct DynamicTable {
    pub(crate) inserted_count: u64,
    pub(crate) dropped_count: u64,
    pub(crate) known_received_count: u64,

    pub(crate) entries: VecDeque<FieldLine>,
    /// The size of the dynamic table is the sum of the size of its entries.
    // assert_eq!(size, entries.iter().map(Entry::size).sum())
    pub(crate) size: u64,
    pub(crate) capacity: u64,
}

impl Default for DynamicTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicTable {
    pub const fn new() -> Self {
        Self {
            inserted_count: 0,
            dropped_count: 0,
            known_received_count: 0,
            entries: VecDeque::new(),
            size: 0,
            capacity: 0,
        }
    }

    pub fn get(&self, index: u64) -> Option<&FieldLine> {
        if index < self.dropped_count {
            return None;
        }
        self.entries.get((index - self.dropped_count) as usize)
    }

    pub fn get_mut(&mut self, index: u64) -> Option<&mut FieldLine> {
        if index < self.dropped_count {
            return None;
        }
        self.entries.get_mut((index - self.dropped_count) as usize)
    }

    pub fn index(&mut self, field_line: FieldLine) -> u64 {
        let absolute_index = self.inserted_count;
        self.size += field_line.size();
        assert!(
            self.size <= self.capacity,
            "Dynamic table size exceeded its capacity"
        );
        self.entries.push_back(field_line);
        self.inserted_count += 1;

        absolute_index
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn evictable(&self) -> bool {
        self.entries.front().is_some() && self.dropped_count < self.known_received_count
    }

    pub fn evict(&mut self) -> (u64, FieldLine) {
        assert!(self.evictable(), "No evictable entry exist");
        let absolute_index = self.dropped_count;
        let entry = self.entries.pop_front().expect("no entry exists");
        self.size -= entry.size();
        self.dropped_count += 1;

        (absolute_index, entry)
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = (u64, &FieldLine)> {
        self.entries
            .iter()
            .enumerate()
            .map(|(offset, entry)| (self.dropped_count + offset as u64, entry))
    }

    pub fn increment_known_received_count(&mut self, increment: u64) {
        self.known_received_count += increment;
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::DynamicTable;
    use crate::qpack::field::FieldLine;

    fn field_line(name: &'static [u8], value: &'static [u8]) -> FieldLine {
        FieldLine {
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
        }
    }

    #[test]
    fn get_and_get_mut_respect_dropped_count() {
        let mut table = DynamicTable::new();
        table.capacity = 128;
        table.index(field_line(b"header-1", b"value-1"));
        table.index(field_line(b"header-2", b"value-2"));
        table.increment_known_received_count(1);

        let (evicted_index, evicted) = table.evict();
        assert_eq!(evicted_index, 0);
        assert_eq!(evicted.name, Bytes::from_static(b"header-1"));
        assert!(table.get(0).is_none());

        let entry = table.get_mut(1).expect("second entry should remain");
        entry.value = Bytes::from_static(b"updated");
        assert_eq!(
            table.get(1).expect("updated entry should exist").value,
            Bytes::from_static(b"updated")
        );
    }

    #[test]
    fn evictable_depends_on_known_received_count() {
        let mut table = DynamicTable::new();
        table.capacity = 64;
        table.index(field_line(b"header-1", b"value-1"));

        assert!(
            !table.evictable(),
            "unacknowledged entry must not be evictable"
        );

        table.increment_known_received_count(1);
        assert!(
            table.evictable(),
            "acknowledged entry should become evictable"
        );
    }

    #[test]
    fn entries_preserve_absolute_indices_after_eviction() {
        let mut table = DynamicTable::new();
        table.capacity = 192;
        table.index(field_line(b"header-1", b"value-1"));
        table.index(field_line(b"header-2", b"value-2"));
        table.index(field_line(b"header-3", b"value-3"));
        table.increment_known_received_count(2);
        table.evict();

        let entries = table
            .entries()
            .map(|(index, entry)| (index, entry.name.clone()))
            .collect::<Vec<_>>();

        assert_eq!(
            entries,
            vec![
                (1, Bytes::from_static(b"header-2")),
                (2, Bytes::from_static(b"header-3")),
            ]
        );
    }

    #[test]
    fn evict_updates_size_and_counts() {
        let mut table = DynamicTable::new();
        let entry = field_line(b"header-1", b"value-1");
        let entry_size = entry.size();
        table.capacity = entry_size;
        table.index(entry);
        table.increment_known_received_count(1);

        let (index, _) = table.evict();

        assert_eq!(index, 0);
        assert_eq!(table.size, 0);
        assert_eq!(table.dropped_count, 1);
        assert!(table.is_empty());
    }

    #[test]
    fn increment_known_received_count_accumulates() {
        let mut table = DynamicTable::new();
        table.increment_known_received_count(2);
        table.increment_known_received_count(3);
        assert_eq!(table.known_received_count, 5);
    }

    #[test]
    fn default_matches_new_empty_table() {
        let table = DynamicTable::default();

        assert_eq!(table.inserted_count, 0);
        assert_eq!(table.dropped_count, 0);
        assert_eq!(table.known_received_count, 0);
        assert_eq!(table.size, 0);
        assert_eq!(table.capacity, 0);
        assert!(table.is_empty());
        assert_eq!(table.entries().len(), 0);
    }

    #[test]
    fn get_mut_returns_none_for_evicted_absolute_index() {
        let mut table = DynamicTable::new();
        table.capacity = 128;
        table.index(field_line(b"header-1", b"value-1"));
        table.index(field_line(b"header-2", b"value-2"));
        table.increment_known_received_count(1);
        table.evict();

        assert!(table.get_mut(0).is_none());
        assert!(table.get_mut(1).is_some());
    }

    #[test]
    #[should_panic(expected = "No evictable entry exist")]
    fn evict_panics_when_no_entry_is_acknowledged() {
        let mut table = DynamicTable::new();
        table.capacity = 64;
        table.index(field_line(b"header-1", b"value-1"));

        table.evict();
    }

    #[test]
    #[should_panic(expected = "Dynamic table size exceeded its capacity")]
    fn index_panics_when_capacity_is_exceeded() {
        let mut table = DynamicTable::new();
        table.capacity = 10;
        table.index(field_line(b"header-1", b"value-1"));
    }
}
