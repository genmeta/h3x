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
        self.entries.get((index - self.dropped_count) as usize)
    }

    pub fn get_mut(&mut self, index: u64) -> Option<&mut FieldLine> {
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
