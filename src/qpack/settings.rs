#[derive(Default, Debug, Clone, Copy)]
pub struct Settings {
    /// To bound the memory requirements of the decoder, the decoder limits
    /// the maximum value the encoder is permitted to set for the dynamic
    /// table capacity. In HTTP/3, this limit is determined by the value of
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY sent by the decoder; see Section 5.
    /// The encoder MUST NOT set a dynamic table capacity that exceeds this
    /// maximum, but it can choose to use a lower dynamic table capacity; see
    /// Section 4.3.1.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-3.2.3-1
    max_table_capacity: u64,
    /// The decoder specifies an upper bound on the number of streams that
    /// can be blocked using the SETTINGS_QPACK_BLOCKED_STREAMS setting; see
    /// Section 5. An encoder MUST limit the number of streams that could
    /// become blocked to the value of SETTINGS_QPACK_BLOCKED_STREAMS at all
    /// times. If a decoder encounters more blocked streams than it promised
    /// to support, it MUST treat this as a connection error of type
    /// QPACK_DECOMPRESSION_FAILED.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-2.1.2-4
    blocked_streams: u64,
}

impl Settings {
    pub const fn new(max_table_capacity: u64, blocked_streams: u64) -> Self {
        Self {
            max_table_capacity,
            blocked_streams,
        }
    }

    pub const fn max_table_capacity(&self) -> u64 {
        self.max_table_capacity
    }

    pub const fn blocked_streams(&self) -> u64 {
        self.blocked_streams
    }
}
