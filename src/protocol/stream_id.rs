pub use qbase::sid::StreamId;
use qbase::varint::VarInt;

use crate::Error;

pub(crate) const MAX_VARINT: u64 = qbase::varint::VARINT_MAX;

pub(crate) trait StreamIdExt {
    fn as_u64(&self) -> u64;
}

impl StreamIdExt for StreamId {
    fn as_u64(&self) -> u64 {
        (*self).into()
    }
}

pub(crate) fn try_from_u64(value: u64) -> Result<StreamId, Error> {
    VarInt::try_from(value)
        .map(StreamId::from)
        .map_err(|_| Error::invalid_stream_id(value))
}

pub(crate) fn from_u64_unchecked(value: u64) -> StreamId {
    StreamId::from(VarInt::try_from(value).expect("stream ID fits a QUIC varint"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_full_quic_varint_range() {
        let id = try_from_u64(MAX_VARINT).expect("maximum QUIC varint is valid");

        assert_eq!(u64::from(id), MAX_VARINT);
    }

    #[test]
    fn rejects_values_outside_the_quic_varint_range() {
        let error = try_from_u64(MAX_VARINT + 1).expect_err("value is out of range");

        assert!(matches!(&error, crate::Error::InvalidMessage { .. }));
        assert_eq!(error.code(), None);
    }
}
