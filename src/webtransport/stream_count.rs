use std::{convert::Infallible, io};

use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    buflist::BufList,
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    varint::VarInt,
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WebTransportStreamCount(VarInt);

impl WebTransportStreamCount {
    pub const ZERO: Self = Self(VarInt::from_u32(0));
    pub const MAX_VALUE: VarInt = match VarInt::from_u64(0x0fff_ffff_ffff_ffff) {
        Ok(value) => value,
        Err(_) => panic!("2^60 - 1 is a valid QUIC varint"),
    };

    pub const fn into_varint(self) -> VarInt {
        self.0
    }

    pub fn checked_increment(self) -> Result<Self, InvalidWebTransportStreamCount> {
        let next = VarInt::from_u64(self.0.into_inner() + 1)
            .expect("a valid webtransport stream count increment is a valid QUIC varint");
        Self::try_from(next)
    }
}

impl TryFrom<VarInt> for WebTransportStreamCount {
    type Error = InvalidWebTransportStreamCount;

    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        if value <= Self::MAX_VALUE {
            Ok(Self(value))
        } else {
            Err(InvalidWebTransportStreamCount { value })
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
#[snafu(display("webtransport stream count {value} exceeds 2^60 - 1"))]
pub struct InvalidWebTransportStreamCount {
    value: VarInt,
}

impl InvalidWebTransportStreamCount {
    pub const fn value(&self) -> VarInt {
        self.value
    }
}

#[derive(Debug, Snafu)]
#[snafu(module(decode_webtransport_stream_count_error), visibility(pub(super)))]
pub enum DecodeWebTransportStreamCountError {
    #[snafu(display("failed to decode webtransport stream count"))]
    Decode { source: io::Error },
    #[snafu(display("invalid webtransport stream count"))]
    Invalid {
        source: InvalidWebTransportStreamCount,
    },
}

impl<S> DecodeFrom<S> for WebTransportStreamCount
where
    S: AsyncRead + Unpin + Send,
{
    type Error = DecodeWebTransportStreamCountError;

    async fn decode_from(mut stream: S) -> Result<Self, Self::Error> {
        let value = stream
            .decode_one::<VarInt>()
            .await
            .context(decode_webtransport_stream_count_error::DecodeSnafu)?;
        Self::try_from(value).context(decode_webtransport_stream_count_error::InvalidSnafu)
    }
}

impl<'s, S> EncodeInto<&'s mut S> for WebTransportStreamCount
where
    S: AsyncWrite + Unpin + Send,
{
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: &'s mut S) -> Result<Self::Output, Self::Error> {
        self.into_varint().encode_into(stream).await
    }
}

impl EncodeInto<BufList> for WebTransportStreamCount {
    type Output = BufList;
    type Error = Infallible;

    async fn encode_into(self, mut stream: BufList) -> Result<Self::Output, Self::Error> {
        stream
            .encode_one(self)
            .await
            .expect("encoding a webtransport stream count into a BufList is infallible");
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_count_accepts_webtransport_boundaries() {
        let zero = WebTransportStreamCount::try_from(VarInt::from_u32(0)).expect("zero");
        assert_eq!(zero.into_varint(), VarInt::from_u32(0));

        let max =
            WebTransportStreamCount::try_from(WebTransportStreamCount::MAX_VALUE).expect("max");
        assert_eq!(max.into_varint(), WebTransportStreamCount::MAX_VALUE);
    }

    #[test]
    fn stream_count_rejects_above_webtransport_limit() {
        let value = VarInt::from_u64(1 << 60).expect("valid varint");
        let error = WebTransportStreamCount::try_from(value).expect_err("above stream-count limit");

        assert_eq!(error.value(), value);
    }

    #[test]
    fn checked_increment_preserves_varint_domain() {
        let count = WebTransportStreamCount::try_from(VarInt::from_u32(7)).expect("count");
        assert_eq!(
            count.checked_increment().expect("increment").into_varint(),
            VarInt::from_u32(8)
        );
    }
}
