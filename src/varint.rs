use std::{cmp::Ordering, convert::TryFrom, fmt, pin::pin};

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::{DecodeFrom, EncodeInto};

/// An integer less than 2^62
///
/// Values of this type are suitable for encoding as QUIC variable-length integer.
/// It would be neat if we could express to Rust that the top two bits are available for use as enum
/// discriminants
///
/// See [variable-length integers](https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VarInt(u64);

/// The maximum value that can be represented by a QUIC variable-length integer.
pub const VARINT_MAX: u64 = 0x3fff_ffff_ffff_ffff;

/// The number of bytes that a QUIC variable-length integer can be encoded in.
///
/// [`VarInt`] doesn't need to be encoded on the minimum number of bytes necessary,
/// with the sole exception of the Frame Type field.
pub enum EncodeBytes {
    One = 1,
    Two = 2,
    Four = 4,
    Eight = 8,
}

impl VarInt {
    /// The largest representable value
    pub const MAX: Self = Self(VARINT_MAX);
    /// The largest encoded value length
    pub const MAX_SIZE: usize = 8;

    /// Construct a `VarInt` from a [`u32`].
    pub const fn from_u32(x: u32) -> Self {
        Self(x as u64)
    }

    /// Construct a `VarInt` from a [`u64`].
    /// Succeeds if `x` < 2^62.
    pub const fn from_u64(value: u64) -> Result<Self, err::Overflow> {
        if value <= VARINT_MAX {
            Ok(Self(value))
        } else {
            Err(err::Overflow { value: value as _ })
        }
    }

    /// Create a VarInt from a [`u64`] without ensuring it's in range
    ///
    /// # Safety
    ///
    /// `x` must be less than 2^62.
    pub unsafe fn from_u64_unchecked(x: u64) -> Self {
        Self(x)
    }

    /// Construct a `VarInt` from a [`u128`].
    /// Succeeds if `x` < 2^62.
    pub fn from_u128(value: u128) -> Result<Self, err::Overflow> {
        if value <= VARINT_MAX as u128 {
            Ok(Self(value as _))
        } else {
            Err(err::Overflow { value })
        }
    }

    /// Extract the integer value
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Compute the number of bytes needed to encode this value
    pub fn encoding_size(self) -> usize {
        let x = self.0;
        if x < (1 << 6) {
            1
        } else if x < (1 << 14) {
            2
        } else if x < (1 << 30) {
            4
        } else if x < (1 << 62) {
            8
        } else {
            unreachable!("malformed VarInt");
        }
    }
}

impl From<VarInt> for u64 {
    fn from(x: VarInt) -> Self {
        x.0
    }
}

impl From<u8> for VarInt {
    fn from(x: u8) -> Self {
        Self(x.into())
    }
}

impl From<u16> for VarInt {
    fn from(x: u16) -> Self {
        Self(x.into())
    }
}

impl From<u32> for VarInt {
    fn from(x: u32) -> Self {
        Self(x.into())
    }
}

impl TryFrom<u128> for VarInt {
    type Error = err::Overflow;

    fn try_from(x: u128) -> Result<Self, Self::Error> {
        Self::from_u128(x)
    }
}

impl TryFrom<u64> for VarInt {
    type Error = err::Overflow;

    /// Succeeds if `x` < 2^62
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        Self::from_u64(x)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = err::Overflow;

    /// Succeeds if `x` < 2^62
    fn try_from(x: usize) -> Result<Self, Self::Error> {
        Self::try_from(x as u64)
    }
}

impl PartialEq<u64> for VarInt {
    fn eq(&self, other: &u64) -> bool {
        self.0.eq(other)
    }
}

impl PartialOrd<u64> for VarInt {
    fn partial_cmp(&self, other: &u64) -> Option<Ordering> {
        self.0.partial_cmp(other)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::LowerHex for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::UpperHex for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Error module for VarInt
pub mod err {
    use std::fmt::Debug;

    use snafu::Snafu;

    /// Overflow error indicating that a value exceeds 2^62
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Snafu)]
    #[snafu(display("value({value}) too large for varint encoding"))]
    pub struct Overflow {
        pub(super) value: u128,
    }

    #[cfg(feature = "serde")]
    impl serde::Serialize for Overflow {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.value.serialize(serializer)
        }
    }

    #[cfg(feature = "serde")]
    impl<'de> serde::Deserialize<'de> for Overflow {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Ok(Self {
                value: u128::deserialize(deserializer)?,
            })
        }
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for VarInt {
    type Error = io::Error;

    async fn decode_from(stream: S) -> io::Result<Self> {
        let mut stream = pin!(stream);
        let first_byte = stream.read_u8().await?;
        let len = 2usize.pow(first_byte as u32 >> 6);
        let mut buf = [first_byte & 0b0011_1111, 0, 0, 0, 0, 0, 0, 0];
        stream.read_exact(&mut buf[1..len]).await?;
        let value = u64::from_be_bytes(buf) >> (8 * (8 - len));
        Ok(Self(value))
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for VarInt {
    type Output = ();

    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<Self::Output, Self::Error> {
        let VarInt(x) = self;
        let mut stream = pin!(stream);
        if x < 1u64 << 6 {
            stream.write_u8(x as u8).await?;
        } else if x < 1u64 << 14 {
            stream.write_u16((0b01 << 14) | x as u16).await?;
        } else if x < 1u64 << 30 {
            stream.write_u32((0b10 << 30) | x as u32).await?;
        } else if x < 1u64 << 62 {
            stream.write_u64((0b11 << 62) | x).await?;
        } else {
            unreachable!("malformed VarInt")
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::codec::{DecodeFrom, EncodeInto};

    #[test]
    fn from_u32_edge_values() {
        assert_eq!(VarInt::from_u32(0).into_inner(), 0);
        assert_eq!(VarInt::from_u32(1).into_inner(), 1);
        assert_eq!(VarInt::from_u32(63).into_inner(), 63);
        assert_eq!(VarInt::from_u32(64).into_inner(), 64);
        assert_eq!(VarInt::from_u32(16383).into_inner(), 16383);
        assert_eq!(VarInt::from_u32(16384).into_inner(), 16384);
        assert_eq!(VarInt::from_u32(u32::MAX).into_inner(), u32::MAX as u64);
    }

    #[test]
    fn from_u64_valid() {
        assert!(VarInt::from_u64(0).is_ok());
        assert!(VarInt::from_u64(1).is_ok());
        assert!(VarInt::from_u64(63).is_ok());
        assert!(VarInt::from_u64(16383).is_ok());
        assert!(VarInt::from_u64(VARINT_MAX - 1).is_ok());
        assert!(VarInt::from_u64(VARINT_MAX).is_ok());
    }

    #[test]
    fn from_u64_overflow() {
        assert!(VarInt::from_u64(VARINT_MAX + 1).is_err());
        assert!(VarInt::from_u64(u64::MAX).is_err());
    }

    #[test]
    fn into_inner_round_trip() {
        for &v in &[0u64, 1, 63, 64, 16383, 16384, 1 << 30, VARINT_MAX - 1] {
            let vi = VarInt::from_u64(v).unwrap();
            assert_eq!(vi.into_inner(), v);
        }
    }

    #[test]
    fn ordering_and_equality() {
        let a = VarInt::from_u32(10);
        let b = VarInt::from_u32(20);
        let c = VarInt::from_u32(10);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, c);
        assert_ne!(a, b);
    }

    #[test]
    fn partial_eq_and_ord_with_u64() {
        let v = VarInt::from_u32(42);
        assert_eq!(v, 42u64);
        assert!(v < 100u64);
        assert!(v > 10u64);
    }

    #[test]
    fn encoding_size() {
        assert_eq!(VarInt::from_u32(0).encoding_size(), 1);
        assert_eq!(VarInt::from_u32(63).encoding_size(), 1);
        assert_eq!(VarInt::from_u32(64).encoding_size(), 2);
        assert_eq!(VarInt::from_u32(16383).encoding_size(), 2);
        assert_eq!(VarInt::from_u32(16384).encoding_size(), 4);
        assert_eq!(VarInt::from_u64((1 << 30) - 1).unwrap().encoding_size(), 4);
        assert_eq!(VarInt::from_u64(1 << 30).unwrap().encoding_size(), 8);
        assert_eq!(VarInt::MAX.encoding_size(), 8);
    }

    #[test]
    fn from_conversions() {
        let _ = VarInt::from(0u8);
        let _ = VarInt::from(0u16);
        let _ = VarInt::from(0u32);
        assert!(VarInt::try_from(0u64).is_ok());
        assert!(VarInt::try_from(VARINT_MAX).is_ok());
        assert!(VarInt::try_from(VARINT_MAX + 1).is_err());
        assert!(VarInt::try_from(0u128).is_ok());
        assert!(VarInt::try_from(VARINT_MAX as u128).is_ok());
        assert!(VarInt::try_from(VARINT_MAX as u128 + 1).is_err());
        assert!(VarInt::try_from(0usize).is_ok());
        #[cfg(target_pointer_width = "64")]
        assert!(VarInt::try_from((VARINT_MAX + 1) as usize).is_err());
    }

    #[test]
    fn unchecked_constructor_and_constants_preserve_raw_value() {
        // SAFETY: 123 is below the QUIC varint 2^62 bound.
        let value = unsafe { VarInt::from_u64_unchecked(123) };

        assert_eq!(value.into_inner(), 123);
        assert_eq!(VarInt::MAX_SIZE, 8);
        assert_eq!(VarInt::MAX.into_inner(), VARINT_MAX);
    }

    #[test]
    fn malformed_unchecked_value_panics_when_sized() {
        // SAFETY: This intentionally violates the unsafe constructor contract to verify
        // the internal invariant guard for malformed values.
        let value = unsafe { VarInt::from_u64_unchecked(VARINT_MAX + 1) };

        let panic = std::panic::catch_unwind(|| value.encoding_size())
            .expect_err("malformed unchecked value should panic");
        assert!(
            panic
                .downcast_ref::<&'static str>()
                .is_some_and(|message| message.contains("malformed VarInt"))
        );
    }

    #[test]
    fn overflow_error_reports_original_value() {
        let overflow = VARINT_MAX as u128 + 1;
        let error = VarInt::from_u128(overflow).expect_err("value above max is rejected");

        assert_eq!(
            error.to_string(),
            format!("value({overflow}) too large for varint encoding")
        );
        assert!(format!("{error:?}").contains(&overflow.to_string()));
    }

    async fn encode_decode_round_trip(value: u64) {
        let vi = VarInt::from_u64(value).unwrap();
        let mut buf = Vec::new();
        vi.encode_into(Cursor::new(&mut buf)).await.unwrap();
        assert_eq!(buf.len(), vi.encoding_size());
        let decoded = VarInt::decode_from(Cursor::new(&buf)).await.unwrap();
        assert_eq!(decoded, vi);
    }

    #[tokio::test]
    async fn encode_decode_1_byte() {
        encode_decode_round_trip(0).await;
        encode_decode_round_trip(1).await;
        encode_decode_round_trip(37).await;
        encode_decode_round_trip(63).await;
    }

    #[tokio::test]
    async fn encode_decode_2_byte() {
        encode_decode_round_trip(64).await;
        encode_decode_round_trip(100).await;
        encode_decode_round_trip(16383).await;
    }

    #[tokio::test]
    async fn encode_decode_4_byte() {
        encode_decode_round_trip(16384).await;
        encode_decode_round_trip(1_000_000).await;
        encode_decode_round_trip((1 << 30) - 1).await;
    }

    #[tokio::test]
    async fn encode_decode_8_byte() {
        encode_decode_round_trip(1 << 30).await;
        encode_decode_round_trip(1 << 40).await;
        encode_decode_round_trip(VARINT_MAX - 1).await;
        encode_decode_round_trip(VARINT_MAX).await;
    }

    #[tokio::test]
    async fn malformed_unchecked_value_panics_when_encoded() {
        // SAFETY: This intentionally violates the unsafe constructor contract to verify
        // the internal invariant guard for malformed values.
        let value = unsafe { VarInt::from_u64_unchecked(VARINT_MAX + 1) };
        let join = tokio::spawn(async move {
            value
                .encode_into(Cursor::new(Vec::<u8>::new()))
                .await
                .expect("malformed unchecked value should panic before returning");
        });

        let error = join
            .await
            .expect_err("malformed unchecked value should panic");
        assert!(error.is_panic());
    }

    #[test]
    fn display_and_hex() {
        let v = VarInt::from_u32(255);
        assert_eq!(format!("{v}"), "255");
        assert_eq!(format!("{v:x}"), "ff");
        assert_eq!(format!("{v:X}"), "FF");
    }

    mod proptest_roundtrip {
        use std::io::Cursor;

        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn varint_encode_decode_roundtrip(value in 0u64..VARINT_MAX) {
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                rt.block_on(async {
                    let vi = VarInt::from_u64(value).unwrap();
                    let mut buf = Vec::new();
                    vi.encode_into(Cursor::new(&mut buf)).await.unwrap();
                    let decoded = VarInt::decode_from(Cursor::new(&buf)).await.unwrap();
                    prop_assert_eq!(decoded, vi);
                    Ok(())
                })?;
            }
        }
    }
}
