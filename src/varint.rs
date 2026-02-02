use std::{cmp::Ordering, convert::TryFrom, fmt, pin::pin};

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::{Decode, Encode};

/// An integer less than 2^62
///
/// Values of this type are suitable for encoding as QUIC variable-length integer.
/// It would be neat if we could express to Rust that the top two bits are available for use as enum
/// discriminants
///
/// See [variable-length integers](https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
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
        if value < VARINT_MAX {
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
        if value < VARINT_MAX as u128 {
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
}

impl<S: AsyncRead> Decode<VarInt> for S {
    type Error = io::Error;

    async fn decode(self) -> io::Result<VarInt> {
        let mut stream = pin!(self);
        let first_byte = stream.read_u8().await?;
        let len = 2usize.pow(first_byte as u32 >> 6);
        let mut buf = [first_byte & 0b0011_1111, 0, 0, 0, 0, 0, 0, 0];
        stream.read_exact(&mut buf[1..len]).await?;
        let value = u64::from_be_bytes(buf) >> (8 * (8 - len));
        Ok(VarInt(value))
    }
}

impl<S: AsyncWrite> Encode<VarInt> for S {
    type Output = ();

    type Error = io::Error;

    async fn encode(self, VarInt(x): VarInt) -> Result<Self::Output, Self::Error> {
        let mut stream = pin!(self);
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
