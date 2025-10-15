use std::task::{Context, Poll, ready};

use bytes::Buf;
use tokio::io::{AsyncBufRead, AsyncWrite};

use crate::codec::{
    error::{DecodeError, DecodeStreamError, EncodeStreamError},
    util::{poll_buffer, poll_write_u8},
};

pub struct DecodingInteger {
    n: u8,
    i: u64,
    m: u32,
}

impl DecodingInteger {
    pub const fn new(prefix: u8, n: u8) -> Result<Self, u64> {
        let mask = (1u8 << n) - 1;
        match prefix & mask {
            i if i == mask => Ok(Self {
                n,
                i: i as u64,
                m: 0,
            }),
            i => Err(i as u64),
        }
    }

    /// Pseudocode to decode an integer I is as follows:
    ///
    /// ```code
    /// decode I from the next N bits
    ///   if I < 2^N - 1, return I
    ///   else
    ///       M = 0
    ///       repeat
    ///           B = next octet
    ///           I = I + (B & 127) * 2^M
    ///           M = M + 7
    ///       while B & 128 == 128
    ///       return I
    /// ```
    pub fn poll_decode(
        &mut self,
        stream: &mut (impl AsyncBufRead + Unpin),
        cx: &mut Context<'_>,
    ) -> Poll<Result<u64, DecodeStreamError>> {
        debug_assert!(
            !(self.m == 0 && self.i < (1u64 << self.n) - 1),
            "No need to decode"
        );

        loop {
            let mut buffer = ready!(poll_buffer(stream, cx)?);
            while !buffer.chunk().is_empty() {
                buffer.advance(0);
                let byte = buffer.chunk()[0];
                let addend = (byte as u64 & 127)
                    .checked_shl(self.m)
                    .ok_or(DecodeError::IntegerOverflow)?;
                self.i = self
                    .i
                    .checked_add(addend)
                    .ok_or(DecodeError::IntegerOverflow)?;
                self.m += 7;

                if (byte & 128) == 0 {
                    return Poll::Ready(Ok(self.i));
                }
            }
        }
    }
}

pub enum IntegerDecoder {
    Decoding(DecodingInteger),
    Decoded(u64),
}

impl IntegerDecoder {
    pub const fn new(prefix: u8, n: u8) -> Self {
        match DecodingInteger::new(prefix, n) {
            Ok(decoding) => Self::Decoding(decoding),
            Err(i) => Self::Decoded(i),
        }
    }

    pub const fn is_decoded(&self) -> bool {
        matches!(self, Self::Decoded(_))
    }

    pub fn poll_decode(
        &mut self,
        stream: &mut (impl AsyncBufRead + Unpin),
        cx: &mut Context<'_>,
    ) -> Poll<Result<u64, DecodeStreamError>> {
        match &mut *self {
            Self::Decoded(i) => Poll::Ready(Ok(*i)),
            Self::Decoding(decoding) => {
                let i = ready!(decoding.poll_decode(stream, cx)?);
                *self = Self::Decoded(i);
                Poll::Ready(Ok(i))
            }
        }
    }
}

pub enum IntegerEncoder {
    Prefix { prefix: u8, n: u8, i: u64 },
    Octets { i: u64 },
    // Encoded = Octets { i: 0 },
}

impl IntegerEncoder {
    pub const fn new(prefix: u8, n: u8, i: u64) -> Self {
        Self::Prefix { prefix, n, i }
    }

    /// Pseudocode to represent an integer I is as follows:
    ///
    /// ``` code
    /// if I < 2^N - 1, encode I on N bits
    /// else
    ///     encode (2^N - 1) on N bits
    ///     I = I - (2^N - 1)
    ///     while I >= 128
    ///          encode (I % 128 + 128) on 8 bits
    ///          I = I / 128
    ///     encode I on 8 bits
    /// ```
    pub fn poll_encode(
        &mut self,
        stream: &mut (impl AsyncWrite + Unpin),
        cx: &mut Context,
    ) -> Poll<Result<(), EncodeStreamError>> {
        match self {
            IntegerEncoder::Prefix { prefix, n, i } if *i < (1 << *n) as u64 - 1 => {
                ready!(poll_write_u8(&mut *stream, cx, *prefix | *i as u8))?;
                *self = IntegerEncoder::Octets { i: 0 };
                // self.poll_encode(stream, cx)
                Poll::Ready(Ok(()))
            }
            IntegerEncoder::Prefix { prefix, n, i } => {
                ready!(poll_write_u8(&mut *stream, cx, *prefix | ((1 << *n) - 1)))?;
                *self = IntegerEncoder::Octets {
                    i: *i - ((1 << *n) - 1) as u64,
                };
                self.poll_encode(stream, cx)
            }
            IntegerEncoder::Octets { i } if *i >= 128 => {
                ready!(poll_write_u8(&mut *stream, cx, ((*i % 128) + 128) as u8))?;
                *i /= 128; // SHR 7
                self.poll_encode(stream, cx)
            }
            IntegerEncoder::Octets { i } if *i > 0 => {
                ready!(poll_write_u8(&mut *stream, cx, *i as u8))?;
                *i = 0;
                // self.poll_encode(stream, cx)
                Poll::Ready(Ok(()))
            }
            IntegerEncoder::Octets { i } => {
                debug_assert!(*i == 0);
                Poll::Ready(Ok(()))
            }
        }
    }
}
