use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures::Sink;
use tokio::io::{AsyncBufRead, AsyncWrite};

use crate::{
    codec::error::{DecodeStreamError, EncodeStreamError},
    qpack::codec::{
        huffman::{DecodingHuffman, HuffmanEncoder},
        integer::{IntegerDecoder, IntegerEncoder},
        literal::{DecodingLiteral, LiteralEncoder},
    },
};

pub enum DecodingString {
    Literal {
        length: IntegerDecoder,
        string: Option<DecodingLiteral>,
    },
    Huffman {
        length: IntegerDecoder,
        string: Option<DecodingHuffman>,
    },
}

impl DecodingString {
    pub fn new(prefix: u8, n: u8) -> Self {
        match (prefix >> (n - 1)) & 1 {
            0 => DecodingString::Literal {
                length: IntegerDecoder::new(prefix, n - 1),
                string: None,
            },
            1 => DecodingString::Huffman {
                length: IntegerDecoder::new(prefix, n - 1),
                string: None,
            },
            _ => unreachable!("H bit must be 0 or 1"),
        }
    }

    pub fn poll_decode(
        &mut self,
        stream: &mut (impl AsyncBufRead + Unpin),
        cx: &mut Context,
    ) -> Poll<Result<Bytes, DecodeStreamError>> {
        match self {
            DecodingString::Literal { length, string } => {
                if string.is_none() {
                    let len = ready!(length.poll_decode(stream, cx))?;
                    *string = Some(DecodingLiteral::new(len));
                }
                match string {
                    Some(string) => string.poll_decode(stream, cx),
                    None => unreachable!(),
                }
            }
            DecodingString::Huffman { length, string } => {
                if string.is_none() {
                    let len = ready!(length.poll_decode(stream, cx))?;
                    *string = Some(DecodingHuffman::new(len));
                }
                match string {
                    Some(string) => string.poll_decode(stream, cx),
                    None => unreachable!(),
                }
            }
        }
    }
}

pub enum StringEncoder {
    Literal {
        length: IntegerEncoder,
        string: LiteralEncoder,
    },
    Huffman {
        length: IntegerEncoder,
        string: HuffmanEncoder,
    },
}

impl StringEncoder {
    pub const fn new(mut prefix: u8, n: u8, huffman: bool, data: Bytes) -> Self {
        let length = data.len() as u64;
        // set H bit
        prefix |= (huffman as u8) << (n - 1);
        match huffman {
            true => Self::Huffman {
                length: IntegerEncoder::new(prefix, n - 1, length),
                string: HuffmanEncoder::new(data),
            },
            false => Self::Literal {
                length: IntegerEncoder::new(prefix, n - 1, length),
                string: LiteralEncoder::new(data),
            },
        }
    }

    pub fn poll_encode<E>(
        &mut self,
        stream: &mut (impl AsyncWrite + Sink<Bytes, Error = E> + Unpin),
        cx: &mut Context,
    ) -> Poll<Result<(), EncodeStreamError>>
    where
        EncodeStreamError: From<E>,
    {
        match self {
            StringEncoder::Literal { length, string } => {
                ready!(length.poll_encode(&mut *stream, cx))?;
                string.poll_encode(stream, cx)
            }
            StringEncoder::Huffman { length, string } => {
                ready!(length.poll_encode(&mut *stream, cx))?;
                string.poll_encode(stream, cx)
            }
        }
    }
}
