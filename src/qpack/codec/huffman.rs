use std::{
    mem,
    ops::Range,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncBufRead, AsyncWrite};

use crate::codec::{
    error::{DecodeError, DecodeStreamError, EncodeError, EncodeStreamError},
    util::poll_write_u8,
};

pub struct DecodingHuffman {
    read: Range<u64>,
    reader: httlib_huffman::Decoder,
    decoded: BytesMut,
}

impl DecodingHuffman {
    pub fn new(len: u64) -> Self {
        Self {
            reader: httlib_huffman::Decoder::new(httlib_huffman::DecoderSpeed::FourBits),
            read: 0..len,
            decoded: BytesMut::new(),
        }
    }

    pub fn poll_decode(
        &mut self,
        stream: &mut (impl AsyncBufRead + Unpin),
        cx: &mut Context,
    ) -> Poll<Result<Bytes, DecodeStreamError>> {
        loop {
            while let Some(code) = self.reader.decode().transpose() {
                self.decoded.put_u8(code.map_err(DecodeError::from)?);
            }

            if self.read.start == self.read.end {
                self.decoded
                    .extend(self.reader.finalize().map_err(DecodeError::from)?);
                return Poll::Ready(Ok(mem::take(&mut self.decoded).freeze()));
            } else {
                match ready!(Pin::new(&mut *stream).poll_fill_buf(cx))? {
                    [] => return Poll::Ready(Err(DecodeError::Incomplete.into())),
                    chunk => {
                        let read = chunk.len().min((self.read.end - self.read.start) as usize);
                        let read = self.reader.read(&chunk[..read]);
                        Pin::new(&mut *stream).consume(read);
                        self.read.start += read as u64;
                    }
                }
            }
        }
    }
}

pub struct HuffmanEncoder {
    data: Bytes,
    encoder: httlib_huffman::Encoder,
    byte: Option<u8>,
}

impl HuffmanEncoder {
    pub const fn new(data: Bytes) -> Self {
        Self {
            data,
            encoder: httlib_huffman::Encoder::new(),
            byte: None,
        }
    }

    pub fn poll_encode(
        &mut self,
        stream: &mut (impl AsyncWrite + Unpin),
        cx: &mut Context,
    ) -> Poll<Result<(), EncodeStreamError>> {
        loop {
            // has pending byte to write
            if let Some(byte) = self.byte {
                ready!(poll_write_u8(&mut *stream, cx, byte))?;
                self.byte.take();
            }
            // has encoded byte to read, then write
            else if let Some(byte) = self.encoder.read() {
                self.byte = Some(byte);
            }
            // has unencoded data, then encode
            else if !self.data.is_empty() {
                let written = self.encoder.write(&self.data).map_err(EncodeError::from)?;
                self.data.advance(written);
            }
            // no pending byte, no encoded byte, no unencoded data, then finalize
            else if let Some(final_byte) = self.encoder.finalize() {
                self.byte = Some(final_byte);
            }
            // all done
            else {
                return Poll::Ready(Ok(()));
            }
        }
    }
}
