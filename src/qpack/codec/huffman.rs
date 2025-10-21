use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::error::{DecodeError, DecodeStreamError, EncodeError, EncodeStreamError};

pub async fn decode_huffman(
    stream: &mut (impl AsyncBufRead + Unpin),
    mut length: u64,
) -> Result<Bytes, DecodeStreamError> {
    let mut decoder = httlib_huffman::Decoder::new(httlib_huffman::DecoderSpeed::FourBits);
    let mut decoded = BytesMut::new();
    while length > 0 {
        let read = decoder.read(stream.fill_buf().await?);
        while let Some(byte) = decoder.decode().map_err(DecodeError::from)? {
            decoded.put_u8(byte);
        }
        stream.consume(read);
        length -= read as u64;
    }
    decoded.extend(decoder.finalize().map_err(DecodeError::from)?);
    Ok(decoded.freeze())
}

pub async fn encode_huffman(
    stream: &mut (impl AsyncWrite + Unpin),
    data: Bytes,
) -> Result<(), EncodeStreamError> {
    let mut encoder = httlib_huffman::Encoder::new();
    let mut data = data;
    while !data.is_empty() {
        let written = encoder.write(&data).map_err(EncodeError::from)?;
        data.advance(written);
        while let Some(byte) = encoder.read() {
            stream.write_u8(byte).await?;
        }
    }
    if let Some(final_byte) = encoder.finalize() {
        stream.write_u8(final_byte).await?;
    }
    Ok(())
}
