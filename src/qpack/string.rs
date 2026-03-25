use bytes::Bytes;
use futures::{Sink, SinkExt};
use httlib_huffman::DecoderSpeed;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::{
    codec::{DecodeError, DecodeStreamError, EncodeError, EncodeStreamError, FixedLengthReader},
    qpack::integer::{decode_integer, encode_integer},
};

pub async fn decode_string(
    stream: impl AsyncRead,
    prefix: u8,
    n: u8,
) -> Result<(bool, Bytes), DecodeStreamError> {
    tokio::pin!(stream);
    let huffman = (prefix >> (n - 1)) & 1 == 1;
    let length = decode_integer(stream.as_mut(), prefix, n - 1).await?;
    let mut value = Vec::with_capacity((length as usize).min(8192));
    FixedLengthReader::new(stream.as_mut(), length)
        .read_to_end(&mut value)
        .await?;
    match huffman {
        true => Ok((huffman, {
            let mut decoded_value = vec![];
            httlib_huffman::decode(&value, &mut decoded_value, DecoderSpeed::FourBits)
                .map_err(DecodeError::from)?;
            Bytes::from_owner(decoded_value)
        })),
        false => Ok((huffman, Bytes::from_owner(value))),
    }
}

pub async fn encode_string<E>(
    stream: impl AsyncWrite + Sink<Bytes, Error = E>,
    mut prefix: u8,
    n: u8,
    huffman: bool,
    data: Bytes,
) -> Result<(), EncodeStreamError>
where
    EncodeStreamError: From<E>,
{
    tokio::pin!(stream);
    // set H bit
    prefix |= (huffman as u8) << (n - 1);

    match huffman {
        true => {
            let mut encoded_data = vec![];
            httlib_huffman::encode(&data, &mut encoded_data).map_err(EncodeError::from)?;
            encode_integer(stream.as_mut(), prefix, n - 1, encoded_data.len() as u64).await?;
            stream.send(Bytes::from_owner(encoded_data)).await?;
            Ok(())
        }
        false => {
            encode_integer(stream.as_mut(), prefix, n - 1, data.len() as u64).await?;
            stream.send(Bytes::from_owner(data)).await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Buf, Bytes};

    use super::*;
    use crate::buflist::BufList;

    async fn round_trip_string(data: &[u8], huffman: bool) {
        let mut writer = BufList::new();
        let prefix: u8 = 0;
        let n: u8 = 8;
        encode_string(&mut writer, prefix, n, huffman, Bytes::from(data.to_vec()))
            .await
            .unwrap();

        // Collect all bytes from BufList (may span multiple internal chunks)
        let total = writer.remaining();
        let encoded = writer.copy_to_bytes(total);
        let (decoded_huffman, decoded_data) =
            decode_string(std::io::Cursor::new(&encoded[1..]), encoded[0], n)
                .await
                .unwrap();
        assert_eq!(decoded_huffman, huffman);
        assert_eq!(&decoded_data[..], data);
    }

    #[tokio::test]
    async fn plain_empty_string() {
        round_trip_string(b"", false).await;
    }

    #[tokio::test]
    async fn plain_ascii_string() {
        round_trip_string(b"hello", false).await;
    }

    #[tokio::test]
    async fn plain_longer_string() {
        round_trip_string(b"www.example.com", false).await;
    }

    #[tokio::test]
    async fn huffman_ascii_string() {
        round_trip_string(b"hello", true).await;
    }

    #[tokio::test]
    async fn huffman_longer_string() {
        round_trip_string(b"www.example.com", true).await;
    }

    #[tokio::test]
    async fn huffman_empty_string() {
        round_trip_string(b"", true).await;
    }

    #[tokio::test]
    async fn huffman_flag_bit_set_correctly() {
        let mut writer = BufList::new();
        let n: u8 = 8;

        // Plain: H bit should be 0
        encode_string(&mut writer, 0, n, false, Bytes::from_static(b"a"))
            .await
            .unwrap();
        let plain_byte = Buf::chunk(&writer)[0];
        assert_eq!(plain_byte & 0x80, 0, "H bit should be 0 for plain");

        // Huffman: H bit should be 1
        let mut writer2 = BufList::new();
        encode_string(&mut writer2, 0, n, true, Bytes::from_static(b"a"))
            .await
            .unwrap();
        let huff_byte = Buf::chunk(&writer2)[0];
        assert_eq!(huff_byte & 0x80, 0x80, "H bit should be 1 for huffman");
    }
}
