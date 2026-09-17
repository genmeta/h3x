use std::io;

use qbase::varint::VarInt;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::ErrorCode;

/// Preserve transport errors and return `None` on FIN, including a partial integer.
/// Cancellation may consume part of the integer; keep polling the same future.
pub(crate) async fn be_varint<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
) -> io::Result<Option<VarInt>> {
    let mut encoded = [0; VarInt::MAX_SIZE];
    if reader.read(&mut encoded[..1]).await? == 0 {
        return Ok(None);
    }
    let len = 1usize << (encoded[0] >> 6);
    let mut read = 1;
    while read < len {
        let count = reader.read(&mut encoded[read..len]).await?;
        if count == 0 {
            return Ok(None);
        }
        read += count;
    }
    qbase::varint::be_varint(&encoded[..len])
        .map(|(_, value)| Some(value))
        .map_err(|_| {
            ErrorCode::H3_FRAME_ERROR
                .reason("malformed or truncated HTTP/3 frame")
                .into()
        })
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn reads_fragmented_varints_and_reports_eof() {
        let encoded: &[u8] = &[
            0x3f, 0x7f, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff,
        ];
        for capacity in 1..=encoded.len() {
            let (mut writer, mut reader) = tokio::io::duplex(capacity);
            let write = async {
                writer.write_all(encoded).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let read = async {
                for expected in [63, 16383, 1073741823, (1u64 << 62) - 1] {
                    assert_eq!(
                        be_varint(&mut reader).await.unwrap().unwrap().into_u64(),
                        expected
                    );
                }
                assert_eq!(be_varint(&mut reader).await.unwrap(), None);
            };
            tokio::join!(write, read);
        }
        for (len, prefix) in [(2, 0x40), (4, 0x80), (8, 0xc0)] {
            let mut partial = [0xff; 8];
            partial[0] = prefix;
            for end in 1..len {
                assert_eq!(be_varint(&mut &partial[..end]).await.unwrap(), None);
            }
        }
    }
}
