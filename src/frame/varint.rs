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
            ErrorCode::FrameError
                .connection("malformed or truncated HTTP/3 frame")
                .into()
        })
}
