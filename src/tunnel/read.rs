//! Cancellation-safe DATA decoding, frame skipping, and receive-side errors.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use qbase::varint::{VarInt, be_varint};
use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use crate::{ArcQpack, Error, ErrorCode, H3ReadStream, protocol::frame::FrameType};

pub(super) struct DataReader<R: StopSending> {
    stream: H3ReadStream<R>,
    state: ReadState,
    qpack: ArcQpack,
}

enum ReadState {
    Header(FrameHeaderReader),
    Data { remaining: u64 },
    Skip { remaining: u64 },
    Eof,
    Failed(Error),
}

/// Keep only the incomplete frame header across polls. Varint decoding uses the
/// same be_varint parser as the rest of the protocol implementation.
#[derive(Default)]
struct FrameHeaderReader {
    bytes: [u8; 2 * VarInt::MAX_SIZE],
    used: usize,
}

impl FrameHeaderReader {
    fn poll_read<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<(FrameType, u64)>>> {
        loop {
            // The slice parser returns Incomplete until the integer is present.
            if let Ok((rest, kind)) = be_varint(&self.bytes[..self.used]) {
                let kind = FrameType::try_from(kind.into_u64()).map_err(io::Error::from)?;
                if !matches!(kind, FrameType::Data | FrameType::Unknown(_)) {
                    return Poll::Ready(Err(ErrorCode::H3_FRAME_UNEXPECTED
                        .with_reason("forbidden frame in CONNECT tunnel")
                        .into()));
                }
                if let Ok((_, length)) = be_varint(rest) {
                    self.used = 0;
                    return Poll::Ready(Ok(Some((kind, length.into_u64()))));
                }
            }
            // Two complete varints fit in bytes; never consume DATA payload here.
            let mut buf = ReadBuf::new(&mut self.bytes[self.used..self.used + 1]);
            ready!(Pin::new(&mut *stream).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return Poll::Ready(if self.used == 0 {
                    Ok(None)
                } else {
                    Err(ErrorCode::H3_FRAME_ERROR
                        .with_reason("truncated tunnel frame header")
                        .into())
                });
            }
            self.used += 1;
        }
    }
}

impl<R: AsyncRead + StopSending + Unpin> DataReader<R> {
    pub(super) fn new(stream: H3ReadStream<R>, qpack: ArcQpack) -> Self {
        Self {
            stream,
            qpack,
            state: ReadState::Header(FrameHeaderReader::default()),
        }
    }

    pub(super) fn abort(&mut self, error: Error) {
        self.stream.close(error.clone());
        if !matches!(self.state, ReadState::Failed(_)) {
            self.state = ReadState::Failed(error);
        }
    }

    fn fail(&mut self, error: Error) -> Poll<io::Result<()>> {
        self.abort(error.clone());
        if matches!(
            error.code,
            ErrorCode::H3_FRAME_ERROR | ErrorCode::H3_FRAME_UNEXPECTED
        ) {
            self.qpack.on_error(error.clone());
        }
        Poll::Ready(Err(error.into()))
    }
}

/// Read within the current frame without consuming the next frame's header.
fn poll_read_payload<R: AsyncRead + Unpin>(
    stream: &mut R,
    cx: &mut Context<'_>,
    remaining: &mut u64,
    output: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    let before = output.filled().len();
    let mut payload = stream.take(*remaining);
    ready!(Pin::new(&mut payload).poll_read(cx, output))?;
    *remaining = payload.limit();
    if output.filled().len() == before {
        return Poll::Ready(Err(ErrorCode::H3_FRAME_ERROR
            .with_reason("truncated tunnel frame payload")
            .into()));
    }
    Poll::Ready(Ok(()))
}

impl<R: AsyncRead + StopSending + Unpin> AsyncRead for DataReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Bound work even if the peer sends a stream of empty or unknown frames.
        for _ in 0..64 {
            match &mut this.state {
                ReadState::Eof => return Poll::Ready(Ok(())),
                ReadState::Failed(error) => return Poll::Ready(Err(error.clone().into())),
                ReadState::Header(header) => {
                    this.state = match ready!(header.poll_read(&mut this.stream, cx)) {
                        Ok(Some((FrameType::Data, remaining))) => ReadState::Data { remaining },
                        Ok(Some((_, remaining))) => ReadState::Skip { remaining },
                        Ok(None) => ReadState::Eof,
                        Err(error) => return this.fail(error.into()),
                    };
                }
                ReadState::Data { remaining: 0 } | ReadState::Skip { remaining: 0 } => {
                    this.state = ReadState::Header(FrameHeaderReader::default());
                }
                ReadState::Data { remaining } => {
                    return match ready!(poll_read_payload(&mut this.stream, cx, remaining, output))
                    {
                        Ok(()) => Poll::Ready(Ok(())),
                        Err(error) => this.fail(error.into()),
                    };
                }
                ReadState::Skip { remaining } => {
                    let mut scratch = [0; 4096];
                    let mut discard = ReadBuf::new(&mut scratch);
                    if let Err(error) = ready!(poll_read_payload(
                        &mut this.stream,
                        cx,
                        remaining,
                        &mut discard
                    )) {
                        return this.fail(error.into());
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
