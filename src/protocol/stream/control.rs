//! Control stream state and frame I/O. Keep futures alive through partial I/O.
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Mutex as AsyncMutex, mpsc, oneshot},
};

use super::bi::BiStreams;
use crate::{
    Error, Result, Role,
    protocol::{
        connection::{Goaway, Settings},
        frame::{self, FrameType, H3Frame, Write as _},
        qpack::{self, Qpack},
    },
};

pub(crate) struct Control {
    pub(crate) sender: mpsc::Sender<(H3Frame, oneshot::Sender<Result<()>>)>,
    pub(crate) receiver: AsyncMutex<mpsc::Receiver<(H3Frame, oneshot::Sender<Result<()>>)>>,
}

impl Default for Control {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel(1);
        Self {
            sender,
            receiver: AsyncMutex::new(receiver),
        }
    }
}

pub(crate) struct ControlStream<S> {
    send: S,
}

impl<S: AsyncWrite + Unpin> ControlStream<S> {
    pub(crate) fn new(send: S) -> Self {
        Self { send }
    }

    pub(crate) async fn write(&mut self, frame: &H3Frame) -> Result<()> {
        write(&mut self.send, frame).await
    }
}

pub(crate) async fn receive_control<R: AsyncRead + Unpin, W>(
    recv: &mut R,
    role: &Role,
    settings: &Settings,
    qpack: &Qpack,
    goaway: &Goaway,
    bi: &BiStreams<R, W>,
) -> Result<()> {
    let H3Frame::Settings(frame) = read(recv, true).await? else {
        return Err(Error::H3_MISSING_SETTINGS);
    };
    let (peer, max_fields) = qpack::limits(&frame.payload);
    qpack.configure(peer, max_fields)?;
    *settings.peer.lock().unwrap() = Some(frame.payload);
    let mut max_push = None;
    loop {
        let frame = read(recv, false).await?;
        match (role, &frame) {
            (Role::Client, H3Frame::Goaway(frame))
                if !frame.payload.id.into_u64().is_multiple_of(4) =>
            {
                return Err(Error::H3_ID_ERROR);
            }
            (_, H3Frame::Goaway(_)) => {}
            (Role::Server, H3Frame::MaxPushId(frame)) => {
                let id = frame.payload.push_id.into_u64();
                if max_push.is_some_and(|previous| id < previous) {
                    return Err(Error::H3_ID_ERROR);
                }
                max_push = Some(id);
            }
            (Role::Server, H3Frame::CancelPush(_)) => return Err(Error::H3_ID_ERROR),
            _ => return Err(Error::H3_FRAME_UNEXPECTED),
        }
        if let H3Frame::Goaway(frame) = frame {
            let id = frame.payload.id.into_u64();
            goaway.receive(id)?;
            if *role == Role::Client {
                bi.goaway(id, qpack);
            }
        }
    }
}

pub(crate) async fn read<R: AsyncRead + Unpin>(recv: &mut R, first: bool) -> Result<H3Frame> {
    loop {
        let ty = frame::be_varint(recv)
            .await
            .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?
            .into_u64();
        let ty = match (first, ty) {
            (true, 4) => Some(FrameType::Settings),
            (true, _) => return Err(Error::H3_MISSING_SETTINGS),
            (false, 3) => Some(FrameType::CancelPush),
            (false, 7) => Some(FrameType::Goaway),
            (false, 13) => Some(FrameType::MaxPushId),
            (false, 0..=9) => return Err(Error::H3_FRAME_UNEXPECTED),
            _ => None,
        };
        let length = frame::be_varint(recv)
            .await
            .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
        if let Some(ty) = ty {
            if length.into_u64() > frame::MAX_BUFFERED_FRAME_PAYLOAD as u64 {
                return Err(Error::H3_EXCESSIVE_LOAD);
            }
            let mut payload = vec![0; length.into_u64() as usize];
            recv.read_exact(&mut payload)
                .await
                .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
            return frame::be_frame_payload(&mut payload.as_slice(), ty, length).await;
        }
        frame::skip_payload(recv, length.into_u64())
            .await
            .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
    }
}

pub(crate) async fn write<W: AsyncWrite + Unpin>(send: &mut W, frame: &H3Frame) -> Result<()> {
    let mut bytes = Vec::new();
    bytes.put_frame(frame);
    send.write_all(&bytes)
        .await
        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
    send.flush()
        .await
        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shared_varints_preserve_critical_io_and_malformed_payload_errors() {
        for partial in [&[][..], &[0x40][..], &[0xc0, 0, 0][..]] {
            assert_eq!(
                read(&mut &partial[..], true).await,
                Err(Error::H3_CLOSED_CRITICAL_STREAM)
            );
        }
        assert_eq!(
            read(&mut &[4, 0x40][..], true).await,
            Err(Error::H3_CLOSED_CRITICAL_STREAM)
        );
        assert_eq!(
            read(&mut &[4, 1, 1][..], true).await,
            Err(Error::H3_FRAME_ERROR)
        );
        assert_eq!(
            read(&mut &[4, 2, 1][..], true).await,
            Err(Error::H3_CLOSED_CRITICAL_STREAM)
        );
    }

    #[tokio::test]
    async fn control_types_and_unknown_payloads_keep_their_wire_boundaries() {
        use qbase::varint::{VarInt, WriteVarInt};
        for ty in [0, 1, 2, 4, 5, 6, 8, 9] {
            assert_eq!(
                read(&mut &[ty, 0][..], false).await,
                Err(Error::H3_FRAME_UNEXPECTED)
            );
        }
        for ty in [3, 7, 13, 0x21] {
            assert_eq!(
                read(&mut &[ty, 0][..], true).await,
                Err(Error::H3_MISSING_SETTINGS)
            );
        }
        for ty in [3, 7, 13] {
            assert!(read(&mut &[ty, 1, 0][..], false).await.is_ok());
        }
        let mut wire = vec![0x21];
        let length = frame::MAX_BUFFERED_FRAME_PAYLOAD + 1;
        wire.put_varint(&VarInt::try_from(length).unwrap());
        wire.resize(wire.len() + length, 0xff); // Unknown frames can exceed the known-frame budget.
        wire.extend_from_slice(&[0x22, 0, 7, 1, 4, 0xff]);
        let mut input = wire.as_slice();
        let H3Frame::Goaway(frame) = read(&mut input, false).await.unwrap() else {
            panic!()
        };
        assert_eq!(frame.payload.id.into_u64(), 4);
        assert_eq!(input, &[0xff]);
        assert_eq!(
            read(&mut &[0x21, 2, 0][..], false).await,
            Err(Error::H3_CLOSED_CRITICAL_STREAM)
        );
    }
}
