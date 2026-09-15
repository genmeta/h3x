//! Peer unidirectional stream admission, dispatch, and task lifetime.
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use qrecovery::recv::StopSending;

use super::H3Connection;
use crate::{
    Error, Result, Transport,
    protocol::{frame, stream::control},
};

pub(super) fn spawn<T: Transport>(connection: H3Connection<T>) {
    let streams = Arc::new(UniStreams { connection });
    tokio::spawn(streams.accept());
}

struct UniStreams<T: Transport> {
    connection: H3Connection<T>,
}

impl<T: Transport> UniStreams<T> {
    async fn accept(self: Arc<Self>) {
        // Bit N records whether critical stream type N has been admitted.
        let seen = Arc::new(AtomicU8::new(0));
        loop {
            match self.connection.transport.accept_uni().await {
                Ok((_, recv)) => {
                    tokio::spawn(self.clone().receive(recv, seen.clone()));
                }
                Err(error) => {
                    self.close(error);
                    return;
                }
            }
        }
    }

    async fn receive(self: Arc<Self>, mut recv: T::StreamReader, seen: Arc<AtomicU8>) {
        // Retain the half until failure handling completes, including transport close.
        tokio::select! {
            biased;
            result = self.dispatch(&mut recv, &seen) => if let Err(error) = result {
                self.fail(error).await;
            },
            error = self.connection.transport.terminated() => self.close(error),
        }
    }

    async fn dispatch(&self, recv: &mut T::StreamReader, seen: &AtomicU8) -> Result<()> {
        // FIN/RESET is stream-local until its full type is known.
        let stream_type = match frame::be_varint(recv).await {
            Ok(Some(ty)) => ty.into_u64(),
            Ok(None) => return Ok(()),
            Err(error)
                if error
                    .get_ref()
                    .is_some_and(|source| source.is::<qbase::frame::ResetStreamError>()) =>
            {
                return Ok(());
            }
            Err(error) => return Err(Error::from(error)),
        };
        let bit = match stream_type {
            0 | 2 | 3 => 1u8 << stream_type,
            1 => return Err(Error::H3_ID_ERROR),
            _ => {
                recv.stop(Error::H3_NO_ERROR.as_u64());
                return Ok(());
            }
        };
        // Only uniqueness is shared; no other state is published by this flag.
        if seen.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
            return Err(Error::H3_STREAM_CREATION_ERROR);
        }
        let connection = &self.connection;
        match stream_type {
            0 => {
                control::receive_control(
                    recv,
                    connection.transport.as_ref(),
                    &connection.settings,
                    &connection.qpack,
                    &connection.cursor,
                    &connection.bi_streams,
                )
                .await
            }
            2 => connection.qpack.receive_encoder(recv).await,
            3 => connection.qpack.receive_decoder(recv).await,
            _ => unreachable!(),
        }
    }

    fn close(&self, error: Error) {
        let error = self.connection.qpack.close(error);
        self.connection.bi_streams.close(error);
    }

    async fn fail(&self, error: Error) {
        let connection = &self.connection;
        // Prefer an existing transport result over a new protocol error.
        tokio::select! {
            biased;
            ended = connection.transport.terminated() => self.close(ended),
            _ = std::future::ready(()) => {
                let error = connection.qpack.close(error);
                let _ = connection.transport.close(error.to_string(), error.as_u64());
                connection.bi_streams.close(error);
            },
        }
    }
}
