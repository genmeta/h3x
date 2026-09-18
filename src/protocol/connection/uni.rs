//! Peer unidirectional stream admission, dispatch, and task lifetime.
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use super::H3Connection;
use crate::{
    Error, ErrorCode, Transport,
    protocol::frame::{self, StreamType},
};

impl<T: Transport> H3Connection<T> {
    pub(super) async fn accept_and_process_uni(self) {
        let peer_critical_streams = Arc::new(AtomicU8::new(0));
        let error = loop {
            tokio::select! {
                biased;
                error = self.qpack.failed() => break error,
                accepted = self.transport.accept_uni() => match accepted {
                    Ok((_, recv)) => {
                        tokio::spawn(self.clone().receive(recv, peer_critical_streams.clone()));
                    }
                    Err(error) => break error,
                },
            }
        };
        let error = self.qpack.on_error(error);
        let _ = self
            .transport
            .close(error.reason.clone(), error.code.as_u64());
        self.on_terminated(error);
    }

    async fn receive(self, mut recv: T::StreamReader, peer_critical_streams: Arc<AtomicU8>) {
        let result = async {
            let Some(stream_type) = frame::be_stream_type(&mut recv).await? else {
                return Ok(());
            };
            if matches!(
                stream_type,
                StreamType::Control | StreamType::QpackEncoder | StreamType::QpackDecoder
            ) {
                // Claim before reading any payload. Receive tasks share this atomic
                // bitset for the connection's lifetime; claims are never released.
                let bit = 1 << (stream_type as u8);
                if peer_critical_streams.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
                    return Err(ErrorCode::H3_STREAM_CREATION_ERROR
                        .reason(format!("duplicate peer {stream_type:?} stream")));
                }
            }
            match stream_type {
                StreamType::Control => {
                    self.control
                        .receive_control(
                            &mut recv,
                            self.transport.role(),
                            |settings| {
                                let (peer, max_fields) = crate::protocol::qpack::limits(settings);
                                self.qpack.configure(peer, max_fields)
                            },
                            |id| {
                                self.bi_streams
                                    .lock()
                                    .unwrap()
                                    .receive_goaway(id, self.qpack.clone())
                            },
                        )
                        .await
                }
                StreamType::Push => {
                    Err(ErrorCode::H3_ID_ERROR.reason("invalid stream or push identifier"))
                }
                StreamType::QpackEncoder => self.qpack.receive_encoder(&mut recv).await,
                StreamType::QpackDecoder => self.qpack.receive_decoder(&mut recv).await,
            }
        };
        let result = tokio::select! {
            biased;
            error = self.qpack.failed() => Err(error),
            result = result => result,
        };
        // Retain the half until failure handling completes, including transport close.
        if let Err(error) = result {
            let error = self.qpack.on_error(error);
            let _ = self.transport.close(error.reason, error.code.as_u64());
        }
    }

    /// Apply the failure observed by stream I/O and wake H3-level waiters.
    pub(crate) fn on_terminated(&self, error: Error) {
        let error = self.qpack.on_error(error);
        self.bi_streams.lock().unwrap().close(error);
    }
}
