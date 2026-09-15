//! Peer unidirectional stream admission, dispatch, and task lifetime.
use qbase::sid::{Dir, StreamId};
use tokio::io::AsyncWriteExt;

use super::H3Connection;
use crate::{
    Error, Result, Transport,
    protocol::{
        frame::{self, Control, Frame, StreamType, WriteControl as _, be_control},
        qpack,
    },
};

impl<T: Transport> H3Connection<T> {
    pub(super) async fn accept_uni(self) {
        loop {
            match self.transport.accept_uni().await {
                Ok((_, recv)) => {
                    tokio::spawn(self.clone().receive(recv));
                }
                Err(error) => {
                    self.close(error);
                    return;
                }
            }
        }
    }

    async fn receive(self, mut recv: T::StreamReader) {
        let result = async {
            let Some(stream_type) = frame::be_stream_type(&mut recv).await? else {
                return Ok(());
            };
            match stream_type {
                StreamType::Control => self.receive_control(&mut recv).await,
                StreamType::Push => Err(Error::H3_ID_ERROR),
                StreamType::QpackEncoder => self.qpack.receive_encoder(&mut recv).await,
                StreamType::QpackDecoder => self.qpack.receive_decoder(&mut recv).await,
            }
        };
        let result = tokio::select! {
            biased;
            error = self.transport.terminated() => {
                self.close(error);
                return;
            }
            result = result => result,
        };
        // Retain the half until failure handling completes, including transport close.
        if let Err(error) = result {
            self.fail(error).await;
        }
    }

    fn close(&self, error: Error) {
        let error = self.qpack.close(error);
        self.bi_streams.close(error);
    }

    async fn fail(&self, error: Error) {
        // Prefer an existing transport result over a new protocol error.
        tokio::select! {
            biased;
            ended = self.transport.terminated() => self.close(ended),
            _ = std::future::ready(()) => {
                let error = self.qpack.close(error);
                let _ = self.transport.close(error.to_string(), error.as_u64());
                self.bi_streams.close(error);
            },
        }
    }
}

impl<T: Transport> H3Connection<T> {
    pub(super) async fn send_uni(self) {
        let mut send = match self.transport.open_uni().await {
            Ok(Some((_, send))) => send,
            Ok(None) => {
                self.fail(Error::H3_STREAM_CREATION_ERROR).await;
                return;
            }
            Err(error) => {
                self.close(error);
                return;
            }
        };
        let result = tokio::select! {
            biased;
            error = self.transport.terminated() => {
                self.close(error);
                return;
            }
            result = async {
                self.send_control(&mut send).await?;
                self.cursor.peer_goaway().await?;
                self.bi_streams.drained().await;
                self.transport
                    .close(Error::H3_NO_ERROR.to_string(), Error::H3_NO_ERROR.as_u64())
            } => result,
        };
        if let Err(error) = result {
            self.fail(error).await;
            return;
        }
        // Keep the critical stream open after GOAWAY until transport termination.
        let error = self.transport.terminated().await;
        self.close(error);
    }

    async fn send_control(&self, send: &mut T::StreamWriter) -> Result<()> {
        let mut bytes = vec![StreamType::Control as u8];
        bytes.put_control(&Control::Settings(Frame::new(self.settings.local.clone())?));
        async {
            send.write_all(&bytes).await?;
            send.flush().await
        }
        .await
        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;

        let id = self.cursor.local_goaway().await?;
        bytes.clear();
        bytes.put_control(&Control::Goaway(Frame::new(frame::Goaway {
            id: id.into(),
        })?));
        async {
            send.write_all(&bytes).await?;
            send.flush().await
        }
        .await
        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
        Ok(())
    }

    async fn receive_control(&self, recv: &mut T::StreamReader) -> Result<()> {
        let settings = match be_control(recv).await {
            Ok(Control::Settings(frame)) => frame.payload,
            Err(error) if error != Error::H3_FRAME_UNEXPECTED => return Err(error),
            _ => return Err(Error::H3_MISSING_SETTINGS),
        };
        let (peer, max_fields) = qpack::limits(&settings);
        self.qpack.configure(peer, max_fields)?;
        *self.settings.peer.lock().unwrap() = Some(settings);

        let role = self.transport.role();
        let mut last_goaway_id = None;
        loop {
            match be_control(recv).await? {
                Control::Goaway(frame) => {
                    let id = StreamId::from(frame.payload.id);
                    if id.role() != role
                        || id.dir() != Dir::Bi
                        || last_goaway_id.is_some_and(|previous| id > previous)
                    {
                        return Err(Error::H3_ID_ERROR);
                    }
                    last_goaway_id = Some(id);
                    self.bi_streams.goaway(u64::from(id), &self.qpack);
                    self.cursor.receive_goaway(id);
                }
                // Server push is not supported.
                Control::MaxPushId(_) | Control::CancelPush(_) => {
                    return Err(Error::H3_ID_ERROR);
                }
                Control::Unknown { length, .. } => {
                    frame::skip_payload(recv, length.into_u64())
                        .await
                        .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
                }
                _ => return Err(Error::H3_FRAME_UNEXPECTED),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        task::{Context, Waker},
        time::Duration,
    };

    use qbase::sid::{Dir, StreamId};

    use crate::{Error, Role, Transport, test_support};

    #[tokio::test]
    async fn cancelling_goaway_wait_keeps_control_drain_running() {
        let connection = test_support::connection();
        let mut closing = Box::pin(connection.clone().goaway());
        assert!(
            closing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(closing);
        tokio::task::yield_now().await;
        let mut ended = Box::pin(connection.transport.terminated());
        assert!(
            ended
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        connection
            .cursor
            .receive_goaway(StreamId::new(Role::Client, Dir::Bi, 0));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), ended)
                .await
                .unwrap(),
            Error::H3_NO_ERROR
        );
        assert!(connection.goaway().await.is_ok());
    }

    #[tokio::test]
    async fn goaway_reports_transport_failure() {
        let connection = test_support::connection();
        connection
            .transport
            .close(String::new(), Error::H3_INTERNAL_ERROR.as_u64())
            .unwrap();
        assert_eq!(connection.goaway().await, Err(Error::H3_INTERNAL_ERROR));
    }
}
