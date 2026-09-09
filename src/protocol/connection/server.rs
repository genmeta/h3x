//! Incoming requests: accept, read headers, deliver, then respond on the same stream.
use dquic::prelude::{StreamReader, StreamWriter};
use http_body::Body;
use http_body_util::BodyExt;

use super::*;
use crate::{
    platform::MaybeSend,
    protocol::message::{response_body, send_body},
};

impl<T: transport::Connection> Connection<T> {
    pub async fn accept(
        &self,
    ) -> Result<Option<(http::Request<ChunkBody>, ResponseSender)>, Error> {
        let _accepting = self.accepting.lock().await;
        loop {
            let queued = {
                let mut state = self.inner.state.lock().unwrap();
                if state.terminated {
                    let error = self.inner.failure();
                    return if error.code() == Some(Code::H3_NO_ERROR) {
                        Ok(None)
                    } else {
                        Err(error)
                    };
                }
                let queued = state.queued.pop_front();
                if let Some(queued) = &queued {
                    state.goaway.max_delivered = Some(
                        state
                            .goaway
                            .max_delivered
                            .map_or(queued.stream_id, |previous| previous.max(queued.stream_id)),
                    );
                }
                queued
            };
            let Some(queued) = queued else {
                tokio::select! {
                    _ = stopped(&self.inner.terminal) => {},
                    _ = self.inner.request_ready.notified() => {},
                }
                continue;
            };
            let method = queued.request_head.method.clone();
            let body = self.inner.wrap_body(queued.reader, queued.message_body);
            let mut request = http::Request::from_parts(queued.request_head, body);
            request.extensions_mut().insert(queued.stream_id);
            let response_sender = ResponseSender {
                stream_id: queued.stream_id,
                method,
                writer: queued.writer,
                qpack: self.inner.qpack.clone(),
                terminal: self.inner.terminal.clone(),
            };
            return Ok(Some((request, response_sender)));
        }
    }
}

impl<T: transport::Connection> H3Connection<T> {
    pub(super) async fn accept_requests(self: &Arc<Self>) -> Result<(), Error> {
        let classifying = Arc::new(Semaphore::new(MAX_CLASSIFYING));
        loop {
            tokio::task::consume_budget().await;
            let (id, (mut recv, mut send)) = self
                .transport
                .accept_bi()
                .await
                .map_err(map_connection_error)?;
            let Some(permit) = reserve_classification(&classifying, &mut recv, &mut send) else {
                continue;
            };
            let inner = self.clone();
            self.tasks.spawn(self.clone(), async move {
                inner.read_request(id, recv, send, permit).await
            });
        }
    }

    pub(super) async fn read_request(
        self: Arc<Self>,
        id: StreamId,
        recv: StreamReader,
        send: StreamWriter,
        classification: OwnedSemaphorePermit,
    ) -> Result<(), Error> {
        let mut reader = ChunkReader::new(id, recv);
        let mut writer = ResetOnDrop::new(send);
        let first = self.until_stopped(reader.read_varint()).await?;
        let Some(first) = first else {
            return Ok(());
        };
        #[cfg(feature = "webtransport")]
        if first == wire::WEBTRANSPORT_BIDI_SIGNAL {
            let _session = self
                .until_stopped(reader.read_varint())
                .await?
                .ok_or_else(|| {
                    Error::connection_protocol(
                        Code::H3_FRAME_ERROR,
                        "missing WebTransport session ID",
                    )
                })?;
            // No WT transport hooks are attached to a plain HTTP connection.
            reader.stop(Code::WT_BUFFERED_STREAM_REJECTED)?;
            writer.reset(Code::WT_BUFFERED_STREAM_REJECTED);
            return Ok(());
        }
        let (stop, registration) = AbortHandle::new_pair();
        self.register_incoming(id, stop, &mut reader, &mut writer)?;
        drop(classification);
        let _pending = PendingIncoming {
            connection: self.clone(),
            stream_id: id,
        };
        let mut reader = MessageReader::new(reader, self.qpack.clone(), id);
        self.track_request(&mut reader, &mut writer);
        let work = async {
            let (parts, message_body) = self.until_stopped(reader.request(first)).await?;
            let queued = QueuedRequest {
                stream_id: id,
                request_head: parts,
                reader,
                message_body,
                writer,
            };
            self.deliver_request(queued)
        };
        cancel_on_abort(work, registration).await
    }
}

/// The unique sending capability for an accepted request.
pub struct ResponseSender {
    pub(super) stream_id: StreamId,
    pub(super) method: http::Method,
    pub(super) writer: ResetOnDrop,
    pub(super) qpack: Arc<qpack::Qpack>,
    pub(super) terminal: watch::Sender<Option<Error>>,
}
impl std::fmt::Debug for ResponseSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseSender")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}
impl ResponseSender {
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub async fn send<B>(mut self, response: http::Response<B>) -> Result<(), Error>
    where
        B: Body<Data = Bytes> + MaybeSend + 'static,
        B::Error: Into<crate::BoxError>,
    {
        let (parts, body) = response.into_parts();
        let message_body =
            response_body(&self.method, &parts, true).map_err(Error::into_invalid_message)?;
        message_body.validate_size(body.size_hint())?;
        let mut body = body
            .map_err(|e| Error::Body {
                source: Arc::from(e.into()),
            })
            .boxed_unsync();
        let result = tokio::select! {
            biased;
            error = stopped(&self.terminal) => Err(error),
            result = async {
                let encoded = self.qpack.encode_response(self.stream_id, parts).await?;
                write_frame(self.writer.writer(), wire::FrameType::Headers, encoded).await?;
                send_body(&mut self.writer, &mut body, message_body, &self.qpack, self.stream_id).await
            } => result,
        };
        if let Err(error) = &result {
            self.writer
                .reset(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
        }
        self.qpack.fail_on_connection(result)
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn webtransport_runtime(&self) -> Option<Arc<crate::webtransport::Runtime>> {
        None
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn webtransport_keepalive(&self) -> crate::platform::KeepAlive {
        Arc::new(())
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn reject(self, _code: Code) {
        drop(self);
    }

    #[cfg(feature = "webtransport")]
    pub(crate) async fn start_webtransport_response(
        self,
        _response: http::Response<()>,
    ) -> Result<StreamWriter, Error> {
        Err(Error::Unsupported {
            operation: "WebTransport upgrade",
        })
    }
}

impl<T: transport::Connection> H3Connection<T> {
    pub(super) fn deliver_request(&self, mut queued: QueuedRequest) -> Result<(), Error> {
        let mut state = self.state.lock().unwrap();
        if state.terminated {
            return Err(self.failure());
        }
        if state.goaway.local_boundary.is_some() || state.queued.len() == REQUEST_QUEUE_SIZE {
            drop(state);
            let error = Error::request_rejected("connection draining or request queue full");
            queued.writer.reset(Code::H3_REQUEST_REJECTED);
            queued.reader.fail(error.clone());
            return Err(error);
        }
        state.queued.push_back(queued);
        self.request_ready.notify_one();
        Ok(())
    }
}

pub(super) fn reserve_classification(
    classifying: &Arc<Semaphore>,
    recv: &mut StreamReader,
    send: &mut StreamWriter,
) -> Option<OwnedSemaphorePermit> {
    match classifying.clone().try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            dquic::prelude::StopSending::stop(recv, Code::H3_REQUEST_REJECTED.as_u64());
            dquic::prelude::CancelStream::cancel(send, Code::H3_REQUEST_REJECTED.as_u64());
            None
        }
    }
}
