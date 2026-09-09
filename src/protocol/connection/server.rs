//! Read a request and send its response on the same bidirectional stream.
use dquic::prelude::{StreamReader, StreamWriter};
use http_body::Body;
use http_body_util::BodyExt;

use super::*;
use crate::protocol::message::{response_body, send_body};

impl<T: transport::Connection> Connection<T> {
    /// Read a request from a peer bidirectional stream and retain its reply direction.
    /// Run each stream in its own task so stalled headers do not block other requests.
    /// Dropping this future cancels both directions. An empty stream returns None.
    pub fn read_request(
        &self,
        id: StreamId,
        recv: StreamReader,
        send: StreamWriter,
    ) -> impl Future<Output = Result<Option<(http::Request<ChunkBody>, ResponseSender)>, Error>>
    + Send
    + 'static {
        let inner = self.inner().clone();
        let mut reader = ChunkReader::new(id, recv);
        let mut writer = BodyWriter::new(send, inner.qpack.clone(), id, MessageBody::Unknown);
        async move {
            let _admission = {
                let goaway = inner.goaway.lock().unwrap();
                if inner.terminal.borrow().is_some() {
                    return Err(inner.failure());
                }
                if goaway.local_boundary.is_some() {
                    writer.reset(Code::H3_REQUEST_REJECTED);
                    reader.stop(Code::H3_REQUEST_REJECTED);
                    return Err(Error::request_rejected("connection draining"));
                }
                inner.drain.guard()
            };
            let work = async {
                let Some(first) = reader.read_varint().await? else {
                    return Ok(None);
                };
                #[cfg(feature = "webtransport")]
                if first == wire::WEBTRANSPORT_BIDI_SIGNAL {
                    reader.read_varint().await?.ok_or_else(|| {
                        Error::connection_protocol(
                            Code::H3_FRAME_ERROR,
                            "missing WebTransport session ID",
                        )
                    })?;
                    reader.stop(Code::WT_BUFFERED_STREAM_REJECTED);
                    writer.reset(Code::WT_BUFFERED_STREAM_REJECTED);
                    return Ok(None);
                }
                let mut reader = MessageReader::new(reader, inner.qpack.clone(), id);
                let reading = inner.drain.guard();
                let writing = inner.drain.guard();
                reader.on_finish(move || drop(reading));
                writer.writing = Some(writing);
                let (parts, message_body) = reader.request(first).await?;
                // Delivery and GOAWAY share the lock: either this request is included
                // in the drain boundary, or it is rejected before reaching the service.
                {
                    let mut goaway = inner.goaway.lock().unwrap();
                    if inner.terminal.borrow().is_some() {
                        return Err(inner.failure());
                    }
                    if goaway.local_boundary.is_some() {
                        drop(goaway);
                        writer.reset(Code::H3_REQUEST_REJECTED);
                        return Err(reader.fail(Error::request_rejected("connection draining")));
                    }
                    goaway.max_delivered =
                        Some(goaway.max_delivered.map_or(id, |previous| previous.max(id)));
                }
                let method = parts.method.clone();
                let mut request =
                    http::Request::from_parts(parts, inner.wrap_body(reader, message_body));
                request.extensions_mut().insert(id);
                let reply = ResponseSender {
                    stream_id: id,
                    method,
                    writer,
                    qpack: inner.qpack.clone(),
                    terminal: inner.terminal.clone(),
                };
                Ok(Some((request, reply)))
            };
            inner
                .run_or_terminate(async {
                    tokio::select! {
                        error = inner.local_shutdown() => Err(error),
                        result = work => result,
                    }
                })
                .await
        }
    }
}

/// The unique sending capability for an accepted request.
pub struct ResponseSender {
    pub(super) stream_id: StreamId,
    pub(super) method: http::Method,
    pub(super) writer: BodyWriter,
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
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<crate::BoxError>,
    {
        let (parts, body) = response.into_parts();
        let message_body =
            response_body(&self.method, &parts, true).map_err(Error::into_invalid_message)?;
        message_body.validate_size(body.size_hint())?;
        let fields = headers::response_fields(parts).map_err(Error::into_invalid_message)?;
        let mut body = body
            .map_err(|e| Error::Body {
                source: Arc::from(e.into()),
            })
            .boxed_unsync();
        let result = tokio::select! {
            biased;
            error = stopped(&self.terminal) => Err(error),
            result = async {
                let encoded = self.qpack.encode_fields(self.stream_id, fields).await?;
                write_frame(self.writer.stream(), wire::FrameType::Headers, encoded).await?;
                send_body(&mut self.writer, &mut body, message_body, &self.qpack, self.stream_id).await
            } => result,
        };
        if let Err(error) = &result {
            self.writer
                .reset(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
        }
        self.qpack.terminate_on_connection_error(result)
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn webtransport_runtime(&self) -> Option<Arc<crate::webtransport::Runtime>> {
        None
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn webtransport_keepalive(&self) -> std::sync::Arc<dyn Send + Sync> {
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
