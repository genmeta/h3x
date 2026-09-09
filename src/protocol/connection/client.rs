//! Outgoing requests: submit headers, upload, then read the response independently.
use http_body::Body;
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};

use super::*;
use crate::{body, platform::MaybeSend};

impl<T: transport::Connection> Connection<T> {
    pub async fn request<B>(
        &self,
        request: http::Request<B>,
    ) -> Result<http::Response<ChunkBody>, Error>
    where
        B: Body<Data = Bytes> + MaybeSend + 'static,
        B::Error: Into<crate::BoxError>,
    {
        let (parts, body) = request.into_parts();
        headers::validate_request(&parts).map_err(Error::into_invalid_message)?;
        let message_body = message::request_body(&parts)?;
        message_body.validate_size(body.size_hint())?;
        let (response, write_body_handler) = self
            .inner
            .exec(
                parts,
                Outgoing::Body(
                    body.map_err(|e| Error::Body {
                        source: Arc::from(e.into()),
                    })
                    .boxed_unsync(),
                ),
            )
            .await?;
        let mut cancellation = AbortOnDrop(Some(write_body_handler));
        let result = response.await;
        if result.is_ok() {
            cancellation.0.take();
        } // Final delivery leaves upload independently owned.
        result
    }

    pub async fn request_streaming(
        &self,
        parts: http::request::Parts,
    ) -> Result<(BodyWriter, ResponseFuture), Error> {
        headers::validate_request(&parts).map_err(Error::into_invalid_message)?;
        let (mut writer, upload) = BodyWriter::channel();
        let (response, write_body_handler) =
            self.inner.exec(parts, Outgoing::Upload(upload)).await?;
        writer.cancel_with(write_body_handler);
        Ok((writer, response))
    }
}

impl<T: transport::Connection> H3Connection<T> {
    async fn exec(
        self: &Arc<Self>,
        request_head: http::request::Parts,
        request_body: Outgoing,
    ) -> Result<(ResponseFuture, AbortHandle), Error> {
        let message_body =
            message::request_body(&request_head).map_err(Error::into_invalid_message)?;
        let method = request_head.method.clone();
        let fields = headers::request_fields(request_head).map_err(Error::into_invalid_message)?;
        let (preparation, preparation_cancel) = self.prepare_request()?;
        let work = async {
            let (stream_id, (read_stream, write_stream)) = self
                .transport
                .open_bi()
                .await
                .map_err(map_connection_error)?;
            let mut reader = MessageReader::new(
                ChunkReader::new(stream_id, read_stream),
                self.qpack.clone(),
                stream_id,
            );
            let mut writer = ResetOnDrop::new(write_stream);
            let (response_waiter, pending_response, response_cancel) =
                self.register_pending_response(stream_id)?;
            self.track_request(&mut reader, &mut writer);
            let encoded_headers = self.qpack.encode_fields(stream_id, fields).await?;
            write_frame(writer.writer(), wire::FrameType::Headers, encoded_headers).await?;

            // Shutdown and task handoff are decided under the same state lock.
            let state = self.state.lock().unwrap();
            if state.terminated {
                return Err(self.failure());
            }
            if state.goaway.local_boundary.is_some() {
                return Err(Error::Draining);
            }
            if !state.pending_responses.contains_key(&stream_id) {
                return Err(state
                    .goaway
                    .peer_boundary
                    .map_or(Error::Cancelled, |boundary| Error::Goaway { boundary }));
            }
            let inner = self.clone();
            let (write_body_handler, upload_cancel) = AbortHandle::new_pair();
            self.tasks.spawn(self.clone(), async move {
                inner
                    .write_body(stream_id, writer, request_body, message_body, upload_cancel)
                    .await
            });
            let mut upload_start = AbortOnDrop(Some(write_body_handler));
            self.tasks.spawn(
                self.clone(),
                cancel_on_abort(
                    self.clone().read_response(pending_response, reader, method),
                    response_cancel,
                ),
            );
            drop(state);
            Ok((response_waiter, upload_start.0.take().unwrap()))
        };
        let result = self
            .until_stopped(cancel_on_abort(work, preparation_cancel))
            .await;
        // Stream cleanup now updates the request state; preparation can finish.
        drop(preparation);
        result
    }

    /// Upload owns the send direction; failure reaches a still-pending response.
    async fn write_body(
        &self,
        stream_id: StreamId,
        mut writer: ResetOnDrop,
        mut outgoing: Outgoing,
        message_body: MessageBody,
        upload_cancel: AbortRegistration,
    ) -> Result<(), Error> {
        let work = async {
            match &mut outgoing {
                Outgoing::Body(body) => {
                    message::send_body(&mut writer, body, message_body, &self.qpack, stream_id)
                        .await
                }
                Outgoing::Upload(upload) => {
                    message::send_upload(&mut writer, upload, message_body, &self.qpack, stream_id)
                        .await
                }
            }
        };
        let result = self
            .until_stopped(cancel_on_abort(work, upload_cancel))
            .await;
        if let Outgoing::Upload(upload) = outgoing {
            upload.complete(result.clone());
        }
        if let Err(error) = &result {
            writer.reset(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
            self.complete_response(stream_id, Err(error.clone()));
        }
        result
    }

    /// Final headers complete the waiter; the returned Body owns further reads.
    async fn read_response(
        self: Arc<Self>,
        pending: PendingResponse<T>,
        mut reader: MessageReader,
        method: http::Method,
    ) -> Result<(), Error> {
        let result = async {
            let (parts, message_body) = self.until_stopped(reader.response(&method)).await?;
            let body = self.wrap_body(reader, message_body);
            let mut response = http::Response::from_parts(parts, body);
            response.extensions_mut().insert(pending.stream_id);
            Ok(response)
        }
        .await;
        let completion = result.as_ref().map(|_| ()).map_err(Clone::clone);
        self.complete_response(pending.stream_id, result);
        completion
    }
}

pub(super) enum Outgoing {
    Body(UnsyncBoxBody<Bytes, Error>),
    Upload(body::Upload),
}

pub(super) struct AbortOnDrop(pub(super) Option<AbortHandle>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(stop) = self.0.take() {
            stop.abort();
        }
    }
}
