//! Outgoing requests: submit headers, upload, then read the response independently.
use http_body::Body;
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};

use super::*;

impl<T: transport::Connection> Connection<T> {
    pub async fn request<B>(
        &self,
        request: http::Request<B>,
    ) -> Result<http::Response<ChunkBody>, Error>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<crate::BoxError>,
    {
        let (parts, body) = request.into_parts();
        let message_body = message::request_body(&parts).map_err(Error::into_invalid_message)?;
        let method = parts.method.clone();
        let fields = headers::request_fields(parts).map_err(Error::into_invalid_message)?;
        message_body.validate_size(body.size_hint())?;
        let (response, work) = self
            .inner()
            .exec(
                (method, fields, message_body),
                Some(
                    body.map_err(|e| Error::Body {
                        source: Arc::from(e.into()),
                    })
                    .boxed_unsync(),
                ),
            )
            .await?;
        let RequestWork::Automatic(mut cancellation) = work else {
            unreachable!()
        };
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
        let message_body = message::request_body(&parts).map_err(Error::into_invalid_message)?;
        let method = parts.method.clone();
        let fields = headers::request_fields(parts).map_err(Error::into_invalid_message)?;
        let (response, work) = self
            .inner()
            .exec((method, fields, message_body), None)
            .await?;
        let RequestWork::Streaming(writer) = work else {
            unreachable!()
        };
        Ok((writer, response))
    }
}

impl<T: transport::Connection> H3Connection<T> {
    async fn exec(
        self: &Arc<Self>,
        prepared: (http::Method, Vec<qpack::Field>, MessageBody),
        request_body: Option<UnsyncBoxBody<Bytes, Error>>,
    ) -> Result<(ResponseFuture, RequestWork), Error> {
        let (method, fields, message_body) = prepared;
        let preparation = {
            let goaway = self.goaway.lock().unwrap();
            if self.terminal.borrow().is_some() {
                return Err(self.failure());
            }
            if let Some(boundary) = goaway.peer_boundary {
                return Err(Error::Goaway { boundary });
            }
            if goaway.local_boundary.is_some() {
                return Err(Error::Draining);
            }
            self.drain.guard()
        };
        let work = async {
            let (stream_id, (read_stream, write_stream)) = tokio::select! {
                error = self.peer_rejected(None) => return Err(error),
                result = self.transport.open_bi() => result.map_err(map_connection_error)?,
            };
            let mut reader = MessageReader::new(
                ChunkReader::new(stream_id, read_stream),
                self.qpack.clone(),
                stream_id,
            );
            let mut writer =
                BodyWriter::new(write_stream, self.qpack.clone(), stream_id, message_body);
            let (reply, receive) = oneshot::channel();
            let (stop, response_cancel) = AbortHandle::new_pair();
            let response_waiter = ResponseFuture {
                reply: receive,
                stop: Some(stop),
            };
            let (upload_failed, upload_error) = oneshot::channel();
            let reading = self.drain.guard();
            let writing = self.drain.guard();
            reader.on_finish(move || drop(reading));
            writer.writing = Some(writing);
            tokio::select! {
                error = self.peer_rejected(Some(stream_id)) => return Err(error),
                result = async {
                    let encoded = self.qpack.encode_fields(stream_id, fields).await?;
                    write_frame(writer.stream(), wire::FrameType::Headers, encoded).await
                } => result?,
            }

            // Declare the owned handoff before the lock so unwinding releases
            // the admission lock before a streaming writer runs its cleanup.
            let sending;
            // Shutdown and task handoff are decided under the same GOAWAY lock.
            let goaway = self.goaway.lock().unwrap();
            if self.terminal.borrow().is_some() {
                return Err(self.failure());
            }
            if goaway.local_boundary.is_some() {
                return Err(Error::Draining);
            }
            if let Some(boundary) = goaway.peer_boundary
                && stream_id >= boundary
            {
                return Err(Error::Goaway { boundary });
            }
            sending = match request_body {
                Some(body) => {
                    let inner = self.clone();
                    let (write_body_handler, upload_cancel) = AbortHandle::new_pair();
                    self.tasks.spawn(self.clone(), async move {
                        let result = inner
                            .write_body(stream_id, writer, body, message_body, upload_cancel)
                            .await;
                        if let Err(error) = &result {
                            let _ = upload_failed.send(error.clone());
                        }
                        result
                    });
                    RequestWork::Automatic(AbortOnDrop(Some(write_body_handler)))
                }
                None => {
                    writer.report_upload_failure(upload_failed);
                    RequestWork::Streaming(writer)
                }
            };
            self.tasks.spawn(
                self.clone(),
                self.clone().read_response(
                    stream_id,
                    reader,
                    method,
                    reply,
                    upload_error,
                    response_cancel,
                ),
            );
            drop(goaway);
            Ok((response_waiter, sending))
        };
        let result = self
            .run_or_terminate(async {
                tokio::select! {
                    error = self.local_shutdown() => Err(error),
                    result = work => result,
                }
            })
            .await;
        // The stream guards are now responsible for draining; release preparation.
        drop(preparation);
        result
    }

    /// Upload owns the send direction; failure reaches a still-pending response.
    async fn write_body(
        &self,
        stream_id: StreamId,
        mut writer: BodyWriter,
        mut body: UnsyncBoxBody<Bytes, Error>,
        message_body: MessageBody,
        upload_cancel: AbortRegistration,
    ) -> Result<(), Error> {
        let work = message::send_body(&mut writer, &mut body, message_body, &self.qpack, stream_id);
        let result = self
            .run_or_terminate(cancel_on_abort(work, upload_cancel))
            .await;
        if let Err(error) = &result {
            writer.reset(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
        }
        result
    }

    /// This task owns its waiter and observes only its own upload/GOAWAY failures.
    async fn read_response(
        self: Arc<Self>,
        stream_id: StreamId,
        mut reader: MessageReader,
        method: http::Method,
        reply: ResponseReply,
        mut upload_error: oneshot::Receiver<Error>,
        cancellation: AbortRegistration,
    ) -> Result<(), Error> {
        let work = async {
            let (parts, message_body) = tokio::select! {
                biased;
                Ok(error) = &mut upload_error => return Err(error),
                error = self.peer_rejected(Some(stream_id)) => return Err(error),
                result = reader.response(&method) => result?,
            };
            let body = self.wrap_body(reader, message_body);
            let mut response = http::Response::from_parts(parts, body);
            response.extensions_mut().insert(stream_id);
            // Final delivery and GOAWAY are decided under the same lock.
            // Declare the response first so its Body is never dropped under that lock.
            let goaway = self.goaway.lock().unwrap();
            if self.terminal.borrow().is_some() {
                return Err(self.failure());
            }
            if let Some(boundary) = goaway.peer_boundary
                && stream_id >= boundary
            {
                return Err(Error::Goaway { boundary });
            }
            Ok(response)
        };
        let result = self
            .run_or_terminate(cancel_on_abort(work, cancellation))
            .await;
        let completion = result.as_ref().map(|_| ()).map_err(Clone::clone);
        let _ = reply.send(result);
        completion
    }
}

enum RequestWork {
    Automatic(AbortOnDrop),
    Streaming(BodyWriter),
}

pub(super) struct AbortOnDrop(pub(super) Option<AbortHandle>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(stop) = self.0.take() {
            stop.abort();
        }
    }
}
