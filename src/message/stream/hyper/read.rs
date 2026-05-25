use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{StreamExt, stream};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Empty, StreamBody};

use super::{
    MessageStreamError, ReadStream,
    upgrade::{RemainStream, TakeoverSlot},
};
use crate::error::H3MessageError;

pin_project_lite::pin_project! {
    #[project = EitherProj]
    pub enum Either<L, R> {
        Left { #[pin] body: L },
        Right { #[pin] body: R }
    }
}

impl<L, R> Either<L, R> {
    pub fn left(body: L) -> Self {
        Self::Left { body }
    }

    pub fn right(body: R) -> Self {
        Self::Right { body }
    }
}

impl<L: Body, R: Body<Data = L::Data, Error = L::Error>> Body for Either<L, R> {
    type Data = L::Data;
    type Error = L::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            EitherProj::Left { body } => body.poll_frame(cx),
            EitherProj::Right { body } => body.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Either::Left { body } => body.is_end_stream(),
            Either::Right { body } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Either::Left { body } => body.size_hint(),
            Either::Right { body } => body.size_hint(),
        }
    }
}

impl ReadStream {
    pub async fn read_hyper_request_parts(
        &mut self,
    ) -> Result<http::request::Parts, MessageStreamError> {
        let Some(field_section) = self.read_header().await? else {
            let error = self
                .handle_stream_error(H3MessageError::MissingHeaderSection.into())
                .await;
            return Err(error.into());
        };
        match http::request::Parts::try_from(field_section) {
            Ok(parts) => Ok(parts),
            Err(error) => {
                let error = self.handle_stream_error(error.into()).await;
                Err(error.into())
            }
        }
    }

    pub async fn read_hyper_response_parts(
        &mut self,
    ) -> Result<http::response::Parts, MessageStreamError> {
        let Some(field_section) = self.read_header().await? else {
            let error = self
                .handle_stream_error(H3MessageError::MissingHeaderSection.into())
                .await;
            return Err(error.into());
        };
        match http::response::Parts::try_from(field_section) {
            Ok(parts) => Ok(parts),
            Err(error) => {
                let error = self.handle_stream_error(error.into()).await;
                Err(error.into())
            }
        }
    }

    pub async fn read_hyper_frame(&mut self) -> Result<Option<Frame<Bytes>>, MessageStreamError> {
        if let Some(data) = self.read_data_chunk().await? {
            return Ok(Some(Frame::data(data)));
        }

        let Some(field_section) = self.read_header().await? else {
            return Ok(None);
        };

        if !field_section.is_trailer() {
            let error = self
                .handle_stream_error(H3MessageError::UnexpectedHeadersInBody.into())
                .await;
            return Err(error.into());
        }

        Ok(Some(Frame::trailers(field_section.into_header_map())))
    }

    pub fn as_hyper_body(&mut self) -> impl Body<Data = Bytes, Error = MessageStreamError> + Send {
        StreamBody::new(
            stream::unfold(self, async |stream| {
                let frame = stream.read_hyper_frame().await.transpose()?;
                Some((frame, stream))
            })
            .fuse(),
        )
    }

    pub fn into_hyper_body(self) -> impl Body<Data = Bytes, Error = MessageStreamError> + Send {
        StreamBody::new(
            stream::unfold(self, async |mut stream| {
                let frame = stream.read_hyper_frame().await.transpose()?;
                Some((frame, stream))
            })
            .fuse(),
        )
    }

    pub async fn into_hyper_request(
        mut self,
    ) -> Result<
        http::Request<impl Body<Data = Bytes, Error = MessageStreamError> + Send>,
        MessageStreamError,
    > {
        let mut parts = self.read_hyper_request_parts().await?;
        if parts.method == http::Method::CONNECT {
            parts
                .extensions
                .insert(TakeoverSlot::new(RemainStream::immediately(self)));
            let body = Either::right(Empty::new().map_err(|n| match n {}));
            Ok(http::Request::from_parts(parts, body))
        } else {
            let body = Either::left(self.into_hyper_body());
            Ok(http::Request::from_parts(parts, body))
        }
    }

    pub async fn into_hyper_response(
        mut self,
    ) -> Result<
        http::Response<impl Body<Data = Bytes, Error = MessageStreamError> + Send>,
        MessageStreamError,
    > {
        let mut parts = self.read_hyper_response_parts().await?;
        match parts.status.is_informational() {
            true => {
                parts.extensions.insert(RemainStream::immediately(self));
                let body = Either::right(Empty::new().map_err(|n| match n {}));
                Ok(http::Response::from_parts(parts, body))
            }
            false => {
                // no remain
                let body = self.into_hyper_body();
                Ok(http::Response::from_parts(parts, Either::left(body)))
            }
        }
    }
}
