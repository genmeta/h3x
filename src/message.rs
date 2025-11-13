use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::codec::error::DecodeStreamError;

pub struct Body {}

impl http_body::Body for Body {
    type Data = Bytes;

    type Error = DecodeStreamError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        todo!()
    }
}
