#![allow(dead_code)]

use futures::{Sink, Stream};

pub(crate) trait FrameIo<Out, In, Error>:
    Sink<Out, Error = Error> + Stream<Item = Result<In, Error>>
{
}

impl<T, Out, In, Error> FrameIo<Out, In, Error> for T where
    T: Sink<Out, Error = Error> + Stream<Item = Result<In, Error>>
{
}
