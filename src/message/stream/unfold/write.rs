//! since futures::sink::unfold only works for send, we implement our own version here to support flush and close as well.

use std::{
    ops::Deref,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::Sink;

use super::super::{MessageStreamError, WriteStream};
use crate::{
    codec::SinkWriter,
    quic::{self, CancelStream, GetStreamId},
    varint::VarInt,
};

/// A message-level byte sink that also supports QUIC stream control operations.
///
/// This is the message-layer analog of [`quic::WriteStream`], combining DATA-frame
/// byte sinking with the underlying QUIC stream's [`CancelStream`] and
/// [`GetStreamId`] capabilities.
pub trait WriteMessageStream:
    CancelStream + GetStreamId + Sink<Bytes, Error = MessageStreamError> + Send
{
}

impl<T: CancelStream + GetStreamId + Sink<Bytes, Error = MessageStreamError> + Send + ?Sized>
    WriteMessageStream for T
{
}

/// Boxed stream writer with QUIC stream control traits preserved.
pub type BoxMessageStreamWriter<'s> = SinkWriter<Pin<Box<dyn WriteMessageStream + 's>>>;

// ---------------------------------------------------------------------------
// Unfold – custom sink unfold that preserves QUIC traits
// ---------------------------------------------------------------------------

pin_project_lite::pin_project! {
    #[project = StateProj]
    #[project_replace = StateProjReplace]
    #[derive(Debug)]
    enum State<T, S, F, C> {
        Value {
            value: T,
        },
        Send {
            #[pin]
            future: S,
        },
        Flush {
            #[pin]
            future: F,
        },
        Close {
            #[pin]
            future: C,
        },
        Empty,
    }
}

impl<T, S, F, C> State<T, S, F, C> {
    fn take_value(self: Pin<&mut Self>) -> Option<T> {
        match &*self {
            Self::Value { .. } => match self.project_replace(Self::Empty) {
                StateProjReplace::Value { value } => Some(value),
                _ => unreachable!(),
            },
            _ => None,
        }
    }

    fn poll_value<E>(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<T, E>>
    where
        S: Future<Output = Result<T, E>>,
        F: Future<Output = Result<T, E>>,
        C: Future<Output = Result<T, E>>,
    {
        match self.as_mut().project() {
            StateProj::Send { future } => future.poll(cx),
            StateProj::Flush { future } => future.poll(cx),
            StateProj::Close { future } => future.poll(cx),
            StateProj::Value { .. } | StateProj::Empty => {
                Poll::Ready(Ok(self.take_value().expect("value lost, this is a bug")))
            }
        }
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    #[must_use = "sinks do nothing unless polled"]
    pub struct Unfold<T, S, F, C, SF, FF, CF> {
        send: S,
        flush: F,
        close: C,
        #[pin]
        state: State<T, SF, FF, CF>,
    }
}

impl<T, S, F, C, SF, FF, CF, Item, E> Sink<Item> for Unfold<T, S, F, C, SF, FF, CF>
where
    S: FnMut(T, Item) -> SF,
    SF: Future<Output = Result<T, E>>,
    F: FnMut(T) -> FF,
    FF: Future<Output = Result<T, E>>,
    C: FnMut(T) -> CF,
    CF: Future<Output = Result<T, E>>,
{
    type Error = E;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut project = self.project();
        let value = ready!(project.state.as_mut().poll_value(cx)?);
        project.state.set(State::Value { value });
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        let mut project = self.project();
        let future = match project.state.as_mut().take_value() {
            Some(value) => (project.send)(value, item),
            None => panic!("start_send called without poll_ready being called first"),
        };
        project.state.set(State::Send { future });
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            if matches!(self.deref().state, State::Flush { .. }) {
                return self.poll_ready(cx);
            }

            let mut project = self.as_mut().project();
            let value = ready!(project.state.as_mut().poll_value(cx))?;
            project.state.set(State::Flush {
                future: (project.flush)(value),
            });
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            if matches!(self.deref().state, State::Close { .. }) {
                return self.poll_ready(cx);
            }

            let mut project = self.as_mut().project();
            let value = ready!(project.state.as_mut().poll_value(cx))?;
            project.state.set(State::Close {
                future: (project.close)(value),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// QUIC control trait forwarding for Unfold
// ---------------------------------------------------------------------------

impl<T: GetStreamId + Unpin, S, F, C, SF, FF, CF> GetStreamId
    for Unfold<T, S, F, C, SF, FF, CF>
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let this = self.project();
        match this.state.project() {
            StateProj::Value { value } => Pin::new(value).poll_stream_id(cx),
            _ => Poll::Pending,
        }
    }
}

impl<T: CancelStream + Unpin, S, F, C, SF, FF, CF> CancelStream
    for Unfold<T, S, F, C, SF, FF, CF>
{
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let this = self.project();
        match this.state.project() {
            StateProj::Value { value } => Pin::new(value).poll_cancel(cx, code),
            _ => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Unfold constructor
// ---------------------------------------------------------------------------

pub fn unfold<T, S, F, C, SF, FF, CF, Item, E>(
    init: T,
    send: S,
    flush: F,
    close: C,
) -> Unfold<T, S, F, C, SF, FF, CF>
where
    S: FnMut(T, Item) -> SF,
    SF: Future<Output = Result<T, E>>,
    F: FnMut(T) -> FF,
    FF: Future<Output = Result<T, E>>,
    C: FnMut(T) -> CF,
    CF: Future<Output = Result<T, E>>,
{
    let state = State::Value { value: init };
    Unfold {
        send,
        flush,
        close,
        state,
    }
}

// ---------------------------------------------------------------------------
// WriteStream conversion methods
// ---------------------------------------------------------------------------

impl WriteStream {
    pub fn as_bytes_sink(&mut self) -> impl WriteMessageStream + '_ {
        unfold(
            self,
            async |stream: &mut WriteStream, buf: Bytes| {
                stream.send_data(buf).await.map(|_| stream)
            },
            async |stream: &mut WriteStream| stream.flush().await.map(|_| stream),
            async |stream: &mut WriteStream| stream.close().await.map(|_| stream),
        )
    }

    pub fn as_writer(&mut self) -> SinkWriter<impl WriteMessageStream + '_> {
        SinkWriter::new(self.as_bytes_sink())
    }

    pub fn as_box_writer(&mut self) -> BoxMessageStreamWriter<'_> {
        SinkWriter::new(Box::pin(self.as_bytes_sink()))
    }

    pub fn into_bytes_sink(self) -> impl WriteMessageStream {
        unfold(
            self,
            async |mut stream: WriteStream, buf: Bytes| {
                stream.send_data(buf).await.map(|_| stream)
            },
            async |mut stream: WriteStream| stream.flush().await.map(|_| stream),
            async |mut stream: WriteStream| stream.close().await.map(|_| stream),
        )
    }

    pub fn into_writer(self) -> SinkWriter<impl WriteMessageStream> {
        SinkWriter::new(self.into_bytes_sink())
    }

    pub fn into_box_writer(self) -> BoxMessageStreamWriter<'static> {
        SinkWriter::new(Box::pin(self.into_bytes_sink()))
    }
}
