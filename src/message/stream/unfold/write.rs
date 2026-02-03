//! since futures::sink::unfold only works for send, we implement our own version here to support flush and close as well.

use std::{
    ops::Deref,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Buf;
use futures::Sink;

use super::super::{StreamError, WriteStream};

pin_project_lite::pin_project! {
    #[project = UnfoldStateProj]
    #[project_replace = UnfoldStateProjReplace]
    #[derive(Debug)]
    enum UnfoldState<T, S, F, C> {
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

impl<T, S, F, C> UnfoldState<T, S, F, C> {
    fn take_value(self: Pin<&mut Self>) -> Option<T> {
        match &*self {
            Self::Value { .. } => match self.project_replace(Self::Empty) {
                UnfoldStateProjReplace::Value { value } => Some(value),
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
            UnfoldStateProj::Send { future } => future.poll(cx),
            UnfoldStateProj::Flush { future } => future.poll(cx),
            UnfoldStateProj::Close { future } => future.poll(cx),
            UnfoldStateProj::Value { .. } | UnfoldStateProj::Empty => {
                Poll::Ready(Ok(self.take_value().expect("value lost, this is a bug")))
            }
        }
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    #[must_use = "sinks do nothing unless polled"]
    struct Unfold<T, S, F, C, SF, FF, CF> {
        send: S,
        flush: F,
        close: C,
        #[pin]
        state: UnfoldState<T, SF, FF, CF>,
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
        project.state.set(UnfoldState::Value { value });
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        let mut project = self.project();
        let future = match project.state.as_mut().take_value() {
            Some(value) => (project.send)(value, item),
            None => panic!("start_send called without poll_ready being called first"),
        };
        project.state.set(UnfoldState::Send { future });
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            if matches!(self.deref().state, UnfoldState::Flush { .. }) {
                return self.poll_ready(cx);
            }

            let mut project = self.as_mut().project();
            let value = ready!(project.state.as_mut().poll_value(cx))?;
            project.state.set(UnfoldState::Flush {
                future: (project.flush)(value),
            });
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            if matches!(self.deref().state, UnfoldState::Close { .. }) {
                return self.poll_ready(cx);
            }

            let mut project = self.as_mut().project();
            let value = ready!(project.state.as_mut().poll_value(cx))?;
            project.state.set(UnfoldState::Close {
                future: (project.close)(value),
            });
        }
    }
}

fn unfold<T, S, F, C, SF, FF, CF, Item, E>(
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
    let state = UnfoldState::Value { value: init };
    Unfold {
        send,
        flush,
        close,
        state,
    }
}

impl WriteStream {
    pub fn as_bytes_sink<B: Buf>(&mut self) -> impl Sink<B, Error = StreamError> {
        unfold(
            self,
            async |stream: &mut WriteStream, buf: B| stream.send_data(buf).await.map(|_| stream),
            async |stream: &mut WriteStream| stream.flush().await.map(|_| stream),
            async |stream: &mut WriteStream| stream.close().await.map(|_| stream),
        )
    }

    pub fn into_bytes_sink<B: Buf>(self) -> impl Sink<B, Error = StreamError> {
        unfold(
            self,
            async |mut stream: WriteStream, buf: B| stream.send_data(buf).await.map(|_| stream),
            async |mut stream: WriteStream| stream.flush().await.map(|_| stream),
            async |mut stream: WriteStream| stream.close().await.map(|_| stream),
        )
    }
}
