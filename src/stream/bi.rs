//! Connection ownership and GOAWAY dispatch for bidirectional streams.
use std::{
    collections::{HashMap, HashSet},
    mem,
    ops::Deref,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll},
};

use futures::task::AtomicWaker;
use qbase::{ArcReceiving, sid::StreamId};
use qrecovery::{recv::StopSending, send::CancelStream};

use super::{
    ArcH3Stream, H3ReadStream, H3WriteStream, StreamEvent, StreamEventHandler, view::StreamView,
};
use crate::{ArcQpack, Error, ErrorCode, Result, Role};

/// Admission boundaries and registered streams share the connection's lock.
pub(crate) struct BiStreams<R: StopSending, W: CancelStream> {
    view: StreamView,
    reads: HashMap<u64, ArcH3Stream<R>>,
    writes: HashMap<u64, ArcH3Stream<W>>,
    drain: ArcDrain,
}

impl<R: StopSending, W: CancelStream> BiStreams<R, W> {
    pub(crate) fn new(role: Role) -> Self {
        Self {
            view: StreamView::new(role),
            reads: HashMap::default(),
            writes: HashMap::default(),
            drain: ArcDrain::default(),
        }
    }

    pub(crate) fn try_wake(&self) {
        self.drain
            .clean_if(|| self.reads.is_empty() && self.writes.is_empty());
    }

    fn remove_read(&mut self, id: u64) {
        self.reads.remove(&id);
        self.try_wake();
    }

    fn remove_write(&mut self, id: u64) {
        self.writes.remove(&id);
        self.try_wake();
    }

    #[cfg(test)]
    pub(crate) fn local_not_goway(&self) -> Result<()> {
        self.view.local_not_goaway()
    }

    pub(crate) fn remote_no_goway(&self) -> Result<()> {
        self.view.remote_not_goway()
    }

    pub(crate) fn accept(&mut self, id: StreamId) -> Result<()> {
        self.view.accept(id)
    }

    pub(crate) fn local_goaway(&self) -> impl Future<Output = StreamId> + use<R, W> {
        self.view.local_goaway()
    }

    pub(crate) fn recv_goway(&self) -> ArcReceiving<()> {
        self.view.recv_goway()
    }

    fn reject_from(&mut self, id: u64, qpack: &ArcQpack) -> Result<()> {
        let mut rejected = HashSet::new();
        for (id, read) in remove_rejected(&mut self.reads, id) {
            if read.goaway(|io| io.stop(ErrorCode::RequestRejected.as_u64())) {
                rejected.insert(id);
            }
        }
        for (id, write) in remove_rejected(&mut self.writes, id) {
            if write.goaway(|io| io.cancel(ErrorCode::RequestRejected.as_u64())) {
                rejected.insert(id);
            }
        }
        for id in rejected {
            qpack.cancel_decode(id)?;
        }
        self.try_wake();
        Ok(())
    }

    /// Freeze admission and cancel rejected requests without waiting for the write.
    pub(crate) fn goaway(&mut self, qpack: &ArcQpack) -> Result<StreamId> {
        let id = self.view.goaway();
        self.drain.goaway();
        self.reject_from(id.into(), qpack)?;
        Ok(id)
    }

    pub(crate) fn on_goaway(&mut self, id: StreamId, qpack: ArcQpack) -> Result<()> {
        self.view.on_goaway(id);
        self.reject_from(id.into(), &qpack)?;
        Ok(())
    }

    pub(crate) fn close(&mut self, error: Error) {
        let reads = mem::take(&mut self.reads);
        let writes = mem::take(&mut self.writes);
        for read in reads.into_values() {
            read.terminate(|io| io.stop(error.code.as_u64()));
        }
        for write in writes.into_values() {
            write.terminate(|io| io.cancel(error.code.as_u64()));
        }
        self.try_wake();
    }
}

pub(crate) struct ArcBiStreams<R: StopSending, W: CancelStream> {
    inner: Arc<Mutex<BiStreams<R, W>>>,
}

impl<R: StopSending, W: CancelStream> Clone for ArcBiStreams<R, W> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<R: StopSending, W: CancelStream> Deref for ArcBiStreams<R, W> {
    type Target = Mutex<BiStreams<R, W>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<R: StopSending, W: CancelStream> ArcBiStreams<R, W> {
    pub(crate) fn new(role: Role) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BiStreams::new(role))),
        }
    }

    /// Wait for both directions to finish after admission has been frozen.
    /// Only one drain waiter may be polled at a time.
    pub(crate) fn drain(&self) -> ArcDrain {
        let guard = self.inner.lock().unwrap();
        guard.drain.clone()
    }
}

#[derive(Default, Clone)]
pub(crate) struct ArcDrain(Arc<Mutex<Drain>>);
impl ArcDrain {
    fn clean_if(&self, predicet: impl Fn() -> bool) {
        self.0.lock().unwrap().clean_if(predicet);
    }

    fn dirty(&self) {
        self.0.lock().unwrap().dirty();
    }

    fn goaway(&self) {
        self.0.lock().unwrap().goaway();
    }
}

#[derive(Default)]
pub(crate) struct Drain {
    waker: AtomicWaker,
    gone: AtomicU8,
}

impl Drain {
    const GONE: u8 = 0x01;
    const CLEAN: u8 = 0x02;

    fn goaway(&self) {
        self.gone.fetch_or(Self::GONE, Ordering::AcqRel);
    }

    fn dirty(&self) {
        self.gone.fetch_and(!Self::CLEAN, Ordering::AcqRel);
    }

    fn clean_if(&self, predicet: impl Fn() -> bool) {
        if self.gone.load(Ordering::Acquire) != 0 && predicet() {
            self.gone.store(Self::GONE | Self::CLEAN, Ordering::Release);
            self.waker.wake();
        }
    }

    fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.gone.load(Ordering::Acquire) == Self::GONE | Self::CLEAN {
            return Poll::Ready(());
        }
        self.waker.register(cx.waker());
        Poll::Pending
    }
}

impl Future for ArcDrain {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let guard = self.get_mut().0.lock().unwrap();
        guard.poll(cx)
    }
}

impl<R, W> ArcBiStreams<R, W>
where
    R: StopSending + Send + 'static,
    W: CancelStream + Send + 'static,
{
    fn on_read_aborted(streams: &Mutex<BiStreams<R, W>>, qpack: &ArcQpack, id: u64, code: u64) {
        let write = {
            let mut guard = streams.lock().unwrap();
            let write = guard.writes.get(&id).cloned();
            guard.remove_read(id);
            write
        };
        if code != ErrorCode::NoError.as_u64()
            && write.is_some_and(|write| write.terminate(|io| io.cancel(code)))
        {
            streams.lock().unwrap().remove_write(id);
        }
        if let Err(error) = qpack.cancel_decode(id) {
            qpack.on_connection_error(error);
        }
    }

    fn on_write_aborted(streams: &Mutex<BiStreams<R, W>>, qpack: &ArcQpack, id: u64, code: u64) {
        let read = {
            let mut guard = streams.lock().unwrap();
            let read = guard.reads.get(&id).cloned();
            guard.remove_write(id);
            read
        };
        if code != ErrorCode::NoError.as_u64()
            && read.is_some_and(|read| read.terminate(|io| io.stop(code)))
        {
            streams.lock().unwrap().remove_read(id);
        }
        if code != ErrorCode::NoError.as_u64()
            && let Err(error) = qpack.cancel_decode(id)
        {
            qpack.on_connection_error(error);
        }
    }

    fn read_event_handler(&self, id: u64, qpack: ArcQpack) -> StreamEventHandler {
        let streams = Arc::downgrade(&self.inner);
        Arc::new(move |event| {
            if let Some(streams) = streams.upgrade() {
                match event {
                    StreamEvent::Finished => streams.lock().unwrap().remove_read(id),
                    StreamEvent::Aborted { code } => {
                        Self::on_read_aborted(&streams, &qpack, id, code)
                    }
                }
            }
        })
    }

    fn write_event_handler(&self, id: u64, qpack: ArcQpack) -> StreamEventHandler {
        let streams = Arc::downgrade(&self.inner);
        Arc::new(move |event| {
            if let Some(streams) = streams.upgrade() {
                match event {
                    StreamEvent::Finished => streams.lock().unwrap().remove_write(id),
                    StreamEvent::Aborted { code } => {
                        Self::on_write_aborted(&streams, &qpack, id, code)
                    }
                }
            }
        })
    }

    // The caller holds the admission lock across checking and registration.
    pub(crate) fn insert(
        &self,
        guard: &mut BiStreams<R, W>,
        id: u64,
        recv: R,
        send: W,
        qpack: ArcQpack,
    ) -> (H3ReadStream<R>, H3WriteStream<W>) {
        // A stream may be opened after local GOAWAY and before peer GOAWAY.
        // Such a stream invalidates any CLEAN state recorded while the registry
        // was temporarily empty.
        guard.drain.dirty();
        let read = H3ReadStream::new(id, recv, self.read_event_handler(id, qpack.clone()));
        let write = H3WriteStream::new(id, send, self.write_event_handler(id, qpack));
        guard.reads.insert(id, read.state.clone());
        guard.writes.insert(id, write.state.clone());
        (read, write)
    }
}

fn remove_rejected<T>(streams: &mut HashMap<u64, T>, boundary: u64) -> Vec<(u64, T)> {
    let ids: Vec<_> = streams
        .keys()
        .copied()
        .filter(|id| id % 4 == boundary % 4 && *id >= boundary)
        .collect();
    ids.into_iter()
        .filter_map(|id| streams.remove(&id).map(|stream| (id, stream)))
        .collect()
}

#[cfg(test)]
mod tests;
