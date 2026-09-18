//! Connection ownership and GOAWAY dispatch for bidirectional streams.
use std::{
    collections::HashMap,
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

use super::{H3ReadStream, H3WriteStream, view::StreamView};
use crate::{ArcQpack, Error, Result, Role};

/// Admission boundaries and registered streams share the connection's lock.
pub(crate) struct BiStreams<R: StopSending, W: CancelStream> {
    view: StreamView,
    reads: HashMap<u64, H3ReadStream<R>>,
    writes: HashMap<u64, H3WriteStream<W>>,
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

    pub(crate) fn local_not_goway(&self) -> Result<()> {
        self.view.local_not_goaway()
    }

    pub(crate) fn remote_no_goway(&self) -> Result<()> {
        self.view.remote_not_goway()
    }

    pub(crate) fn accept(&mut self, id: StreamId) -> Result<()> {
        self.view.accept(id)
    }

    pub(crate) fn send_goaway(&self) -> impl Future<Output = StreamId> + use<R, W> {
        self.view.send_goaway()
    }

    pub(crate) fn recv_goway(&self) -> ArcReceiving<()> {
        self.view.recv_goway()
    }

    fn reject_from(&mut self, id: u64) -> Vec<u64> {
        let mut rejected = Vec::new();
        reject(&mut self.reads, id, H3ReadStream::reject, &mut rejected);
        reject(&mut self.writes, id, H3WriteStream::reject, &mut rejected);
        self.try_wake();
        rejected.sort_unstable();
        rejected.dedup();
        rejected
    }

    /// Freeze admission and cancel rejected requests without waiting for the write.
    pub(crate) fn goaway(&mut self, qpack: &ArcQpack) -> Result<()> {
        let id = self.view.goaway();
        self.drain.goaway();
        let rejected = self.reject_from(id.into());
        for id in rejected {
            qpack.cancel(id)?
        }
        Ok(())
    }

    pub(crate) fn on_goaway(&mut self, id: StreamId, qpack: ArcQpack) -> Result<()> {
        self.view.on_goaway(id);
        let rejected = self.reject_from(id.into());
        self.try_wake();
        for id in rejected {
            qpack.cancel(id)?
        }
        Ok(())
    }

    pub(crate) fn close(&mut self, error: Error) {
        let reads = mem::take(&mut self.reads);
        let writes = mem::take(&mut self.writes);
        for read in reads.into_values() {
            read.close(error.clone());
        }
        for write in writes.into_values() {
            (&write).cancel(error.code.as_u64());
        }
        self.try_wake();
    }

    pub(crate) fn read_streams(&mut self) -> &mut HashMap<u64, H3ReadStream<R>> {
        &mut self.reads
    }

    pub(crate) fn write_streams(&mut self) -> &mut HashMap<u64, H3WriteStream<W>> {
        &mut self.writes
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
    // The caller holds the admission lock across checking and registration.
    pub(crate) fn insert(
        &self,
        guard: &mut BiStreams<R, W>,
        id: u64,
        recv: R,
        send: W,
    ) -> (H3ReadStream<R>, H3WriteStream<W>) {
        let mut read = H3ReadStream::new(id, recv);
        let mut write = H3WriteStream::new(id, send);
        guard.reads.insert(id, read.registered());
        guard.writes.insert(id, write.registered());
        write.on_finish({
            let bistreams = self.inner.clone();
            move || {
                let mut guard = bistreams.lock().unwrap();
                guard.write_streams().remove(&id);
                guard.try_wake();
            }
        });
        read.on_finish({
            let bistreams = self.inner.clone();
            move || {
                let mut guard = bistreams.lock().unwrap();
                guard.read_streams().remove(&id);
                guard.try_wake();
            }
        });
        (read, write)
    }
}

fn reject<T>(
    directions: &mut HashMap<u64, T>,
    boundary: u64,
    reject: impl Fn(&T) -> bool,
    rejected: &mut Vec<u64>,
) {
    // Release the registry lock before touching I/O state or waking application tasks.
    let removed: Vec<_> = {
        let ids: Vec<_> = directions
            .keys()
            .copied()
            .filter(|id| id % 4 == boundary % 4 && *id >= boundary)
            .collect();
        ids.into_iter()
            .filter_map(|id| directions.remove(&id).map(|stream| (id, stream)))
            .collect()
    };
    for (id, stream) in removed {
        if reject(&stream) {
            rejected.push(id);
        }
    }
}

#[cfg(test)]
mod tests;
