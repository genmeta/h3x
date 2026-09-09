//! GOAWAY boundaries, admission, and termination.
//! Admission checks and transitions share the GOAWAY lock, including rejection and cancellation.
//! Stream parsing, request delivery, and task supervision live in the connection flows.

use bytes::Bytes;
use qbase::varint::{VarInt, WriteVarInt};
use tokio::sync::watch;

use super::{H3Connection, map_connection_error};
use crate::{Code, Error, StreamId, transport};

#[derive(Default)]
pub(super) struct Goaway {
    pub(super) local_boundary: Option<u64>,
    pub(super) peer_boundary: Option<StreamId>,
    pub(super) max_delivered: Option<StreamId>,
}
impl Goaway {
    pub(super) fn begin_shutdown(&mut self) -> Result<u64, Error> {
        if self.local_boundary.is_some() {
            return Err(Error::invalid_state("shutdown"));
        }
        let boundary = self
            .max_delivered
            .map_or(Some(0), |id| u64::from(id).checked_add(4))
            .filter(|v| *v <= qbase::varint::VARINT_MAX)
            .ok_or_else(|| {
                Error::connection_protocol(Code::H3_ID_ERROR, "GOAWAY boundary overflow")
            })?;
        self.local_boundary = Some(boundary);
        Ok(boundary)
    }
}

pub(super) async fn stopped(terminal: &watch::Sender<Option<Error>>) -> Error {
    let mut receiver = terminal.subscribe();
    receiver
        .wait_for(|value| value.is_some())
        .await
        .expect("H3Connection owns terminal sender")
        .clone()
        .unwrap()
}

impl<T: transport::Connection> H3Connection<T> {
    pub(super) fn failure(&self) -> Error {
        self.terminal
            .borrow()
            .clone()
            .unwrap_or(Error::OwnerStopped)
    }

    pub(super) fn is_draining(&self) -> bool {
        let goaway = self.goaway.lock().unwrap();
        self.terminal.borrow().is_some()
            || goaway.local_boundary.is_some()
            || goaway.peer_boundary.is_some()
    }

    // Close admission and publish the first terminal error under the same lock.
    pub(crate) fn terminate(&self, error: Error) {
        let _goaway = self.goaway.lock().unwrap();
        if self.terminal.borrow().is_some() {
            return;
        }
        self.terminal.send_replace(Some(error));
    }

    pub(super) fn terminate_on_connection_error<V>(
        &self,
        result: Result<V, Error>,
    ) -> Result<V, Error> {
        if let Err(error) = &result
            && error.is_connection()
        {
            self.terminate(error.clone());
        }
        result
    }

    pub(super) async fn local_shutdown(&self) -> Error {
        let mut changed = self.admission_changed.subscribe();
        loop {
            if self.goaway.lock().unwrap().local_boundary.is_some() {
                return Error::Cancelled;
            }
            changed
                .changed()
                .await
                .expect("connection owns admission signal");
        }
    }

    pub(super) async fn peer_rejected(&self, id: Option<StreamId>) -> Error {
        let mut changed = self.admission_changed.subscribe();
        loop {
            if let Some(boundary) = self.goaway.lock().unwrap().peer_boundary
                && id.is_none_or(|id| id >= boundary)
            {
                return Error::Goaway { boundary };
            }
            changed
                .changed()
                .await
                .expect("connection owns admission signal");
        }
    }

    pub(super) fn on_peer_goaway(&self, value: u64) -> Result<(), Error> {
        let role = self.transport.role().map_err(map_connection_error)?;
        if value != 0 && value & 3 != role as u64 {
            return Err(Error::connection_protocol(
                Code::H3_ID_ERROR,
                "GOAWAY has the wrong stream role",
            ));
        }
        let boundary = VarInt::try_from(value)
            .map(StreamId::from)
            .map_err(|_| Error::invalid_stream_id(value))?;
        let mut goaway = self.goaway.lock().unwrap();
        if !self.terminal.borrow().is_some() {
            if goaway
                .peer_boundary
                .is_some_and(|previous| boundary > previous)
            {
                return Err(Error::connection_protocol(
                    Code::H3_ID_ERROR,
                    "GOAWAY boundary increased",
                ));
            }
            goaway.peer_boundary = Some(boundary);
            self.admission_changed.send_replace(());
        }
        Ok(())
    }

    pub(super) fn begin_shutdown(&self) -> Result<Bytes, Error> {
        let mut goaway = self.goaway.lock().unwrap();
        if self.terminal.borrow().is_some() {
            return Err(Error::invalid_state("shutdown"));
        }
        let boundary = goaway.begin_shutdown()?;
        self.admission_changed.send_replace(());
        let mut payload = Vec::new();
        payload.put_varint(&VarInt::try_from(boundary).expect("validated GOAWAY boundary"));
        Ok(Bytes::from(payload))
    }
}
