//! Unidirectional stream opening, type classification, and receive dispatch.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use qrecovery::recv::StopSending;

use super::{bi::BiStreams, control};
use crate::{
    Error, Result, Transport,
    protocol::{
        connection::{Settings, StreamCursor, close_connection, finish_connection},
        frame,
        qpack::Qpack,
    },
};

#[derive(Default)]
struct CriticalStreams {
    control: AtomicBool,
    encoder: AtomicBool,
    decoder: AtomicBool,
}

pub(crate) async fn receive<T: Transport>(
    transport: &Arc<T>,
    settings: &Arc<Settings>,
    qpack: &Arc<Qpack<T>>,
    cursor: &Arc<Mutex<StreamCursor>>,
    bi: &Arc<BiStreams<T::Recv, T::Send>>,
) {
    let critical = Arc::new(CriticalStreams::default());
    loop {
        let (_, mut recv) = match transport.accept_uni_stream().await {
            Ok(stream) => stream,
            Err(error) => {
                finish_connection(qpack, bi, error);
                return;
            }
        };
        let (transport, settings, qpack, cursor, bi, critical) = (
            transport.clone(),
            settings.clone(),
            qpack.clone(),
            cursor.clone(),
            bi.clone(),
            critical.clone(),
        );
        tokio::spawn(async move {
            tokio::select! {
                biased;
                result = async {
                    // FIN/RESET is stream-local until its full type is known.
                    let stream_type = match frame::be_varint_or_eof(&mut recv).await {
                        Ok(Some(ty)) => ty.into_u64(),
                        Ok(None) => return Ok(()),
                        Err(error) if error.get_ref().is_some_and(|source| {
                            source.is::<qbase::frame::ResetStreamError>()
                        }) => return Ok(()),
                        Err(error) => return Err(Error::from(error)),
                    };
                    let seen = match stream_type {
                        0 => &critical.control,
                        2 => &critical.encoder,
                        3 => &critical.decoder,
                        1 => return Err(Error::H3_ID_ERROR),
                        _ => { recv.stop(Error::H3_NO_ERROR.as_u64()); return Ok(()); }
                    };
                    if seen.swap(true, Ordering::AcqRel) { return Err(Error::H3_STREAM_CREATION_ERROR); }
                    match stream_type {
                        0 => control::receive_control(&mut recv, transport.as_ref(), &settings, &qpack, &cursor, &bi).await,
                        2 => qpack.receive_encoder(&mut recv).await,
                        3 => qpack.receive_decoder(&mut recv).await,
                        _ => unreachable!(),
                    }
                } => if let Err(error) = result {
                    // Prefer an existing transport result over a new protocol error.
                    // The half stays alive throughout this task's failure handling.
                    tokio::select! {
                        biased;
                        ended = transport.terminated() => finish_connection(&qpack, &bi, ended),
                        _ = std::future::ready(()) => close_connection(transport.as_ref(), &qpack, &bi, error),
                    }
                },
                error = transport.terminated() => finish_connection(&qpack, &bi, error),
            }
        });
    }
}

pub(super) async fn open_stream<T: Transport>(transport: &T) -> Result<T::Send> {
    let (_, send) = transport
        .open_uni_stream()
        .await?
        .ok_or(Error::H3_STREAM_CREATION_ERROR)?;
    Ok(send)
}
