#![allow(dead_code)]

use std::{borrow::Cow, sync::Arc};

use futures::future::BoxFuture;
use snafu::Snafu;

use crate::{quic, rpc::lifecycle::LifecycleExt, varint::VarInt};

const DRIVER_PROTOCOL_ERROR_KIND: VarInt = VarInt::from_u32(0x3f00);
const DRIVER_PROTOCOL_ERROR_FRAME_TYPE: VarInt = VarInt::from_u32(0x3f01);

#[derive(Debug, Snafu)]
#[snafu(module)]
pub(crate) enum DriverProtocolError {
    #[snafu(display("stop ack code {actual} does not match committed stop code {expected}"))]
    StopAckCodeMismatch { expected: VarInt, actual: VarInt },
    #[snafu(display("reset ack code {actual} does not match committed reset code {expected}"))]
    ResetAckCodeMismatch { expected: VarInt, actual: VarInt },
    #[snafu(display("received frame that is invalid for the current reader operation"))]
    UnexpectedReaderFrame,
    #[snafu(display("received writer ack without a matching committed operation"))]
    UnexpectedWriterAck,
    #[snafu(display("received duplicate writer credit before previous credit was consumed"))]
    DuplicateWriterCredit,
    #[snafu(display("start_send called without writer credit"))]
    StartSendWithoutCredit,
    #[snafu(display("typed frame stream ended before operation completed"))]
    FrameEof,
}

pub(crate) enum DeferredStreamError {
    Ready {
        error: quic::StreamError,
    },
    Pending {
        future: BoxFuture<'static, quic::StreamError>,
    },
}

pub(crate) fn protocol_connection_error(error: DriverProtocolError) -> quic::ConnectionError {
    quic::ConnectionError::Transport {
        source: quic::TransportError {
            kind: DRIVER_PROTOCOL_ERROR_KIND,
            frame_type: DRIVER_PROTOCOL_ERROR_FRAME_TYPE,
            // Lossy: QUIC transport error reason is a protocol string field for
            // local bridge-driver protocol failures.
            reason: Cow::Owned(error.to_string()),
        },
    }
}

pub(crate) fn latch_protocol_error<L>(
    lifecycle: &L,
    error: DriverProtocolError,
) -> quic::StreamError
where
    L: LifecycleExt,
{
    let source = lifecycle
        .latch()
        .latch_with(|| protocol_connection_error(error));
    quic::StreamError::Connection { source }
}

pub(crate) fn latch_frame_io_error<L, E>(lifecycle: &L, error: E) -> quic::StreamError
where
    L: LifecycleExt,
    quic::ConnectionError: From<E>,
{
    let source = lifecycle
        .latch()
        .latch_with(|| quic::ConnectionError::from(error));
    quic::StreamError::Connection { source }
}

pub(crate) fn defer_err_conn<L>(lifecycle: Arc<L>) -> DeferredStreamError
where
    L: LifecycleExt + 'static,
{
    match quic::Lifecycle::check(lifecycle.as_ref()) {
        Ok(()) => DeferredStreamError::Pending {
            future: Box::pin(async move {
                let source = quic::Lifecycle::closed(lifecycle.as_ref()).await;
                quic::StreamError::Connection { source }
            }),
        },
        Err(source) => DeferredStreamError::Ready {
            error: quic::StreamError::Connection { source },
        },
    }
}
