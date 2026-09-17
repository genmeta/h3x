//! Verify actual qrecovery control frames, not only calls to mock trait methods.
use std::sync::{Arc, Mutex};

use qbase::{
    frame::{StreamCtlFrame, io::SendFrame},
    param::{
        ArcParameters, Parameters,
        handy::{client_parameters, server_parameters},
    },
    role::Role,
    sid::handy::DemandConcurrency,
};
use qrecovery::{recv::StopSending, send::CancelStream, streams::DataStreams};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{H3ReadStream, H3WriteStream, bi::BiStreams};
use crate::{ErrorCode, test_support::TestStream};

#[derive(Clone, Default)]
struct Frames(Arc<Mutex<Vec<StreamCtlFrame>>>);

impl SendFrame<StreamCtlFrame> for Frames {
    fn send_frame<I: IntoIterator<Item = StreamCtlFrame>>(&self, frames: I) {
        self.0.lock().unwrap().extend(frames);
    }
}

fn transport() -> (DataStreams<Frames>, ArcParameters, Frames) {
    let frames = Frames::default();
    let streams = DataStreams::new(
        Role::Client,
        &client_parameters(),
        &server_parameters(),
        Box::new(DemandConcurrency),
        frames.clone(),
        Default::default(),
        None,
    );
    let params = Parameters::new_client(
        client_parameters(),
        Some(server_parameters()),
        Default::default(),
    )
    .into();
    (streams, params, frames)
}

#[tokio::test]
async fn dquic_queues_stop_and_reset_for_local_error_goaway_and_drop() {
    for cause in ["error", "goaway", "drop"] {
        let (transport, params, frames) = transport();
        let (id, (read, write)) = transport.open_bi(&params).await.unwrap().unwrap();
        let streams = BiStreams::new();
        let (send, recv) = streams.insert(id.into(), read, write).unwrap();
        let code = match cause {
            "error" => {
                recv.close(ErrorCode::H3_MESSAGE_ERROR.with_reason("invalid message"));
                (&send).cancel(ErrorCode::H3_MESSAGE_ERROR.as_u64());
                ErrorCode::H3_MESSAGE_ERROR
            }
            "goaway" => {
                assert_eq!(streams.goaway(id.into()), [u64::from(id)]);
                ErrorCode::H3_REQUEST_REJECTED
            }
            _ => ErrorCode::H3_REQUEST_CANCELLED,
        };
        drop((recv, send));
        let frames = frames.0.lock().unwrap();
        assert_eq!(frames.len(), 2, "{cause}");
        assert!(matches!(frames[0], StreamCtlFrame::StopSending(frame)
            if frame.stream_id() == id && frame.app_err_code() == code.as_u64()));
        assert!(matches!(frames[1], StreamCtlFrame::ResetStream(frame)
            if frame.stream_id() == id && frame.app_error_code() == code.as_u64()));
    }
}

#[tokio::test]
async fn malformed_headers_queue_dquic_stop_with_message_error() {
    let (transport, params, frames) = transport();
    let (id, (read, write)) = transport.open_bi(&params).await.unwrap().unwrap();
    // HEADERS with an empty QPACK field section: mandatory request fields are missing.
    let bytes = bytes::Bytes::from_static(&[1, 2, 0, 0]);
    transport
        .recv_data((qbase::frame::StreamFrame::new(id, 0, bytes.len()), bytes))
        .unwrap();
    let send = H3WriteStream::new(id.into(), write);
    let connection = crate::test_support::connection().await;
    let error = crate::server::read_request(
        H3ReadStream::new(id.into(), read),
        connection.qpack().clone(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR);
    {
        let frames = frames.0.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert!(matches!(frames[0], StreamCtlFrame::StopSending(frame)
            if frame.stream_id() == id && frame.app_err_code() == ErrorCode::H3_MESSAGE_ERROR.as_u64()));
    }
    drop(send);
}

#[test]
fn rejection_and_drop_terminate_each_direction_once() {
    for reject in [false, true] {
        let read = TestStream::new(tokio::io::empty());
        let write = TestStream::new(tokio::io::sink());
        let stopped = read.stopped.clone();
        let cancelled = write.cancelled.clone();
        let streams = BiStreams::new();
        let (send, mut recv) = streams.insert(4, read, write).unwrap();
        let code = if reject {
            assert_eq!(streams.goaway(4), [4]);
            assert!(streams.goaway(4).is_empty());
            // Later explicit termination must not overwrite the rejection.
            recv.stop(ErrorCode::H3_REQUEST_CANCELLED.as_u64());
            (&send).cancel(ErrorCode::H3_REQUEST_CANCELLED.as_u64());
            ErrorCode::H3_REQUEST_REJECTED
        } else {
            ErrorCode::H3_REQUEST_CANCELLED
        };
        drop(recv);
        drop(send);
        assert_eq!(*stopped.lock().unwrap(), [code.as_u64()]);
        assert_eq!(*cancelled.lock().unwrap(), [code.as_u64()]);
    }
}

#[tokio::test]
async fn normal_completion_and_streams_below_goaway_are_not_cancelled() {
    for finished in [false, true] {
        let read = TestStream::new(tokio::io::empty());
        let write = TestStream::new(tokio::io::sink());
        let stopped = read.stopped.clone();
        let cancelled = write.cancelled.clone();
        let streams = BiStreams::new();
        let (mut send, mut recv) = streams.insert(0, read, write).unwrap();
        if finished {
            assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
            send.shutdown().await.unwrap();
        }
        assert!(streams.goaway(4).is_empty());
        assert!(stopped.lock().unwrap().is_empty());
        assert!(cancelled.lock().unwrap().is_empty());
        if !finished {
            assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
            send.shutdown().await.unwrap();
        }
        drop((recv, send));
        assert!(stopped.lock().unwrap().is_empty());
        assert!(cancelled.lock().unwrap().is_empty());
    }
}

#[test]
fn local_errors_preserve_the_first_transport_code() {
    for code in [
        ErrorCode::H3_MESSAGE_ERROR,
        ErrorCode::H3_REQUEST_CANCELLED,
        ErrorCode::H3_REQUEST_REJECTED,
    ] {
        let read = TestStream::new(tokio::io::empty());
        let write = TestStream::new(tokio::io::sink());
        let stopped = read.stopped.clone();
        let cancelled = write.cancelled.clone();
        let recv = H3ReadStream::new(0, read);
        let send = H3WriteStream::new(0, write);
        recv.close(code.with_reason("read error"));
        (&send).cancel(code.as_u64());
        recv.close(ErrorCode::H3_INTERNAL_ERROR.with_reason("later error"));
        (&send).cancel(ErrorCode::H3_INTERNAL_ERROR.as_u64());
        drop((recv, send));
        assert_eq!(*stopped.lock().unwrap(), [code.as_u64()]);
        assert_eq!(*cancelled.lock().unwrap(), [code.as_u64()]);
    }
}
