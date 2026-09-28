use std::{
    pin::Pin,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use qbase::varint::{VarInt, WriteVarInt};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use super::*;
use crate::frame::Write as _;

#[derive(Default)]
struct Io {
    bytes: Vec<u8>,
    offset: usize,
    stops: Vec<u64>,
}

impl Io {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            ..Self::default()
        }
    }
}

impl AsyncRead for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = (self.bytes.len() - self.offset).min(buf.remaining());
        buf.put_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl StopSending for Io {
    fn stop(&mut self, code: u64) {
        self.stops.push(code);
    }
}

impl TransportError for Io {
    fn map_error(error: io::Error) -> Error {
        Error::from_stream_io(error)
    }
}

struct PendingIo {
    bytes: Vec<u8>,
    offset: usize,
    stops: Arc<Mutex<Vec<u64>>>,
}

impl AsyncRead for PendingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset == self.bytes.len() {
            return Poll::Pending;
        }
        let count = (self.bytes.len() - self.offset).min(buf.remaining());
        buf.put_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl StopSending for PendingIo {
    fn stop(&mut self, code: u64) {
        self.stops.lock().unwrap().push(code);
    }
}

impl TransportError for PendingIo {
    fn map_error(error: io::Error) -> Error {
        Error::from_stream_io(error)
    }
}

#[tokio::test]
async fn dropping_header_futures_stops_unpolled_and_pending_native_reads() {
    use futures::FutureExt;

    for response in [false, true] {
        for poll_before_drop in [false, true] {
            let stops = Arc::new(Mutex::new(Vec::new()));
            let stream = H3ReadStream::new(
                0,
                PendingIo {
                    bytes: Vec::new(),
                    offset: 0,
                    stops: stops.clone(),
                },
                events(),
            );
            let state = stream.state.clone();
            let qpack = crate::qpack::tests::qpack();
            let mut reading = if response {
                stream
                    .read_response(http::Method::GET, qpack)
                    .map(|result| result.map(|_| ()))
                    .boxed()
            } else {
                stream
                    .read_request(qpack)
                    .map(|result| result.map(|_| ()))
                    .boxed()
            };
            if poll_before_drop {
                poll_fn(|cx| {
                    assert!(reading.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            assert!(stops.lock().unwrap().is_empty());
            drop(reading);
            assert_eq!(
                *stops.lock().unwrap(),
                [ErrorCode::RequestCancelled.as_u64()]
            );
            assert_eq!(
                state.0.lock().unwrap().as_ref().err().unwrap().code,
                ErrorCode::RequestCancelled
            );
        }
    }
}

#[tokio::test]
async fn header_failure_preserves_original_error_and_native_stop_code() {
    for response in [false, true] {
        let stops = Arc::new(Mutex::new(Vec::new()));
        // A DATA frame before HEADERS is a connection-level FRAME_UNEXPECTED.
        let stream = H3ReadStream::new(
            0,
            PendingIo {
                bytes: vec![0, 0],
                offset: 0,
                stops: stops.clone(),
            },
            events(),
        );
        let state = stream.state.clone();
        let qpack = crate::qpack::tests::qpack();
        let error = if response {
            stream
                .read_response(http::Method::GET, qpack)
                .await
                .err()
                .unwrap()
        } else {
            stream.read_request(qpack).await.err().unwrap()
        };
        assert_eq!(error.code, ErrorCode::FrameUnexpected);
        assert!(error.is_connection());
        assert_eq!(
            *stops.lock().unwrap(),
            [ErrorCode::FrameUnexpected.as_u64()]
        );
        assert_eq!(state.0.lock().unwrap().as_ref().err().unwrap(), &error);
    }
}

#[test]
fn read_poll_preserves_transient_errors_and_reports_terminal_error_once() {
    struct ScriptedIo(usize);

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.0 += 1;
            match self.0 {
                1 => Poll::Pending,
                2 => Poll::Ready(Err(io::ErrorKind::Interrupted.into())),
                3 => Poll::Ready(Err(io::ErrorKind::WouldBlock.into())),
                4 => {
                    buf.put_slice(b"x");
                    Poll::Ready(Ok(()))
                }
                5 => Poll::Ready(Err(ErrorCode::InternalError.connection("fatal").into())),
                _ => panic!("failed I/O must not be polled again"),
            }
        }
    }

    impl StopSending for ScriptedIo {
        fn stop(&mut self, _: u64) {}
    }

    impl TransportError for ScriptedIo {
        fn map_error(error: io::Error) -> Error {
            Error::from_stream_io(error)
        }
    }

    let reported = Arc::new(Mutex::new(Vec::new()));
    let captured = reported.clone();
    let mut stream = H3ReadStream::new(4, ScriptedIo(0), events());
    let shared = stream.state.clone();
    stream.handler = Arc::new(move |event| {
        assert!(shared.0.try_lock().is_ok(), "notify outside the state lock");
        captured.lock().unwrap().push(event);
    });
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut bytes = [0; 8];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(
        Pin::new(&mut stream)
            .poll_read(&mut cx, &mut buf)
            .is_pending()
    );
    assert!(matches!(
        *stream.state.0.lock().unwrap(),
        Ok(H3Stream::Polling(_, _))
    ));
    for kind in [io::ErrorKind::Interrupted, io::ErrorKind::WouldBlock] {
        let Poll::Ready(Err(error)) = Pin::new(&mut stream).poll_read(&mut cx, &mut buf) else {
            panic!("transient error must be returned");
        };
        assert_eq!(error.kind(), kind);
    }
    assert!(matches!(
        Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(buf.filled(), b"x");
    assert!(reported.lock().unwrap().is_empty());
    let expected = ErrorCode::InternalError.connection("fatal");
    for _ in 0..2 {
        let Poll::Ready(Err(error)) = Pin::new(&mut stream).poll_read(&mut cx, &mut buf) else {
            panic!("terminal error must be retained");
        };
        assert_eq!(Error::from_stream_io(error), expected);
    }
    drop(stream);
    assert_eq!(reported.lock().unwrap().as_slice(), [Err(expected)]);
}

fn events() -> StreamEventHandler {
    Arc::new(|_| {})
}

#[test]
fn stop_before_decode_registration_prevents_a_new_qpack_wait() {
    let qpack = crate::qpack::tests::qpack();
    qpack
        .with_state(|state| {
            state.decoder.on_instruction(|_| Ok(()));
            Ok(())
        })
        .unwrap();

    let event_qpack = qpack.clone();
    let stream = Arc::new(H3ReadStream::new(
        4,
        Io::default(),
        Arc::new(move |event| {
            if event.is_err() {
                event_qpack.cancel_decode(vec![4]).unwrap();
            }
        }),
    ));
    let headers_read = Arc::new(Barrier::new(2));
    let resume_decode = Arc::new(Barrier::new(2));

    std::thread::scope(|scope| {
        let receiving = stream.clone();
        let receiving_qpack = qpack.clone();
        let receiving_headers_read = headers_read.clone();
        let receiving_resume_decode = resume_decode.clone();
        let receive = scope.spawn(move || {
            // RIC=1, Base=0, post-Base index 0: this would wait for an insert.
            let payload = Bytes::from_static(&[0x02, 0x80, 0x10]);
            let mut decoding = Box::pin(receiving.decode(&receiving_qpack, payload));
            receiving_headers_read.wait();
            receiving_resume_decode.wait();
            let mut cx = Context::from_waker(futures::task::noop_waker_ref());
            decoding.as_mut().poll(&mut cx)
        });

        headers_read.wait();
        let mut application = &*stream;
        application.stop(ErrorCode::RequestCancelled.as_u64());
        resume_decode.wait();

        let Poll::Ready(Err(error)) = receive.join().unwrap() else {
            panic!("a stopped stream must not start another QPACK wait")
        };
        assert_eq!(error.code, ErrorCode::RequestCancelled);
    });
}

fn headers(bytes: &'static [u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.put_frame(
        &Frame::new(frame::Headers {
            field_section: Bytes::from_static(bytes),
        })
        .unwrap(),
    );
    wire
}

#[tokio::test]
async fn header_and_next_frame_readers_skip_extensions_and_enforce_placement() {
    let mut wire = Vec::new();
    wire.put_varint(&VarInt::from_u32(42));
    wire.put_varint(&VarInt::from_u32(2));
    wire.extend_from_slice(b"xx");
    wire.extend_from_slice(&headers(b"head"));
    let mut stream = H3ReadStream::new(4, Io::new(wire), events());
    assert_eq!(stream.stream_id(), 4);
    assert_eq!(
        stream
            .read_headers_frame()
            .await
            .unwrap()
            .unwrap()
            .payload
            .field_section,
        Bytes::from_static(b"head")
    );
    assert!(stream.read_headers_frame().await.unwrap().is_none());

    let mut stream = H3ReadStream::new(8, Io::new(vec![0, 1, b'x']), events());
    let Some(NextFrame::Data(frame)) = stream.read_next_frame(false).await.unwrap() else {
        panic!("expected DATA")
    };
    assert_eq!(frame.length.into_u64(), 1);
    let mut payload = [0];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload, [b'x']);
    assert!(stream.read_next_frame(false).await.unwrap().is_none());

    let mut stream = H3ReadStream::new(12, Io::new(headers(b"trailers")), events());
    assert!(matches!(
        stream.read_next_frame(false).await.unwrap(),
        Some(NextFrame::Trailer(_))
    ));
    assert!(stream.read_next_frame(true).await.unwrap().is_none());

    let mut stream = H3ReadStream::new(14, Io::new(vec![0x21, 2, b'x', b'y']), events());
    assert!(stream.read_next_frame(true).await.unwrap().is_none());

    let mut stream = H3ReadStream::new(16, Io::new(vec![0, 0]), events());
    assert_eq!(
        stream.read_headers_frame().await.unwrap_err().code,
        ErrorCode::FrameUnexpected
    );
    let mut stream = H3ReadStream::new(20, Io::new(vec![7, 1, 0]), events());
    assert_eq!(
        stream.read_next_frame(false).await.err().unwrap().code,
        ErrorCode::FrameUnexpected
    );
    let mut stream = H3ReadStream::new(24, Io::new(vec![0]), events());
    assert_eq!(
        stream.read_next_frame(true).await.err().unwrap().code,
        ErrorCode::FrameUnexpected
    );

    let mut stream = H3ReadStream::new(28, Io::new(vec![0x21, 2, b'x']), events());
    assert_eq!(
        stream.read_next_frame(true).await.err().unwrap().code,
        ErrorCode::FrameError
    );
}

#[tokio::test]
async fn read_completion_notifies_finish_once() {
    fn reject<R: StopSending>(stream: &H3ReadStream<R>) -> bool {
        let error = ErrorCode::RequestRejected.stream("request rejected by GOAWAY");
        stream
            .state
            .fail(error.clone(), |io| io.stop(error.code.as_u64()))
    }

    let completed = Arc::new(AtomicUsize::new(0));
    let count = completed.clone();
    let mut stream = H3ReadStream::new(
        0,
        Io::new(b"abc".to_vec()),
        Arc::new(move |event| {
            if event.is_ok() {
                count.fetch_add(1, Ordering::SeqCst);
            }
        }),
    );
    let _registered = stream.state.clone();
    assert_eq!(stream.read(&mut []).await.unwrap(), 0);
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"abc");
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    stream.stop(ErrorCode::InternalError.as_u64());
    assert!(!reject(&stream));
    stream.stop(9);
    assert_eq!(completed.load(Ordering::SeqCst), 1);

    let completed = Arc::new(AtomicUsize::new(0));
    let count = completed.clone();
    let mut rejected = H3ReadStream::new(
        4,
        Io::default(),
        Arc::new(move |event| {
            if event.is_ok() {
                count.fetch_add(1, Ordering::SeqCst);
            }
        }),
    );
    assert!(reject(&rejected));
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    let mut byte = [0];
    let error = rejected.read(&mut byte).await.unwrap_err();
    assert_eq!(crate::Error::from(error).code, ErrorCode::RequestRejected);
}

#[tokio::test]
async fn read_request_rejects_a_stream_without_initial_headers() {
    let completed = Arc::new(AtomicUsize::new(0));
    let count = completed.clone();
    let stream = H3ReadStream::new(
        0,
        Io::default(),
        Arc::new(move |event| {
            if event.is_ok() {
                count.fetch_add(1, Ordering::SeqCst);
            }
        }),
    );
    let result: crate::Result<crate::Request<crate::R>> =
        stream.read_request(crate::qpack::tests::qpack()).await;
    let Err(error) = result else {
        panic!("a message without HEADERS must fail")
    };
    assert_eq!(error.code, ErrorCode::RequestIncomplete);
    assert_eq!(completed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn short_data_reads_share_a_slab_without_window_copies() {
    struct ShortIo {
        wire: Vec<u8>,
        offset: usize,
        payload_start: usize,
        addresses: Arc<Mutex<Vec<usize>>>,
    }
    impl AsyncRead for ShortIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if buf.remaining() > 0 && self.offset < self.wire.len() {
                let start = buf.filled().len();
                buf.put_slice(&self.wire[self.offset..self.offset + 1]);
                if self.offset >= self.payload_start {
                    self.addresses
                        .lock()
                        .unwrap()
                        .push(buf.filled()[start..].as_ptr() as usize);
                }
                self.offset += 1;
            }
            Poll::Ready(Ok(()))
        }
    }
    impl StopSending for ShortIo {
        fn stop(&mut self, _: u64) {}
    }
    impl TransportError for ShortIo {
        fn map_error(error: io::Error) -> Error {
            Error::from_stream_io(error)
        }
    }
    for response in [false, true] {
        let qpack = crate::qpack::tests::qpack();
        let field = |name: &'static [u8], value: &'static [u8]| crate::qpack::Field {
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
            never_index: false,
        };
        let fields = if response {
            vec![field(b":status", b"200")]
        } else {
            vec![
                field(b":method", b"GET"),
                field(b":scheme", b"https"),
                field(b":authority", b"example.com"),
                field(b":path", b"/"),
            ]
        };
        let mut wire = Vec::new();
        wire.put_frame(
            &Frame::new(frame::Headers {
                field_section: qpack.encode(0, fields).unwrap(),
            })
            .unwrap(),
        );
        wire.put_frame(&Frame::new(frame::Data(64)).unwrap());
        let payload_start = wire.len();
        wire.extend_from_slice(&[42; 64]);
        let addresses = Arc::new(Mutex::new(Vec::new()));
        let stream = H3ReadStream::new(
            0,
            ShortIo {
                wire,
                offset: 0,
                payload_start,
                addresses: addresses.clone(),
            },
            events(),
        );
        let body = if response {
            stream
                .read_response(http::Method::GET, qpack)
                .await
                .unwrap()
                .into_body()
        } else {
            stream.read_request(qpack).await.unwrap().into_body()
        };
        // Retain all chunks so the allocator cannot reuse a freed address.
        let mut chunks = Vec::new();
        loop {
            let chunk = body.read_chunk(64).await.unwrap();
            if chunk.is_empty() {
                break;
            }
            assert_eq!(&chunk[..], &[42]);
            chunks.push(chunk);
        }
        let received: Vec<_> = chunks.iter().map(|b| b.as_ptr() as usize).collect();
        let addresses = addresses.lock().unwrap();
        assert_eq!(received.len(), 64);
        assert_eq!(
            received, *addresses,
            "transport buffer reaches the consumer unchanged"
        );
        assert!(
            received.windows(2).all(|pair| pair[1] == pair[0] + 1),
            "short reads share the slab instead of allocating one slab per byte"
        );
    }
}

#[tokio::test]
async fn cancelling_request_body_stops_the_pending_transport_read() {
    let qpack = crate::qpack::tests::qpack();
    let field = |name: &'static [u8], value: &'static [u8]| crate::qpack::Field {
        name: Bytes::from_static(name),
        value: Bytes::from_static(value),
        never_index: false,
    };
    let fields = vec![
        field(b":method", b"GET"),
        field(b":scheme", b"https"),
        field(b":authority", b"example.com"),
        field(b":path", b"/"),
    ];
    let field_section = qpack.encode(0, fields).unwrap();
    let mut wire = Vec::new();
    wire.put_frame(
        &Frame::new(frame::Headers { field_section })
            .expect("small literal headers fit in one frame"),
    );
    let stops = Arc::new(Mutex::new(Vec::new()));
    let stream = H3ReadStream::new(
        0,
        PendingIo {
            bytes: wire,
            offset: 0,
            stops: stops.clone(),
        },
        events(),
    );
    let mut request = stream.read_request(qpack).await.unwrap();
    request.stop(ErrorCode::RequestCancelled.as_u64());
    assert_eq!(
        &*stops.lock().unwrap(),
        &[ErrorCode::RequestCancelled.as_u64()]
    );
    assert_eq!(
        Error::from(request.read(&mut [0]).await.unwrap_err()).code,
        ErrorCode::RequestCancelled
    );
}
