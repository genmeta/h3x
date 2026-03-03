//! Integration tests for the protocol layering system.
//!
//! These tests verify the `ProtocolLayer` trait mechanics (accept/pass/peek/reset)
//! without requiring a real QUIC connection. The routing loop pattern tested is:
//! ```text
//! for layer in layers {
//!     match layer.accept_uni(stream) {
//!         Accepted => break,
//!         Passed(s) => stream = s,
//!     }
//! }
//! ```

use std::{
    any::Any,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Stream, future::BoxFuture};
use h3x::{
    codec::{DecodeExt, StreamReader, peekable::PeekableStreamReader},
    layer::{PeekableBiStream, PeekableUniStream, ProtocolLayer, StreamVerdict},
    quic::{self, ConnectionError, GetStreamId, StopStream},
    varint::VarInt,
};

// ---------------------------------------------------------------------------
// Mock stream types — needed because `quic::test` is `#[cfg(test)]` and thus
// unavailable from integration tests.
// ---------------------------------------------------------------------------

/// A minimal read stream backed by an in-memory list of `Bytes` chunks.
/// Implements the traits required by `quic::ReadStream`.
struct MockReadStream {
    stream_id: VarInt,
    chunks: Vec<Bytes>,
    index: usize,
}

impl MockReadStream {
    fn new(stream_id: VarInt, chunks: Vec<Bytes>) -> Self {
        Self {
            stream_id,
            chunks,
            index: 0,
        }
    }
}

impl GetStreamId for MockReadStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl StopStream for MockReadStream {
    fn poll_stop(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for MockReadStream {
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.index < this.chunks.len() {
            let chunk = this.chunks[this.index].clone();
            this.index += 1;
            Poll::Ready(Some(Ok(chunk)))
        } else {
            Poll::Ready(None)
        }
    }
}

/// A minimal write stream that discards everything.
/// Implements the traits required by `quic::WriteStream`.
struct MockWriteStream {
    stream_id: VarInt,
}

impl GetStreamId for MockWriteStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl quic::CancelStream for MockWriteStream {
    fn poll_cancel(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        Poll::Ready(Ok(()))
    }
}

impl futures::Sink<Bytes> for MockWriteStream {
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// MockLayer — a configurable test layer that accepts uni streams whose VarInt
// stream-type header matches a set of "accepted" types.
// ---------------------------------------------------------------------------

/// A test-only protocol layer that accepts unidirectional streams whose leading
/// VarInt stream-type is in `accepted_types`. All other uni streams (and all bi
/// streams) are passed through.
struct MockLayer {
    layer_name: &'static str,
    accepted_types: Vec<VarInt>,
}

impl MockLayer {
    fn new(name: &'static str, accepted_types: Vec<VarInt>) -> Self {
        Self {
            layer_name: name,
            accepted_types,
        }
    }
}

impl<C: Send + Sync + 'static> ProtocolLayer<C> for MockLayer {
    fn name(&self) -> &'static str {
        self.layer_name
    }

    fn init(&self, _quic: &C) -> BoxFuture<'_, Result<(), ConnectionError>> {
        Box::pin(async { Ok(()) })
    }

    fn accept_uni(
        &self,
        mut stream: PeekableUniStream,
    ) -> BoxFuture<'_, Result<StreamVerdict<PeekableUniStream>, ConnectionError>> {
        Box::pin(async move {
            // Peek the VarInt stream type using the standard codec pattern.
            let stream_type: VarInt = match stream.decode_one::<VarInt>().await {
                Ok(v) => v,
                Err(_) => {
                    // Cannot decode — reset and pass through.
                    stream.reset();
                    return Ok(StreamVerdict::Passed(stream));
                }
            };

            if self.accepted_types.contains(&stream_type) {
                // Accept: commit the peeked VarInt.
                stream.commit();
                Ok(StreamVerdict::Accepted)
            } else {
                // Pass: reset cursor so the next layer can re-read the VarInt.
                stream.reset();
                Ok(StreamVerdict::Passed(stream))
            }
        })
    }

    fn accept_bi(
        &self,
        stream: PeekableBiStream,
    ) -> BoxFuture<'_, Result<StreamVerdict<PeekableBiStream>, ConnectionError>> {
        // MockLayer only cares about uni streams.
        Box::pin(async { Ok(StreamVerdict::Passed(stream)) })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a `PeekableUniStream` from in-memory byte chunks (synchronous, no
/// spawning needed).
fn peekable_uni_from_chunks(chunks: Vec<&'static [u8]>) -> PeekableUniStream {
    let bytes_chunks: Vec<Bytes> = chunks.into_iter().map(Bytes::from_static).collect();
    let reader = MockReadStream::new(VarInt::from_u32(0), bytes_chunks);
    let boxed: Pin<Box<dyn quic::ReadStream + Send>> = Box::pin(reader);
    PeekableStreamReader::new(StreamReader::new(boxed))
}

/// Create a `PeekableBiStream` from in-memory byte chunks on the read side.
fn peekable_bi_from_chunks(read_chunks: Vec<&'static [u8]>) -> PeekableBiStream {
    let bytes_chunks: Vec<Bytes> = read_chunks.into_iter().map(Bytes::from_static).collect();
    let reader = MockReadStream::new(VarInt::from_u32(4), bytes_chunks);
    let writer = MockWriteStream {
        stream_id: VarInt::from_u32(4),
    };

    let boxed_reader: Pin<Box<dyn quic::ReadStream + Send>> = Box::pin(reader);
    let boxed_writer: Pin<Box<dyn quic::WriteStream + Send>> = Box::pin(writer);
    let peekable = PeekableStreamReader::new(StreamReader::new(boxed_reader));
    (peekable, boxed_writer)
}

/// Simulate the routing loop used by `Connection`'s background task:
/// iterate layers, pass or accept.
async fn route_uni(
    layers: &[&dyn ProtocolLayer<()>],
    stream: PeekableUniStream,
) -> Result<(&'static str, StreamVerdict<PeekableUniStream>), ConnectionError> {
    let mut current = stream;
    for layer in layers {
        match layer.accept_uni(current).await? {
            StreamVerdict::Accepted => return Ok((layer.name(), StreamVerdict::Accepted)),
            StreamVerdict::Passed(s) => current = s,
        }
    }
    Ok(("none", StreamVerdict::Passed(current)))
}

// ===========================================================================
// Tests
// ===========================================================================

#[tokio::test]
async fn mock_layer_accepts_matching_uni_stream() {
    let _guard = tracing_subscriber::fmt::try_init();

    // MockLayer that accepts stream type 0x41 (2-byte VarInt: 0x40, 0x41).
    let layer = MockLayer::new("test", vec![VarInt::from_u32(0x41)]);

    // Construct a uni stream whose first bytes are the VarInt 0x41 followed by payload.
    let stream = peekable_uni_from_chunks(vec![&[0x40, 0x41], b"payload"]);
    let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;

    assert!(result.is_ok());
    assert!(
        matches!(result.unwrap(), StreamVerdict::Accepted),
        "MockLayer should accept stream type 0x41"
    );
}

#[tokio::test]
async fn mock_layer_passes_non_matching_uni_stream() {
    let _guard = tracing_subscriber::fmt::try_init();

    // MockLayer that only accepts stream type 0x10.
    let layer = MockLayer::new("test", vec![VarInt::from_u32(0x10)]);

    // Send stream type 0x05 — should be passed.
    let stream = peekable_uni_from_chunks(vec![&[0x05], b"data"]);
    let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;

    assert!(result.is_ok());
    assert!(
        matches!(result.unwrap(), StreamVerdict::Passed(_)),
        "MockLayer should pass stream type 0x05 when it only accepts 0x10"
    );
}

#[tokio::test]
async fn mock_layer_passes_bi_streams() {
    let _guard = tracing_subscriber::fmt::try_init();

    let layer = MockLayer::new("test", vec![VarInt::from_u32(0x00)]);
    let stream = peekable_bi_from_chunks(vec![b"some data"]);
    let result = ProtocolLayer::<()>::accept_bi(&layer, stream).await;

    assert!(result.is_ok());
    assert!(
        matches!(result.unwrap(), StreamVerdict::Passed(_)),
        "MockLayer should always pass bi streams"
    );
}

#[tokio::test]
async fn mock_layer_with_no_accepted_types_passes_everything() {
    let _guard = tracing_subscriber::fmt::try_init();

    let layer = MockLayer::new("empty", vec![]);

    // Any stream type should be passed.
    let stream = peekable_uni_from_chunks(vec![&[0x00]]);
    let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
    assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));

    let stream = peekable_uni_from_chunks(vec![&[0x02]]);
    let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
    assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));
}

#[tokio::test]
async fn mock_layer_init_succeeds() {
    let _guard = tracing_subscriber::fmt::try_init();

    let layer = MockLayer::new("init-test", vec![]);
    let result = ProtocolLayer::<()>::init(&layer, &()).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Peek / reset round-trip: after a layer passes, the next layer can re-read
// the same VarInt stream-type header.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn peek_reset_preserves_bytes_across_layers() {
    let _guard = tracing_subscriber::fmt::try_init();

    // Stream type 0x02 (1-byte VarInt) followed by payload.
    let stream = peekable_uni_from_chunks(vec![&[0x02], b"rest"]);

    // First layer does NOT accept 0x02 — it peeks, resets, passes.
    let layer_a = MockLayer::new("layer-a", vec![VarInt::from_u32(0x99)]);
    let result = ProtocolLayer::<()>::accept_uni(&layer_a, stream)
        .await
        .unwrap();

    let stream = match result {
        StreamVerdict::Passed(s) => s,
        StreamVerdict::Accepted => panic!("layer-a should not accept 0x02"),
    };

    // Second layer DOES accept 0x02 — it peeks the same bytes (due to reset by layer-a).
    let layer_b = MockLayer::new("layer-b", vec![VarInt::from_u32(0x02)]);
    let result = ProtocolLayer::<()>::accept_uni(&layer_b, stream)
        .await
        .unwrap();

    assert!(
        matches!(result, StreamVerdict::Accepted),
        "layer-b should accept 0x02 after layer-a passed it"
    );
}

#[tokio::test]
async fn peek_reset_with_multibyte_varint() {
    let _guard = tracing_subscriber::fmt::try_init();

    // 2-byte VarInt: 0x40, 0x41 = 0x41 = 65
    let stream = peekable_uni_from_chunks(vec![&[0x40, 0x41], b"payload"]);

    // Layer that doesn't accept 0x41
    let layer_a = MockLayer::new("layer-a", vec![VarInt::from_u32(0x00)]);
    let result = ProtocolLayer::<()>::accept_uni(&layer_a, stream)
        .await
        .unwrap();
    let stream = match result {
        StreamVerdict::Passed(s) => s,
        StreamVerdict::Accepted => panic!("should pass"),
    };

    // Layer that does accept 0x41
    let layer_b = MockLayer::new("layer-b", vec![VarInt::from_u32(0x41)]);
    let result = ProtocolLayer::<()>::accept_uni(&layer_b, stream)
        .await
        .unwrap();
    assert!(matches!(result, StreamVerdict::Accepted));
}

// ---------------------------------------------------------------------------
// Routing loop simulation: multi-layer chain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn routing_loop_first_layer_accepts() {
    let _guard = tracing_subscriber::fmt::try_init();

    let layer_a = MockLayer::new("alpha", vec![VarInt::from_u32(0x00)]);
    let layer_b = MockLayer::new("beta", vec![VarInt::from_u32(0x01)]);
    let layers: Vec<&dyn ProtocolLayer<()>> = vec![&layer_a, &layer_b];

    // Stream type 0x00 — accepted by first layer.
    let stream = peekable_uni_from_chunks(vec![&[0x00], b"control"]);
    let (name, verdict) = route_uni(&layers, stream).await.unwrap();
    assert_eq!(name, "alpha");
    assert!(matches!(verdict, StreamVerdict::Accepted));
}

#[tokio::test]
async fn routing_loop_second_layer_accepts() {
    let _guard = tracing_subscriber::fmt::try_init();

    let layer_a = MockLayer::new("alpha", vec![VarInt::from_u32(0x00)]);
    let layer_b = MockLayer::new("beta", vec![VarInt::from_u32(0x01)]);
    let layers: Vec<&dyn ProtocolLayer<()>> = vec![&layer_a, &layer_b];

    // Stream type 0x01 — passed by alpha, accepted by beta.
    let stream = peekable_uni_from_chunks(vec![&[0x01], b"push"]);
    let (name, verdict) = route_uni(&layers, stream).await.unwrap();
    assert_eq!(name, "beta");
    assert!(matches!(verdict, StreamVerdict::Accepted));
}

#[tokio::test]
async fn routing_loop_no_layer_accepts_fallback() {
    let _guard = tracing_subscriber::fmt::try_init();

    let layer_a = MockLayer::new("alpha", vec![VarInt::from_u32(0x00)]);
    let layer_b = MockLayer::new("beta", vec![VarInt::from_u32(0x01)]);
    let layers: Vec<&dyn ProtocolLayer<()>> = vec![&layer_a, &layer_b];

    // Stream type 0x99 — no layer accepts.
    // VarInt 0x99 is a 2-byte encoding: 0x40, 0x99
    let stream = peekable_uni_from_chunks(vec![&[0x40, 0x99]]);
    let (name, verdict) = route_uni(&layers, stream).await.unwrap();
    assert_eq!(name, "none");
    assert!(
        matches!(verdict, StreamVerdict::Passed(_)),
        "unrecognized stream type should fall through all layers"
    );
}

#[tokio::test]
async fn routing_loop_three_layers() {
    let _guard = tracing_subscriber::fmt::try_init();

    let qpack = MockLayer::new(
        "qpack",
        vec![VarInt::from_u32(0x02), VarInt::from_u32(0x03)],
    );
    let dhttp = MockLayer::new(
        "dhttp",
        vec![VarInt::from_u32(0x00), VarInt::from_u32(0x01)],
    );
    let custom = MockLayer::new("custom", vec![VarInt::from_u32(0x10)]);
    let layers: Vec<&dyn ProtocolLayer<()>> = vec![&qpack, &dhttp, &custom];

    // QPACK encoder stream (0x02) → accepted by qpack layer
    let stream = peekable_uni_from_chunks(vec![&[0x02]]);
    let (name, _) = route_uni(&layers, stream).await.unwrap();
    assert_eq!(name, "qpack");

    // Control stream (0x00) → passed by qpack, accepted by dhttp
    let stream = peekable_uni_from_chunks(vec![&[0x00], b"settings"]);
    let (name, _) = route_uni(&layers, stream).await.unwrap();
    assert_eq!(name, "dhttp");

    // Custom type 0x10 → passed by qpack and dhttp, accepted by custom
    let stream = peekable_uni_from_chunks(vec![&[0x10]]);
    let (name, _) = route_uni(&layers, stream).await.unwrap();
    assert_eq!(name, "custom");

    // Unknown type 0x50 → falls through all (2-byte VarInt: 0x40, 0x50)
    let stream = peekable_uni_from_chunks(vec![&[0x40, 0x50]]);
    let (name, verdict) = route_uni(&layers, stream).await.unwrap();
    assert_eq!(name, "none");
    assert!(matches!(verdict, StreamVerdict::Passed(_)));
}

// ---------------------------------------------------------------------------
// PeekableStreamReader peek/reset unit tests (using mock streams)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn peekable_stream_peek_varint_and_reset() {
    let _guard = tracing_subscriber::fmt::try_init();

    // VarInt 0x02 (1 byte) followed by "rest"
    let mut stream = peekable_uni_from_chunks(vec![&[0x02], b"rest"]);

    // Peek the VarInt
    let v: VarInt = stream.decode_one::<VarInt>().await.unwrap();
    assert_eq!(v, VarInt::from_u32(0x02));
    assert!(stream.peeked() > 0);

    // Reset — VarInt bytes should be re-readable
    stream.reset();
    assert_eq!(stream.peeked(), 0);

    // Re-read the same VarInt
    let v2: VarInt = stream.decode_one::<VarInt>().await.unwrap();
    assert_eq!(v2, VarInt::from_u32(0x02));
}

#[tokio::test]
async fn peekable_stream_commit_advances_permanently() {
    let _guard = tracing_subscriber::fmt::try_init();

    // VarInt 0x03 followed by VarInt 0x04
    let mut stream = peekable_uni_from_chunks(vec![&[0x03, 0x04]]);

    // Peek and commit the first VarInt
    let v: VarInt = stream.decode_one::<VarInt>().await.unwrap();
    assert_eq!(v, VarInt::from_u32(0x03));
    stream.commit();

    // Reset after commit should NOT bring back 0x03
    stream.reset();
    let v2: VarInt = stream.decode_one::<VarInt>().await.unwrap();
    assert_eq!(
        v2,
        VarInt::from_u32(0x04),
        "after commit, the next VarInt should be 0x04"
    );
}

#[tokio::test]
async fn peekable_stream_peek_multiple_and_reset() {
    let _guard = tracing_subscriber::fmt::try_init();

    // Two 1-byte VarInts: 0x02, 0x03, then payload
    let mut stream = peekable_uni_from_chunks(vec![&[0x02, 0x03], b"payload"]);

    // Peek two VarInts
    let v1: VarInt = stream.decode_one::<VarInt>().await.unwrap();
    assert_eq!(v1, VarInt::from_u32(0x02));
    let v2: VarInt = stream.decode_one::<VarInt>().await.unwrap();
    assert_eq!(v2, VarInt::from_u32(0x03));

    // Reset — both should be re-readable
    stream.reset();
    let v1_again: VarInt = stream.decode_one::<VarInt>().await.unwrap();
    assert_eq!(v1_again, VarInt::from_u32(0x02));
    let v2_again: VarInt = stream.decode_one::<VarInt>().await.unwrap();
    assert_eq!(v2_again, VarInt::from_u32(0x03));
}

// ---------------------------------------------------------------------------
// DHttpLayer routing test — verify the real DHttpLayer accepts HTTP/3 streams
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dhttp_layer_routes_control_stream() {
    use h3x::layer::dhttp::DHttpLayer;

    let _guard = tracing_subscriber::fmt::try_init();

    let layer = DHttpLayer::with_default_settings();

    // Install a dispatch channel so accept_uni can dispatch the control stream.
    let (control_tx, _control_rx) = futures::channel::oneshot::channel();
    layer.set_control_dispatch_channel(control_tx);

    // Stream type 0x00 = HTTP/3 control stream
    let stream = peekable_uni_from_chunks(vec![&[0x00], b"settings_frame"]);
    let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
    assert!(result.is_ok());
    assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
}

#[tokio::test]
async fn dhttp_layer_passes_unknown_stream() {
    use h3x::layer::dhttp::DHttpLayer;

    let _guard = tracing_subscriber::fmt::try_init();

    let layer = DHttpLayer::with_default_settings();

    // Stream type 0x04 is not an HTTP/3 type — should be passed.
    let stream = peekable_uni_from_chunks(vec![&[0x04], b"data"]);
    let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
    assert!(result.is_ok());
    assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));
}

#[tokio::test]
async fn dhttp_layer_accepts_all_bi_streams() {
    use h3x::layer::dhttp::DHttpLayer;

    let _guard = tracing_subscriber::fmt::try_init();

    let layer = DHttpLayer::with_default_settings();
    let stream = peekable_bi_from_chunks(vec![b"request"]);
    let result = ProtocolLayer::<()>::accept_bi(&layer, stream).await;
    assert!(result.is_ok());
    assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
}

// ---------------------------------------------------------------------------
// Trait object / Any downcasting
// ---------------------------------------------------------------------------

#[test]
fn mock_layer_trait_object_downcast() {
    let _guard = tracing_subscriber::fmt::try_init();

    let layer = MockLayer::new("downcast-test", vec![]);
    let any_ref: &dyn Any = &layer;
    assert!(any_ref.downcast_ref::<MockLayer>().is_some());
}

#[test]
fn mock_layer_name() {
    let _guard = tracing_subscriber::fmt::try_init();

    let layer = MockLayer::new("my-layer", vec![VarInt::from_u32(0x42)]);
    assert_eq!(ProtocolLayer::<()>::name(&layer), "my-layer");
}

// ---------------------------------------------------------------------------
// Edge case: empty stream (no data to decode)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mock_layer_handles_empty_stream() {
    let _guard = tracing_subscriber::fmt::try_init();

    let layer = MockLayer::new("test", vec![VarInt::from_u32(0x00)]);

    // Empty stream — decode_one will fail, should pass through.
    let stream = peekable_uni_from_chunks(vec![]);
    let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
    assert!(result.is_ok());
    assert!(
        matches!(result.unwrap(), StreamVerdict::Passed(_)),
        "empty stream should be passed through"
    );
}

#[tokio::test]
async fn routing_loop_empty_stream_falls_through() {
    let _guard = tracing_subscriber::fmt::try_init();

    let layer_a = MockLayer::new("alpha", vec![VarInt::from_u32(0x00)]);
    let layer_b = MockLayer::new("beta", vec![VarInt::from_u32(0x01)]);
    let layers: Vec<&dyn ProtocolLayer<()>> = vec![&layer_a, &layer_b];

    let stream = peekable_uni_from_chunks(vec![]);
    let (name, verdict) = route_uni(&layers, stream).await.unwrap();
    assert_eq!(name, "none");
    assert!(matches!(verdict, StreamVerdict::Passed(_)));
}
