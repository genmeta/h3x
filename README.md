# h3x

HTTP/3 message, frame, and stream primitives.

The public API currently focuses on request and response messages:

- `client::Request` and `client::Response`
- `server::Request` and `server::Response`
- buffered `bytes::Bytes` bodies
- streaming `ArcWndBuf` bodies

Message construction and access are provided by the traits exported at `h3x`:
`WriteRequest`, `ReadRequest`, `WriteResponse`, `ReadResponse`, `WriteBody`,
`ReadBody`, `WriteStream`, and `ReadStream`.

`client::Request` writes requests; `client::Response` reads responses.
`server::Request` reads requests; `server::Response` writes responses.
Request types have no response status API, and response types have no request
method API. Incoming messages cannot be converted into writable messages.
Internal message types and read/write markers are not public.
Frame encoding, stream state, and static-table QPACK are internal protocol
building blocks while the connection layer is being rebuilt.

With an existing bidirectional stream, initiate one exchange with
`client::request(request, recv, send)`. On the accepting side,
`server::accept(recv)` parses the request and `server::respond(response, send)`
writes the response.

```rust,ignore
let request = client::Request::post("https://example.com/upload")?
    .header(header::CONTENT_LENGTH, "5".parse()?)
    .body(Bytes::from_static(b"hello"));
let response = client::request(request, recv, send).await?;

let request = server::accept(recv).await?;
let mut response = server::Response::default();
response.set_status(StatusCode::OK).set_body(Bytes::new());
server::respond(response, send).await?;
```

Use `streaming_post(url)`, `streaming_put`, `streaming_patch`, or
`streaming_connect` to construct a streaming request directly with a default 16 KiB buffer. Call `.clone()`
to create a handle that shares the same message and body stream.

```rust,ignore
let request = client::Request::streaming_post("https://example.com/upload")?;
let mut upload = request.clone();
// Send `request` concurrently with writing to `upload` and calling `finish()`.
```
