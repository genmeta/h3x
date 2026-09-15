use std::io::Cursor;

use http::{HeaderValue, Method, header};
use tokio::io::{AsyncReadExt, duplex};

use super::*;
use crate::{
    ReadStream,
    common::message::{ReadResponse, WriteRequest, WriteStream},
    protocol::qpack::{self, WriteFieldSection},
};

mod lifecycle;
mod request;
mod response;

use std::pin::Pin;

use crate::common::message::ArcMessage;
// Caller-side policy retained for lifecycle regression tests, not a library API.
fn request<RS, WS, R, T: Transport>(
    request: R,
    recv: H3ReadStream<RS>,
    send: H3WriteStream<WS>,
    qpack: Arc<Qpack<T>>,
) -> impl Future<Output = Result<Response>> + Send
where
    RS: AsyncRead + Unpin + Send + 'static,
    WS: AsyncWrite + Unpin + Send + 'static,
    R: Into<common::Request<Write>>,
{
    use crate::ReadRequest;
    let request = request.into();

    async move {
        let method = request.method();
        let encoder = qpack.clone();
        let mut sending: Pin<Box<dyn Future<Output = Result<()>> + Send>> = match request {
            common::Request::Bytes(request) => {
                Box::pin(send_bytes_request(&request, send, encoder)?)
            }
            common::Request::Streaming(request) => {
                Box::pin(send_streaming_request(&request, send, encoder)?)
            }
        };
        let receiving = read_response(recv, qpack, Some(method));
        tokio::pin!(receiving);
        let response = tokio::select! {
            response = &mut receiving => response,
            _ = &mut sending => return receiving.await,
        }?;
        // Only a delivered response transfers the remaining upload to the background.
        tokio::spawn(sending);
        Ok(response)
    }
}
