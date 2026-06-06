#![cfg(feature = "hyper")]

use bytes::Bytes;
use http_body_util::Empty;

#[test]
fn owner_local_hyper_modules_are_public() {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://example.test/")
        .body(())
        .expect("request should build");
    let fields = h3x::qpack::field::hyper::validated_hyper_request_parts_to_field_lines(
        request.into_parts().0,
    )
    .expect("request pseudo headers should be valid");
    assert!(!fields.is_empty());

    let _message_takeover = std::any::TypeId::of::<
        h3x::dhttp::message::hyper::upgrade::TakeoverSlot<h3x::dhttp::message::MessageReader>,
    >();
    let _endpoint_service = h3x::endpoint::hyper::TowerService(());
    let _endpoint_hyper_service = h3x::endpoint::hyper::HyperService(());
}

#[test]
fn top_level_hyper_is_facade_without_client_or_server_modules() {
    let _request_error = std::any::TypeId::of::<h3x::hyper::RequestError<std::io::Error>>();
    let _send_error = std::any::TypeId::of::<h3x::hyper::SendMessageError<std::io::Error>>();
    let _handle_error = std::any::TypeId::of::<
        h3x::hyper::HandleRequestError<std::io::Error, std::io::Error>,
    >();
    let _tower = h3x::hyper::TowerService(());
    let _hyper = h3x::hyper::HyperService(());
    let _upgrade_error = h3x::hyper::upgrade::MissingStream::Both;
    let _body = Empty::<Bytes>::new();
}
