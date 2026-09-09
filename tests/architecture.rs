use std::{fs, path::Path};

#[test]
fn protocol_and_transport_do_not_depend_on_identity_or_application_api() {
    fn check(path: &Path) {
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                check(&entry.unwrap().path());
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let source = fs::read_to_string(path).unwrap();
            for forbidden in [
                "crate::api",
                "crate::runtime",
                "Endpoint",
                "RemoteAuthority",
                "RequestAuthority",
                "rustls::",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "{} depends on {forbidden}",
                    path.display()
                );
            }
        }
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for name in ["protocol.rs", "protocol", "transport.rs"] {
        check(&src.join(name));
    }
}

#[test]
fn client_and_server_messages_have_separate_public_paths() {
    use h3x::{client, server};
    let outgoing = client::Request::new(
        http::Method::GET,
        "https://peer.test/",
        client::Fixed::default(),
    )
    .unwrap();
    assert_eq!(outgoing.request().uri(), "https://peer.test/");
    assert_ne!(
        std::any::TypeId::of::<http::Response<()>>(),
        std::any::TypeId::of::<server::Response<()>>()
    );
    assert_ne!(
        std::any::TypeId::of::<client::Request<()>>(),
        std::any::TypeId::of::<server::Request<()>>()
    );
    assert_ne!(
        std::any::TypeId::of::<client::Response<()>>(),
        std::any::TypeId::of::<server::Response<()>>()
    );
}
