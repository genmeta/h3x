mod common;

use std::time::Duration;

use tokio::time::timeout;

#[test]
fn peer_settings_resolve_after_h3_connection_setup_without_request_streams() {
    common::run(
        "peer_settings_resolve_after_h3_connection_setup_without_request_streams",
        async {
            let mut server = common::test_server().await;
            let client = common::test_client().await;
            let authority = server.1.clone();

            let (server_connection, client_connection) = timeout(Duration::from_secs(10), async {
                tokio::join!(server.0.accept(), client.connect(authority))
            })
            .await
            .expect("connections should be established");
            let server_connection = server_connection.expect("server h3 connection");
            let client_connection = client_connection.expect("client h3 connection");

            timeout(Duration::from_secs(5), client_connection.peer_settings())
                .await
                .expect("client peer settings should arrive")
                .expect("client peer settings should be ok");
            timeout(Duration::from_secs(5), server_connection.peer_settings())
                .await
                .expect("server peer settings should arrive")
                .expect("server peer settings should be ok");
        },
    );
}
