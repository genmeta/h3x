use super::*;

#[tokio::test]
async fn validates_ids_and_freezes_both_goaway_boundaries() {
    let mut view = StreamView::new(Role::Client);
    let wrong_role = StreamId::new(Role::Client, Dir::Bi, 0);
    let wrong_direction = StreamId::new(Role::Server, Dir::Uni, 0);
    assert_eq!(
        view.accept(wrong_role).unwrap_err().code,
        ErrorCode::InternalError
    );
    assert_eq!(
        view.accept(wrong_direction).unwrap_err().code,
        ErrorCode::InternalError
    );

    let largest_server_bi = StreamId::from(VarInt::try_from((1_u64 << 62) - 3).unwrap());
    let error = view.accept(largest_server_bi).unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestRejected);
    assert!(matches!(error, crate::Error::Stream(_)));

    let local = view.goaway();
    assert_eq!(view.goaway(), local);
    assert_eq!(
        view.local_not_goaway().unwrap_err().code,
        ErrorCode::RequestRejected
    );
    assert_eq!(
        view.accept(StreamId::new(Role::Server, Dir::Bi, 0))
            .unwrap_err()
            .code,
        ErrorCode::RequestRejected
    );
    assert_eq!(view.local_goaway().await, local);

    let remote = StreamId::new(Role::Client, Dir::Bi, 1);
    view.on_goaway(remote);
    view.recv_goway().await.unwrap();
    assert_eq!(
        view.remote_not_goway().unwrap_err().code,
        ErrorCode::RequestRejected
    );
}
