use super::*;

pub(crate) fn shared() -> Arc<Qpack<crate::test_support::TestTransport>> {
    Qpack::new(
        Arc::new(crate::test_support::TestTransport::default()),
        &crate::Settings::default(),
        Arc::new(crate::protocol::stream::bi::BiStreams::default()),
    )
    .unwrap()
}
