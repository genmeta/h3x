use snafu::Snafu;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(module, visibility(pub))]
pub enum PendingWriteStreamError {
    #[snafu(display("pending write stream is unsupported"))]
    Unsupported,
    #[snafu(display("pending write stream was already taken"))]
    AlreadyTaken,
    #[snafu(display("pending write stream provider was dropped before delivery"))]
    Aborted,
    #[snafu(display("pending message body could not be released"))]
    BodyNotReleased,
}

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum IntoStreamsError {
    #[snafu(display("failed to obtain pending write stream"))]
    PendingWriteStream { source: PendingWriteStreamError },
}
