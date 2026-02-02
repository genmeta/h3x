pub mod stream;

use std::mem;

use bytes::Buf;
use http::{
    HeaderMap,
    header::{InvalidHeaderName, InvalidHeaderValue},
};
use snafu::Snafu;

use crate::{
    buflist::{BufList, Cursor},
    qpack::field_section::{FieldSection, MalformedHeaderSection, PseudoHeaders},
};

#[derive(Debug, Clone)]
enum Body {
    Streaming { count: u64 },
    Chunked { buflist: Cursor<BufList> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageStage {
    /// Receiving/Sending header section, including interim response headers
    Header = 0,
    /// Receiving/Sending message body
    Body = 1,
    /// Receiving/Sending trailer section
    Trailer = 2,
    /// Message is completely sent/received
    Complete = 3,

    /// Message struct is malformed
    Malformed = 4,
    /// Message struct is already taken/dropped
    // State can be removed after async drop stablizes
    Dropped = 5,
}

#[derive(Debug, Snafu)]
pub enum MalformedMessageError {
    // === 状态相关错误 ===
    #[snafu(display("cannot modify header section after it has been sent"))]
    HeaderAlreadySent,
    #[snafu(display("cannot modify body while it is being sent"))]
    BodyAlreadySending,
    #[snafu(display("cannot replace body content while sending"))]
    BodyReplacementDuringSend,
    #[snafu(display("cannot modify trailer section after it has been sent"))]
    TrailerAlreadySent,
    #[snafu(display("cannot change body mode after transfer has started"))]
    BodyModeChangeAfterTransferStarted,

    // === 模式不匹配错误 ===
    #[snafu(display("chunked body operation cannot be performed on streaming body"))]
    ChunkedOperationOnStreamingBody,
    #[snafu(display("streaming body operation cannot be performed on chunked body"))]
    StreamingOperationOnChunkedBody,

    // === 协议语义错误 ===
    #[snafu(display("cannot send malformed pseudo header section"))]
    MalformedPseudoHeader { source: MalformedHeaderSection },
    #[snafu(display("cannot set body or trailer for interim (1xx) response"))]
    BodyOrTrailerOnInterimResponse,
    #[snafu(display("cannot close response stream without sending a final response"))]
    FinalResponseRequired,
}

impl From<MalformedHeaderSection> for MalformedMessageError {
    fn from(source: MalformedHeaderSection) -> Self {
        MalformedMessageError::MalformedPseudoHeader { source }
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    header: FieldSection,
    body: Body,
    trailer: FieldSection,

    stage: MessageStage,
}

#[derive(Debug, Snafu)]
pub enum InvalidHeader {
    #[snafu(transparent)]
    Name { source: InvalidHeaderName },
    #[snafu(transparent)]
    Value { source: InvalidHeaderValue },
}

impl Message {
    pub fn unresolved_request() -> Self {
        Self {
            header: FieldSection::header(PseudoHeaders::unresolved_request(), HeaderMap::default()),
            body: Body::Streaming { count: 0 },
            trailer: FieldSection::trailer(HeaderMap::default()),
            stage: MessageStage::Header,
        }
    }

    pub fn unresolved_response() -> Self {
        Self {
            header: FieldSection::header(
                PseudoHeaders::unresolved_response(),
                HeaderMap::default(),
            ),
            body: Body::Streaming { count: 0 },
            trailer: FieldSection::trailer(HeaderMap::default()),
            stage: MessageStage::Header,
        }
    }

    pub fn is_request(&self) -> bool {
        self.header.is_request_header()
    }

    pub fn is_response(&self) -> bool {
        self.header.is_response_header()
    }

    pub fn streaming_body(&mut self) -> Result<&mut u64, MalformedMessageError> {
        if let Body::Chunked { buflist } = &self.body {
            match self.stage {
                MessageStage::Header => {}
                MessageStage::Body if !buflist.inner().has_remaining() => {}
                _ => return Err(MalformedMessageError::BodyModeChangeAfterTransferStarted),
            }

            self.body = Body::Streaming { count: 0 }
        }
        match &mut self.body {
            Body::Streaming { count } => Ok(count),
            Body::Chunked { .. } => unreachable!(),
        }
    }

    pub fn chunked_body(&mut self) -> Result<&mut Cursor<BufList>, MalformedMessageError> {
        if let Body::Streaming { count } = &self.body {
            match self.stage {
                MessageStage::Header => { /* Ok to change mode: body unused */ }
                MessageStage::Body if *count == 0 => { /* Ok to change mode: body unused */ }
                _ => return Err(MalformedMessageError::BodyModeChangeAfterTransferStarted),
            }

            self.body = Body::Chunked {
                buflist: Cursor::new(BufList::new()),
            };
        }
        match &mut self.body {
            Body::Streaming { .. } => unreachable!(),
            Body::Chunked { buflist } => Ok(buflist),
        }
    }

    pub fn is_interim_response(&self) -> bool {
        self.is_response()
            && self.header().check_pseudo().is_ok()
            && self.header().status().is_informational()
    }

    pub fn header_mut(&mut self) -> &mut FieldSection {
        &mut self.header
    }

    pub fn header(&self) -> &FieldSection {
        &self.header
    }

    pub fn is_streaming(&self) -> bool {
        matches!(self.body, Body::Streaming { .. })
    }

    pub fn is_chunked(&self) -> bool {
        matches!(self.body, Body::Chunked { .. })
    }

    /// Set body to buffer mode with given content
    pub fn set_body(&mut self, mut content: impl Buf) {
        let mut buflist = BufList::new();
        while content.has_remaining() {
            buflist.write(content.copy_to_bytes(content.chunk().len()));
        }
        self.body = Body::Chunked {
            buflist: Cursor::new(buflist),
        };
    }

    pub fn trailers(&self) -> &HeaderMap {
        &self.trailer.header_map
    }

    pub fn trailers_mut(&mut self) -> &mut HeaderMap {
        &mut self.trailer.header_map
    }

    pub fn stage(&self) -> MessageStage {
        self.stage
    }

    pub fn is_complete(&self) -> bool {
        self.stage() == MessageStage::Complete
    }

    pub fn is_dropped(&self) -> bool {
        self.stage() == MessageStage::Dropped
    }

    pub fn is_malformed(&self) -> bool {
        self.stage() == MessageStage::Malformed
    }

    pub fn set_malformed(&mut self) {
        self.stage = MessageStage::Malformed;
    }

    /// Reset the message to unsent state
    pub fn to_unsend(mut self) -> Self {
        assert!(!self.is_dropped(), "cannot unsend a dropped message");
        self.stage = MessageStage::Header;
        // reset cursor
        if let Body::Chunked { buflist } = &mut self.body {
            buflist.reset();
        }
        self
    }

    pub fn take(&mut self) -> Self {
        assert!(!self.is_dropped(), "cannot take a dropped message");
        let message = if self.is_request() {
            mem::replace(self, Self::unresolved_request())
        } else {
            mem::replace(self, Self::unresolved_response())
        };
        self.stage = MessageStage::Dropped;

        message
    }
}
