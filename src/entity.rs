pub mod stream;

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
    Streaming { received: u64 },
    Chunked { buflist: Cursor<BufList> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntityStage {
    Header = 0,
    Body = 1,
    Trailer = 2,
    Complete = 3,
}

#[derive(Debug, Snafu)]
pub enum IllegalEntityOperator {
    #[snafu(display("Header section cannot be modified after sent"))]
    ModifyHeaderAfterSent,
    #[snafu(display("Malformed pseudo header section cannot be sent"))]
    SendMalformedPseudoHeader { source: MalformedHeaderSection },
    #[snafu(display("Body cannot be modified: Body is sending"))]
    ModifyBodyAfterSent,
    #[snafu(display("Chunked cannot be modified while sending"))]
    ReplaceBodyWhileSending,
    #[snafu(display("Chunked body operation cannot be performed on streaming entity body"))]
    ChunkedOperatorOnStreamingBody,
    #[snafu(display("Streaming body operation cannot be performed on chunked entity body"))]
    StreamingOperatorOnChunkedBody,
    #[snafu(display("Body mode cannot be changed which sending"))]
    ChangeBodyModeInTransport,
    #[snafu(display("Header frame payload too large, maybe too may header fields"))]
    HeaderFramePayloadTooLarge,
    #[snafu(display("Data frame payload too large, try smaller chunk size"))]
    DataFramePayloadTooLarge,
    #[snafu(display("Trailer section cannot be modified after sent"))]
    ModifyTrailerAfterSent,
    #[snafu(display("Body or trailer sections cannot be set for interim response"))]
    SendBodyOrTrailerForInterimResponse,
    #[snafu(display("Response stream cannot be closed without final response"))]
    MissingFinalResponse,
}

#[derive(Debug, Clone)]
pub struct Entity {
    header: FieldSection,
    body: Body,
    trailer: FieldSection,

    stage: EntityStage,
}

#[derive(Debug, Snafu)]
pub enum InvalidHeader {
    #[snafu(transparent)]
    Name { source: InvalidHeaderName },
    #[snafu(transparent)]
    Value { source: InvalidHeaderValue },
}

impl Entity {
    pub fn unresolved_request() -> Self {
        Self {
            header: FieldSection::header(PseudoHeaders::unresolved_request(), HeaderMap::default()),
            body: Body::Chunked {
                buflist: Cursor::new(BufList::new()),
            },
            trailer: FieldSection::trailer(HeaderMap::default()),
            stage: EntityStage::Header,
        }
    }

    pub fn unresolved_response() -> Self {
        Self {
            header: FieldSection::header(
                PseudoHeaders::unresolved_response(),
                HeaderMap::default(),
            ),
            body: Body::Chunked {
                buflist: Cursor::new(BufList::new()),
            },
            trailer: FieldSection::trailer(HeaderMap::default()),
            stage: EntityStage::Header,
        }
    }

    pub fn is_request(&self) -> bool {
        matches!(
            self.header.pseudo_headers,
            Some(PseudoHeaders::Request { .. })
        )
    }

    pub fn is_response(&self) -> bool {
        matches!(
            self.header.pseudo_headers,
            Some(PseudoHeaders::Response { .. })
        )
    }

    pub fn enable_streaming(&mut self) -> Result<(), IllegalEntityOperator> {
        if let Body::Chunked { buflist } = &self.body {
            match self.stage {
                EntityStage::Header => {}
                EntityStage::Body if !buflist.inner().has_remaining() => {}
                _ => return Err(IllegalEntityOperator::ChangeBodyModeInTransport),
            }

            self.body = Body::Streaming { received: 0 }
        }
        Ok(())
    }

    pub fn chunked_body(&mut self) -> Result<&mut Cursor<BufList>, IllegalEntityOperator> {
        if let Body::Streaming { received } = &self.body {
            match self.stage {
                EntityStage::Header => { /* Ok to change mode: body unused */ }
                EntityStage::Body if *received == 0 => { /* Ok to change mode: body unused */ }
                _ => return Err(IllegalEntityOperator::ChangeBodyModeInTransport),
            }
        }
        match &mut self.body {
            Body::Streaming { .. } => unreachable!(),
            Body::Chunked { buflist } => Ok(buflist),
        }
    }

    pub fn is_interim_response(&self) -> bool {
        self.is_response() && self.header().status().is_informational()
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
    pub fn set_body(&mut self, mut content: impl Buf) -> Result<(), IllegalEntityOperator> {
        if self.is_interim_response() {
            return Err(IllegalEntityOperator::SendBodyOrTrailerForInterimResponse);
        }

        let mut buflist = BufList::new();
        while content.has_remaining() {
            buflist.write(content.copy_to_bytes(content.chunk().len()));
        }
        self.body = Body::Chunked {
            buflist: Cursor::new(buflist),
        };

        Ok(())
    }

    pub fn trailers(&self) -> &HeaderMap {
        &self.trailer.header_map
    }

    pub fn trailers_mut(&mut self) -> Result<&mut HeaderMap, IllegalEntityOperator> {
        if self.is_interim_response() {
            return Err(IllegalEntityOperator::SendBodyOrTrailerForInterimResponse);
        }
        Ok(&mut self.trailer.header_map)
    }

    pub fn stage(&self) -> EntityStage {
        self.stage
    }

    pub fn is_complete(&self) -> bool {
        self.stage() == EntityStage::Complete
    }
}
