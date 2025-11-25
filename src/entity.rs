pub mod stream;

use bytes::Buf;
use http::{
    HeaderMap,
    header::{InvalidHeaderName, InvalidHeaderValue},
};
use snafu::Snafu;

use crate::{
    buflist::{BufList, Cursor},
    qpack::field_section::{FieldSection, PseudoHeaders},
};

enum Body {
    Streaming,
    Chunked(Cursor<BufList>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EntityStage {
    Header = 0,
    Body = 1,
    Trailer = 2,
    Complete = 3,
}

#[derive(Debug, Snafu, Clone)]
pub enum IllegalEntityOperator {
    #[snafu(display("Header cannot be modified: Header section already sent"))]
    ModifyHeaderAfterSent,
    #[snafu(display("Entity with incomplete pseudo headers cannot be sent"))]
    SendIncompleteHeader,
    #[snafu(display("Body cannot be modified: Body is sending"))]
    ModifyBodyAfterSent,
    #[snafu(display("Buffered body be replaced: Body is sending"))]
    ReplaceBodyWhileSending,
    #[snafu(display("Cannot perform chunked operation on streaming entity body"))]
    ChunkedOperatorOnStreamingBody,
    #[snafu(display("Cannot perform streaming operation on chunked entity body"))]
    StreamingOperatorOnChunkedBody,
    #[snafu(display("Cannot switch body mode after body started sending"))]
    SwitchBodyModeAfterSent,
    #[snafu(display("Header frame payload too large, maybe too may header fields"))]
    HeaderFramePayloadTooLarge,
    #[snafu(display("Data frame payload too large, try smaller chunk size"))]
    DataFramePayloadTooLarge,
    #[snafu(display("Trailer cannot be modified: Trailer section already sent"))]
    ModifyTrailerAfterSent,
    #[snafu(display("Cannot set body or trailer sections for interim response"))]
    SendBodyOrTrailerForInterimResponse,
    #[snafu(display("Response stream cannot be closed without final response"))]
    MissingFinalResponse,
}

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
            body: Body::Chunked(Cursor::new(BufList::new())),
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
            body: Body::Chunked(Cursor::new(BufList::new())),
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

    pub fn chunked_body(&mut self) -> Result<&mut Cursor<BufList>, IllegalEntityOperator> {
        if let Body::Streaming = &self.body {
            if self.stage != EntityStage::Header {
                return Err(IllegalEntityOperator::SwitchBodyModeAfterSent);
            }
            self.body = Body::Chunked(Cursor::new(BufList::new()));
        }
        match &mut self.body {
            Body::Streaming => unreachable!(),
            Body::Chunked(cursor) => Ok(cursor),
        }
    }

    pub fn enbale_streaming(&mut self) -> Result<(), IllegalEntityOperator> {
        if let Body::Chunked(_) = &self.body {
            if self.stage != EntityStage::Header {
                return Err(IllegalEntityOperator::SwitchBodyModeAfterSent);
            }
            self.body = Body::Streaming;
        }
        Ok(())
    }

    pub fn is_interim_response(&self) -> bool {
        self.is_response() && self.header().status().is_informational()
    }

    pub fn is_header_complete(&self) -> bool {
        todo!("checks for pseudo headers")
    }

    pub fn header_mut(&mut self) -> Result<&mut FieldSection, IllegalEntityOperator> {
        if self.stage != EntityStage::Header {
            return Err(IllegalEntityOperator::ModifyHeaderAfterSent);
        }
        Ok(&mut self.header)
    }

    pub fn header(&self) -> &FieldSection {
        &self.header
    }

    pub fn is_streaming(&self) -> bool {
        matches!(self.body, Body::Streaming)
    }

    pub fn is_chunked(&self) -> bool {
        matches!(self.body, Body::Chunked(_))
    }

    /// Set body to buffer mode with given content
    pub fn set_body(&mut self, mut content: impl Buf) -> Result<(), IllegalEntityOperator> {
        if self.is_interim_response() {
            return Err(IllegalEntityOperator::SendBodyOrTrailerForInterimResponse);
        }
        if self.stage >= EntityStage::Trailer {
            return Err(IllegalEntityOperator::ModifyBodyAfterSent);
        }
        if self.stage == EntityStage::Body {
            return Err(IllegalEntityOperator::ReplaceBodyWhileSending);
        }

        let mut buflist = BufList::new();
        while content.has_remaining() {
            buflist.write(content.copy_to_bytes(content.chunk().len()));
        }
        self.body = Body::Chunked(Cursor::new(buflist));

        Ok(())
    }

    pub fn trailers(&mut self) -> &HeaderMap {
        &self.trailer.header_map
    }

    pub fn trailers_mut(&mut self) -> Result<&mut HeaderMap, IllegalEntityOperator> {
        if self.is_interim_response() {
            return Err(IllegalEntityOperator::SendBodyOrTrailerForInterimResponse);
        }
        if self.stage > EntityStage::Trailer {
            return Err(IllegalEntityOperator::ModifyTrailerAfterSent);
        }
        Ok(&mut self.trailer.header_map)
    }

    pub fn is_complete(&self) -> bool {
        self.stage == EntityStage::Complete
    }
}
