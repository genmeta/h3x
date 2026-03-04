use std::mem;

use bytes::{Buf, Bytes};
use http::{
    HeaderMap,
    header::{InvalidHeaderName, InvalidHeaderValue},
};
use snafu::Snafu;

use crate::{
    buflist::{BufList, Cursor},
    codec::EncodeError,
    connection,
    error::Code,
    frame::Frame,
    message::stream::{DEFAULT_COMPRESS_ALGO, MessageStreamError, ReadStream, WriteStream},
    qpack::{
        encoder::EncodeHeaderSectionError,
        field::{FieldSection, MalformedHeaderSection, PseudoHeaders, malformed_header_section},
    },
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

#[derive(Debug, Snafu)]
pub enum ReadToStringError {
    #[snafu(transparent)]
    Stream { source: MessageStreamError },
    #[snafu(transparent)]
    Utf8 { source: std::string::FromUtf8Error },
}

fn message_used_after_dropped() -> ! {
    unreachable!("Message used after destroyed, this is a bug");
}

impl ReadStream {
    pub async fn try_message_io<T>(
        &mut self,
        message: &mut Message,
        f: impl AsyncFnOnce(&mut Self, &mut Message) -> Result<T, connection::StreamError>,
    ) -> Result<T, MessageStreamError> {
        self.try_stream_io(async move |this| {
            let result = f(this, message).await;
            if let Err(connection::StreamError::Code { source }) = &result
                && source.code().is_known_stream_error()
            {
                message.set_malformed();
            }
            result
        })
        .await
    }

    pub async fn read_message_header<'e>(
        &mut self,
        message: &'e mut Message,
    ) -> Result<&'e FieldSection, MessageStreamError> {
        match message.stage {
            MessageStage::Header => {}
            // header already read
            MessageStage::Body | MessageStage::Trailer | MessageStage::Complete => {
                return Ok(&message.header);
            }
            MessageStage::Malformed => {
                return Err(MessageStreamError::MalformedIncomingMessage);
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        message.header = self
            .try_message_io(message, async |this, message| {
                let Some(field_section) = this.read_header_frame().await.transpose()? else {
                    if this.peek_frame().await.transpose()?.is_some() {
                        return Err(Code::H3_FRAME_UNEXPECTED.into());
                    } else {
                        return Err(Code::H3_MESSAGE_ERROR.into());
                    }
                };

                field_section.check_pseudo()?;
                if message.header.is_request_header() {
                    if !field_section.is_request_header() {
                        malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail()?;
                    }
                } else {
                    debug_assert!(message.header.is_response_header());
                    if !field_section.is_response_header() {
                        malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail()?;
                    }
                }
                Ok(field_section)
            })
            .await?;

        // check header complete/valid

        if message.is_interim_response() {
            message.stage = MessageStage::Header;
        } else {
            message.stage = MessageStage::Body;
        }
        Ok(&message.header)
    }

    pub async fn read_message_body_chunk(
        &mut self,
        message: &mut Message,
    ) -> Option<Result<Bytes, MessageStreamError>> {
        match message.stage {
            MessageStage::Header => {
                while message.stage == MessageStage::Header {
                    match self.read_message_header(message).await {
                        Ok(..) => (),
                        Err(error) => return Some(Err(error)),
                    }
                }
                debug_assert_eq!(message.stage, MessageStage::Body);
            }
            MessageStage::Body => {}
            MessageStage::Trailer | MessageStage::Complete => {
                match &mut message.body {
                    Body::Streaming { .. } => return None,
                    Body::Chunked { buflist } => {
                        if buflist.has_remaining() {
                            return Some(Ok(buflist.copy_to_bytes(buflist.chunk().len())));
                        }
                    }
                };
            }
            MessageStage::Malformed => {
                return Some(Err(MessageStreamError::MalformedIncomingMessage));
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        let try_read_next_chunk = self.try_message_io(message, async |this, message| {
            match this.read_data_frame_chunk().await.transpose()? {
                Some(chunk) => Ok(Some(chunk)),
                None => {
                    if this.peek_frame().await.transpose()?.is_some() {
                        message.stage = MessageStage::Trailer
                    } else {
                        message.stage = MessageStage::Complete
                    }
                    Ok(None)
                }
            }
        });

        match try_read_next_chunk.await {
            Ok(Some(bytes)) => Some(Ok(bytes)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }

    pub async fn read_message_full_body<'e>(
        &mut self,
        message: &'e mut Message,
    ) -> Result<impl Buf + 'e, MessageStreamError> {
        enum Buffer<'e> {
            Owned(BufList),
            Borrow(&'e mut Cursor<BufList>),
        }

        impl Buf for Buffer<'_> {
            fn remaining(&self) -> usize {
                match self {
                    Buffer::Owned(b) => b.remaining(),
                    Buffer::Borrow(b) => b.remaining(),
                }
            }

            fn has_remaining(&self) -> bool {
                match self {
                    Buffer::Owned(b) => b.has_remaining(),
                    Buffer::Borrow(b) => b.has_remaining(),
                }
            }

            fn chunk(&self) -> &[u8] {
                match self {
                    Buffer::Owned(b) => b.chunk(),
                    Buffer::Borrow(b) => b.chunk(),
                }
            }

            fn chunks_vectored<'a>(&'a self, dst: &mut [std::io::IoSlice<'a>]) -> usize {
                match self {
                    Buffer::Owned(b) => b.chunks_vectored(dst),
                    Buffer::Borrow(b) => b.chunks_vectored(dst),
                }
            }

            fn advance(&mut self, cnt: usize) {
                match self {
                    Buffer::Owned(b) => b.advance(cnt),
                    Buffer::Borrow(b) => b.advance(cnt),
                }
            }

            fn copy_to_bytes(&mut self, len: usize) -> bytes::Bytes {
                match self {
                    Buffer::Owned(b) => b.copy_to_bytes(len),
                    Buffer::Borrow(b) => b.copy_to_bytes(len),
                }
            }
        }

        match &mut message.body {
            Body::Streaming { .. } => {
                let mut buflist = BufList::new();
                while let Some(body_part) =
                    self.read_message_body_chunk(message).await.transpose()?
                {
                    buflist.write(body_part);
                }
                Ok(Buffer::Owned(buflist))
            }
            Body::Chunked { .. } => {
                while let Some(body_part) =
                    self.read_message_body_chunk(message).await.transpose()?
                {
                    message.chunked_body().expect("checked").write(body_part);
                }
                Ok(Buffer::Borrow(message.chunked_body().expect("checked")))
            }
        }
    }

    pub async fn read_message_body_to_bytes(
        &mut self,
        message: &mut Message,
    ) -> Result<Bytes, MessageStreamError> {
        let mut bytes = self.read_message_full_body(message).await?;
        Ok(bytes.copy_to_bytes(bytes.remaining()))
    }

    pub async fn read_message_body_to_string(
        &mut self,
        message: &mut Message,
    ) -> Result<String, ReadToStringError> {
        // TODO: preallocate buffer with content-length
        let mut vec = vec![];
        while let Some(bytes) = self.read_message(message).await.transpose()? {
            vec.extend_from_slice(&bytes);
        }
        Ok(String::from_utf8(vec)?)
    }

    pub async fn read_message(
        &mut self,
        message: &mut Message,
    ) -> Option<Result<Bytes, MessageStreamError>> {
        loop {
            match &mut message.body {
                Body::Streaming { .. } => return self.read_message_body_chunk(message).await,
                Body::Chunked { buflist } => {
                    if buflist.has_remaining() {
                        return Some(Ok(buflist.copy_to_bytes(buflist.chunk().len())));
                    }
                    match self.read_message_body_chunk(message).await? {
                        Ok(body_part) => {
                            message.chunked_body().expect("checked").write(body_part);
                            continue;
                        }
                        Err(error) => return Some(Err(error)),
                    }
                }
            }
        }
    }

    pub async fn read_message_trailer<'e>(
        &mut self,
        message: &'e mut Message,
    ) -> Result<&'e HeaderMap, MessageStreamError> {
        match message.stage {
            MessageStage::Header | MessageStage::Body => {
                match &message.body {
                    Body::Streaming { .. } => {
                        // read and discard body
                        while let Some(_body_part) =
                            self.read_message_body_chunk(message).await.transpose()?
                        {
                        }
                    }
                    Body::Chunked { .. } => {
                        self.read_message_full_body(message).await?;
                    }
                }
            }
            MessageStage::Trailer => {}
            MessageStage::Complete => return Ok(message.trailers()),
            MessageStage::Malformed => return Err(MessageStreamError::MalformedIncomingMessage),
            MessageStage::Dropped => message_used_after_dropped(),
        }

        message.trailer = self
            .try_message_io(message, async |this, _| {
                let Some(field_section) = this.read_header_frame().await.transpose()? else {
                    if this.peek_frame().await.transpose()?.is_some() {
                        return Err(Code::H3_FRAME_UNEXPECTED.into());
                    } else {
                        // no trailer
                        return Ok(FieldSection::trailer(HeaderMap::new()));
                    }
                };

                if !field_section.is_trailer() {
                    return Err(MalformedHeaderSection::PseudoHeaderInTrailer.into());
                }
                Ok(field_section)
            })
            .await?;

        message.stage = MessageStage::Complete;

        Ok(message.trailers())
    }
}

impl WriteStream {
    pub async fn send_message_header(
        &mut self,
        message: &mut Message,
    ) -> Result<(), MessageStreamError> {
        match message.stage {
            MessageStage::Header => {}
            // header already sent
            MessageStage::Body | MessageStage::Trailer | MessageStage::Complete => return Ok(()),
            MessageStage::Malformed => {
                return self.cancel(Code::H3_REQUEST_CANCELLED).await;
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        self.send_header(message.header.iter()).await?;
        if message.is_interim_response() {
            message.stage = MessageStage::Header;
        } else {
            message.stage = MessageStage::Body;
        }

        Ok(())
    }

    pub async fn send_data(&mut self, data: impl Buf) -> Result<(), MessageStreamError> {
        let frame = Frame::new(Frame::DATA_FRAME_TYPE, data)
            .map_err(|_| MessageStreamError::DataFrameTooLarge)?;
        self.try_stream_io(async |this| Ok(this.send_frame(frame).await?))
            .await
    }

    pub async fn send_message_streaming_body(
        &mut self,
        message: &mut Message,
        content: impl Buf,
    ) -> Result<(), MessageStreamError> {
        // if message.is_interim_response() {
        //     // malformed message
        // }
        // message.enable_streaming()?; // violate of set_body call

        match message.stage {
            MessageStage::Header => {
                self.send_message_header(message).await?;
                debug_assert_eq!(message.stage, MessageStage::Body);
            }
            MessageStage::Body => {}
            MessageStage::Trailer | MessageStage::Complete => {
                /* this will cause H3_FRAME_UNEXPECTED error */
            }
            MessageStage::Malformed => {
                return self.cancel(Code::H3_REQUEST_CANCELLED).await;
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        let len = content.remaining();
        self.send_data(content).await?;
        *message
            .streaming_body()
            .expect("call send_streaming_body on chunked body, this is a bug") += len as u64;

        Ok(())
    }

    pub async fn send_message_chunked_body(
        &mut self,
        message: &mut Message,
    ) -> Result<(), MessageStreamError> {
        // if message.is_interim_response() {
        //     // malformed message
        // }

        match message.stage {
            MessageStage::Header => {
                self.send_message_header(message).await?;
                debug_assert_eq!(message.stage, MessageStage::Body);
            }
            MessageStage::Body => {}
            MessageStage::Trailer | MessageStage::Complete => {
                /* this will cause H3_FRAME_UNEXPECTED error */
            }
            MessageStage::Malformed => {
                return self.cancel(Code::H3_REQUEST_CANCELLED).await;
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        let Body::Chunked { buflist } = &mut message.body else {
            unreachable!("Call send_chunked_body on non-chunked body, this is a bug");
        };

        while buflist.has_remaining() {
            let bytes = buflist.copy_to_bytes(buflist.chunk().len());
            let frame = Frame::new(Frame::DATA_FRAME_TYPE, bytes)
                .map_err(|_| MessageStreamError::DataFrameTooLarge)?;
            self.try_stream_io(async |this| Ok(this.send_frame(frame).await?))
                .await?;
        }

        message.stage = MessageStage::Trailer;
        Ok(())
    }

    pub async fn send_message_trailer(
        &mut self,
        message: &mut Message,
    ) -> Result<(), MessageStreamError> {
        // prepare
        match message.stage {
            MessageStage::Header | MessageStage::Body => {
                if message.is_chunked() {
                    self.send_message_chunked_body(message).await?;
                    debug_assert_eq!(message.stage, MessageStage::Trailer);
                } else {
                    self.send_message_header(message).await?;
                    debug_assert_eq!(message.stage, MessageStage::Body);
                    // no body or streaming body already sent
                }
            }
            MessageStage::Trailer => {}
            MessageStage::Complete => return Ok(()),
            MessageStage::Malformed => {
                return self.cancel(Code::H3_REQUEST_CANCELLED).await;
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        // TODO: check FieldLines size
        let field_lines = message.trailer.iter();
        let algo = &DEFAULT_COMPRESS_ALGO;

        let result = self
            .try_stream_io(async move |this| {
                let stream = &mut this.stream;
                match this.qpack_encoder.encode(field_lines, algo, stream).await {
                    Ok(frame) => Ok(Ok(this.send_frame(frame).await?)),
                    Err(EncodeHeaderSectionError::Encode { source }) => Ok(Err(source)),
                    Err(EncodeHeaderSectionError::Stream { source }) => Err(source),
                }
            })
            .await?;

        match result {
            Ok(()) => {
                message.stage = MessageStage::Complete;
                Ok(())
            }
            Err(error) => match error {
                EncodeError::FramePayloadTooLarge => Err(MessageStreamError::TrailerTooLarge),
                EncodeError::HuffmanEncoding => {
                    unreachable!("FieldSection contain invalid header name/value, this is a bug")
                }
            },
        }
    }

    pub async fn send_message(&mut self, message: &mut Message) -> Result<(), MessageStreamError> {
        match message.stage {
            MessageStage::Header | MessageStage::Body => {
                if message.header().is_empty() {
                    return Ok(());
                }
                if message.is_chunked() {
                    self.send_message_chunked_body(message).await?;
                    debug_assert_eq!(message.stage, MessageStage::Trailer);
                } else {
                    self.send_message_header(message).await?;
                    if message.is_interim_response() {
                        debug_assert!(message.stage == MessageStage::Header);
                    } else {
                        debug_assert!(message.stage == MessageStage::Body);
                    }
                }

                if !message.trailers().is_empty() {
                    self.send_message_trailer(message).await?;
                    debug_assert_eq!(message.stage, MessageStage::Complete)
                }
            }
            MessageStage::Trailer => {
                if !message.trailers().is_empty() {
                    self.send_message_trailer(message).await?;
                    debug_assert_eq!(message.stage, MessageStage::Complete)
                } else {
                    // no trailer to send
                }
            }
            MessageStage::Complete => {}
            MessageStage::Malformed => {
                return self.cancel(Code::H3_REQUEST_CANCELLED).await;
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        Ok(())
    }

    pub async fn flush_message(&mut self, message: &mut Message) -> Result<(), MessageStreamError> {
        self.send_message(message).await?;
        self.flush().await
    }

    pub async fn close_message(&mut self, message: &mut Message) -> Result<(), MessageStreamError> {
        self.send_message(message).await?;
        self.close().await
    }
}
