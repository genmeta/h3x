use std::{future::Future, mem, ops::ControlFlow};

use bytes::{Buf, Bytes};
use http::{
    HeaderMap,
    header::{InvalidHeaderName, InvalidHeaderValue},
};
use snafu::Snafu;

use crate::{
    buflist::{BufList, BuflistCursor},
    codec::EncodeError,
    connection,
    dhttp::frame::Frame,
    error::{Code, H3FrameUnexpected, H3MessageError},
    message::stream::{DEFAULT_COMPRESS_ALGO, MessageStreamError, ReadStream, WriteStream},
    qpack::{
        encoder::EncodeHeaderSectionError,
        field::{
            FieldLine, FieldSection, MalformedHeaderSection, PseudoHeaders,
            malformed_header_section,
        },
    },
};

#[derive(Debug, Clone)]
enum Body {
    Streaming { count: u64 },
    Chunked { buflist: BuflistCursor },
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
    /// Message sending failed and cannot be resumed
    Failed = 5,
    /// Message struct is already taken/dropped
    // State can be removed after async drop stabilizes
    Dropped = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageWriteGoal {
    Header,
    Body,
    Complete,
}

pub type MessageWriteFlow = ControlFlow<Result<(), MessageStreamError>, ()>;

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
    #[snafu(display("cannot modify body after transfer has ended"))]
    BodyAlreadyComplete,
    #[snafu(display("cannot mutate malformed message"))]
    MessageMalformed,
    #[snafu(display("cannot mutate message after sending failed"))]
    MessageFailed,
    #[snafu(display("cannot mutate dropped message"))]
    MessageDropped,

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

// todo: 通过泛型区分请求和响应，避免运行时检查。虽现版本无法支持自定义泛型作为常量泛型，但可以通过零大小类型（ZST）和特化实现来达到类似效果。
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

    fn terminal_stage_error(&self) -> Option<MalformedMessageError> {
        match self.stage {
            MessageStage::Malformed => Some(MalformedMessageError::MessageMalformed),
            MessageStage::Failed => Some(MalformedMessageError::MessageFailed),
            MessageStage::Dropped => Some(MalformedMessageError::MessageDropped),
            MessageStage::Header
            | MessageStage::Body
            | MessageStage::Trailer
            | MessageStage::Complete => None,
        }
    }

    pub fn streaming_body(&mut self) -> Result<&mut u64, MalformedMessageError> {
        if let Some(error) = self.terminal_stage_error() {
            return Err(error);
        }
        if self.stage > MessageStage::Body {
            return Err(MalformedMessageError::BodyAlreadyComplete);
        }

        if let Body::Chunked { buflist } = &self.body {
            match self.stage {
                MessageStage::Header if !buflist.inner().has_remaining() => {}
                _ => return Err(MalformedMessageError::BodyModeChangeAfterTransferStarted),
            }

            self.body = Body::Streaming { count: 0 }
        }
        match &mut self.body {
            Body::Streaming { count } => Ok(count),
            Body::Chunked { .. } => unreachable!(),
        }
    }

    pub fn chunked_body(&mut self) -> Result<&mut BuflistCursor, MalformedMessageError> {
        if let Some(error) = self.terminal_stage_error() {
            return Err(error);
        }
        if self.stage > MessageStage::Body {
            return Err(MalformedMessageError::BodyAlreadyComplete);
        }

        if let Body::Streaming { .. } = &self.body {
            if self.stage != MessageStage::Header {
                return Err(MalformedMessageError::BodyModeChangeAfterTransferStarted);
            }
            self.body = Body::Chunked {
                buflist: BuflistCursor::new(BufList::new()),
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

    pub fn header_mut(&mut self) -> Result<&mut FieldSection, MalformedMessageError> {
        if let Some(error) = self.terminal_stage_error() {
            return Err(error);
        }
        if self.stage > MessageStage::Header {
            return Err(MalformedMessageError::HeaderAlreadySent);
        }
        Ok(&mut self.header)
    }

    pub(crate) fn header_mut_unchecked(&mut self) -> &mut FieldSection {
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
    pub fn set_body(&mut self, mut content: impl Buf) -> Result<(), MalformedMessageError> {
        if let Some(error) = self.terminal_stage_error() {
            return Err(error);
        }
        match self.stage {
            MessageStage::Header => {}
            MessageStage::Body => return Err(MalformedMessageError::BodyReplacementDuringSend),
            MessageStage::Trailer | MessageStage::Complete => {
                return Err(MalformedMessageError::BodyAlreadyComplete);
            }
            MessageStage::Malformed | MessageStage::Failed | MessageStage::Dropped => {
                unreachable!("terminal stages are checked above")
            }
        }

        let mut buflist = BufList::new();
        while content.has_remaining() {
            buflist.write(content.copy_to_bytes(content.chunk().len()));
        }
        self.body = Body::Chunked {
            buflist: BuflistCursor::new(buflist),
        };
        Ok(())
    }

    pub fn trailers(&self) -> &HeaderMap {
        self.trailer.header_map()
    }

    pub fn trailers_mut(&mut self) -> Result<&mut HeaderMap, MalformedMessageError> {
        if let Some(error) = self.terminal_stage_error() {
            return Err(error);
        }
        if self.stage > MessageStage::Trailer {
            return Err(MalformedMessageError::TrailerAlreadySent);
        }
        Ok(self.trailer.header_map_mut())
    }

    pub(crate) fn trailers_mut_unchecked(&mut self) -> &mut HeaderMap {
        self.trailer.header_map_mut()
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

    pub fn is_failed(&self) -> bool {
        self.stage() == MessageStage::Failed
    }

    pub fn set_failed(&mut self) {
        self.stage = MessageStage::Failed;
    }

    fn set_failed_unless_malformed(&mut self) {
        if !self.is_malformed() {
            self.set_failed();
        }
    }

    pub fn set_dropped(&mut self) {
        self.stage = MessageStage::Dropped;
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
            if let Err(connection::StreamError::H3 { .. }) = &result {
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
            MessageStage::Failed => return Err(MessageStreamError::MessageSendFailed),
            MessageStage::Dropped => message_used_after_dropped(),
        }

        message.header = self
            .try_message_io(message, async |this, message| {
                let Some(field_section) = this.read_header_frame().await.transpose()? else {
                    if this.peek_frame().await.transpose()?.is_some() {
                        return Err(H3FrameUnexpected::UnexpectedFrameType.into());
                    } else {
                        return Err(H3MessageError::MissingHeaderSection.into());
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
            MessageStage::Failed => return Some(Err(MessageStreamError::MessageSendFailed)),
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
            Borrow(&'e mut BuflistCursor),
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
                    let Body::Chunked { buflist } = &mut message.body else {
                        unreachable!("message body mode changed while reading chunked body")
                    };
                    buflist.write(body_part);
                }
                let Body::Chunked { buflist } = &mut message.body else {
                    unreachable!("message body mode changed while reading chunked body")
                };
                Ok(Buffer::Borrow(buflist))
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
                            let Body::Chunked { buflist } = &mut message.body else {
                                unreachable!("message body mode changed while reading chunked body")
                            };
                            buflist.write(body_part);
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
            MessageStage::Failed => return Err(MessageStreamError::MessageSendFailed),
            MessageStage::Dropped => message_used_after_dropped(),
        }

        message.trailer = self
            .try_message_io(message, async |this, _| {
                let Some(field_section) = this.read_header_frame().await.transpose()? else {
                    if this.peek_frame().await.transpose()?.is_some() {
                        return Err(H3FrameUnexpected::UnexpectedFrameDuringTrailer.into());
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
    /// Sends one atomic message write step toward `goal`.
    ///
    /// The method synchronously advances `message` before returning the future so
    /// the returned future does not borrow `message`. The returned future must be
    /// awaited to completion. Dropping it may leave `message` marked as if this step
    /// was written even though the frame was not sent.
    ///
    /// `ControlFlow::Continue(())` means the step was written successfully and the
    /// same goal still has more work. `ControlFlow::Break(Ok(()))` means the goal is
    /// satisfied. `ControlFlow::Break(Err(_))` means the step failed.
    ///
    /// # Error state
    ///
    /// Because the returned future no longer holds `message`, I/O errors are not
    /// written back into the message state. Callers using this low-level method
    /// directly must mark the message failed or malformed as appropriate.
    pub fn send_message_step<'s>(
        &'s mut self,
        message: &mut Message,
        goal: MessageWriteGoal,
    ) -> impl Future<Output = MessageWriteFlow> + use<'s> {
        let action = prepare_message_write_step(message, goal);

        async move { self.execute_message_write_step(action).await }
    }

    pub async fn send_data(&mut self, data: impl Buf + Send) -> Result<(), MessageStreamError> {
        let frame = Frame::new(Frame::DATA_FRAME_TYPE, data)?;
        self.try_stream_io(async |this| Ok(this.send_frame(frame).await?))
            .await
    }

    /// Sends one streaming body chunk.
    ///
    /// # Cancellation safety
    ///
    /// This method synchronously advances the message body count before returning
    /// the future so the returned future does not borrow `message`. The returned
    /// future must be awaited to completion. Dropping it may leave the message body
    /// count advanced even though the data was not written.
    ///
    /// # Error state
    ///
    /// Because the returned future no longer holds `message`, I/O errors are not
    /// written back into the message state. Callers using this low-level method
    /// directly must mark the message failed or malformed as appropriate.
    pub fn send_message_streaming_body<'s, B>(
        &'s mut self,
        message: &mut Message,
        content: B,
    ) -> impl Future<Output = Result<(), MessageStreamError>> + use<'s, B>
    where
        B: Buf + Send + 's,
    {
        // if message.is_interim_response() {
        //     // malformed message
        // }
        // message.enable_streaming()?; // violate of set_body call

        let additional = content.remaining() as u64;
        let action = match message.stage {
            MessageStage::Header | MessageStage::Body => {
                if let Err(_error) = message.streaming_body().map(|count| *count += additional) {
                    message.set_malformed();
                    StreamingBodyAction::Cancel
                } else {
                    StreamingBodyAction::Send {
                        header: prepare_message_write_step(message, MessageWriteGoal::Header),
                        content,
                    }
                }
            }
            MessageStage::Trailer | MessageStage::Complete => {
                message.set_malformed();
                StreamingBodyAction::Cancel
            }
            MessageStage::Malformed => StreamingBodyAction::Cancel,
            MessageStage::Failed => StreamingBodyAction::Failed,
            MessageStage::Dropped => message_used_after_dropped(),
        };

        async move {
            match action {
                StreamingBodyAction::Send { header, content } => {
                    match self.execute_message_write_step(header).await {
                        ControlFlow::Break(Ok(())) => {}
                        ControlFlow::Break(Err(error)) => return Err(error),
                        ControlFlow::Continue(()) => {
                            unreachable!("header goal cannot require another write step")
                        }
                    }
                    self.send_data(content).await
                }
                StreamingBodyAction::Cancel => self.cancel(Code::H3_REQUEST_CANCELLED).await,
                StreamingBodyAction::Failed => Err(MessageStreamError::MessageSendFailed),
            }
        }
    }

    /// Sends the complete buffered body.
    ///
    /// This wrapper marks `message` as failed when an awaited write returns an I/O
    /// error. It is still not cancellation-safe: cancelling the future may leave the
    /// message partially advanced.
    pub async fn send_message_chunked_body(
        &mut self,
        message: &mut Message,
    ) -> Result<(), MessageStreamError> {
        self.drive_message_to(message, MessageWriteGoal::Body).await
    }

    /// Sends the buffered body, if any, followed by the trailer frame.
    ///
    /// This wrapper marks `message` as failed when an awaited write returns an I/O
    /// error. It is still not cancellation-safe: cancelling the future may leave the
    /// message partially advanced.
    pub async fn send_message_trailer(
        &mut self,
        message: &mut Message,
    ) -> Result<(), MessageStreamError> {
        self.drive_message_to(message, MessageWriteGoal::Complete)
            .await
    }

    async fn send_trailer_header(
        &mut self,
        field_lines: impl IntoIterator<Item = FieldLine> + Send,
    ) -> Result<(), MessageStreamError> {
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

        // Flush encoder instructions (dynamic table insertions) to the encoder stream.
        // Encoder stream errors are connection-level: reset = connection error per RFC 9204.
        if let Err(error) = self.qpack_encoder.flush_instructions().await {
            let quic_error = self.handle_stream_error(error).await;
            return Err(quic_error.into());
        }

        match result {
            Ok(()) => Ok(()),
            Err(error) => match error {
                EncodeError::FramePayloadTooLarge => Err(MessageStreamError::TrailerTooLarge),
                EncodeError::HuffmanEncoding => {
                    unreachable!("FieldSection contain invalid header name/value, this is a bug")
                }
            },
        }
    }

    async fn execute_message_write_step(
        &mut self,
        action: MessageWriteStepAction,
    ) -> MessageWriteFlow {
        match action {
            MessageWriteStepAction::BreakOk => ControlFlow::Break(Ok(())),
            MessageWriteStepAction::Cancel => {
                ControlFlow::Break(self.cancel(Code::H3_REQUEST_CANCELLED).await)
            }
            MessageWriteStepAction::Failed => {
                ControlFlow::Break(Err(MessageStreamError::MessageSendFailed))
            }
            MessageWriteStepAction::Header { fields, flow } => {
                match self.send_header(fields).await {
                    Ok(()) => flow.into_control_flow(),
                    Err(error) => ControlFlow::Break(Err(error)),
                }
            }
            MessageWriteStepAction::Data { data, flow } => match self.send_data(data).await {
                Ok(()) => flow.into_control_flow(),
                Err(error) => ControlFlow::Break(Err(error)),
            },
            MessageWriteStepAction::Trailer(fields) => match self.send_trailer_header(fields).await
            {
                Ok(()) => ControlFlow::Break(Ok(())),
                Err(error) => ControlFlow::Break(Err(error)),
            },
        }
    }

    async fn drive_message_to(
        &mut self,
        message: &mut Message,
        goal: MessageWriteGoal,
    ) -> Result<(), MessageStreamError> {
        loop {
            match self.send_message_step(message, goal).await {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(result) => {
                    if result.is_err() {
                        message.set_failed_unless_malformed();
                    }
                    return result;
                }
            }
        }
    }

    /// Sends all currently buffered message parts.
    ///
    /// This wrapper marks `message` as failed when an awaited write returns an I/O
    /// error. It is still not cancellation-safe: cancelling the future may leave the
    /// message partially advanced.
    pub async fn send_message(&mut self, message: &mut Message) -> Result<(), MessageStreamError> {
        if matches!(message.stage, MessageStage::Header | MessageStage::Body)
            && message.header().is_empty()
        {
            return Ok(());
        }

        self.drive_message_to(message, MessageWriteGoal::Complete)
            .await
    }

    /// Sends all currently buffered message parts and flushes the stream.
    ///
    /// This method is not cancellation-safe because message state may be advanced
    /// before all stream I/O completes.
    pub async fn flush_message(&mut self, message: &mut Message) -> Result<(), MessageStreamError> {
        self.send_message(message).await?;
        self.flush().await
    }

    /// Sends all currently buffered message parts and closes the stream.
    ///
    /// This method is not cancellation-safe because message state may be advanced
    /// before all stream I/O completes.
    pub async fn close_message(&mut self, message: &mut Message) -> Result<(), MessageStreamError> {
        self.send_message(message).await?;
        self.close().await
    }
}

impl Message {
    pub async fn read_header<'e>(
        &'e mut self,
        stream: &mut ReadStream,
    ) -> Result<&'e FieldSection, MessageStreamError> {
        stream.read_message_header(self).await
    }

    pub async fn read_body_chunk(
        &mut self,
        stream: &mut ReadStream,
    ) -> Option<Result<Bytes, MessageStreamError>> {
        stream.read_message_body_chunk(self).await
    }

    pub async fn read_full_body<'e>(
        &'e mut self,
        stream: &mut ReadStream,
    ) -> Result<impl Buf + 'e, MessageStreamError> {
        stream.read_message_full_body(self).await
    }

    pub async fn read_to_bytes(
        &mut self,
        stream: &mut ReadStream,
    ) -> Result<Bytes, MessageStreamError> {
        stream.read_message_body_to_bytes(self).await
    }

    pub async fn read_to_string(
        &mut self,
        stream: &mut ReadStream,
    ) -> Result<String, ReadToStringError> {
        stream.read_message_body_to_string(self).await
    }

    pub async fn read(
        &mut self,
        stream: &mut ReadStream,
    ) -> Option<Result<Bytes, MessageStreamError>> {
        stream.read_message(self).await
    }

    pub async fn read_trailers<'e>(
        &'e mut self,
        stream: &mut ReadStream,
    ) -> Result<&'e HeaderMap, MessageStreamError> {
        stream.read_message_trailer(self).await
    }

    pub fn write_step<'s>(
        &mut self,
        stream: &'s mut WriteStream,
        goal: MessageWriteGoal,
    ) -> impl Future<Output = MessageWriteFlow> + use<'s> {
        stream.send_message_step(self, goal)
    }

    pub fn write_body_chunk<'s, B>(
        &mut self,
        stream: &'s mut WriteStream,
        content: B,
    ) -> impl Future<Output = Result<(), MessageStreamError>> + use<'s, B>
    where
        B: Buf + Send + 's,
    {
        stream.send_message_streaming_body(self, content)
    }

    pub async fn write_chunked_body(
        &mut self,
        stream: &mut WriteStream,
    ) -> Result<(), MessageStreamError> {
        stream.send_message_chunked_body(self).await
    }

    pub async fn write_trailers(
        &mut self,
        stream: &mut WriteStream,
    ) -> Result<(), MessageStreamError> {
        stream.send_message_trailer(self).await
    }

    pub async fn write_all(&mut self, stream: &mut WriteStream) -> Result<(), MessageStreamError> {
        stream.send_message(self).await
    }

    pub async fn flush(&mut self, stream: &mut WriteStream) -> Result<(), MessageStreamError> {
        stream.flush_message(self).await
    }

    pub async fn close(&mut self, stream: &mut WriteStream) -> Result<(), MessageStreamError> {
        stream.close_message(self).await
    }
}

enum MessageWriteStepAction {
    BreakOk,
    Cancel,
    Failed,
    Header {
        fields: Vec<FieldLine>,
        flow: MessageWriteStepFlow,
    },
    Data {
        data: Bytes,
        flow: MessageWriteStepFlow,
    },
    Trailer(Vec<FieldLine>),
}

#[derive(Debug, Clone, Copy)]
enum MessageWriteStepFlow {
    BreakOk,
    Continue,
}

impl MessageWriteStepFlow {
    fn into_control_flow(self) -> MessageWriteFlow {
        match self {
            MessageWriteStepFlow::BreakOk => ControlFlow::Break(Ok(())),
            MessageWriteStepFlow::Continue => ControlFlow::Continue(()),
        }
    }
}

fn prepare_message_write_step(
    message: &mut Message,
    goal: MessageWriteGoal,
) -> MessageWriteStepAction {
    match message.stage {
        MessageStage::Header => prepare_message_header_step(message, goal),
        MessageStage::Body => match goal {
            MessageWriteGoal::Header => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Body | MessageWriteGoal::Complete => {
                prepare_message_body_step(message, goal)
            }
        },
        MessageStage::Trailer => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
        MessageStage::Complete => MessageWriteStepAction::BreakOk,
        MessageStage::Malformed => MessageWriteStepAction::Cancel,
        MessageStage::Failed => MessageWriteStepAction::Failed,
        MessageStage::Dropped => message_used_after_dropped(),
    }
}

fn prepare_message_header_step(
    message: &mut Message,
    goal: MessageWriteGoal,
) -> MessageWriteStepAction {
    let fields = message.header.iter().collect::<Vec<_>>();
    let is_interim = message.is_interim_response();
    if !is_interim {
        message.stage = MessageStage::Body;
    }

    let flow = if is_interim {
        MessageWriteStepFlow::BreakOk
    } else {
        match goal {
            MessageWriteGoal::Header => MessageWriteStepFlow::BreakOk,
            MessageWriteGoal::Body => {
                if message.is_chunked() {
                    MessageWriteStepFlow::Continue
                } else {
                    MessageWriteStepFlow::BreakOk
                }
            }
            MessageWriteGoal::Complete => {
                if message.is_chunked() || !message.trailers().is_empty() {
                    MessageWriteStepFlow::Continue
                } else {
                    MessageWriteStepFlow::BreakOk
                }
            }
        }
    };

    MessageWriteStepAction::Header { fields, flow }
}

fn prepare_message_body_step(
    message: &mut Message,
    goal: MessageWriteGoal,
) -> MessageWriteStepAction {
    match &message.body {
        Body::Streaming { .. } => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
        Body::Chunked { .. } => prepare_message_chunked_body_step(message, goal),
    }
}

fn prepare_message_chunked_body_step(
    message: &mut Message,
    goal: MessageWriteGoal,
) -> MessageWriteStepAction {
    let data = {
        let Body::Chunked { buflist } = &mut message.body else {
            unreachable!("message body mode changed while preparing chunked body")
        };

        if buflist.has_remaining() {
            let data = buflist.copy_to_bytes(buflist.chunk().len());
            if !buflist.has_remaining() {
                message.stage = MessageStage::Trailer;
            }
            Some(data)
        } else {
            message.stage = MessageStage::Trailer;
            None
        }
    };

    match data {
        Some(data) => {
            let flow = if message.stage == MessageStage::Trailer {
                match goal {
                    MessageWriteGoal::Complete if !message.trailers().is_empty() => {
                        MessageWriteStepFlow::Continue
                    }
                    MessageWriteGoal::Header
                    | MessageWriteGoal::Body
                    | MessageWriteGoal::Complete => MessageWriteStepFlow::BreakOk,
                }
            } else {
                MessageWriteStepFlow::Continue
            };
            MessageWriteStepAction::Data { data, flow }
        }
        None => match goal {
            MessageWriteGoal::Header | MessageWriteGoal::Body => MessageWriteStepAction::BreakOk,
            MessageWriteGoal::Complete => prepare_message_trailer_step(message),
        },
    }
}

fn prepare_message_trailer_step(message: &mut Message) -> MessageWriteStepAction {
    if message.trailers().is_empty() {
        MessageWriteStepAction::BreakOk
    } else {
        let fields = message.trailer.iter().collect::<Vec<_>>();
        message.stage = MessageStage::Complete;
        MessageWriteStepAction::Trailer(fields)
    }
}

enum StreamingBodyAction<B> {
    Send {
        header: MessageWriteStepAction,
        content: B,
    },
    Cancel,
    Failed,
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;

    use super::*;
    use crate::varint::VarInt;

    #[tokio::test]
    async fn send_message_step_future_releases_message_before_await() {
        let mut stream = crate::message::test::write_stream_for_test(VarInt::from_u32(0));
        let mut message = Message::unresolved_request();

        let send = message.write_step(&mut stream, MessageWriteGoal::Header);

        assert_eq!(message.stage(), MessageStage::Body);
        assert!(matches!(send.await, ControlFlow::Break(Ok(()))));
    }

    #[test]
    fn set_body_keeps_header_stage_before_io() {
        let mut message = Message::unresolved_request();

        message
            .set_body(Bytes::from_static(b"abc"))
            .expect("set body");

        assert_eq!(message.stage(), MessageStage::Header);
    }

    #[test]
    fn set_body_does_not_clear_terminal_error_stage() {
        let mut malformed = Message::unresolved_request();
        malformed.set_malformed();
        assert!(malformed.set_body(Bytes::from_static(b"abc")).is_err());
        assert!(malformed.is_malformed());

        let mut failed = Message::unresolved_request();
        failed.set_failed();
        assert!(failed.set_body(Bytes::from_static(b"abc")).is_err());
        assert!(failed.is_failed());

        let mut dropped = Message::unresolved_request();
        dropped.set_dropped();
        assert!(dropped.set_body(Bytes::from_static(b"abc")).is_err());
        assert!(dropped.is_dropped());
    }

    #[tokio::test]
    async fn set_body_does_not_suppress_header_frame() {
        let mut stream = crate::message::test::write_stream_for_test(VarInt::from_u32(0));
        let mut message = Message::unresolved_request();
        message
            .set_body(Bytes::from_static(b"abc"))
            .expect("set body");

        let send = message.write_step(&mut stream, MessageWriteGoal::Header);

        assert_eq!(message.stage(), MessageStage::Body);
        assert!(matches!(send.await, ControlFlow::Break(Ok(()))));
    }

    #[tokio::test]
    async fn body_goal_reports_more_work_after_sending_header_for_buffered_body() {
        let mut stream = crate::message::test::write_stream_for_test(VarInt::from_u32(0));
        let mut message = Message::unresolved_request();
        message
            .set_body(Bytes::from_static(b"abc"))
            .expect("set body");

        let flow = message
            .write_step(&mut stream, MessageWriteGoal::Body)
            .await;

        assert!(matches!(flow, ControlFlow::Continue(())));
        assert_eq!(message.stage(), MessageStage::Body);
    }
}
