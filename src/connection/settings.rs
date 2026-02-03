use std::{
    collections::{BTreeMap, btree_map},
    convert::Infallible,
    iter,
    pin::pin,
};

use bytes::Buf;
use futures::TryStreamExt;
use snafu::Snafu;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite};

use crate::{
    buflist::BufList,
    codec::{Decode, DecodeExt, DecodeStreamError, Encode, EncodeExt},
    connection::StreamError,
    error::{Code, H3CriticalStreamClosed, HasErrorCode},
    frame::Frame,
    quic,
    varint::VarInt,
};

/// ``` ignore
/// Setting {
///   Identifier (i),
///   Value (i),
/// }
/// ```
///
/// https://datatracker.ietf.org/doc/html/rfc9114#name-settings
pub struct Setting {
    pub id: VarInt,
    pub value: VarInt,
}

impl Setting {
    pub const fn new(id: VarInt, value: VarInt) -> Self {
        Self { id, value }
    }

    /// An HTTP/3 implementation MAY impose a limit on the maximum size of
    /// the message header it will accept on an individual HTTP message. A
    /// server that receives a larger header section than it is willing to
    /// handle can send an HTTP 431 (Request Header Fields Too Large) status
    /// code ([RFC6585]). A client can discard responses that it cannot
    /// process. The size of a field list is calculated based on the
    /// uncompressed size of fields, including the length of the name and
    /// value in bytes plus an overhead of 32 bytes for each field.
    ///
    /// If an implementation wishes to advise its peer of this limit, it can
    /// be conveyed as a number of bytes in the
    /// SETTINGS_MAX_FIELD_SECTION_SIZE parameter. An implementation that has
    /// received this parameter SHOULD NOT send an HTTP message header that
    /// exceeds the indicated size, as the peer will likely refuse to process
    /// it. However, an HTTP message can traverse one or more intermediaries
    /// before reaching the origin server; see Section 3.7 of [HTTP].
    /// Because this limit is applied separately by each implementation that
    /// processes the message, messages below this limit are not guaranteed
    /// to be accepted.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-header-size-constraints
    // TODO: implement this setting
    pub const MAX_FIELD_SECTION_SIZE_ID: VarInt = VarInt::from_u32(0x06);
    /// The default value is unlimited. See Section 4.2.2 for usage.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9114#section-7.2.4.1-2.2.1
    pub const MAX_FIELD_SECTION_SIZE_DEFAULT_VALUE: Option<VarInt> = None;

    pub const fn max_field_section_size(value: VarInt) -> Self {
        Self {
            id: Self::MAX_FIELD_SECTION_SIZE_ID,
            value,
        }
    }

    /// To bound the memory requirements of the decoder, the decoder limits
    /// the maximum value the encoder is permitted to set for the dynamic
    /// table capacity. In HTTP/3, this limit is determined by the value of
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY sent by the decoder; see Section 5.
    /// The encoder MUST NOT set a dynamic table capacity that exceeds this
    /// maximum, but it can choose to use a lower dynamic table capacity; see
    /// Section 4.3.1.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-3.2.3-1
    pub const QPACK_MAX_TABLE_CAPACITY_ID: VarInt = VarInt::from_u32(0x01);
    /// The default value is zero. See Section 3.2 for usage. This is the
    /// equivalent of the SETTINGS_HEADER_TABLE_SIZE from HTTP/2.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-5-2.2.1
    pub const QPACK_MAX_TABLE_CAPACITY_DEFAULT_VALUE: VarInt = VarInt::from_u32(0);

    pub const fn qpack_max_table_capacity(value: VarInt) -> Self {
        Self {
            id: Self::QPACK_MAX_TABLE_CAPACITY_ID,
            value,
        }
    }

    /// The decoder specifies an upper bound on the number of streams that
    /// can be blocked using the SETTINGS_QPACK_BLOCKED_STREAMS setting; see
    /// Section 5. An encoder MUST limit the number of streams that could
    /// become blocked to the value of SETTINGS_QPACK_BLOCKED_STREAMS at all
    /// times. If a decoder encounters more blocked streams than it promised
    /// to support, it MUST treat this as a connection error of type
    /// QPACK_DECOMPRESSION_FAILED.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-2.1.2-4
    pub const QPACK_BLOCKED_STREAMS_ID: VarInt = VarInt::from_u32(0x07);
    /// The default value is zero. See Section 2.1.2.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-5-2.4.1
    pub const QPACK_BLOCKED_STREAMS_DEFAULT_VALUE: VarInt = VarInt::from_u32(0);

    pub const fn qpack_blocked_streams(value: VarInt) -> Self {
        Self {
            id: Self::QPACK_BLOCKED_STREAMS_ID,
            value,
        }
    }

    /// [RFC8441] defines a mechanism for running the WebSocket Protocol
    /// [RFC6455] over a single stream of an HTTP/2 connection. It defines an
    /// Extended CONNECT method that specifies a new ":protocol" pseudo-
    /// header field and new semantics for the ":path" and ":authority"
    /// pseudo-header fields. It also defines a new HTTP/2 setting sent by a
    /// server to allow the client to use Extended CONNECT.
    ///
    /// The semantics of the pseudo-header fields and setting are identical
    /// to those in HTTP/2 as defined in [RFC8441]. Appendix A.3 of [HTTP/3]
    /// requires that HTTP/3 settings be registered separately for HTTP/3.
    /// The SETTINGS_ENABLE_CONNECT_PROTOCOL value is 0x08 (decimal 8), as in
    /// HTTP/2.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9220#name-websockets-upgrade-over-htt
    pub const ENABLE_CONNECT_PROTOCOL_ID: VarInt = VarInt::from_u32(0x08);
    pub const ENABLE_CONNECT_PROTOCOL_DEFAULT_VALUE: Option<VarInt> = None;

    pub const fn enable_connect_protocol(enabled: bool) -> Self {
        Self {
            id: Self::ENABLE_CONNECT_PROTOCOL_ID,
            value: VarInt::from_u32(enabled as u32),
        }
    }

    pub fn check(&self) -> Result<(), InvalidSettingValue> {
        if self.id == Self::ENABLE_CONNECT_PROTOCOL_ID
            && self.value != VarInt::from_u32(0)
            && self.value != VarInt::from_u32(1)
        {
            return Err(InvalidSettingValue::ConnectProtocol { value: self.value });
        }
        Ok(())
    }
}

impl From<(VarInt, VarInt)> for Setting {
    fn from((id, value): (VarInt, VarInt)) -> Self {
        Self::new(id, value)
    }
}

#[derive(Snafu, Debug, Clone, Copy)]
pub enum InvalidSettingValue {
    #[snafu(display("The value of the ENABLE_CONNECT_PROTOCOL setting must be 0 or 1"))]
    ConnectProtocol { value: VarInt },
}

impl HasErrorCode for InvalidSettingValue {
    fn code(&self) -> Code {
        Code::H3_SETTINGS_ERROR
    }
}

impl<S: AsyncRead> Decode<Setting> for S {
    type Error = StreamError;

    async fn decode(self) -> Result<Setting, Self::Error> {
        let decode = async move {
            let mut stream = pin!(self);
            let id = stream.decode_one().await?;
            let value = stream.decode_one().await?;
            Ok(Setting { id, value })
        };
        let setting = decode.await.map_err(|error: DecodeStreamError| {
            error.map_stream_closed(
                |_reset_code| H3CriticalStreamClosed::Control.into(),
                |decode_error| Code::H3_FRAME_ERROR.with(decode_error).into(),
            )
        })?;

        setting.check()?;
        Ok(setting)
    }
}

impl<S: AsyncWrite> Encode<Setting> for S {
    type Output = ();

    type Error = StreamError;

    async fn encode(self, Setting { id, value }: Setting) -> Result<Self::Output, Self::Error> {
        let encode = async move {
            let mut stream = pin!(self);
            stream.as_mut().encode_one(id).await?;
            stream.as_mut().encode_one(value).await?;
            Ok(())
        };
        encode
            .await
            .map_err(|error: quic::StreamError| match error {
                quic::StreamError::Reset { .. } => H3CriticalStreamClosed::Control.into(),
                quic::StreamError::Connection { .. } => error.into(),
            })
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Settings {
    map: BTreeMap<VarInt, VarInt>,
}

impl<S> Decode<Settings> for &mut Frame<S>
where
    for<'f> &'f mut Frame<S>: AsyncBufRead,
{
    type Error = StreamError;

    async fn decode(self) -> Result<Settings, Self::Error> {
        assert!(self.r#type() == Frame::SETTINGS_FRAME_TYPE);
        let mut stream = pin!(self.into_decode_stream::<Setting, StreamError>());
        let mut settings = Settings::default();
        while let Some(setting) = stream.try_next().await? {
            settings.set(setting);
        }
        Ok(settings)
    }
}

impl Encode<&Settings> for BufList {
    type Output = Frame<BufList>;

    type Error = Infallible;

    async fn encode(self, settings: &Settings) -> Result<Self::Output, Self::Error> {
        assert!(!self.has_remaining());
        let mut frame = Frame::new(Frame::SETTINGS_FRAME_TYPE, self).unwrap();
        for setting in settings {
            frame.encode_one(setting).await.unwrap();
        }
        Ok(frame)
    }
}

impl Encode<Settings> for BufList {
    type Output = Frame<BufList>;

    type Error = Infallible;

    async fn encode(self, settings: Settings) -> Result<Self::Output, Self::Error> {
        self.encode(&settings).await
    }
}

impl Settings {
    pub fn max_field_section_size(&self) -> Option<VarInt> {
        self.get(Setting::MAX_FIELD_SECTION_SIZE_ID)
    }

    pub fn qpack_max_table_capacity(&self) -> VarInt {
        self.get(Setting::QPACK_MAX_TABLE_CAPACITY_ID).unwrap()
    }

    pub fn qpack_blocked_streams(&self) -> VarInt {
        self.get(Setting::QPACK_BLOCKED_STREAMS_ID).unwrap()
    }

    pub fn enable_connect_protocol(&self) -> bool {
        self.get(Setting::ENABLE_CONNECT_PROTOCOL_ID)
            .is_some_and(|value| value == VarInt::from_u32(1))
    }

    pub fn get(&self, id: VarInt) -> Option<VarInt> {
        match self.map.get(&id).copied() {
            None if id == Setting::MAX_FIELD_SECTION_SIZE_ID => {
                Setting::MAX_FIELD_SECTION_SIZE_DEFAULT_VALUE
            }
            None if id == Setting::QPACK_MAX_TABLE_CAPACITY_ID => {
                Some(Setting::QPACK_MAX_TABLE_CAPACITY_DEFAULT_VALUE)
            }
            None if id == Setting::QPACK_BLOCKED_STREAMS_ID => {
                Some(Setting::QPACK_BLOCKED_STREAMS_DEFAULT_VALUE)
            }
            None if id == Setting::ENABLE_CONNECT_PROTOCOL_ID => {
                Setting::ENABLE_CONNECT_PROTOCOL_DEFAULT_VALUE
            }
            option => option,
        }
    }

    pub fn set(&mut self, Setting { id, value }: Setting) {
        self.map.insert(id, value);
    }
}

impl IntoIterator for Settings {
    type Item = Setting;

    type IntoIter = iter::Map<btree_map::IntoIter<VarInt, VarInt>, fn((VarInt, VarInt)) -> Setting>;

    fn into_iter(self) -> Self::IntoIter {
        self.map
            .into_iter()
            .map(|(id, value)| Setting { id, value })
    }
}

impl<'s> IntoIterator for &'s Settings {
    type Item = Setting;

    type IntoIter = iter::Map<
        btree_map::Iter<'s, VarInt, VarInt>,
        for<'v> fn((&'v VarInt, &'v VarInt)) -> Setting,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.map.iter().map(|(&id, &value)| Setting { id, value })
    }
}

impl FromIterator<Setting> for Settings {
    fn from_iter<T: IntoIterator<Item = Setting>>(iter: T) -> Self {
        Self {
            map: iter
                .into_iter()
                .map(|Setting { id, value }| (id, value))
                .collect::<BTreeMap<_, _>>(),
        }
    }
}

impl Extend<Setting> for Settings {
    fn extend<T: IntoIterator<Item = Setting>>(&mut self, iter: T) {
        self.map
            .extend(iter.into_iter().map(|Setting { id, value }| (id, value)));
    }
}
