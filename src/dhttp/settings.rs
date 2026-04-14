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
    codec::{DecodeExt, DecodeFrom, DecodeStreamError, EncodeExt, EncodeInto},
    connection::StreamError,
    dhttp::{frame::Frame, stream::UnidirectionalStream},
    error::{Code, ErrorScope, H3CriticalStreamClosed, H3Error, H3FrameDecodeError},
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
/// <https://datatracker.ietf.org/doc/html/rfc9114#name-settings>
pub struct Setting {
    pub id: VarInt,
    pub value: VarInt,
}

impl Setting {
    pub const fn new(id: VarInt, value: VarInt) -> Self {
        Self { id, value }
    }

    pub fn check(&self) -> Result<(), InvalidSettingValue> {
        if self.id == EnableConnectProtocol::ID
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
    #[snafu(display("the value of the ENABLE_CONNECT_PROTOCOL setting must be 0 or 1"))]
    ConnectProtocol { value: VarInt },
}

impl H3Error for InvalidSettingValue {
    fn code(&self) -> Code {
        Code::H3_SETTINGS_ERROR
    }
    fn scope(&self) -> ErrorScope {
        ErrorScope::Connection
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for Setting {
    type Error = StreamError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let decode = async move {
            let mut stream = pin!(stream);
            let id = stream.decode_one().await?;
            let value = stream.decode_one().await?;
            Ok(Setting { id, value })
        };
        let setting = decode.await.map_err(|error: DecodeStreamError| {
            error.map_stream_closed(
                |_reset_code| H3CriticalStreamClosed::Control.into(),
                |decode_error| {
                    H3FrameDecodeError {
                        source: decode_error,
                    }
                    .into()
                },
            )
        })?;

        setting.check()?;
        Ok(setting)
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for Setting {
    type Output = ();

    type Error = StreamError;

    async fn encode_into(self, stream: S) -> Result<Self::Output, Self::Error> {
        let Setting { id, value } = self;
        let encode = async move {
            let mut stream = pin!(stream);
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

#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Settings {
    map: BTreeMap<VarInt, VarInt>,
}

impl<S> DecodeFrom<S> for Settings
where
    for<'s> &'s mut S: AsyncBufRead,
    S: Send,
{
    type Error = StreamError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream.into_decode_stream::<Setting, StreamError>());
        let mut settings = Settings::default();
        while let Some(setting) = stream.try_next().await? {
            settings.set(setting);
        }
        Ok(settings)
    }
}

impl EncodeInto<BufList> for &Settings {
    type Output = Frame<BufList>;

    type Error = Infallible;

    async fn encode_into(self, stream: BufList) -> Result<Self::Output, Self::Error> {
        assert!(!stream.has_remaining());
        let mut frame = Frame::new(Frame::SETTINGS_FRAME_TYPE, stream)
            .expect("SETTINGS frame type is a valid VarInt");
        for setting in self {
            frame
                .encode_one(setting)
                .await
                .expect("encoding a Setting into a BufList is infallible");
        }
        Ok(frame)
    }
}

impl EncodeInto<BufList> for Settings {
    type Output = Frame<BufList>;

    type Error = Infallible;

    async fn encode_into(self, stream: BufList) -> Result<Self::Output, Self::Error> {
        (&self).encode_into(stream).await
    }
}

impl Settings {
    /// Typed access to a setting value. The return type depends on the setting:
    ///
    /// - Concrete setting types (`QpackMaxTableCapacity`, `MaxFieldSectionSize`, …)
    ///   apply defaults and return their associated `Value` type.
    /// - A raw [`VarInt`] identifier returns `Option<VarInt>` with no default fallback.
    ///
    /// ```ignore
    /// settings.get(QpackMaxTableCapacity)       // → VarInt (with default)
    /// settings.get(MaxFieldSectionSize)          // → Option<VarInt>
    /// settings.get(VarInt::from_u32(0x06))       // → Option<VarInt> (raw)
    /// ```
    pub fn get<S: SettingId>(&self, id: S) -> S::Value {
        id.value_from(self)
    }

    fn get_raw(&self, id: VarInt) -> Option<VarInt> {
        self.map.get(&id).copied()
    }

    pub fn max_field_section_size(&self) -> Option<VarInt> {
        self.get(MaxFieldSectionSize)
    }

    pub fn qpack_max_table_capacity(&self) -> VarInt {
        self.get(QpackMaxTableCapacity)
    }

    pub fn qpack_blocked_streams(&self) -> VarInt {
        self.get(QpackBlockedStreams)
    }

    pub fn enable_connect_protocol(&self) -> bool {
        self.get(EnableConnectProtocol)
            .is_some_and(|value| value == VarInt::from_u32(1))
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

/// Trait for typed HTTP/3 setting identifiers.
///
/// Each setting has an associated `Value` type that encodes whether a default
/// exists: settings with defaults use `VarInt` (always returns a value),
/// while optional settings use `Option<VarInt>`.
pub trait SettingId {
    /// The value type returned when querying this setting.
    type Value;

    /// The wire-format setting identifier (RFC 9114 / RFC 9204).
    fn id(&self) -> VarInt;

    /// Extract the typed value from `Settings`, applying defaults if applicable.
    fn value_from(&self, settings: &Settings) -> Self::Value;
}

/// Raw access by [`VarInt`] identifier — returns the explicitly set value, or
/// `None` if not present. No default-value fallback is applied.
impl SettingId for VarInt {
    type Value = Option<VarInt>;

    fn id(&self) -> VarInt {
        *self
    }

    fn value_from(&self, settings: &Settings) -> Option<VarInt> {
        settings.get_raw(*self)
    }
}

/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0x01). Default: 0.
///
/// To bound the memory requirements of the decoder, the decoder limits the
/// maximum value the encoder is permitted to set for the dynamic table
/// capacity. In HTTP/3, this limit is determined by the value of
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` sent by the decoder.
///
/// <https://datatracker.ietf.org/doc/html/rfc9204#section-5>
pub struct QpackMaxTableCapacity;

impl QpackMaxTableCapacity {
    pub const ID: VarInt = VarInt::from_u32(0x01);
    /// The default value is zero. See Section 3.2 for usage. This is the
    /// equivalent of the `SETTINGS_HEADER_TABLE_SIZE` from HTTP/2.
    pub const DEFAULT: VarInt = VarInt::from_u32(0);

    pub const fn setting(value: VarInt) -> Setting {
        Setting::new(Self::ID, value)
    }
}

impl SettingId for QpackMaxTableCapacity {
    type Value = VarInt;

    fn id(&self) -> VarInt {
        Self::ID
    }

    fn value_from(&self, settings: &Settings) -> VarInt {
        settings.get_raw(Self::ID).unwrap_or(Self::DEFAULT)
    }
}

/// `SETTINGS_QPACK_BLOCKED_STREAMS` (0x07). Default: 0.
///
/// The decoder specifies an upper bound on the number of streams that can
/// be blocked using the `SETTINGS_QPACK_BLOCKED_STREAMS` setting. An
/// encoder MUST limit the number of streams that could become blocked to
/// the value of `SETTINGS_QPACK_BLOCKED_STREAMS` at all times.
///
/// <https://datatracker.ietf.org/doc/html/rfc9204#section-2.1.2-4>
pub struct QpackBlockedStreams;

impl QpackBlockedStreams {
    pub const ID: VarInt = VarInt::from_u32(0x07);
    /// The default value is zero. See Section 2.1.2.
    pub const DEFAULT: VarInt = VarInt::from_u32(0);

    pub const fn setting(value: VarInt) -> Setting {
        Setting::new(Self::ID, value)
    }
}

impl SettingId for QpackBlockedStreams {
    type Value = VarInt;

    fn id(&self) -> VarInt {
        Self::ID
    }

    fn value_from(&self, settings: &Settings) -> VarInt {
        settings.get_raw(Self::ID).unwrap_or(Self::DEFAULT)
    }
}

/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (0x06). No default (unlimited).
///
/// An HTTP/3 implementation MAY impose a limit on the maximum size of the
/// message header it will accept on an individual HTTP message. The size
/// of a field list is calculated based on the uncompressed size of fields,
/// including the length of the name and value in bytes plus an overhead of
/// 32 bytes for each field.
///
/// <https://datatracker.ietf.org/doc/html/rfc9114#name-header-size-constraints>
pub struct MaxFieldSectionSize;

impl MaxFieldSectionSize {
    pub const ID: VarInt = VarInt::from_u32(0x06);

    pub const fn setting(value: VarInt) -> Setting {
        Setting::new(Self::ID, value)
    }
}

impl SettingId for MaxFieldSectionSize {
    type Value = Option<VarInt>;

    fn id(&self) -> VarInt {
        Self::ID
    }

    fn value_from(&self, settings: &Settings) -> Option<VarInt> {
        settings.get_raw(Self::ID)
    }
}

/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08). No default.
///
/// Enables the Extended CONNECT method for WebSocket upgrades over HTTP/3.
/// The value MUST be 0 or 1.
///
/// <https://datatracker.ietf.org/doc/html/rfc9220>
pub struct EnableConnectProtocol;

impl EnableConnectProtocol {
    pub const ID: VarInt = VarInt::from_u32(0x08);

    pub const fn setting(enabled: bool) -> Setting {
        Setting::new(Self::ID, VarInt::from_u32(enabled as u32))
    }
}

impl SettingId for EnableConnectProtocol {
    type Value = Option<VarInt>;

    fn id(&self) -> VarInt {
        Self::ID
    }

    fn value_from(&self, settings: &Settings) -> Option<VarInt> {
        settings.get_raw(Self::ID)
    }
}

impl UnidirectionalStream<()> {
    /// A control stream is indicated by a stream type of 0x00. Data on this
    ///  stream consists of HTTP/3 frames, as defined in Section 7.2.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9114#name-control-streams>
    pub const CONTROL_STREAM_TYPE: VarInt = VarInt::from_u32(0x00);
}

impl<S: ?Sized> UnidirectionalStream<S> {
    pub const fn is_control_stream(&self) -> bool {
        self.r#type().into_inner() == UnidirectionalStream::CONTROL_STREAM_TYPE.into_inner()
    }

    pub async fn initial_control_stream(stream: S) -> Result<Self, StreamError>
    where
        S: AsyncWrite + Unpin + Sized + Send,
    {
        Self::initial(UnidirectionalStream::CONTROL_STREAM_TYPE, stream)
            .await
            .map_err(|error| error.map_stream_reset(|_| H3CriticalStreamClosed::Control.into()))
    }
}
