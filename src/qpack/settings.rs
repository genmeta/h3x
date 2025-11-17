use std::{
    collections::{BTreeMap, btree_map},
    iter,
    pin::pin,
};

use futures::{SinkExt, TryStreamExt, stream};
use tokio::io::{AsyncBufRead, AsyncWrite};

use crate::{
    codec::{
        error::{DecodeStreamError, EncodeStreamError},
        util::{DecodeFrom, EncodeInto, decoder, encoder},
    },
    error::{Code, H3CriticalStreamClosed},
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
}

impl<S: AsyncBufRead> DecodeFrom<S> for Setting {
    async fn decode_from(stream: S) -> Result<Self, DecodeStreamError> {
        tokio::pin!(stream);
        let id = VarInt::decode_from(stream.as_mut()).await?;
        let value = VarInt::decode_from(stream.as_mut()).await?;
        Ok(Setting { id, value })
    }
}

impl<S: AsyncWrite> EncodeInto<S> for Setting {
    async fn encode_into(self, stream: S) -> Result<(), EncodeStreamError> {
        tokio::pin!(stream);
        self.id.encode_into(stream.as_mut()).await?;
        self.value.encode_into(stream.as_mut()).await?;
        Ok(())
    }
}

#[derive(Default, Debug, Clone)]
pub struct Settings {
    map: BTreeMap<VarInt, VarInt>,
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
            option => option,
        }
    }

    pub fn set(&mut self, id: VarInt, value: VarInt) {
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

impl<S: AsyncBufRead> DecodeFrom<S> for Settings {
    async fn decode_from(stream: S) -> Result<Self, DecodeStreamError> {
        tokio::pin!(stream);
        let stream = decoder(stream);
        tokio::pin!(stream);

        let mut settings = Settings::default();
        while let Some(Setting { id, value }) = stream
            .try_next()
            .await
            .map_err(|error| error.map_stream_reset(|_| H3CriticalStreamClosed::Control.into()))?
        {
            settings.set(id, value);
        }
        Ok(settings)
    }
}

impl<S: AsyncWrite> EncodeInto<S> for Settings {
    async fn encode_into(self, stream: S) -> Result<(), EncodeStreamError> {
        tokio::pin!(stream);
        let mut encoder = pin!(encoder(stream));
        let mut settings = stream::iter(self.into_iter().map(Ok));
        encoder.send_all(&mut settings).await.map_err(|error| {
            error
                .map_stream_reset(|_| H3CriticalStreamClosed::Control.into())
                .map_encode_error(|encode_error| Code::H3_INTERNAL_ERROR.with(encode_error).into())
        })
    }
}
