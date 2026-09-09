use std::collections::BTreeSet;

use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt, be_varint};

use super::{super::frame_error, FrameHeader, FrameType, ParseResult, WriteFrame};
use crate::{Code, Error, Settings};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SettingsFrame {
    pub(crate) settings: Settings,
}

const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const QPACK_BLOCKED_STREAMS: u64 = 0x07;
const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
#[cfg(feature = "webtransport")]
const H3_DATAGRAM: u64 = 0x33;
#[cfg(feature = "webtransport")]
const WEBTRANSPORT: u64 = 0x2c7cf000;

const HTTP2_RESERVED_SETTINGS: [u64; 4] = [0x02, 0x03, 0x04, 0x05];

pub(super) fn be_settings_frame(payload: &Bytes) -> ParseResult<'_, SettingsFrame> {
    let mut payload = payload.as_ref();
    let mut settings = Settings::default();
    let mut identifiers = BTreeSet::new();

    while !payload.is_empty() {
        let (remaining, identifier) = be_varint(payload)
            .map_err(|error| error.map(|_| frame_error("invalid SETTINGS identifier")))?;
        let (remaining, value) = be_varint(remaining)
            .map_err(|error| error.map(|_| frame_error("invalid SETTINGS value")))?;
        payload = remaining;
        let identifier = identifier.into_u64();
        let value = value.into_u64();

        if !identifiers.insert(identifier) {
            return Err(nom::Err::Failure(settings_error(format!(
                "duplicate SETTINGS identifier 0x{identifier:x}"
            ))));
        }
        if HTTP2_RESERVED_SETTINGS.contains(&identifier) {
            return Err(nom::Err::Failure(settings_error(format!(
                "HTTP/2 SETTINGS identifier 0x{identifier:x} is forbidden in HTTP/3"
            ))));
        }

        match identifier {
            QPACK_MAX_TABLE_CAPACITY => settings.set_qpack_max_table_capacity(value),
            MAX_FIELD_SECTION_SIZE => settings.set_max_field_section_size(Some(value)),
            QPACK_BLOCKED_STREAMS => settings.set_qpack_blocked_streams(value),
            ENABLE_CONNECT_PROTOCOL => match value {
                0 => settings.set_enable_connect_protocol(false),
                1 => settings.set_enable_connect_protocol(true),
                _ => {
                    return Err(nom::Err::Failure(settings_error(format!(
                        "SETTINGS_ENABLE_CONNECT_PROTOCOL must be 0 or 1, got {value}"
                    ))));
                }
            },
            #[cfg(feature = "webtransport")]
            H3_DATAGRAM => match value {
                0 => settings.set_h3_datagram(false),
                1 => settings.set_h3_datagram(true),
                _ => {
                    return Err(nom::Err::Failure(settings_error(format!(
                        "SETTINGS_H3_DATAGRAM must be 0 or 1, got {value}"
                    ))));
                }
            },
            #[cfg(feature = "webtransport")]
            WEBTRANSPORT => match value {
                0 => settings.set_webtransport(false),
                1 => settings.set_webtransport(true),
                _ => {
                    return Err(nom::Err::Failure(settings_error(format!(
                        "SETTINGS_WT_ENABLED must be 0 or 1, got {value}"
                    ))));
                }
            },
            _ => {}
        }
    }

    Ok((payload, SettingsFrame { settings }))
}

fn put_setting(identifier: u64, value: u64, output: &mut Vec<u8>) -> Result<(), Error> {
    let value = VarInt::try_from(value)
        .map_err(|_| settings_error("setting exceeds the QUIC variable-length integer range"))?;
    output.put_varint(&VarInt::try_from(identifier).expect("known SETTINGS identifier"));
    output.put_varint(&value);
    Ok(())
}

impl<B: BufMut> WriteFrame<SettingsFrame> for B {
    fn put_frame(&mut self, frame: &SettingsFrame) -> Result<(), Error> {
        let settings = &frame.settings;
        let mut payload = Vec::new();

        if let Some(value) = settings.encoded_qpack_max_table_capacity() {
            put_setting(QPACK_MAX_TABLE_CAPACITY, value, &mut payload)?;
        }
        if let Some(value) = settings.max_field_section_size() {
            put_setting(MAX_FIELD_SECTION_SIZE, value, &mut payload)?;
        }
        if let Some(value) = settings.encoded_qpack_blocked_streams() {
            put_setting(QPACK_BLOCKED_STREAMS, value, &mut payload)?;
        }
        if let Some(value) = settings.encoded_enable_connect_protocol() {
            put_setting(ENABLE_CONNECT_PROTOCOL, u64::from(value), &mut payload)?;
        }
        #[cfg(feature = "webtransport")]
        if let Some(value) = settings.encoded_h3_datagram() {
            put_setting(H3_DATAGRAM, u64::from(value), &mut payload)?;
        }
        #[cfg(feature = "webtransport")]
        if let Some(value) = settings.encoded_webtransport() {
            put_setting(WEBTRANSPORT, u64::from(value), &mut payload)?;
        }

        self.put_frame(&FrameHeader {
            frame_type: FrameType::Settings,
            length: payload.len() as u64,
        })?;
        self.put_slice(&payload);
        Ok(())
    }
}

fn settings_error(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::connection_protocol(Code::H3_SETTINGS_ERROR, message)
}
