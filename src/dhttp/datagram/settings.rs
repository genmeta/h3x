use crate::{
    dhttp::settings::{Setting, SettingId, Settings},
    varint::VarInt,
};

/// `H3_DATAGRAM` (0x33). No default.
///
/// Indicates support for HTTP/3 datagrams (RFC 9297). The value MUST be 0 or 1.
pub struct H3Datagram;

impl H3Datagram {
    pub const ID: VarInt = VarInt::from_u32(0x33);

    pub const fn setting(enabled: bool) -> Setting {
        Setting::new(Self::ID, VarInt::from_u32(enabled as u32))
    }
}

impl SettingId for H3Datagram {
    type Value = bool;

    fn id(&self) -> VarInt {
        Self::ID
    }

    fn value_from(&self, settings: &Settings) -> bool {
        settings
            .get_raw(Self::ID)
            .is_some_and(|value| value == VarInt::from_u32(1))
    }
}

impl Settings {
    pub fn h3_datagram(&self) -> bool {
        self.get(H3Datagram)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::VarInt;

    #[test]
    fn h3_datagram_uses_boolean_value() {
        let mut settings = Settings::default();
        assert!(!settings.h3_datagram());

        settings.set(H3Datagram::setting(true));
        assert!(settings.h3_datagram());
        assert_eq!(
            settings.get(VarInt::from_u32(0x33)),
            Some(VarInt::from_u32(1))
        );
    }
}
