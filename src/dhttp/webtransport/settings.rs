use crate::{
    dhttp::settings::{Setting, SettingId, Settings},
    varint::VarInt,
};

/// `SETTINGS_ENABLE_WEBTRANSPORT` (0x2c7cf000). No default.
///
/// Indicates support for WebTransport over HTTP/3 draft-15. The value MUST be 0 or 1.
pub struct EnableWebTransport;

impl EnableWebTransport {
    pub const ID: VarInt = VarInt::from_u32(0x2c7cf000);

    pub const fn setting(enabled: bool) -> Setting {
        Setting::new(Self::ID, VarInt::from_u32(enabled as u32))
    }
}

impl SettingId for EnableWebTransport {
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
    pub fn enable_webtransport(&self) -> bool {
        self.get(EnableWebTransport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::VarInt;

    #[test]
    fn enable_webtransport_uses_draft15_codepoint() {
        assert_eq!(EnableWebTransport::ID.into_inner(), 0x2c7cf000);

        let mut settings = Settings::default();
        assert!(!settings.enable_webtransport());

        settings.set(EnableWebTransport::setting(true));
        assert!(settings.enable_webtransport());
        assert_eq!(
            settings.get(VarInt::from_u32(0x2c7cf000)),
            Some(VarInt::from_u32(1)),
        );
        assert_eq!(settings.get(VarInt::from_u32(0x2b603742)), None);
    }
}
