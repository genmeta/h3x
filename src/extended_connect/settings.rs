use crate::{
    dhttp::settings::{Setting, SettingId, Settings},
    varint::VarInt,
};

/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08). No default.
///
/// Enables the Extended CONNECT method. The value MUST be 0 or 1.
pub struct EnableConnectProtocol;

impl EnableConnectProtocol {
    pub const ID: VarInt = VarInt::from_u32(0x08);

    pub const fn setting(enabled: bool) -> Setting {
        Setting::new(Self::ID, VarInt::from_u32(enabled as u32))
    }
}

impl SettingId for EnableConnectProtocol {
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
    pub fn enable_connect_protocol(&self) -> bool {
        self.get(EnableConnectProtocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::VarInt;

    #[test]
    fn enable_connect_protocol_round_trips_through_settings() {
        let mut settings = Settings::default();
        assert!(!settings.enable_connect_protocol());

        settings.set(EnableConnectProtocol::setting(true));
        assert!(settings.enable_connect_protocol());
        assert_eq!(
            settings.get(VarInt::from_u32(0x08)),
            Some(VarInt::from_u32(1))
        );
    }

    #[test]
    fn enable_connect_protocol_exposes_id_and_treats_only_one_as_enabled() {
        assert_eq!(EnableConnectProtocol.id(), EnableConnectProtocol::ID);

        let mut settings = Settings::default();
        settings.set(EnableConnectProtocol::setting(false));
        assert!(!settings.enable_connect_protocol());
        assert_eq!(
            settings.get(VarInt::from_u32(0x08)),
            Some(VarInt::from_u32(0))
        );

        settings.set(Setting::new(EnableConnectProtocol::ID, VarInt::from_u32(2)));
        assert!(!settings.enable_connect_protocol());
    }
}
