use crate::{
    dhttp::settings::{Setting, SettingId, Settings},
    extended_connect::settings::EnableConnectProtocol,
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

/// `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` (0x2b64). Default: 0.
pub struct InitialMaxStreamsUni;

impl InitialMaxStreamsUni {
    pub const ID: VarInt = VarInt::from_u32(0x2b64);
    pub const DEFAULT: VarInt = VarInt::from_u32(0);

    pub const fn setting(value: VarInt) -> Setting {
        Setting::new(Self::ID, value)
    }
}

impl SettingId for InitialMaxStreamsUni {
    type Value = VarInt;

    fn id(&self) -> VarInt {
        Self::ID
    }

    fn value_from(&self, settings: &Settings) -> VarInt {
        settings.get_raw(Self::ID).unwrap_or(Self::DEFAULT)
    }
}

/// `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI` (0x2b65). Default: 0.
pub struct InitialMaxStreamsBidi;

impl InitialMaxStreamsBidi {
    pub const ID: VarInt = VarInt::from_u32(0x2b65);
    pub const DEFAULT: VarInt = VarInt::from_u32(0);

    pub const fn setting(value: VarInt) -> Setting {
        Setting::new(Self::ID, value)
    }
}

impl SettingId for InitialMaxStreamsBidi {
    type Value = VarInt;

    fn id(&self) -> VarInt {
        Self::ID
    }

    fn value_from(&self, settings: &Settings) -> VarInt {
        settings.get_raw(Self::ID).unwrap_or(Self::DEFAULT)
    }
}

/// `SETTINGS_WT_INITIAL_MAX_DATA` (0x2b61). Default: 0.
pub struct InitialMaxData;

impl InitialMaxData {
    pub const ID: VarInt = VarInt::from_u32(0x2b61);
    pub const DEFAULT: VarInt = VarInt::from_u32(0);

    pub const fn setting(value: VarInt) -> Setting {
        Setting::new(Self::ID, value)
    }
}

impl SettingId for InitialMaxData {
    type Value = VarInt;

    fn id(&self) -> VarInt {
        Self::ID
    }

    fn value_from(&self, settings: &Settings) -> VarInt {
        settings.get_raw(Self::ID).unwrap_or(Self::DEFAULT)
    }
}

/// HTTP/3 settings fragment advertising WebTransport support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebTransportSupport {
    pub initial_max_streams_bidi: VarInt,
    pub initial_max_streams_uni: VarInt,
    pub initial_max_data: VarInt,
}

impl Default for WebTransportSupport {
    fn default() -> Self {
        Self {
            initial_max_streams_bidi: VarInt::from_u32(16),
            initial_max_streams_uni: VarInt::from_u32(16),
            initial_max_data: VarInt::MAX,
        }
    }
}

impl IntoIterator for WebTransportSupport {
    type Item = Setting;
    type IntoIter = std::array::IntoIter<Setting, 5>;

    fn into_iter(self) -> Self::IntoIter {
        [
            EnableConnectProtocol::setting(true),
            EnableWebTransport::setting(true),
            InitialMaxStreamsBidi::setting(self.initial_max_streams_bidi),
            InitialMaxStreamsUni::setting(self.initial_max_streams_uni),
            InitialMaxData::setting(self.initial_max_data),
        ]
        .into_iter()
    }
}

impl Settings {
    pub fn enable_webtransport(&self) -> bool {
        self.get(EnableWebTransport)
    }

    pub fn wt_initial_max_streams_uni(&self) -> VarInt {
        self.get(InitialMaxStreamsUni)
    }

    pub fn wt_initial_max_streams_bidi(&self) -> VarInt {
        self.get(InitialMaxStreamsBidi)
    }

    pub fn wt_initial_max_data(&self) -> VarInt {
        self.get(InitialMaxData)
    }

    pub fn webtransport_flow_control_enabled(&self) -> bool {
        self.wt_initial_max_streams_uni() != VarInt::from_u32(0)
            || self.wt_initial_max_streams_bidi() != VarInt::from_u32(0)
            || self.wt_initial_max_data() != VarInt::from_u32(0)
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

    #[test]
    fn enable_webtransport_exposes_id_and_treats_only_one_as_enabled() {
        assert_eq!(EnableWebTransport.id(), EnableWebTransport::ID);

        let mut settings = Settings::default();
        settings.set(EnableWebTransport::setting(false));
        assert!(!settings.enable_webtransport());
        assert_eq!(
            settings.get(VarInt::from_u32(0x2c7cf000)),
            Some(VarInt::from_u32(0)),
        );

        settings.set(Setting::new(EnableWebTransport::ID, VarInt::from_u32(2)));
        assert!(!settings.enable_webtransport());
    }

    #[test]
    fn webtransport_flow_control_settings_apply_draft_defaults() {
        let settings = Settings::default();

        assert_eq!(settings.wt_initial_max_streams_uni(), VarInt::from_u32(0));
        assert_eq!(settings.wt_initial_max_streams_bidi(), VarInt::from_u32(0));
        assert_eq!(settings.wt_initial_max_data(), VarInt::from_u32(0));
        assert!(!settings.webtransport_flow_control_enabled());
    }

    #[test]
    fn webtransport_flow_control_settings_use_typed_accessors() {
        let mut settings = Settings::default();
        settings.set(InitialMaxStreamsUni::setting(VarInt::from_u32(11)));
        settings.set(InitialMaxStreamsBidi::setting(VarInt::from_u32(13)));
        settings.set(InitialMaxData::setting(VarInt::MAX));

        assert_eq!(settings.wt_initial_max_streams_uni(), VarInt::from_u32(11));
        assert_eq!(settings.wt_initial_max_streams_bidi(), VarInt::from_u32(13));
        assert_eq!(settings.wt_initial_max_data(), VarInt::MAX);
        assert!(settings.webtransport_flow_control_enabled());
        assert_eq!(InitialMaxStreamsUni.id(), VarInt::from_u32(0x2b64));
        assert_eq!(InitialMaxStreamsBidi.id(), VarInt::from_u32(0x2b65));
        assert_eq!(InitialMaxData.id(), VarInt::from_u32(0x2b61));
    }

    #[test]
    fn webtransport_support_is_a_composable_settings_fragment() {
        let settings = Settings::default()
            .with_all(WebTransportSupport::default())
            .with(crate::dhttp::settings::MaxFieldSectionSize::setting(
                VarInt::from_u32(4096),
            ));

        assert!(settings.enable_connect_protocol());
        assert!(settings.enable_webtransport());
        assert_eq!(settings.wt_initial_max_streams_bidi(), VarInt::from_u32(16));
        assert_eq!(settings.wt_initial_max_streams_uni(), VarInt::from_u32(16));
        assert_eq!(settings.wt_initial_max_data(), VarInt::MAX);
        assert!(settings.webtransport_flow_control_enabled());
        assert_eq!(
            settings.max_field_section_size(),
            Some(VarInt::from_u32(4096)),
        );
    }
}
