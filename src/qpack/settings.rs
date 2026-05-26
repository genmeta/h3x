use crate::{
    dhttp::settings::{Setting, SettingId, Settings},
    varint::VarInt,
};

/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0x01). Default: 0.
pub struct QpackMaxTableCapacity;

impl QpackMaxTableCapacity {
    pub const ID: VarInt = VarInt::from_u32(0x01);
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
pub struct QpackBlockedStreams;

impl QpackBlockedStreams {
    pub const ID: VarInt = VarInt::from_u32(0x07);
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

impl Settings {
    pub fn qpack_max_table_capacity(&self) -> VarInt {
        self.get(QpackMaxTableCapacity)
    }

    pub fn qpack_blocked_streams(&self) -> VarInt {
        self.get(QpackBlockedStreams)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::VarInt;

    #[test]
    fn qpack_settings_apply_defaults_and_overrides() {
        let mut settings = Settings::default();
        assert_eq!(settings.qpack_max_table_capacity(), VarInt::from_u32(0));
        assert_eq!(settings.qpack_blocked_streams(), VarInt::from_u32(0));

        settings.set(QpackMaxTableCapacity::setting(VarInt::from_u32(4096)));
        settings.set(QpackBlockedStreams::setting(VarInt::from_u32(100)));

        assert_eq!(settings.qpack_max_table_capacity(), VarInt::from_u32(4096));
        assert_eq!(settings.qpack_blocked_streams(), VarInt::from_u32(100));
    }

    #[test]
    fn qpack_settings_boundaries_and_ids() {
        assert_eq!(QpackMaxTableCapacity::ID, VarInt::from_u32(0x01));
        assert_eq!(QpackBlockedStreams::ID, VarInt::from_u32(0x07));
        assert_eq!(QpackMaxTableCapacity::DEFAULT, VarInt::from_u32(0));
        assert_eq!(QpackBlockedStreams::DEFAULT, VarInt::from_u32(0));
        assert_eq!(
            QpackMaxTableCapacity::setting(VarInt::MAX).id,
            QpackMaxTableCapacity::ID
        );
        assert_eq!(
            QpackBlockedStreams::setting(VarInt::from_u32(0)).value,
            VarInt::from_u32(0),
        );
    }

    #[test]
    fn qpack_settings_raw_lookup_and_default_fallback() {
        let mut settings = Settings::default();

        assert_eq!(settings.get_raw(QpackMaxTableCapacity::ID), None);
        assert_eq!(
            settings.get(QpackMaxTableCapacity),
            QpackMaxTableCapacity::DEFAULT
        );

        settings.set(QpackMaxTableCapacity::setting(VarInt::from_u32(99)));
        assert_eq!(
            settings.get_raw(QpackMaxTableCapacity::ID),
            Some(VarInt::from_u32(99))
        );
        assert_eq!(settings.qpack_max_table_capacity(), VarInt::from_u32(99));
        assert_eq!(settings.get(QpackMaxTableCapacity), VarInt::from_u32(99));

        settings.set(QpackMaxTableCapacity::setting(VarInt::from_u32(0)));
        assert_eq!(
            settings.get_raw(QpackMaxTableCapacity::ID),
            Some(VarInt::from_u32(0))
        );
        assert_eq!(settings.qpack_max_table_capacity(), VarInt::from_u32(0));
    }

    #[test]
    fn qpack_setting_constructors_stay_well_formed_for_unknown_id_queries() {
        let setting = QpackBlockedStreams::setting(VarInt::MAX);
        let id: VarInt = QpackBlockedStreams::ID;

        assert_eq!(setting.id, id);
        assert_eq!(setting.value, VarInt::MAX);
        assert_eq!(Setting::from((id, VarInt::from_u32(0x7f))).id, id);
    }
}
