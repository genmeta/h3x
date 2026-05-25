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
}
