/// HTTP/3 settings advertised to the peer.
///
/// Only settings implemented by h3x are represented. Unknown peer settings
/// are ignored while decoding, as required by HTTP/3.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    max_field_section_size: Option<u64>,
    qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
    enable_connect_protocol: Option<bool>,
    #[cfg(feature = "webtransport")]
    h3_datagram: Option<bool>,
    #[cfg(feature = "webtransport")]
    webtransport: Option<bool>,
}

impl Settings {
    pub const fn max_field_section_size(&self) -> Option<u64> {
        self.max_field_section_size
    }

    pub fn set_max_field_section_size(&mut self, value: Option<u64>) {
        self.max_field_section_size = value;
    }

    pub const fn qpack_max_table_capacity(&self) -> u64 {
        match self.qpack_max_table_capacity {
            Some(value) => value,
            None => 0,
        }
    }

    pub fn set_qpack_max_table_capacity(&mut self, value: u64) {
        self.qpack_max_table_capacity = Some(value);
    }

    pub const fn qpack_blocked_streams(&self) -> u64 {
        match self.qpack_blocked_streams {
            Some(value) => value,
            None => 0,
        }
    }

    pub fn set_qpack_blocked_streams(&mut self, value: u64) {
        self.qpack_blocked_streams = Some(value);
    }

    pub const fn enable_connect_protocol(&self) -> bool {
        matches!(self.enable_connect_protocol, Some(true))
    }

    pub fn set_enable_connect_protocol(&mut self, enabled: bool) {
        self.enable_connect_protocol = Some(enabled);
    }

    pub(crate) const fn encoded_qpack_max_table_capacity(&self) -> Option<u64> {
        self.qpack_max_table_capacity
    }

    pub(crate) const fn encoded_qpack_blocked_streams(&self) -> Option<u64> {
        self.qpack_blocked_streams
    }

    pub(crate) const fn encoded_enable_connect_protocol(&self) -> Option<bool> {
        self.enable_connect_protocol
    }

    #[cfg(feature = "webtransport")]
    pub const fn h3_datagram(&self) -> bool {
        matches!(self.h3_datagram, Some(true))
    }

    #[cfg(feature = "webtransport")]
    pub const fn webtransport(&self) -> bool {
        matches!(self.webtransport, Some(true))
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn enable_webtransport(&mut self) {
        self.enable_connect_protocol = Some(true);
        self.h3_datagram = Some(true);
        self.webtransport = Some(true);
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn set_h3_datagram(&mut self, enabled: bool) {
        self.h3_datagram = Some(enabled);
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn set_webtransport(&mut self, enabled: bool) {
        self.webtransport = Some(enabled);
    }

    #[cfg(feature = "webtransport")]
    pub(crate) const fn encoded_h3_datagram(&self) -> Option<bool> {
        self.h3_datagram
    }

    #[cfg(feature = "webtransport")]
    pub(crate) const fn encoded_webtransport(&self) -> Option<bool> {
        self.webtransport
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_defaults_match_the_http3_defaults() {
        let settings = Settings::default();

        assert_eq!(settings.max_field_section_size(), None);
        assert_eq!(settings.qpack_max_table_capacity(), 0);
        assert_eq!(settings.qpack_blocked_streams(), 0);
        assert!(!settings.enable_connect_protocol());
        #[cfg(feature = "webtransport")]
        {
            assert!(!settings.h3_datagram());
            assert!(!settings.webtransport());
        }
    }

    #[test]
    fn typed_settings_round_trip() {
        let mut settings = Settings::default();
        settings.set_max_field_section_size(Some(32 * 1024));
        settings.set_qpack_max_table_capacity(4096);
        settings.set_qpack_blocked_streams(16);
        settings.set_enable_connect_protocol(true);

        assert_eq!(settings.max_field_section_size(), Some(32 * 1024));
        assert_eq!(settings.qpack_max_table_capacity(), 4096);
        assert_eq!(settings.qpack_blocked_streams(), 16);
        assert!(settings.enable_connect_protocol());

        settings.set_max_field_section_size(None);
        assert_eq!(settings.max_field_section_size(), None);
    }

    #[cfg(feature = "webtransport")]
    #[test]
    fn enabling_webtransport_enables_its_required_http3_settings() {
        let mut settings = Settings::default();
        settings.enable_webtransport();

        assert!(settings.enable_connect_protocol());
        assert!(settings.h3_datagram());
        assert!(settings.webtransport());
    }
}
