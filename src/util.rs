use std::fmt::Write as _;

const DIAGNOSTIC_PREFIX_BYTES: usize = 16;

pub(crate) fn diagnostic_hex_prefix(data: &[u8]) -> String {
    let prefix_len = data.len().min(DIAGNOSTIC_PREFIX_BYTES);
    let mut encoded = String::with_capacity(prefix_len * 2);
    for byte in &data[..prefix_len] {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub mod deferred;
pub mod ring_channel;
pub mod set_once;
#[cfg(feature = "dquic")]
pub mod tls;
pub mod watch;

#[cfg(test)]
mod tests {
    use super::diagnostic_hex_prefix;

    #[test]
    fn diagnostic_prefix_is_hex_encoded_and_bounded() {
        let bytes = (0_u8..32).collect::<Vec<_>>();
        assert_eq!(
            diagnostic_hex_prefix(&bytes),
            "000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(diagnostic_hex_prefix(&[0xab, 0xcd]), "abcd");
    }
}
