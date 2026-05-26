use std::{sync::Arc, time::Duration};

use crate::dquic::{
    log::{QLog, handy::NoopLogger},
    stream::{ProductStreamsConcurrencyController, handy::ConsistentConcurrency},
};

// ---------------------------------------------------------------------------
// Common
// ---------------------------------------------------------------------------

/// Configuration values that apply to both client and server roles.
#[derive(Clone)]
pub struct CommonQuicConfig {
    /// How long the connection should keep sending probe packets after going
    /// idle. `Duration::ZERO` (the default) disables deferred idle timeouts.
    pub defer_idle_timeout: Duration,
    /// Factory producing per-connection streams concurrency controllers.
    pub stream_strategy_factory: Arc<dyn ProductStreamsConcurrencyController>,
    /// QUIC-events logger (qlog). Defaults to a no-op logger.
    pub qlogger: Arc<dyn QLog + Send + Sync>,
    /// Whether 0-RTT should be enabled if the crypto context permits it.
    pub enable_0rtt: bool,
    /// Enable SSL key logging via `SSLKEYLOGFILE` for debugging captures.
    pub enable_sslkeylog: bool,
}

impl Default for CommonQuicConfig {
    fn default() -> Self {
        Self {
            defer_idle_timeout: Duration::ZERO,
            stream_strategy_factory: Arc::new(ConsistentConcurrency::new),
            qlogger: Arc::new(NoopLogger),
            enable_0rtt: false,
            enable_sslkeylog: false,
        }
    }
}

impl std::fmt::Debug for CommonQuicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonQuicConfig")
            .field("defer_idle_timeout", &self.defer_idle_timeout)
            .field("enable_0rtt", &self.enable_0rtt)
            .field("enable_sslkeylog", &self.enable_sslkeylog)
            .finish_non_exhaustive()
    }
}

impl PartialEq for CommonQuicConfig {
    fn eq(&self, other: &Self) -> bool {
        self.defer_idle_timeout == other.defer_idle_timeout
            && self.enable_0rtt == other.enable_0rtt
            && self.enable_sslkeylog == other.enable_sslkeylog
            && Arc::ptr_eq(
                &self.stream_strategy_factory,
                &other.stream_strategy_factory,
            )
            && Arc::ptr_eq(&self.qlogger, &other.qlogger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_noop_components_and_disabled_features() {
        let config = CommonQuicConfig::default();

        assert_eq!(config.defer_idle_timeout, Duration::ZERO);
        assert!(!config.enable_0rtt);
        assert!(!config.enable_sslkeylog);
        assert_eq!(
            format!("{config:?}"),
            "CommonQuicConfig { defer_idle_timeout: 0ns, enable_0rtt: false, enable_sslkeylog: false, .. }",
        );
    }

    #[test]
    fn clone_preserves_dynamic_component_identity() {
        let config = CommonQuicConfig {
            defer_idle_timeout: Duration::from_secs(5),
            enable_0rtt: true,
            enable_sslkeylog: true,
            ..Default::default()
        };

        let cloned = config.clone();

        assert_eq!(config, cloned);
        assert!(Arc::ptr_eq(
            &config.stream_strategy_factory,
            &cloned.stream_strategy_factory,
        ));
        assert!(Arc::ptr_eq(&config.qlogger, &cloned.qlogger));
    }

    #[test]
    fn equality_requires_same_values_and_same_dynamic_component_arcs() {
        let config = CommonQuicConfig::default();

        let mut different_timeout = config.clone();
        different_timeout.defer_idle_timeout = Duration::from_secs(1);
        assert_ne!(config, different_timeout);

        let mut different_zero_rtt = config.clone();
        different_zero_rtt.enable_0rtt = true;
        assert_ne!(config, different_zero_rtt);

        let mut different_sslkeylog = config.clone();
        different_sslkeylog.enable_sslkeylog = true;
        assert_ne!(config, different_sslkeylog);

        let mut different_strategy = config.clone();
        different_strategy.stream_strategy_factory = Arc::new(ConsistentConcurrency::new);
        assert_ne!(config, different_strategy);

        let mut different_logger = config.clone();
        different_logger.qlogger = Arc::new(NoopLogger);
        assert_ne!(config, different_logger);
    }
}
