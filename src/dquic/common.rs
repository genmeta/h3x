use std::{sync::Arc, time::Duration};

use crate::dquic::{
    log::{QLog, handy::NoopLogger},
    qbase::time::DEFAULT_HEARTBEAT_INTERVAL,
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
    /// Interval between path heartbeat PINGs while active keep-alive is enabled.
    /// Defaults to 20 seconds.
    pub heartbeat_interval: Duration,
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
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
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
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("enable_0rtt", &self.enable_0rtt)
            .field("enable_sslkeylog", &self.enable_sslkeylog)
            .finish_non_exhaustive()
    }
}

impl PartialEq for CommonQuicConfig {
    fn eq(&self, other: &Self) -> bool {
        self.defer_idle_timeout == other.defer_idle_timeout
            && self.heartbeat_interval == other.heartbeat_interval
            && self.enable_0rtt == other.enable_0rtt
            && self.enable_sslkeylog == other.enable_sslkeylog
            && Arc::ptr_eq(
                &self.stream_strategy_factory,
                &other.stream_strategy_factory,
            )
            && Arc::ptr_eq(&self.qlogger, &other.qlogger)
    }
}

impl CommonQuicConfig {
    /// Configure active connection keep-alive.
    ///
    /// `duration` is the maximum window for initiating keep-alive PINGs after
    /// the most recent effective payload. `heartbeat_interval` is the interval
    /// between path heartbeat PINGs during that window.
    pub fn keep_alive(mut self, duration: Duration, heartbeat_interval: Duration) -> Self {
        self.defer_idle_timeout = duration;
        self.heartbeat_interval = heartbeat_interval;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_noop_components_and_disabled_features() {
        let config = CommonQuicConfig::default();

        assert_eq!(config.defer_idle_timeout, Duration::ZERO);
        assert_eq!(config.heartbeat_interval, Duration::from_secs(20));
        assert!(!config.enable_0rtt);
        assert!(!config.enable_sslkeylog);
        assert_eq!(
            format!("{config:?}"),
            "CommonQuicConfig { defer_idle_timeout: 0ns, heartbeat_interval: 20s, enable_0rtt: false, enable_sslkeylog: false, .. }",
        );
    }

    #[test]
    fn clone_preserves_dynamic_component_identity() {
        let config = CommonQuicConfig {
            defer_idle_timeout: Duration::from_secs(5),
            heartbeat_interval: Duration::from_secs(2),
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

        let mut different_interval = config.clone();
        different_interval.heartbeat_interval = Duration::from_secs(1);
        assert_ne!(config, different_interval);

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

    #[test]
    fn keep_alive_sets_duration_and_heartbeat_interval() {
        let config = CommonQuicConfig::default()
            .keep_alive(Duration::from_secs(120), Duration::from_secs(20));

        assert_eq!(config.defer_idle_timeout, Duration::from_secs(120));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(20));
    }
}
