# Changelog

## [0.6.2] - 2026-08-24

### Changed

- Adapt QUIC client and server configuration to dquic's consolidated
  `keep_alive(duration, heartbeat_interval)` interface and pass both values to
  every connection.

### Dependencies

- Align the direct `netdev` dependency with dquic's public interface types by
  upgrading to v0.46 and requiring dquic v0.7.2.

## [0.6.1] - 2026-08-11

### Changed

- Add wildcard interface binding policies to DQuic endpoint construction.
- Adapt the DQuic network and endpoint layers to the latest resolver and
  endpoint APIs.

### Dependencies

- Release manifests target `dquic` v0.7.1.
