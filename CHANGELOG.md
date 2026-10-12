# Changelog

## [0.7.0] - 2026-10-12

### Changed

- Rework native HTTP/3 streams, QPACK feedback and cancellation.
- Coordinate connection pooling and expose validated peer SETTINGS.
- Use qbase and qrecovery 0.7.0 from the dquic 0.8.0 release.

### Release versions

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `h3x` | 0.6.2 | 0.7.0 |


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
