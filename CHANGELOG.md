# Changelog

## [0.1.0] — 2026-05-29

### Added
- step-ca root CA with ACME protocol support — issue and auto-renew internal certs
- `Makefile` auto-generates a random CA password on first `make up`
- cert monitor: TLS endpoint scanner with configurable host list
- Grafana dashboard: expiry countdown table, critical/warning/expired stat panels, time series trend
- `MONITOR_HOSTS` env var — comma-separated `host:port` pairs to watch
- `make ca-fingerprint` — print root CA fingerprint for trust anchoring
- VictoriaMetrics with 365-day retention (cert expiry history matters long-term)
