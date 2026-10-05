# Changelog

## [Unreleased]

### Fixed
- A healthy CA was reported as permanently critical. step-ca's own TLS certificate lives 24 hours and renews itself, but the
  fixed "critical under 7 days" rule is true from the moment it is issued, so the dashboard showed `Expiring Critical: 1` and
  `0 days` forever. Thresholds are now capped at a fraction of each certificate's lifetime (warn 1/3, critical 1/10); 90-day and
  1-year certificates behave as before. Added `pib_cert_hours_remaining`, since days read 0 for the whole life of a 24 h cert.

## [0.1.0] — 2026-05-29

### Added
- step-ca root CA with ACME protocol support — issue and auto-renew internal certs
- `Makefile` auto-generates a random CA password on first `make up`
- cert monitor: TLS endpoint scanner with configurable host list
- Grafana dashboard: expiry countdown table, critical/warning/expired stat panels, time series trend
- `MONITOR_HOSTS` env var — comma-separated `host:port` pairs to watch
- `make ca-fingerprint` — print root CA fingerprint for trust anchoring
- VictoriaMetrics with 365-day retention (cert expiry history matters long-term)
