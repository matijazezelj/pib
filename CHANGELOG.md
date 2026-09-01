# Changelog

## [Unreleased]

### Added
- Root and intermediate CA expiry monitoring, read from the step-ca volume
  (`certs/` only — never `secrets/`), with their own `CA_WARN_DAYS` /
  `CA_CRITICAL_DAYS` thresholds
- Provisioned Grafana alert rules: expired, expiring, CA chain expiring,
  endpoint unreachable, and monitor stalled
- Optional webhook delivery via `ALERT_WEBHOOK_URL` (see
  `contactpoints.yaml.example`)
- `pib_cert_status` and `pib_cert_lifetime_remaining_ratio` metrics; `kind`
  label on all per-certificate metrics
- Dashboard panels for root and intermediate expiry
- Threshold classification tests, run in CI

### Fixed
- Short-lived certificates are judged on fraction of lifetime remaining rather
  than an absolute day count. step-ca's own API certificate lives ~24h and
  renews itself, so the default install reported CRITICAL permanently
- `pib-monitor` now waits for the CA to be healthy before starting, fixing the
  boot-time scan race

## [0.1.0] — 2026-05-29

### Added
- step-ca root CA with ACME protocol support — issue and auto-renew internal certs
- `Makefile` auto-generates a random CA password on first `make up`
- cert monitor: TLS endpoint scanner with configurable host list
- Grafana dashboard: expiry countdown table, critical/warning/expired stat panels, time series trend
- `MONITOR_HOSTS` env var — comma-separated `host:port` pairs to watch
- `make ca-fingerprint` — print root CA fingerprint for trust anchoring
- VictoriaMetrics with 365-day retention (cert expiry history matters long-term)
