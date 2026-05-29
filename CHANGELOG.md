# Changelog

All notable changes to PIB will be documented here.

## [0.1.0] — 2026-05-29

### Added
- Initial release
- `tracker.py` — Python service querying VIB/TIB VictoriaMetrics instances
- Priority score formula: `(cvss_max × 2) + (epss_max × 30) + (kev_count × 20) + (age_days × 0.1)`
- Docker Hub version check for images with explicit tags
- 11 Prometheus metrics pushed to PIB's own VictoriaMetrics
- Grafana dashboard with priority queue table, stat panels, timeseries, and bar gauge
- `--once` flag for on-demand check cycles
- `docker-compose.yml` wiring tracker + VictoriaMetrics + Grafana
- Graceful degradation when VIB or TIB are not configured
