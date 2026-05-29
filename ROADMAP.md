# PIB Roadmap

## v0.2 — Automated Remediation

- Auto-PR generation for images where `newer_version_available=true` — open a GitHub PR updating the image tag in compose/Kubernetes manifests
- Renovate integration — emit Renovate-compatible update hints so teams can opt into automated dependency update PRs

## v0.3 — SLA Enforcement

- SLA breach alerts for unpatched KEV CVEs — trigger Grafana alert (→ PagerDuty / Slack / Telegram) when a KEV CVE has been known for more than N days without the image being updated
- Configurable SLA windows per severity (e.g., KEV: 24h, Critical: 72h, High: 14d)
- Breach history tracking in VictoriaMetrics for audit trails
