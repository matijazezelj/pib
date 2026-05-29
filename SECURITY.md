# Security Policy

## Supported Versions

Only the latest release is actively supported with security fixes.

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately by emailing the maintainer. Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact

We aim to acknowledge reports within 48 hours and provide a fix or mitigation within 14 days for confirmed issues.

## Security Notes

- PIB does not store or transmit CVE data externally — all data stays within your VictoriaMetrics instance
- The Grafana admin password should be changed from the default in `.env` before deployment
- PIB only reads from VIB and TIB VictoriaMetrics — it writes only to its own instance
- No credentials or tokens are stored in container images
