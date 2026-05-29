# Roadmap

## v0.2
- [ ] Grafana alert rule template: fire when any cert has < 14 days remaining
- [ ] Telegram/Slack notification on cert expiry threshold breach
- [ ] step-ca provisioner management via `make` targets (add provisioner, list certs issued)
- [ ] OCSP responder metrics (step-ca supports OCSP — surface revocation stats)

## v0.3
- [ ] Automatic cert renewal via ACME for monitored services (opt-in)
- [ ] CRL (Certificate Revocation List) export and monitoring
- [ ] SSH CA mode — use step-ca to issue short-lived SSH certificates instead of static keys
- [ ] Integration with AIB — attach cert expiry data to asset nodes

## Backlog
- Multi-CA support (monitor certs from external CAs alongside PIB's own)
- Hashicorp Vault PKI backend as an alternative to step-ca
- Export cert inventory report as PDF for audits
