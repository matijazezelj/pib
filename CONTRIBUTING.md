# Contributing

PRs and issues welcome. Ground rules:

1. **One concern per PR.** Monitor changes separate from CA config separate from dashboard.
2. **Test with a real CA.** Run `make up` and verify certificates are issued and metrics appear before opening a PR.
3. **Dashboard changes:** export updated JSON from Grafana and replace `grafana/dashboards/pib-overview.json`.
4. **Don't commit `ca/password.txt`** — it's in `.gitignore` for a reason.

## Dev setup

```bash
cp .env.example .env
make up
docker logs -f pib-monitor
# Check that pib_cert_days_remaining metrics appear
curl -s http://localhost:8433/api/v1/query?query=pib_cert_days_remaining | jq .
```
