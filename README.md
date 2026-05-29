# PIB — PKI in a Box

**One `make up` to get a fully functional internal CA with ACME support and certificate expiry monitoring.**

PIB runs [step-ca](https://smallstep.com/docs/step-ca/) as a self-hosted root CA, issues certificates via the ACME protocol (so your services can auto-renew with `acme.sh` or `certbot`), and monitors all your TLS endpoints for expiry in Grafana.

Part of the [in-a-box-tools](https://in-a-box-tools.tech) ecosystem.

---

## What you get

| Component | Purpose |
|-----------|---------|
| **step-ca** | Root CA + ACME endpoint — issue and renew internal certs |
| **pib-monitor** | TLS cert expiry scanner — checks configured endpoints every 6h |
| **VictoriaMetrics** | Stores cert health metrics (365 day retention) |
| **Grafana** | Dashboard: expiry countdown, cert inventory, color-coded health |

---

## Quick start

```bash
git clone https://github.com/matijazezelj/pib.git
cd pib
cp .env.example .env       # set CA_DNS_NAMES, GRAFANA_ADMIN_PASSWORD
make up                    # generates CA password + starts stack
```

On first start, `make up` generates a random CA password (`ca/password.txt`) and step-ca initialises a root CA. This takes about 10 seconds.

Open **http://localhost:3005** for the Grafana dashboard.

---

## Using the CA

### Get the root CA fingerprint

```bash
make ca-fingerprint
```

### Issue a cert via ACME (acme.sh)

```bash
acme.sh --issue \
  --server https://localhost:9000/acme/acme/directory \
  --domain myservice.internal \
  --webroot /var/www/html \
  --ca-bundle /path/to/pib-root-ca.crt
```

### Issue a cert via step CLI

```bash
step ca certificate myservice.internal cert.pem key.pem \
  --ca-url https://localhost:9000 \
  --fingerprint $(make ca-fingerprint)
```

### Trust the root CA

```bash
# macOS
step certificate install $(make ca-fingerprint)

# Ubuntu/Debian
docker cp pib-ca:/home/step/certs/root_ca.crt /usr/local/share/ca-certificates/pib-root-ca.crt
update-ca-certificates
```

---

## Adding endpoints to monitor

In `.env`:

```env
MONITOR_HOSTS=pib-ca:9000,myservice.internal:443,grafana.internal:443
```

Or on a network where DNS resolves your services. The monitor always includes `pib-ca:9000` automatically.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GRAFANA_ADMIN_PASSWORD` | auto-generated | Grafana admin password |
| `GRAFANA_PORT` | `3005` | Host port for Grafana |
| `VICTORIAMETRICS_PORT` | `8433` | Host port for VictoriaMetrics |
| `CA_PORT` | `9000` | Host port for step-ca (ACME + API) |
| `CA_NAME` | `PIB Root CA` | Display name of the root CA |
| `CA_DNS_NAMES` | `localhost,pib-ca` | DNS names in the CA certificate |
| `MONITOR_HOSTS` | `pib-ca:9000` | Comma-separated `host:port` to monitor |
| `SCAN_INTERVAL_HOURS` | `6` | Monitor scan frequency |
| `WARN_DAYS` | `30` | Days remaining threshold for warning |
| `CRITICAL_DAYS` | `7` | Days remaining threshold for critical |

---

## Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `pib_cert_days_remaining` | `host`, `cn`, `issuer`, `sans` | Days until certificate expires |
| `pib_cert_expiry_timestamp` | `host`, `cn`, `issuer`, `sans` | Expiry as Unix timestamp (ms) |
| `pib_cert_valid_days` | `host`, `cn`, `issuer`, `sans` | Total validity period (days) |
| `pib_certs_total` | — | Total monitored certs |
| `pib_certs_expired` | — | Currently expired certs |
| `pib_certs_expiring_warning` | — | Certs expiring within `WARN_DAYS` |
| `pib_certs_expiring_critical` | — | Certs expiring within `CRITICAL_DAYS` |
| `pib_last_scan_timestamp` | — | Last scan Unix timestamp (ms) |

---

## Useful commands

```bash
make up               # start the stack (generates CA password if needed)
make down             # stop
make logs             # follow all container logs
make scan-now         # trigger an immediate cert scan
make ca-fingerprint   # print root CA fingerprint (for trust anchoring)
make build            # rebuild monitor image
make clean            # stop and delete all volumes (destroys CA and data)
```

---

## In-a-box ecosystem

| Tool | What it does |
|------|-------------|
| [VIB](https://github.com/matijazezelj/vib) | Vulnerability in a Box — CVE scanning |
| [TIB](https://github.com/matijazezelj/tib) | Threat Intelligence in a Box — KEV + EPSS |
| [CIB](https://github.com/matijazezelj/cib) | Compliance in a Box — policy + license + EOL |
| [IIB](https://github.com/matijazezelj/iib) | Incident in a Box — incident management |
| **PIB** | **PKI in a Box** |

---

## License

MIT
