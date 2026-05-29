# PIB — Patch in a Box

A prioritized patch queue for container images. PIB cross-references vulnerability data from **VIB** (Vulnerability in a Box) and threat intelligence from **TIB** (Threat Intel in a Box) to rank which images need patching most urgently.

## How the Score is Computed

```
priority_score = (cvss_max × 2) + (epss_max × 30) + (kev_count × 20) + (age_days × 0.1)
```

| Component | Source | Weight | Rationale |
|-----------|--------|--------|-----------|
| `cvss_max` | VIB | ×2 | Severity of the worst CVE in the image |
| `epss_max` | TIB | ×30 | Probability of exploitation in the next 30 days |
| `kev_count` | TIB | ×20 | Known-exploited vulnerability count — already weaponized |
| `age_days` | VIB scan timestamp | ×0.1 | Drift penalty — stale images are riskier |

A score of 60+ is red (urgent). 30–60 is orange. Below 10 is green.

## Quick Start

```bash
cp .env.example .env
# Edit .env — at minimum change GRAFANA_ADMIN_PASSWORD
make up
```

Open Grafana at http://localhost:3005 (admin / password from .env).

## Ports

| Service | Host Port | Default |
|---------|-----------|---------|
| VictoriaMetrics | `VICTORIAMETRICS_PORT` | 8433 |
| Grafana | `GRAFANA_PORT` | 3005 |

## Metrics

All metrics are stored in PIB's own VictoriaMetrics instance.

| Metric | Labels | Description |
|--------|--------|-------------|
| `pib_priority_score` | `image` | Computed patch priority score |
| `pib_newer_version_available` | `image`, `latest_tag` | 1 if Docker Hub has a newer tag |
| `pib_image_cve_count` | `image` | Total CVE count |
| `pib_image_cve_critical` | `image` | Critical CVE count |
| `pib_image_cve_high` | `image` | High CVE count |
| `pib_image_cvss_max` | `image` | Highest CVSS score |
| `pib_image_epss_max` | `image` | Highest EPSS score |
| `pib_image_kev_count` | `image` | KEV CVE count |
| `pib_image_age_days` | `image` | Days since last VIB scan |
| `pib_images_needing_update` | — | Count of images with newer Docker Hub version |
| `pib_last_check_timestamp` | — | Unix timestamp of last completed check |

## Integrating VIB and TIB

Set these env vars in `.env` (or pass directly to the container):

```env
VIB_VICTORIAMETRICS_URL=http://vib-victoriametrics:8428
TIB_VICTORIAMETRICS_URL=http://tib-victoriametrics:8428
```

If the VIB/TIB containers are on a shared Docker network, add PIB to that network in `docker-compose.yml`:

```yaml
services:
  pib-tracker:
    networks:
      - pib
      - vib_default      # or whatever VIB's network is named
      - tib_default
```

PIB is fully operational without VIB or TIB — Docker Hub version checks still run and scores are computed with available data (zeroed CVE fields when VIB is absent, zeroed EPSS/KEV when TIB is absent).

## Operations

```bash
make up           # Start all services
make down         # Stop all services
make check-now    # Trigger an immediate check cycle (--once mode)
make logs         # Follow all container logs
make restart      # Restart only the tracker (e.g., after env change)
make clean        # Stop and remove all volumes (destructive)
```

## Part of the in-a-box-tools Ecosystem

| Tool | Role |
|------|------|
| **VIB** — Vulnerability in a Box | Scans images for CVEs, exposes `vib_cve_info` + `vib_scan_timestamp` |
| **TIB** — Threat Intel in a Box | Enriches CVEs with EPSS scores + KEV matches |
| **PIB** — Patch in a Box | Aggregates VIB + TIB data, ranks images by patch urgency |
