# Contributing to PIB

## Development Setup

```bash
cd tracker
pip install -r requirements.txt

# Run against a local VictoriaMetrics (or test VM)
VIB_VICTORIAMETRICS_URL=http://localhost:8428 \
VICTORIAMETRICS_URL=http://localhost:8428 \
python tracker.py --once
```

## Code Style

- Python 3.12+
- Keep `tracker.py` self-contained — no new external dependencies without updating `requirements.txt`
- All external calls must handle errors gracefully — no single image failure should crash the tracker
- Log at INFO level for cycle milestones, WARNING for recoverable errors, ERROR for push failures

## Adding New Metrics

1. Add the metric to `_build_prometheus_lines()` in `tracker.py`
2. Add it to the `pib_overview.json` Grafana dashboard
3. Document it in `README.md` metrics table

## Pull Requests

- Keep commits focused — one logical change per commit
- Update `CHANGELOG.md` under an `[Unreleased]` heading
- Ensure `make check-now` exits 0 before opening a PR
