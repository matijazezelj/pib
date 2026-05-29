#!/usr/bin/env python3
"""
PIB Tracker — Patch in a Box
Queries VIB (vulnerability data) and TIB (threat intel) from their
VictoriaMetrics instances, computes a priority score per image, and
pushes metrics to PIB's own VictoriaMetrics.
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import requests
import schedule

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("pib-tracker")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VICTORIAMETRICS_URL = os.getenv("VICTORIAMETRICS_URL", "http://pib-victoriametrics:8428")
VIB_VICTORIAMETRICS_URL = os.getenv("VIB_VICTORIAMETRICS_URL", "").rstrip("/")
TIB_VICTORIAMETRICS_URL = os.getenv("TIB_VICTORIAMETRICS_URL", "").rstrip("/")
CHECK_INTERVAL_HOURS = int(os.getenv("CHECK_INTERVAL_HOURS", "6"))
CHECK_ON_STARTUP = os.getenv("CHECK_ON_STARTUP", "true").lower() == "true"
CHECK_DOCKER_HUB = os.getenv("CHECK_DOCKER_HUB", "true").lower() == "true"

DOCKER_HUB_API = "https://hub.docker.com/v2/repositories"
HTTP_TIMEOUT = 30  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str, params: dict = None, timeout: int = HTTP_TIMEOUT) -> Optional[dict]:
    """GET request returning parsed JSON, or None on failure."""
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        log.warning("Timeout fetching %s", url)
    except requests.exceptions.ConnectionError as exc:
        log.warning("Connection error fetching %s: %s", url, exc)
    except requests.exceptions.HTTPError as exc:
        log.warning("HTTP error fetching %s: %s", url, exc)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("Unexpected error fetching %s: %s", url, exc)
    return None


def _query_vm(base_url: str, metric: str) -> list[dict]:
    """
    Query VictoriaMetrics instant query endpoint.
    Returns list of {"metric": {labels}, "value": [ts, value]} dicts.
    """
    url = f"{base_url}/api/v1/query"
    data = _get(url, params={"query": metric})
    if data is None:
        return []
    if data.get("status") != "success":
        log.warning("VM query for %r returned status %r", metric, data.get("status"))
        return []
    return data.get("data", {}).get("result", [])


# ---------------------------------------------------------------------------
# VIB data
# ---------------------------------------------------------------------------

def fetch_vib_data() -> tuple[dict, dict]:
    """
    Returns:
        cve_info: {image: {cve_id: {"severity": str, "cvss": float, "has_fix": bool}}}
        scan_timestamps: {image: float (unix)}
    """
    if not VIB_VICTORIAMETRICS_URL:
        log.info("VIB not configured, skipping CVE data")
        return {}, {}

    log.info("Fetching VIB CVE data from %s", VIB_VICTORIAMETRICS_URL)
    cve_results = _query_vm(VIB_VICTORIAMETRICS_URL, "vib_cve_info")
    ts_results = _query_vm(VIB_VICTORIAMETRICS_URL, "vib_scan_timestamp")

    cve_info: dict = {}
    for series in cve_results:
        labels = series.get("metric", {})
        image = labels.get("image", "")
        cve_id = labels.get("cve_id", "")
        if not image or not cve_id:
            continue
        try:
            cvss = float(series["value"][1])
        except (KeyError, IndexError, ValueError):
            cvss = 0.0

        cve_info.setdefault(image, {})[cve_id] = {
            "severity": labels.get("severity", "UNKNOWN"),
            "cvss": cvss,
            "has_fix": labels.get("has_fix", "false").lower() == "true",
        }

    scan_timestamps: dict = {}
    for series in ts_results:
        labels = series.get("metric", {})
        image = labels.get("image", "")
        if not image:
            continue
        try:
            scan_timestamps[image] = float(series["value"][1])
        except (KeyError, IndexError, ValueError):
            pass

    log.info(
        "VIB: %d images with CVE data, %d with scan timestamps",
        len(cve_info),
        len(scan_timestamps),
    )
    return cve_info, scan_timestamps


# ---------------------------------------------------------------------------
# TIB data
# ---------------------------------------------------------------------------

def fetch_tib_data() -> tuple[dict, dict]:
    """
    Returns:
        epss_scores: {image: {cve_id: float}}
        kev_matches: {image: set[cve_id]}
    """
    if not TIB_VICTORIAMETRICS_URL:
        log.info("TIB not configured, skipping threat intel data")
        return {}, {}

    log.info("Fetching TIB data from %s", TIB_VICTORIAMETRICS_URL)
    epss_results = _query_vm(TIB_VICTORIAMETRICS_URL, "tib_cve_epss_score")
    kev_results = _query_vm(TIB_VICTORIAMETRICS_URL, "tib_kev_match")

    epss_scores: dict = {}
    for series in epss_results:
        labels = series.get("metric", {})
        image = labels.get("image", "")
        cve_id = labels.get("cve_id", "")
        if not image or not cve_id:
            continue
        try:
            score = float(series["value"][1])
        except (KeyError, IndexError, ValueError):
            score = 0.0
        epss_scores.setdefault(image, {})[cve_id] = score

    kev_matches: dict = {}
    for series in kev_results:
        labels = series.get("metric", {})
        image = labels.get("image", "")
        cve_id = labels.get("cve_id", "")
        if not image or not cve_id:
            continue
        try:
            val = float(series["value"][1])
        except (KeyError, IndexError, ValueError):
            val = 0.0
        if val == 1.0:
            kev_matches.setdefault(image, set()).add(cve_id)

    log.info(
        "TIB: %d images with EPSS data, %d with KEV matches",
        len(epss_scores),
        len(kev_matches),
    )
    return epss_scores, kev_matches


# ---------------------------------------------------------------------------
# Docker Hub version check
# ---------------------------------------------------------------------------

def _parse_image_ref(image_ref: str) -> Optional[tuple[str, str, str]]:
    """
    Parse an image reference into (registry, namespace/name, tag).
    Returns None if we should skip this image.
    Examples:
      nginx:1.24              -> ("", "library/nginx", "1.24")
      myorg/app:2.1           -> ("", "myorg/app", "2.1")
      ghcr.io/owner/img:v1.0  -> skip (non-Docker Hub)
      nginx@sha256:abc123     -> skip (digest only)
      nginx:latest            -> skip (latest tag)
    """
    # Strip digest — can't compare tags from digest-only refs
    if "@sha256:" in image_ref:
        return None

    # Split tag
    if ":" in image_ref.rsplit("/", 1)[-1]:
        name_part, tag = image_ref.rsplit(":", 1)
    else:
        name_part, tag = image_ref, "latest"

    if tag == "latest":
        return None

    # Detect non-Docker Hub registry (contains a dot or colon in the first component)
    parts = name_part.split("/")
    if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0]):
        # e.g., ghcr.io/..., registry.k8s.io/...
        return None

    # Official library images have no slash
    if len(parts) == 1:
        namespace_name = f"library/{parts[0]}"
    else:
        namespace_name = name_part  # e.g., myorg/app

    return ("", namespace_name, tag)


def check_docker_hub(image_ref: str) -> tuple[bool, Optional[str]]:
    """
    Returns (newer_available, latest_tag).
    """
    parsed = _parse_image_ref(image_ref)
    if parsed is None:
        log.debug("Skipping Docker Hub check for %r (non-DockerHub or latest/digest)", image_ref)
        return False, None

    _, namespace_name, current_tag = parsed
    url = f"{DOCKER_HUB_API}/{namespace_name}/tags"
    params = {"page_size": 20, "ordering": "last_updated"}
    data = _get(url, params=params)

    if data is None:
        return False, None

    results = data.get("results", [])
    if not results:
        return False, None

    # The first result is the most recently updated tag
    latest = results[0]
    latest_tag = latest.get("name", "")
    latest_updated = latest.get("last_updated", "")

    if not latest_tag or latest_tag == "latest":
        # Try to find a more meaningful tag
        for r in results:
            if r.get("name", "latest") != "latest":
                latest = r
                latest_tag = r.get("name", "")
                latest_updated = r.get("last_updated", "")
                break

    if latest_tag == current_tag:
        return False, None

    # Compare timestamps if available to avoid false positives
    # We accept "newer" if latest_updated exists and we have no creation time to compare
    # The caller can decide; here we just report the latest tag
    if latest_tag and latest_tag != current_tag:
        return True, latest_tag

    return False, None


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------

def compute_scores(
    cve_info: dict,
    scan_timestamps: dict,
    epss_scores: dict,
    kev_matches: dict,
) -> list[dict]:
    """
    Aggregate per-image data and compute priority scores.
    Returns list of image dicts sorted by priority_score descending.
    """
    now = datetime.now(timezone.utc).timestamp()

    # Collect all known images across all data sources
    all_images = (
        set(cve_info.keys())
        | set(scan_timestamps.keys())
        | set(epss_scores.keys())
        | set(kev_matches.keys())
    )

    if not all_images and not CHECK_DOCKER_HUB:
        log.warning("No image data available from VIB or TIB")
        return []

    results = []
    for image in all_images:
        try:
            result = _compute_image_score(
                image, cve_info, scan_timestamps, epss_scores, kev_matches, now
            )
            results.append(result)
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("Failed to compute score for image %r: %s", image, exc)

    results.sort(key=lambda x: x["priority_score"], reverse=True)
    return results


def _compute_image_score(
    image: str,
    cve_info: dict,
    scan_timestamps: dict,
    epss_scores: dict,
    kev_matches: dict,
    now: float,
) -> dict:
    cves = cve_info.get(image, {})
    epss = epss_scores.get(image, {})
    kev = kev_matches.get(image, set())

    cvss_max = max((c["cvss"] for c in cves.values()), default=0.0)
    epss_max = max(epss.values(), default=0.0) if epss else 0.0
    kev_count = len(kev)

    cve_count = len(cves)
    cve_critical = sum(1 for c in cves.values() if c["severity"].upper() == "CRITICAL")
    cve_high = sum(1 for c in cves.values() if c["severity"].upper() == "HIGH")

    scan_ts = scan_timestamps.get(image, now)
    age_days = max(0.0, (now - scan_ts) / 86400.0)

    priority_score = (cvss_max * 2) + (epss_max * 30) + (kev_count * 20) + (age_days * 0.1)

    return {
        "image": image,
        "cvss_max": cvss_max,
        "epss_max": epss_max,
        "kev_count": kev_count,
        "cve_count": cve_count,
        "cve_critical": cve_critical,
        "cve_high": cve_high,
        "age_days": age_days,
        "newer_version_available": False,
        "latest_tag": None,
        "priority_score": priority_score,
    }


# ---------------------------------------------------------------------------
# Docker Hub enrichment
# ---------------------------------------------------------------------------

def enrich_with_docker_hub(image_data: list[dict]) -> list[dict]:
    """Check Docker Hub for newer versions and annotate image_data in-place."""
    if not CHECK_DOCKER_HUB:
        return image_data

    log.info("Checking Docker Hub for newer image versions (%d images)", len(image_data))
    for item in image_data:
        image = item["image"]
        try:
            newer, latest_tag = check_docker_hub(image)
            item["newer_version_available"] = newer
            item["latest_tag"] = latest_tag if newer else None
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("Docker Hub check failed for %r: %s", image, exc)

    return image_data


# ---------------------------------------------------------------------------
# Metrics push
# ---------------------------------------------------------------------------

def _build_prometheus_lines(image_data: list[dict], check_ts: float) -> str:
    """Build Prometheus text format metrics string."""
    lines = []

    newer_update_count = sum(1 for item in image_data if item["newer_version_available"])

    # Scalar metrics
    lines.append(f"pib_images_needing_update {newer_update_count}")
    lines.append(f"pib_last_check_timestamp {check_ts}")

    for item in image_data:
        image = item["image"]
        # Escape label value (double-quotes and backslashes)
        image_label = image.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

        def metric(name: str, value, extra_labels: str = "") -> str:
            labels = f'image="{image_label}"'
            if extra_labels:
                labels += f",{extra_labels}"
            return f'{name}{{{labels}}} {value}'

        lines.append(metric("pib_priority_score", f'{item["priority_score"]:.4f}'))
        lines.append(metric("pib_image_cve_count", item["cve_count"]))
        lines.append(metric("pib_image_cve_critical", item["cve_critical"]))
        lines.append(metric("pib_image_cve_high", item["cve_high"]))
        lines.append(metric("pib_image_cvss_max", f'{item["cvss_max"]:.4f}'))
        lines.append(metric("pib_image_epss_max", f'{item["epss_max"]:.6f}'))
        lines.append(metric("pib_image_kev_count", item["kev_count"]))
        lines.append(metric("pib_image_age_days", f'{item["age_days"]:.2f}'))

        # newer_version_available with latest_tag label
        newer_val = 1 if item["newer_version_available"] else 0
        latest_tag = item.get("latest_tag") or ""
        latest_tag_label = latest_tag.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        lines.append(metric(
            "pib_newer_version_available",
            newer_val,
            extra_labels=f'latest_tag="{latest_tag_label}"',
        ))

    return "\n".join(lines) + "\n"


def push_metrics(image_data: list[dict], check_ts: float) -> None:
    """Push metrics to PIB's VictoriaMetrics via /api/v1/import/prometheus."""
    payload = _build_prometheus_lines(image_data, check_ts)
    url = f"{VICTORIAMETRICS_URL.rstrip('/')}/api/v1/import/prometheus"
    try:
        resp = requests.post(url, data=payload.encode("utf-8"), timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        log.info(
            "Pushed metrics for %d images to VictoriaMetrics (%d bytes)",
            len(image_data),
            len(payload),
        )
    except requests.exceptions.ConnectionError as exc:
        log.error("Cannot reach VictoriaMetrics at %s: %s", VICTORIAMETRICS_URL, exc)
    except requests.exceptions.HTTPError as exc:
        log.error("VictoriaMetrics rejected metrics push: %s", exc)
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Failed to push metrics: %s", exc)


# ---------------------------------------------------------------------------
# Main check loop
# ---------------------------------------------------------------------------

def run_check() -> None:
    """Run a single check cycle: fetch, compute, push."""
    log.info("=== PIB check cycle starting ===")
    start = time.monotonic()

    cve_info, scan_timestamps = fetch_vib_data()
    epss_scores, kev_matches = fetch_tib_data()

    image_data = compute_scores(cve_info, scan_timestamps, epss_scores, kev_matches)

    if CHECK_DOCKER_HUB:
        image_data = enrich_with_docker_hub(image_data)

    check_ts = datetime.now(timezone.utc).timestamp()
    push_metrics(image_data, check_ts)

    elapsed = time.monotonic() - start
    needing_update = sum(1 for item in image_data if item["newer_version_available"])
    kev_images = sum(1 for item in image_data if item["kev_count"] > 0)

    log.info(
        "=== Check complete in %.1fs | %d images | %d need update | %d have KEV CVEs ===",
        elapsed,
        len(image_data),
        needing_update,
        kev_images,
    )

    if image_data:
        log.info("Top 5 by priority score:")
        for item in image_data[:5]:
            log.info(
                "  %s  score=%.1f  cvss=%.1f  epss=%.4f  kev=%d  age=%.1fd  new=%s",
                item["image"],
                item["priority_score"],
                item["cvss_max"],
                item["epss_max"],
                item["kev_count"],
                item["age_days"],
                item["newer_version_available"],
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="PIB Tracker — Patch in a Box")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one check cycle and exit (useful for `make check-now`)",
    )
    args = parser.parse_args()

    log.info("PIB Tracker starting")
    log.info("  VictoriaMetrics (own): %s", VICTORIAMETRICS_URL)
    log.info("  VIB VM:  %s", VIB_VICTORIAMETRICS_URL or "(not configured)")
    log.info("  TIB VM:  %s", TIB_VICTORIAMETRICS_URL or "(not configured)")
    log.info("  Interval: %dh | on_startup=%s | docker_hub=%s",
             CHECK_INTERVAL_HOURS, CHECK_ON_STARTUP, CHECK_DOCKER_HUB)

    if args.once:
        run_check()
        sys.exit(0)

    if CHECK_ON_STARTUP:
        run_check()

    schedule.every(CHECK_INTERVAL_HOURS).hours.do(run_check)

    log.info("Scheduler running — next check in %dh", CHECK_INTERVAL_HOURS)
    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    main()
