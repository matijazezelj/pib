"""
PIB Monitor — PKI in a Box

Connects to configured TLS endpoints, inspects certificates, and pushes
expiry metrics to VictoriaMetrics.
"""

import ipaddress
import logging
import math
import os
import signal
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone

import requests
import schedule
from cryptography import x509
from cryptography.x509.oid import NameOID

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("pib")

_shutdown = threading.Event()


def _handle_sigterm(signum, frame):
    _shutdown.set()


signal.signal(signal.SIGTERM, _handle_sigterm)
signal.signal(signal.SIGINT, _handle_sigterm)

# ── Config ────────────────────────────────────────────────────────────────────

VICTORIAMETRICS_URL = os.environ.get("VICTORIAMETRICS_URL", "http://pib-victoriametrics:8428")


def _int_env(name: str, default: str) -> int:
    raw = os.environ.get(name, default)
    try:
        return int(raw)
    except (TypeError, ValueError) as e:
        logger.error("Invalid value for env var %s=%r: %s", name, raw, e)
        sys.exit(1)


def _float_env(name: str, default: str) -> float:
    raw = os.environ.get(name, default)
    try:
        return float(raw)
    except (TypeError, ValueError) as e:
        logger.error("Invalid value for env var %s=%r: %s", name, raw, e)
        sys.exit(1)


SCAN_INTERVAL_HOURS = _float_env("SCAN_INTERVAL_HOURS", "6")
SCAN_ON_STARTUP = os.environ.get("SCAN_ON_STARTUP", "true").lower() == "true"

# Comma-separated list of host or host:port to monitor (default port 443)
MONITOR_HOSTS = [
    h.strip() for h in os.environ.get("MONITOR_HOSTS", "").split(",") if h.strip()
]

# Always monitor the local CA if configured
CA_HOST = os.environ.get("CA_HOST", "")
if CA_HOST and CA_HOST not in MONITOR_HOSTS:
    MONITOR_HOSTS.insert(0, CA_HOST)

# Thresholds for warning/critical stats
WARN_DAYS = _int_env("WARN_DAYS", "30")
CRITICAL_DAYS = _int_env("CRITICAL_DAYS", "7")

SESSION = requests.Session()


# ── TLS cert inspection ───────────────────────────────────────────────────────

def _parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError:
        raise ValueError(f"invalid port {raw!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return port


def _parse_host_port(entry: str) -> tuple[str, int]:
    # Handle [::1]:443 style bracketed IPv6
    if entry.startswith("["):
        end = entry.find("]")
        if end != -1:
            host = entry[1:end]
            rest = entry[end + 1:]
            if rest.startswith(":"):
                return host, _parse_port(rest[1:])
            return host, 443
    if ":" in entry and entry.count(":") == 1:
        host, port = entry.rsplit(":", 1)
        return host, _parse_port(port)
    return entry, 443


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_cert(entry: str) -> dict | None:
    try:
        host, port = _parse_host_port(entry)
    except ValueError as e:
        logger.warning("Skipping malformed MONITOR_HOSTS entry %r: %s", entry, e)
        return None

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    # We intentionally accept any cert — we want to inspect even expired/self-signed
    ctx.verify_mode = ssl.CERT_NONE

    # SNI doesn't accept IP literals — pass None for IPs
    server_hostname = None if _is_ip_address(host) else host

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.settimeout(10)
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception as e:
        logger.warning("Could not connect to %s:%d — %s", host, port, e)
        return None

    if der is None:
        logger.warning("TLS handshake completed but no cert returned for %s", entry)
        return None

    try:
        cert_obj = x509.load_der_x509_certificate(der)
    except Exception as e:
        logger.warning("Could not parse DER cert for %s: %s", entry, e)
        return None

    try:
        not_after = cert_obj.not_valid_after_utc
        not_before = cert_obj.not_valid_before_utc
        now = datetime.now(timezone.utc)
        # math.floor handles negative deltas correctly: -0.5 → -1
        days_remaining = math.floor((not_after - now).total_seconds() / 86400)
        is_expired = days_remaining < 0
        is_not_yet_valid = now < not_before
        is_critical = not is_expired and days_remaining < CRITICAL_DAYS
        is_warning = not is_expired and not is_critical and days_remaining < WARN_DAYS

        try:
            cn = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            cn = host
        try:
            issuer_cn = cert_obj.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            issuer_cn = "unknown"

        try:
            san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        serial = str(cert_obj.serial_number)

        return {
            "host": entry,
            "cn": cn,
            "sans": ",".join(sans) if sans else cn,
            "issuer": issuer_cn,
            "serial": serial,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "valid_days": int((not_after - not_before).total_seconds() / 86400),
            "is_expired": is_expired,
            "is_not_yet_valid": is_not_yet_valid,
            "is_warning": is_warning,
            "is_critical": is_critical,
        }
    except Exception as e:
        logger.warning("Error processing cert for %s: %s", entry, e)
        return None


# ── Metrics ───────────────────────────────────────────────────────────────────

def _safe_label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _ts_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def push_metrics(certs: list[dict], failed: list[str]) -> None:
    ts = _ts_ms()
    lines = []

    expired = sum(1 for c in certs if c["is_expired"])
    expiring_warn = sum(1 for c in certs if c["is_warning"])
    expiring_crit = sum(1 for c in certs if c["is_critical"])

    lines += [
        f"pib_certs_total {len(certs)} {ts}",
        f"pib_certs_expired {expired} {ts}",
        f"pib_certs_expiring_warning {expiring_warn} {ts}",
        f"pib_certs_expiring_critical {expiring_crit} {ts}",
        f"pib_certs_unreachable {len(failed)} {ts}",
        f"pib_last_scan_timestamp {ts} {ts}",
    ]

    # Emitted for every configured host, including ones we could not reach —
    # without this a host that stops responding just keeps serving its last
    # known days_remaining and the expiry countdown silently freezes.
    for entry in [c["host"] for c in certs] + failed:
        lines.append(
            f'pib_cert_check_success{{host="{_safe_label(entry)}"}} '
            f'{0 if entry in failed else 1} {ts}'
        )

    for c in certs:
        labels = (
            f'host="{_safe_label(c["host"])}",'
            f'cn="{_safe_label(c["cn"])}",'
            f'issuer="{_safe_label(c["issuer"])}",'
            f'sans="{_safe_label(c["sans"])}"'
        )
        lines += [
            f"pib_cert_days_remaining{{{labels}}} {c['days_remaining']} {ts}",
            f"pib_cert_expiry_timestamp{{{labels}}} {int(datetime.fromisoformat(c['not_after']).timestamp() * 1000)} {ts}",
            f"pib_cert_valid_days{{{labels}}} {c['valid_days']} {ts}",
            f"pib_cert_not_yet_valid{{{labels}}} {1 if c['is_not_yet_valid'] else 0} {ts}",
        ]

    payload = "\n".join(lines) + "\n"
    url = f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus"
    headers = {"Content-Type": "text/plain"}

    for attempt in (1, 2):
        try:
            resp = SESSION.post(url, data=payload, headers=headers, timeout=10)
            if 500 <= resp.status_code < 600 and attempt == 1:
                logger.warning("Metric push got HTTP %d, retrying in 2s", resp.status_code)
                time.sleep(2)
                continue
            resp.raise_for_status()
            return
        except (requests.ConnectionError, requests.Timeout) as e:
            if attempt == 1:
                logger.warning("Metric push connection error: %s — retrying in 2s", e)
                time.sleep(2)
                continue
            logger.error("Metric push failed after retry: %s", e)
            return
        except Exception as e:
            logger.error("Metric push failed: %s", e)
            return


# ── Scan cycle ────────────────────────────────────────────────────────────────

def run_scan() -> None:
    if not MONITOR_HOSTS:
        logger.warning("No hosts configured. Set MONITOR_HOSTS env var.")
        push_metrics([], [])
        return

    logger.info("─── PIB scan: %d hosts ───", len(MONITOR_HOSTS))
    certs = []
    failed = []

    for entry in MONITOR_HOSTS:
        cert = check_cert(entry)
        if cert is None:
            failed.append(entry)
            continue
        certs.append(cert)
        status = "EXPIRED" if cert["is_expired"] else (
            "CRITICAL" if cert["is_critical"] else (
                "WARNING" if cert["is_warning"] else "OK"
            )
        )
        logger.info("  %s — %s — %d days remaining [%s]",
                    entry, cert["cn"], cert["days_remaining"], status)

    push_metrics(certs, failed)
    logger.info("─── PIB scan complete: %d/%d certs checked, %d unreachable ───",
                len(certs), len(MONITOR_HOSTS), len(failed))


def main() -> None:
    if "--once" in sys.argv:
        run_scan()
        return

    logger.info("PIB monitor starting (interval=%.1fh, warn=%dd, critical=%dd)",
                SCAN_INTERVAL_HOURS, WARN_DAYS, CRITICAL_DAYS)

    if SCAN_ON_STARTUP:
        run_scan()

    schedule.every(SCAN_INTERVAL_HOURS).hours.do(run_scan)

    while not _shutdown.is_set():
        schedule.run_pending()
        _shutdown.wait(60)
    logger.info("Shutdown signal received, exiting.")


if __name__ == "__main__":
    main()
