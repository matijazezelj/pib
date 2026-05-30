"""
PIB Monitor — PKI in a Box

Connects to configured TLS endpoints, inspects certificates, and pushes
expiry metrics to VictoriaMetrics.
"""

import logging
import os
import signal
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

import requests
import schedule
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("pib")

_shutdown = False


def _handle_sigterm(signum, frame):
    global _shutdown
    _shutdown = True


signal.signal(signal.SIGTERM, _handle_sigterm)

# ── Config ────────────────────────────────────────────────────────────────────

VICTORIAMETRICS_URL = os.environ.get("VICTORIAMETRICS_URL", "http://pib-victoriametrics:8428")
SCAN_INTERVAL_HOURS = float(os.environ.get("SCAN_INTERVAL_HOURS", "6"))
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
WARN_DAYS = int(os.environ.get("WARN_DAYS", "30"))
CRITICAL_DAYS = int(os.environ.get("CRITICAL_DAYS", "7"))

SESSION = requests.Session()


# ── TLS cert inspection ───────────────────────────────────────────────────────

def _parse_host_port(entry: str) -> tuple[str, int]:
    if ":" in entry:
        host, port = entry.rsplit(":", 1)
        return host, int(port)
    return entry, 443


def check_cert(entry: str) -> dict | None:
    host, port = _parse_host_port(entry)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    # We intentionally accept any cert — we want to inspect even expired/self-signed
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.settimeout(10)
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception as e:
        logger.warning("Could not connect to %s:%d — %s", host, port, e)
        return None

    try:
        cert_obj = x509.load_der_x509_certificate(der, default_backend())
    except Exception as e:
        logger.warning("Could not parse DER cert for %s: %s", entry, e)
        return None

    not_after = cert_obj.not_valid_after_utc
    not_before = cert_obj.not_valid_before_utc
    now = datetime.now(timezone.utc)
    days_remaining = int((not_after - now).total_seconds() / 86400)
    is_expired = days_remaining < 0
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
        "is_warning": is_warning,
        "is_critical": is_critical,
    }


# ── Metrics ───────────────────────────────────────────────────────────────────

def _safe_label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _ts_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def push_metrics(certs: list[dict]) -> None:
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
        f"pib_last_scan_timestamp {ts} {ts}",
    ]

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
        ]

    payload = "\n".join(lines) + "\n"
    try:
        SESSION.post(
            f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
            data=payload,
            headers={"Content-Type": "text/plain"},
            timeout=10,
        ).raise_for_status()
    except Exception as e:
        logger.error("Metric push failed: %s", e)


# ── Scan cycle ────────────────────────────────────────────────────────────────

def run_scan() -> None:
    if not MONITOR_HOSTS:
        logger.warning("No hosts configured. Set MONITOR_HOSTS env var.")
        push_metrics([])
        return

    logger.info("─── PIB scan: %d hosts ───", len(MONITOR_HOSTS))
    certs = []

    for entry in MONITOR_HOSTS:
        cert = check_cert(entry)
        if cert is None:
            continue
        certs.append(cert)
        status = "EXPIRED" if cert["is_expired"] else (
            "CRITICAL" if cert["is_critical"] else (
                "WARNING" if cert["is_warning"] else "OK"
            )
        )
        logger.info("  %s — %s — %d days remaining [%s]",
                    entry, cert["cn"], cert["days_remaining"], status)

    push_metrics(certs)
    logger.info("─── PIB scan complete: %d/%d certs checked ───", len(certs), len(MONITOR_HOSTS))


def main() -> None:
    if "--once" in sys.argv:
        run_scan()
        return

    logger.info("PIB monitor starting (interval=%.1fh, warn=%dd, critical=%dd)",
                SCAN_INTERVAL_HOURS, WARN_DAYS, CRITICAL_DAYS)

    if SCAN_ON_STARTUP:
        run_scan()

    schedule.every(SCAN_INTERVAL_HOURS).hours.do(run_scan)

    while True:
        if _shutdown:
            logger.info("SIGTERM received, exiting.")
            break
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    main()
