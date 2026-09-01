"""Threshold classification tests for the PIB monitor.

Self-contained: `python monitor/test_monitor.py`, or `pytest monitor/` if you
have it. Only needs `cryptography`, which the monitor already depends on.
"""

import datetime as dt
import importlib.util
import os
import pathlib

# Pin the thresholds the cases below assume, before monitor.py reads them.
os.environ.update(
    MONITOR_HOSTS="", CA_HOST="",
    WARN_DAYS="30", CRITICAL_DAYS="7",
    CA_WARN_DAYS="365", CA_CRITICAL_DAYS="90",
)

_spec = importlib.util.spec_from_file_location(
    "pib_monitor", pathlib.Path(__file__).with_name("monitor.py"))
monitor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(monitor)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_KEY = ec.generate_private_key(ec.SECP256R1())
DAY, HOUR = dt.timedelta(days=1), dt.timedelta(hours=1)


def _cert(cn, lifetime, elapsed):
    """A cert with total validity `lifetime`, issued `elapsed` ago."""
    not_before = dt.datetime.now(dt.timezone.utc) - elapsed
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(_KEY.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_before + lifetime)
            .sign(_KEY, hashes.SHA256()))


def _status(lifetime, elapsed, kind):
    described = monitor._describe_cert(
        _cert("test", lifetime, elapsed), "test", kind, fallback_cn="test")
    return monitor.STATUS_NAMES[described["status"]]


# Short-lived certs are renewed automatically, so an absolute day count says
# nothing about them — step-ca's own API leaf lives ~24h and would otherwise
# read CRITICAL forever. These are judged on fraction of lifetime left.
def test_short_lived_cert_is_healthy_when_fresh():
    assert _status(DAY, 1 * HOUR, "endpoint") == "OK"


def test_short_lived_cert_is_ok_at_the_renewal_point():
    # step-ca renews at ~1/3 remaining; that is normal, not a problem.
    assert _status(DAY, 16 * HOUR, "endpoint") == "OK"


def test_short_lived_cert_warns_when_renewal_is_overdue():
    assert _status(DAY, 19 * HOUR, "endpoint") == "WARNING"


def test_short_lived_cert_is_critical_near_the_end_of_its_life():
    assert _status(DAY, 22 * HOUR, "endpoint") == "CRITICAL"


# Ordinary leaf certs use the absolute WARN_DAYS / CRITICAL_DAYS thresholds.
def test_long_lived_cert_healthy_mid_life():
    assert _status(90 * DAY, 45 * DAY, "endpoint") == "OK"


def test_long_lived_cert_warns_inside_warn_days():
    assert _status(90 * DAY, 70 * DAY, "endpoint") == "WARNING"


def test_long_lived_cert_critical_inside_critical_days():
    assert _status(90 * DAY, 85 * DAY, "endpoint") == "CRITICAL"


def test_expired_cert_reports_expired():
    assert _status(90 * DAY, 95 * DAY, "endpoint") == "EXPIRED"


# Root and intermediate use the much longer CA_* thresholds: replacing them
# means re-anchoring trust everywhere, so a month's notice is not enough.
def test_root_healthy_years_out():
    assert _status(3650 * DAY, 365 * DAY, "root") == "OK"


def test_root_warns_a_year_out():
    assert _status(3650 * DAY, 3450 * DAY, "root") == "WARNING"


def test_root_critical_inside_ca_critical_days():
    assert _status(3650 * DAY, 3620 * DAY, "root") == "CRITICAL"


def test_intermediate_expired():
    assert _status(3650 * DAY, 3700 * DAY, "intermediate") == "EXPIRED"


# A 10-year root must not be mistaken for a short-lived auto-renewed cert.
def test_ca_thresholds_are_not_the_leaf_thresholds():
    assert _status(3650 * DAY, 3300 * DAY, "root") == "WARNING"
    assert _status(3650 * DAY, 3300 * DAY, "endpoint") == "OK"


def test_malformed_host_entries_are_rejected():
    for bad in ("host:abc", "host:0", "host:70000", "[::1]:nope"):
        try:
            monitor._parse_host_port(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} should have been rejected")


if __name__ == "__main__":
    tests = sorted((n, f) for n, f in globals().items() if n.startswith("test_"))
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
