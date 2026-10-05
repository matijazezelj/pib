import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("MONITOR_HOSTS", "example.invalid:443")
import monitor  # noqa: E402

DAY = 86400
H = 3600


class TestClassifyExpiry(unittest.TestCase):
    def test_long_lived_cert_keeps_configured_days(self):
        # 90-day cert: 30 days warn, 7 days critical, exactly as before
        self.assertEqual(monitor.classify_expiry(40 * DAY, 90 * DAY), (False, False, False))
        self.assertEqual(monitor.classify_expiry(20 * DAY, 90 * DAY), (False, False, True))
        self.assertEqual(monitor.classify_expiry(5 * DAY, 90 * DAY), (False, True, False))

    def test_one_year_cert_unchanged(self):
        self.assertEqual(monitor.classify_expiry(100 * DAY, 365 * DAY), (False, False, False))
        self.assertEqual(monitor.classify_expiry(6 * DAY, 365 * DAY), (False, True, False))

    def test_fresh_24h_cert_is_not_critical(self):
        """The bug: step-ca's own 24h cert was 'critical, 0 days' from the minute it was issued."""
        self.assertEqual(monitor.classify_expiry(21 * H, 24 * H), (False, False, False))
        self.assertEqual(monitor.classify_expiry(23.9 * H, 24 * H), (False, False, False))

    def test_24h_cert_still_alerts_when_renewal_has_failed(self):
        self.assertEqual(monitor.classify_expiry(6 * H, 24 * H), (False, False, True))
        self.assertEqual(monitor.classify_expiry(2 * H, 24 * H), (False, True, False))

    def test_expired_is_expired_not_critical(self):
        self.assertEqual(monitor.classify_expiry(-1, 24 * H), (True, False, False))
        self.assertEqual(monitor.classify_expiry(-5 * DAY, 90 * DAY), (True, False, False))

    def test_never_both_critical_and_warning(self):
        for life in (1 * H, 24 * H, 7 * DAY, 90 * DAY, 825 * DAY):
            for frac in (0.01, 0.05, 0.1, 0.2, 0.3, 0.5, 0.9):
                _, c, w = monitor.classify_expiry(life * frac, life)
                self.assertFalse(c and w, (life, frac))


class TestCertStatus(unittest.TestCase):
    def _cert(self, remaining_s, lifetime_s):
        expired, critical, warning = monitor.classify_expiry(remaining_s, lifetime_s)
        return {"is_expired": expired, "is_critical": critical, "is_warning": warning}

    def test_status_follows_lifetime_capped_thresholds(self):
        self.assertEqual(monitor.cert_status(self._cert(16 * H, 24 * H)), 0)
        self.assertEqual(monitor.cert_status(self._cert(6 * H, 24 * H)), 1)
        self.assertEqual(monitor.cert_status(self._cert(2 * H, 24 * H)), 2)
        self.assertEqual(monitor.cert_status(self._cert(-1, 24 * H)), 3)
        self.assertEqual(monitor.cert_status(self._cert(20 * DAY, 90 * DAY)), 1)

    def test_status_is_pushed_per_cert(self):
        cert = {
            "host": "pib-ca:9000", "cn": "Step Online CA", "issuer": "Intermediate", "sans": "pib-ca",
            "not_after": "2026-10-06T12:00:00+00:00", "days_remaining": 0, "hours_remaining": 16.0,
            "valid_days": 1, "is_not_yet_valid": False, **self._cert(16 * H, 24 * H),
        }
        with mock.patch.object(monitor.SESSION, "post", return_value=mock.Mock(status_code=204)) as post:
            monitor.push_metrics([cert], [])
        payload = post.call_args.kwargs["data"]
        self.assertRegex(payload, r'pib_cert_status\{host="pib-ca:9000",cn="Step Online CA",[^}]*\} 0 ')


if __name__ == "__main__":
    unittest.main()
