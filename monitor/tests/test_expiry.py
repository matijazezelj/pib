import os
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
