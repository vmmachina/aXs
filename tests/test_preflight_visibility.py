"""A green preflight is a receipt, not a black box.

Preflight quietly verifies four things -- the OVA, the ovftool version, that
vCenter answers a login, and what DNS returns for the tenant -- then collapsed
all of it into "done". The operator asked to SEE it. When done, the findings now
ride in `warning` (the one field a done phase still renders): a compact head line
for the board, and every check with its value for the log and the plain path.
"""

from __future__ import annotations

import unittest

from ws1access.phases import p00_preflight as pf

GREEN = [
    ("OVA present", True, "input/ova/alma-9.6.ova"),
    ("ovftool >= 5.1.0", True, "5.1.0"),
    ("vCenter reachable + login", True, "vc01.lab.vmguru.io"),
    ("DNS access.lab.vmguru.io -> LB", True, "10.10.50.133 (expected 10.10.50.133)"),
]


class TestPreflightVisibility(unittest.TestCase):
    def probe_for(self, checks):
        real = pf._checks
        pf._checks = lambda _ctx: checks
        try:
            return pf.is_done(None)
        finally:
            pf._checks = real

    def test_a_passing_preflight_is_done(self):
        self.assertTrue(self.probe_for(GREEN).done)

    def test_it_shows_the_values_it_verified(self):
        # Not just "done": the ovftool version, the vCenter host and the DNS
        # answer must be visible.
        w = self.probe_for(GREEN).warning
        self.assertIn("5.1.0", w)
        self.assertIn("vc01.lab.vmguru.io", w)
        self.assertIn("10.10.50.133", w)

    def test_the_board_line_is_a_compact_head(self):
        # The first warning line is what the board shows -- one compact "verified"
        # line, not the first of four.
        head = self.probe_for(GREEN).warning.splitlines()[0]
        self.assertTrue(head.startswith("verified:"), head)
        self.assertIn("ovftool=5.1.0", head)

    def test_the_log_gets_every_check_with_its_value(self):
        w = self.probe_for(GREEN).warning
        self.assertIn("[ok] OVA present", w)
        self.assertIn("[ok] vCenter reachable + login", w)

    def test_a_failing_check_makes_it_not_done_and_shows_the_failure(self):
        checks = list(GREEN)
        checks[1] = ("ovftool >= 5.1.0", False, "4.6.3")   # too old
        probe = self.probe_for(checks)
        self.assertFalse(probe.done)
        self.assertIn("FAIL", probe.detail)
        self.assertIn("4.6.3", probe.detail)

    def test_a_failing_preflight_does_not_dress_the_failure_as_verified(self):
        checks = list(GREEN)
        checks[2] = ("vCenter reachable + login", False, "wrong password")
        probe = self.probe_for(checks)
        # The reason belongs in detail (shown for a not-done phase), not in a
        # "verified" warning that reads as success.
        self.assertNotIn("verified:", probe.warning or "")


if __name__ == "__main__":
    unittest.main()
