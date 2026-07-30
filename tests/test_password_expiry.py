"""The configuser password's expiry is evaluated, not just displayed.

docs/08 B10: it expires 60 days after the OVA deploy -- docs/06 even names the
lab's date, 2026-09-20 -- and when it does, EVERY ssh path breaks at once: this
tool's and wso's ansible alike. The date was already collected by the node
probe and printed as a detail line. Nothing ever compared it to today.

So a deploy could start with two days left, run for an hour, and die somewhere
in phase 60/70 on an auth error that looks like a completely different problem.
That is the same confusion that cost hours on 2026-07-29 from the other end: a
refused password that presented as a hang.

Three states, deliberately: expiring, never, and COULD NOT TELL. The third is
not "fine" -- an unparsed date or a locale that slipped past LC_ALL=C must not
be reported as either healthy or expired (docs/08 A9).
"""

from __future__ import annotations

import unittest
from datetime import date

from ws1access import collect
from ws1access.phases import p20_nodes_ready

TODAY = date(2026, 7, 30)


class TestInterpretingChageOutput(unittest.TestCase):
    def test_a_date_far_out(self):
        # The lab's real value, from docs/06.
        self.assertEqual(collect.password_expiry("Sep 20, 2026", TODAY),
                         ("days", 52))

    def test_a_date_close_by(self):
        self.assertEqual(collect.password_expiry("Aug 05, 2026", TODAY),
                         ("days", 6))

    def test_a_date_already_past_is_negative(self):
        kind, days = collect.password_expiry("Jul 01, 2026", TODAY)
        self.assertEqual(kind, "days")
        self.assertLess(days, 0)

    def test_never_is_its_own_state(self):
        self.assertEqual(collect.password_expiry("never", TODAY),
                         ("never", None))
        self.assertEqual(collect.password_expiry("Never", TODAY),
                         ("never", None))

    def test_nothing_at_all_is_unknown(self):
        for value in (None, "", "   "):
            self.assertEqual(collect.password_expiry(value, TODAY),
                             ("unknown", None))

    def test_an_unparseable_value_is_unknown_not_fine(self):
        # A locale that slipped past LC_ALL=C, or a chage that changed format.
        # Must not read as healthy, and must not read as expired either.
        for value in ("20.09.2026", "2026-09-20", "irgendwas"):
            self.assertEqual(collect.password_expiry(value, TODAY),
                             ("unknown", None), value)

    def test_the_probe_forces_a_deterministic_locale(self):
        # chage's date format follows the locale; without LC_ALL=C the parse
        # above would work on one appliance and silently fail on another.
        #
        # EVERY chage invocation, not just one: the probe has two (a sudo
        # attempt and a plain fallback), and asserting the string appears
        # somewhere let a mutation strip it from the sudo branch unnoticed --
        # which is the branch that actually runs.
        call = "chage -l configuser"
        segments = collect.NODE_PROBE.split(call)
        self.assertGreater(len(segments), 1, "no chage invocation in NODE_PROBE")
        for preceding in segments[:-1]:          # the text before each call
            # Same shell line only -- a LC_ALL=C three lines up would not apply.
            same_line = preceding.rsplit("\n", 1)[-1]
            self.assertIn("LC_ALL=C", same_line,
                          f"a chage call is not locale-pinned: ...{same_line[-60:]!r}")


def node(*, ip="10.0.0.1", hostname=None, expires=None, reachable=True):
    state = collect.NodeState(ip=ip, expected_hostname=hostname,
                             reachable=reachable)
    state.password_expires = expires
    return state


class TestWhatThePhaseSays(unittest.TestCase):
    def warn(self, *states):
        return p20_nodes_ready._expiry_warning(list(states))

    def test_plenty_of_time_says_nothing(self):
        # 52 days out -- not worth a line.
        self.assertEqual(self.warn(node(expires="Sep 20, 2026")), "")

    def test_never_says_nothing(self):
        self.assertEqual(self.warn(node(expires="never")), "")

    def test_expiring_soon_warns_and_names_the_node(self):
        said = self.warn(node(hostname="wsa-platform-01", expires="Aug 05, 2026"))
        self.assertIn("expires soon", said)
        self.assertIn("wsa-platform-01", said)
        self.assertIn("in 6 days", said)

    def test_already_expired_says_so_distinctly(self):
        said = self.warn(node(hostname="wsa-acc-01", expires="Jul 01, 2026"))
        self.assertIn("ALREADY EXPIRED", said)
        self.assertIn("wsa-acc-01", said)

    def test_it_names_the_remedy_and_that_it_is_every_node(self):
        # Setting it on one node is the trap: the tool and wso's ansible both
        # need the SAME password everywhere.
        said = self.warn(node(expires="Aug 05, 2026"))
        self.assertIn("passwd configuser", said)
        self.assertIn("EVERY node", said)

    def test_an_undeterminable_date_is_reported_as_such(self):
        said = self.warn(node(hostname="wsa-platform-02", expires="20.09.2026"))
        self.assertIn("could not determine", said)
        self.assertIn("wsa-platform-02", said)
        # Must not be dressed up as either verdict.
        self.assertNotIn("expires soon", said)
        self.assertNotIn("ALREADY EXPIRED", said)

    def test_unreachable_nodes_are_skipped_not_guessed_about(self):
        # Phase 20's own reachability check already reports those; claiming
        # anything about their password expiry would be inventing data.
        self.assertEqual(self.warn(node(reachable=False, expires=None)), "")

    def test_several_nodes_are_all_named(self):
        said = self.warn(
            node(hostname="a", expires="Aug 05, 2026"),
            node(hostname="b", expires="Aug 07, 2026"),
            node(hostname="c", expires="Sep 20, 2026"),
        )
        self.assertIn("a", said)
        self.assertIn("b", said)
        # The healthy one must not be dragged into the warning.
        self.assertNotIn("c (", said)

    def test_expired_and_expiring_are_reported_separately(self):
        said = self.warn(
            node(hostname="old", expires="Jul 01, 2026"),
            node(hostname="soon", expires="Aug 05, 2026"),
        )
        self.assertIn("ALREADY EXPIRED", said)
        self.assertIn("expires soon", said)
        # And each in its own group, not merged into one list.
        self.assertLess(said.index("ALREADY EXPIRED"), said.index("expires soon"))


class TestItReachesTheOperator(unittest.TestCase):
    """A warning nobody sees is the silent green in another costume -- the
    lesson Probe.warning was built for yesterday."""

    class _Ctx:
        user = "configuser"
        network = {}
        configuser_password = "pw"
        nodes = [{"ip": "10.0.0.1", "hostname": "wsa-platform-01"}]

        def __init__(self):
            self.reports = []

        def report(self, message):
            self.reports.append(message)

    def patched(self, expires):
        """Run the phase against one node with a given expiry value."""
        ctx = self._Ctx()
        real = collect.collect_node
        collect.collect_node = lambda ip, **kw: node(
            ip=ip, hostname=kw.get("expected_hostname"), expires=expires)
        try:
            return ctx, p20_nodes_ready.is_done(ctx)
        finally:
            collect.collect_node = real

    def test_the_probe_carries_it_as_a_warning(self):
        _ctx, probe = self.patched("Aug 05, 2026")
        self.assertTrue(probe.done, probe.detail)      # the node is fine
        self.assertIn("expires soon", probe.warning)   # but say this anyway

    def test_it_does_not_make_the_phase_fail(self):
        # A password close to expiry does not stop anything working right now;
        # a red phase here would block a deploy that would have completed.
        _ctx, probe = self.patched("Jul 01, 2026")
        self.assertTrue(probe.done)
        self.assertIn("ALREADY EXPIRED", probe.warning)

    def test_a_healthy_password_leaves_the_warning_empty(self):
        _ctx, probe = self.patched("Sep 20, 2026")
        self.assertEqual(probe.warning, "")

    def test_run_reports_it_to_the_progress_sink_too(self):
        # run() is the path about to spend the next hour or two on this
        # cluster, and the sink is where the operator is actually looking.
        import inspect
        source = inspect.getsource(p20_nodes_ready.run)
        self.assertIn("_expiry_warning", source)


if __name__ == "__main__":
    unittest.main()
