"""Phase 70 acceptance and its blocker semantics.

The retry loop stops early when an attempt made NO forward progress. What counts
as progress is the whole question, and getting it wrong cost a day on
2026-07-28: the old check compared the last 'Deploying service' line, so a
deploy that walked its list twice ended on the same name both times and was read
as "stuck there". It accused `usergroup` -- which was READY -- while `opensearch`,
an infrastructure service that readiness never even lists, went unnamed; twenty
innocent services each got a remediation command (docs/08, A7).

Blockers therefore carry their KIND. `missing` (never deployed) and `not_ready`
(deployed, still coming up) are different states, and the step from the first to
the second is real progress -- collapsing both to a bare name made a service
that had just started coming up look unchanged, and the retry gave up on it.
"""

from __future__ import annotations

import json
import unittest

from ws1access.health import ACCESS_CORE, UNREADABLE
from ws1access.phases.p70_services import _acceptance

from ._fakes import FakeCtx, healthcheck_json, readiness_json

READINESS = "check-service-readiness"
HEALTHCHECK = "healthcheck"


def accept(readiness: str, healthcheck: str | None = None):
    """Run _acceptance against canned wso output. Returns (ok, detail, blockers)."""
    ctx = FakeCtx({
        READINESS: (0, readiness),
        HEALTHCHECK: (0, healthcheck if healthcheck is not None
                      else healthcheck_json()),
    })
    return _acceptance(ctx)


class TestGreen(unittest.TestCase):
    def test_both_gates_green(self):
        ok, detail, blockers = accept(readiness_json())
        self.assertTrue(ok, detail)
        self.assertEqual(blockers, ())

    def test_readiness_green_but_platform_unhealthy_is_not_accepted(self):
        # Both gates are required: readiness lists only the ~20 Access services.
        ok, detail, _ = accept(readiness_json(),
                               healthcheck_json(vault_sealed=True))
        self.assertFalse(ok)
        self.assertIn("SEALED", detail)


class TestBlockerKind(unittest.TestCase):
    """missing -> not_ready is progress, and the tuple must show it."""

    def test_missing_service_is_kind_missing(self):
        _, _, blockers = accept(readiness_json(launcher=None))
        self.assertEqual(blockers, (("missing", "launcher"),))

    def test_not_ready_service_is_kind_not_ready(self):
        _, _, blockers = accept(readiness_json(launcher="NOT_READY"))
        self.assertEqual(blockers, (("not_ready", "launcher"),))

    def test_missing_to_not_ready_is_visible_as_progress(self):
        # The same service name in both attempts. Without the kind these two
        # tuples compare equal and the retry declares the deploy stuck on a
        # service that had just started coming up.
        _, _, first = accept(readiness_json(launcher=None))
        _, _, second = accept(readiness_json(launcher="NOT_READY"))
        self.assertNotEqual(first, second)

    def test_unchanged_state_compares_equal(self):
        # The other direction: genuinely no progress must still be detectable,
        # or the early stop never triggers.
        _, _, first = accept(readiness_json(launcher="NOT_READY"))
        _, _, second = accept(readiness_json(launcher="NOT_READY"))
        self.assertEqual(first, second)

    def test_key_order_in_wsos_answer_is_not_mistaken_for_change(self):
        # wso gives no ordering guarantee, and json.loads keeps whatever order
        # it sent. If that order reached the blocker tuple, two attempts against
        # an UNCHANGED cluster would compare unequal and the early stop -- the
        # entire point of the comparison -- could never fire.
        names = sorted(ACCESS_CORE)
        stuck = {"cds", "launcher"}

        def answer(order):
            return json.dumps({n: ("NOT_READY" if n in stuck else "READY")
                               for n in order})

        first = accept(answer(names))[2]
        second = accept(answer(reversed(names)))[2]
        self.assertNotEqual(answer(names), answer(reversed(names)))  # inputs differ
        self.assertEqual(first, second)
        self.assertEqual(first, (("not_ready", "cds"), ("not_ready", "launcher")))

    def test_advisory_services_are_not_blockers(self):
        # Tolerated, and named as tolerated -- but they must not stop the retry.
        ok, detail, blockers = accept(
            readiness_json(**{"control-plane-logging": "NOT_READY"}))
        self.assertFalse(ok)
        self.assertEqual(blockers, ())
        self.assertIn("tolerated advisory", detail)


class TestUnreadableOutput(unittest.TestCase):
    """A command that answered nothing usable is not twenty missing services."""

    def test_unreadable_readiness_is_not_reported_as_missing_services(self):
        ok, detail, blockers = accept("wso: error: connection to Nomad refused")
        self.assertFalse(ok)
        self.assertIn("could not read", detail)
        self.assertIn("connection to Nomad refused", detail)
        self.assertNotIn("never deployed", detail)

    def test_unreadable_placeholder_never_becomes_a_blocker(self):
        # UNREADABLE is a marker, not a service. Feeding it to the retry would
        # print a remediation command for a service that does not exist.
        _, _, blockers = accept("wso: error")
        self.assertNotIn(UNREADABLE, [name for _kind, name in blockers])
        self.assertEqual(blockers, ())

    def test_silent_command_says_so(self):
        _, detail, _ = accept("")
        self.assertIn("answered nothing at all", detail)

    def test_detail_is_redacted_when_the_secret_starts_its_line(self):
        # The raw tail goes on screen, so it passes through redact() first.
        _, detail, _ = accept("wso: error\nvault_token: s.leakedValue")
        self.assertNotIn("s.leakedValue", detail)

    def test_detail_is_redacted_when_the_line_carries_a_log_prefix(self):
        # This tail is redacted RAW, without stripping the cp_logger prefix the
        # way clean_tail()/humanize_log() do -- so redact() has to cope with the
        # prefix itself. See tests/test_redact.py for the rule.
        _, detail, _ = accept(
            "2026-07-28 13:18:22,001 p=1 u=root n=cp INFO| "
            "vault_token: s.leakedValue")
        self.assertNotIn("s.leakedValue", detail)


class TestDetail(unittest.TestCase):
    """'reached: usergroup' told the operator nothing about whether one service
    is settling or twenty were never deployed. `detail` already knew."""

    def test_missing_services_are_named(self):
        _, detail, _ = accept(readiness_json(launcher=None))
        self.assertIn("MISSING", detail)
        self.assertIn("launcher", detail)

    def test_not_ready_services_are_named_separately(self):
        _, detail, _ = accept(readiness_json(launcher="NOT_READY"))
        self.assertIn("NOT_READY (critical)", detail)
        self.assertIn("launcher", detail)

    def test_detail_is_bounded(self):
        # The message has to fit a terminal. Every core service missing is NOT
        # enough to reach the limit (that detail is ~300 chars), so the input
        # here also lists unknown services with long names -- otherwise the
        # test would pass with the truncation removed.
        crowded = {f"custom-service-{i:02d}-with-a-long-name": "NOT_READY"
                   for i in range(30)}
        _, detail, _ = accept(json.dumps(crowded),
                              healthcheck_json(vault_sealed=True))
        self.assertLessEqual(len(detail), 400)


if __name__ == "__main__":
    unittest.main()
