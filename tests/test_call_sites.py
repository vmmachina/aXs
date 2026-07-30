"""The call sites, not just the helpers.

Testing a shared helper proves the helper. It does not prove that the code
which broke actually uses it -- and "repaired in one place, not in the others"
is the exact shape two review rounds found twice on 2026-07-28.

Both regressions below survive a suite that only tests health.py and
context.redact: reverting `include_services=False` in phase 60, or dropping
`redact()` from `report_log`, restores the original defect verbatim while every
helper test stays green. So they are pinned here, at the caller.
"""

from __future__ import annotations

import unittest

from ws1access import profile_yml
from ws1access.context import Context
from ws1access.phases import p50_cluster_init, p60_platform
from ws1access.profile_yml import patch

from ._fakes import FakeCtx, healthcheck_json

HASH_LINE = "Folder Hash: 9f2c1ab4"


class TestPhase60IgnoresForeignServices(unittest.TestCase):
    """A2. Phase 60 owns Vault/Consul/Nomad; the services belong to phase 70.

    Folding both into one verdict made phase 60's done-probe flip back to "todo"
    whenever a phase-70 service was mid-deploy -- and a restart then launched
    `wso cp deploy` alongside the running `wso services deploy`. Observed live
    2026-07-28 13:18.
    """

    def _probe(self, **hc):
        ctx = FakeCtx({
            "healthcheck": (0, healthcheck_json(**hc)),
            "grep": (0, HASH_LINE),
        })
        return p60_platform.is_done(ctx)

    def test_done_while_a_phase_70_service_is_still_coming_up(self):
        probe = self._probe(service_issues=["opensearch: 0/3 allocations"])
        self.assertTrue(probe.done, probe.detail)

    def test_healthy_platform_with_no_service_issues_is_done(self):
        self.assertTrue(self._probe().done)

    def test_a_real_platform_problem_still_blocks(self):
        # Narrowing the question must not weaken it.
        probe = self._probe(vault_sealed=True,
                            service_issues=["opensearch: 0/3 allocations"])
        self.assertFalse(probe.done)
        self.assertIn("SEALED", probe.detail)
        self.assertNotIn("opensearch", probe.detail)

    def test_no_folder_hash_is_not_done(self):
        ctx = FakeCtx({"healthcheck": (0, healthcheck_json()), "grep": (0, "")})
        probe = p60_platform.is_done(ctx)
        self.assertFalse(probe.done)
        self.assertIn("no Folder Hash", probe.detail)


TEMPLATE = ("cluster_name: lab\ndeployment_size: small\n"
            "#ntp_server: us.pool.ntp.org\n#nfs_host: 10.0.0.9\n"
            "#nfs_path: /controlplanenfs/us04pA\n")
NFS = {"nfs_host": "10.0.0.9", "nfs_path": "/exports/cp"}


class _DriftCtx(FakeCtx):
    """FakeCtx plus the two attributes phase 50's probe reads."""

    def __init__(self, answers, settings):
        super().__init__(answers)
        self.deployment_settings = settings


class TestPhase50ComparesConfigWithTheCluster(unittest.TestCase):
    """B1. `wso access validate` answers about the LAST run's files.

    A setting added after a successful deploy -- an NFS backup target, which
    wso's own warning asks for -- gave `already done`, then a green phase 60
    off the historical folder hash, and a complete run with no backup in it.
    profile_yml.drift() can see that; this pins that the probe ASKS it.
    """

    def probe(self, remote: str, settings=NFS, cat_ok=True):
        ctx = _DriftCtx({
            "wso access validate": (0, "inventory ok"),
            "cat ": (0 if cat_ok else 1, remote),
        }, settings)
        return p50_cluster_init.is_done(ctx), ctx

    def test_retrofittable_drift_makes_the_phase_red(self):
        # It used to stay done and only warn, because a red phase 50 would
        # rewrite profile.yml and 60/70/80 would still skip themselves on their
        # own green probes -- DEPS orders the phases, it does not cascade. The
        # pending marker plus the engines' re-probe closed that, so red is now
        # the correct answer: red is what makes this phase RUN and apply the
        # change. Going back to a warning would restore the silent green.
        result, _ = self.probe(TEMPLATE)
        self.assertFalse(result.done)
        self.assertIn("nfs_host", result.detail)
        self.assertIn("/exports/cp", result.detail)

    def test_being_red_says_the_rollout_follows(self):
        # `detail` is the only field an operator sees for a NOT-done phase, so
        # the reason has to be in there. And it must say that phase 60 rolls it
        # out: a red phase whose remedy is unstated reads as a broken cluster.
        result, _ = self.probe(TEMPLATE)
        self.assertFalse(result.done)
        self.assertIn("60", result.detail)

    def test_a_logging_change_only_warns_and_stays_done(self):
        # docs/09 §4: Omnissa's own note says logging needs a full
        # redeployment, so `wso cp deploy` cannot apply it. A red phase here
        # could never go green again -- worse than the drift it reports.
        settings = {"logging": {"loki_server": {"url": "http://loki:3100"}}}
        remote = "logging:\n  loki_server:\n    url: http://old:3100\n"
        ctx = _DriftCtx({"wso access validate": (0, "inventory ok"),
                         "cat ": (0, remote)}, settings)
        result = p50_cluster_init.is_done(ctx)
        self.assertTrue(result.done, result.detail)
        self.assertIn("CANNOT apply", result.warning)
        self.assertIn("loki", result.warning)

    def test_a_logging_change_never_sets_the_marker(self):
        # The marker makes phase 60 red. Setting it for a key `wso cp deploy`
        # cannot apply would produce exactly the phase that never goes green.
        keys = ["logging.loki_server.url", "ntp_server"]
        apply_now, needs_rebuild = profile_yml.classify(keys)
        self.assertEqual(apply_now, ["ntp_server"])
        self.assertEqual(needs_rebuild, ["logging.loki_server.url"])

    def test_no_warning_when_they_agree(self):
        result, _ = self.probe(patch(TEMPLATE, NFS))
        self.assertTrue(result.done)
        self.assertEqual(result.warning, "")

    def test_nothing_configured_costs_no_round_trip(self):
        # The probe runs on every phase; reading profile.yml when aXs owns no
        # key in it would be an SSH call for a question with no answer.
        result, ctx = self.probe(TEMPLATE, settings={})
        self.assertTrue(result.done)
        self.assertFalse(any(c.startswith("cat ") for c in ctx.calls), ctx.calls)

    def test_an_unreadable_profile_is_reported_not_swallowed(self):
        result, _ = self.probe("", cat_ok=False)
        self.assertTrue(result.done)
        self.assertIn("NOT compared", result.warning)

    def test_an_unparseable_profile_is_not_reported_as_drift(self):
        # docs/08 A9 in this phase: "I could not read it" told as "these keys
        # disagree" would name a parse failure as a drifted key. And it must not
        # make the phase red either -- that would re-init a healthy cluster over
        # a parse failure.
        result, _ = self.probe("nfs_host: [unclosed\n")
        self.assertTrue(result.done)
        self.assertIn("NOT compared", result.warning)
        self.assertNotIn("disagree", result.warning)

    def test_a_hand_edited_profile_cannot_crash_the_probe(self):
        # An exception here is not a warning: the TUI reads it as "not done"
        # and RUNS phase 50 against a healthy cluster, and the plain path dies
        # on a traceback. Both are worse than the drift being missed.
        #
        # Asserts no exception, NOT that the phase is done: with settings=NFS
        # these files genuinely do drift on the nfs keys, so red is correct.
        # The earlier version of this test asserted `done` and would have
        # passed for the wrong reason once the verdict changed.
        for broken in ("logging: enabled\n",
                       "logging:\n  syslog_servers:\n    - host: h\n"
                       "      port: default\n",
                       "logging:\n  loki_server: yes\n",
                       "logging:\n  syslog_servers: notalist\n"):
            with self.subTest(broken=broken):
                result, _ = self.probe(broken)
                self.assertIsInstance(result.done, bool)

    def test_a_failed_validate_is_still_not_done(self):
        # The drift check must not turn a red probe green.
        ctx = _DriftCtx({"wso access validate": (1, "inventory rejected")}, NFS)
        result = p50_cluster_init.is_done(ctx)
        self.assertFalse(result.done)
        self.assertIn("rejected", result.detail)


class _Sink:
    """A Context stand-in for report_log: it only needs a log_sink."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.log_sink = self.lines.append


class TestReportLogRedacts(unittest.TestCase):
    """A14. `report()` masked; `report_log` passed raw remote tails straight
    through -- and phase 80 tails exactly the file that holds the single-use
    admin reset link. On a phase-80 failure the live box stays on screen until
    the operator quits."""

    def emit(self, text: str) -> str:
        sink = _Sink()
        Context.report_log(sink, text)
        return "\n".join(sink.lines)

    def test_reset_link_is_masked(self):
        out = self.emit("Reset password link: https://acc.example.com/r?c=DEADBEEF")
        self.assertNotIn("DEADBEEF", out)

    def test_credential_in_a_tail_is_masked(self):
        self.assertNotIn("s.7Xy9Qq", self.emit("vault_token: s.7Xy9Qq"))

    def test_ordinary_output_still_arrives(self):
        # A sink that masks everything is no better than one that masks nothing.
        out = self.emit("TASK [install nomad]")
        self.assertIn("TASK [install nomad]", out)

    def test_readiness_output_survives(self):
        self.assertIn('"token": "READY"', self.emit('  "token": "READY"'))


if __name__ == "__main__":
    unittest.main()
