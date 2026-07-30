"""Phase 80's done-probe -- ask the cluster, not only the load balancer.

docs/08 B5: HTTP 200 on the tenant login page was the entire probe, and it is
wrong in both directions.

  * A load balancer serving a maintenance page answers 200. The phase skips
    itself: no tenant, no admin, no reset link -- and it surfaces at the first
    login attempt, long after the deploy reported success.
  * If the bootstrap cannot reach the LB VIP (hairpin), a perfectly good tenant
    never answers 200 and the phase stays red forever.

`create-tenant.log` now decides -- the same string `run()` already gated on, so
the two finally agree. HTTP stays, because it is real evidence and because on a
cluster whose log is gone it is the ONLY evidence. What it no longer does is
decide silently.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from ws1access.phases import p80_tenant
from ws1access.ssh import SshResult

CREATED = ("2026-07-28 18:07:11 INFO| Creating tenant access ...\n"
           "2026-07-28 18:07:44 INFO| Tenant access created successfully\n"
           "Reset Password Link: https://access.lab.example.com/r?c=ABC\n")
FAILED = ("2026-07-28 18:07:11 INFO| Creating tenant access ...\n"
          "2026-07-28 18:07:19 ERROR| saas did not come back\n")


class _Ctx:
    """A Context stand-in that RUNS the log query instead of imitating it.

    The query is a shell pipeline with a negation guard in it. Reimplementing
    that in Python here would test the reimplementation -- the same mistake as
    checking a generated command with shlex instead of running it. So the log
    goes into a real file in a temp directory and /bin/sh answers.
    """

    access = {"domain": "lab.example.com",
              "first_tenant": {"tenant_name": "access"}}

    def __init__(self, log: str, http: str) -> None:
        self.log = log
        self.http = http
        self.calls: list[str] = []
        self.reports: list[str] = []

    def bootstrap_run(self, command: str, **_kw):
        self.calls.append(command)
        if "curl" in command:
            return SshResult(0, self.http)
        with tempfile.TemporaryDirectory() as d:
            Path(d, p80_tenant._LOG).write_text(self.log)
            p = subprocess.run(["/bin/sh", "-c", command], cwd=d,
                               capture_output=True, text=True)
        return SshResult(p.returncode, p.stdout + p.stderr)

    def report(self, message: str) -> None:
        self.reports.append(message)


def probe(log: str, http: str):
    """The done-probe against a given log and a given HTTP answer."""
    ctx = _Ctx(log, http)
    return p80_tenant.is_done(ctx), ctx


class TestTheClusterDecides(unittest.TestCase):
    def test_created_and_reachable(self):
        result, _ = probe(CREATED, "200")
        self.assertTrue(result.done)
        self.assertEqual(result.warning, "")

    def test_created_but_unreachable_is_still_done(self):
        # The false RED: a hairpin between bootstrap and LB VIP used to keep a
        # finished tenant permanently open.
        result, _ = probe(CREATED, "000")
        self.assertTrue(result.done)
        self.assertTrue(result.warning)

    def test_created_but_unreachable_offers_both_readings(self):
        # The log proves a tenant was created ONCE. It does not prove this
        # tenant exists NOW -- first_tenant may have been renamed, or the
        # tenant removed by hand. A warning that says "the tenant exists" would
        # be asserting something the evidence does not carry, and would send
        # the operator to the load balancer for a tenant that is not there.
        result, _ = probe(CREATED, "503")
        self.assertTrue(result.done)
        self.assertIn("load balancer", result.warning)          # reading 1
        self.assertIn("renamed", result.warning)                # reading 2
        self.assertIn("--force", result.warning)                # and the way out

    def test_the_warning_does_not_claim_the_tenant_exists(self):
        result, _ = probe(CREATED, "503")
        self.assertNotIn("the tenant exists", result.warning.lower())

    def test_the_string_matches_case_insensitively(self):
        result, _ = probe("Tenant CREATED SUCCESSFULLY\n", "000")
        self.assertTrue(result.done)

    def test_a_tenant_created_in_an_earlier_run_still_counts(self):
        # The log is appended to across runs. Only the reset LINK expires --
        # the tenant does not, so this reads the whole file, not the last
        # segment.
        log = ("===== aXs start 2026-07-28 14:00 =====\n" + CREATED +
               "===== aXs start 2026-07-28 16:22 =====\n"
               "Bootstrap already completed. Skipping bootstrap.\n")
        result, _ = probe(log, "000")
        self.assertTrue(result.done)


class TestHttpAloneIsNoLongerSilent(unittest.TestCase):
    """The false GREEN. Still done -- reporting 'not done' would re-run
    create-tenant against a tenant that may well exist, and what that does is
    unmeasured. But it no longer passes without a word."""

    def test_http_200_without_the_log_is_done_but_warns(self):
        result, _ = probe("", "200")
        self.assertTrue(result.done)
        self.assertTrue(result.warning)

    def test_the_warning_names_the_maintenance_page(self):
        result, _ = probe("", "200")
        self.assertIn("maintenance page", result.warning)
        self.assertIn("ALONE", result.warning)

    def test_a_failed_run_is_not_green_from_http_silently(self):
        result, _ = probe(FAILED, "200")
        self.assertTrue(result.done)
        self.assertIn("created successfully", result.warning)


class TestNotDone(unittest.TestCase):
    def test_no_log_and_no_answer(self):
        result, _ = probe("", "")
        self.assertFalse(result.done)
        self.assertIn("no 'created successfully'", result.detail)

    def test_a_failed_create_is_not_done(self):
        result, _ = probe(FAILED, "503")
        self.assertFalse(result.done)

    def test_the_detail_names_both_signals(self):
        result, _ = probe(FAILED, "503")
        self.assertIn("create-tenant.log", result.detail)
        self.assertIn("503", result.detail)

    def test_no_answer_at_all_is_said_plainly(self):
        result, _ = probe("", "")
        self.assertIn("no answer", result.detail)


class TestBothSignalsAreAsked(unittest.TestCase):
    def test_the_log_is_read_and_the_url_is_probed(self):
        _, ctx = probe(CREATED, "200")
        self.assertTrue(any("create-tenant.log" in c and "grep" in c
                            for c in ctx.calls), ctx.calls)
        self.assertTrue(any("curl" in c for c in ctx.calls), ctx.calls)

    def test_the_probed_url_is_the_tenant_login_page(self):
        _, ctx = probe(CREATED, "200")
        curl = [c for c in ctx.calls if "curl" in c][0]
        self.assertIn("https://access.lab.example.com/auth/login", curl)

    def test_redirects_are_followed(self):
        # The login endpoint 302s to /SAAS/auth/login; without -L a healthy
        # tenant answers 302 and would read as broken.
        _, ctx = probe(CREATED, "200")
        curl = [c for c in ctx.calls if "curl" in c][0]
        self.assertIn("-skL", curl)


class TestTheStringIsNotFooled(unittest.TestCase):
    """A substring match cannot tell a success from a sentence containing one.

    This is wso's wording, not an interface -- as brittle as p60's _NO_CHANGES,
    and B7 is the standing example of a second wording nobody knew about. What
    can be guarded here is guarded; what cannot is said in the comment.
    """

    def test_a_negated_line_does_not_count_as_success(self):
        result, _ = probe("Tenant access was not created successfully\n", "503")
        self.assertFalse(result.done)

    def test_a_negation_does_not_mask_a_real_success(self):
        # Both lines present -- an attempt that failed, then one that worked.
        log = ("Tenant access was not created successfully\n"
               "Tenant access created successfully\n")
        result, _ = probe(log, "503")
        self.assertTrue(result.done)

    def test_an_empty_log_is_not_a_success(self):
        self.assertFalse(probe("", "503")[0].done)

    def test_a_missing_log_is_not_a_success(self):
        # grep on a file that does not exist: rc 2, no marker for success.
        ctx = _Ctx("", "503")
        ctx.log = None                      # signals "do not create the file"
        original = ctx.bootstrap_run

        def without_log(command, **kw):
            if "curl" in command:
                return original(command, **kw)
            ctx.calls.append(command)
            with tempfile.TemporaryDirectory() as d:
                p = subprocess.run(["/bin/sh", "-c", command], cwd=d,
                                   capture_output=True, text=True)
            return SshResult(p.returncode, p.stdout + p.stderr)

        ctx.bootstrap_run = without_log
        self.assertFalse(p80_tenant.is_done(ctx).done)

    def test_an_unreachable_bootstrap_is_not_a_success(self):
        # No marker in the output at all -- neither branch of the shell ran.
        class Dead(_Ctx):
            def bootstrap_run(self, command, **kw):
                self.calls.append(command)
                return SshResult(255, "ssh: connect to host: Operation timed out")

        result = p80_tenant.is_done(Dead("", ""))
        self.assertFalse(result.done)


class TestRunAgreesWithTheProbe(unittest.TestCase):
    """run() and is_done() used to test different things -- run() the log,
    is_done() the HTTP code. Sharing one helper is the point of the change."""

    def test_run_gates_on_the_same_evidence(self):
        import inspect
        source = inspect.getsource(p80_tenant.run)
        self.assertIn("_tenant_created", source)
        self.assertNotIn("created successfully", source,
                         "run() re-implements the check instead of sharing it")


if __name__ == "__main__":
    unittest.main()
