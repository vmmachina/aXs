"""Phase 30 asks the bootstrap, not the operator's laptop.

docs/08 B6: split-horizon DNS answers by the CLIENT'S SOURCE IP, not by which
server is asked. A query sent from the operator's machine -- even aimed
explicitly at the cluster's own DNS servers -- can get a different answer than
the cluster itself gets, because the cluster's nodes and the operator's laptop
sit in different networks. The old check asked from the laptop and could
falsely accept a broken cluster or falsely reject a correct one.

Before the bootstrap exists there is nothing to ask, so this falls back to an
ADVISORY check from the laptop -- useful for catching a plain typo early, but
it can never mark the phase done. Only the bootstrap's own answer can.

Fable's review of the first version found two things worth pinning explicitly,
both fixed here:

  * an SSH auth failure (port 22 open, login refused) was reported the same
    as "bootstrap not up yet", which blames DNS/the LB for 20 minutes over
    what is actually an expired configuser password;
  * `getent hosts` prefers AAAA over A, so a dual-stack DNS record would
    report only an IPv6 address and reject a perfectly correct IPv4 LB.
"""

from __future__ import annotations

import subprocess
import sys
import unittest

from ws1access import netcheck
from ws1access.phases import p30_lb
from ws1access.ssh import SshResult

LB_IP = "10.10.50.133"
FQDN = "access.lab.example.com"


class _Ctx:
    """A Context stand-in: node_run to the bootstrap, report, and the two
    config blocks phase 30 reads."""

    bootstrap_ip = "10.10.50.30"
    access = {"domain": "lab.example.com",
              "first_tenant": {"tenant_name": "access"},
              "lb_ip": LB_IP}
    network = {"dns": ["10.10.80.1"]}

    def __init__(self, *, port_open: bool = True, ssh_ok: bool = True,
                 getent_addrs: list[str] | None = None) -> None:
        self.port_open = port_open
        self.ssh_ok = ssh_ok
        # None means "not found"; a list means those addresses come back.
        self.getent_addrs = getent_addrs
        self.calls: list[tuple[str, str]] = []      # (ip, command)
        self.reports: list[str] = []

    def node_run(self, ip: str, command: str) -> SshResult:
        self.calls.append((ip, command))
        if not self.ssh_ok:
            return SshResult(255, "ssh: connect to host port 22: "
                                  "Operation timed out")
        if self.getent_addrs is None:
            return SshResult(0, f"{p30_lb._NOTFOUND}")
        lines = "\n".join(f"{a}        STREAM {FQDN}" for a in self.getent_addrs)
        return SshResult(0, f"{lines}\n{p30_lb._FOUND}")

    def report(self, message: str) -> None:
        self.reports.append(message)


def patch_transport(ctx: _Ctx, *, advisory_addrs: set[str] | None = None):
    """Swap the two things that would otherwise touch a real network."""
    real_port_open, real_resolve = netcheck.port_open, netcheck.resolve_via
    netcheck.port_open = lambda host, port, timeout=4.0: ctx.port_open
    netcheck.resolve_via = lambda hostname, servers, timeout=5.0: (
        advisory_addrs or set())
    return real_port_open, real_resolve


def restore_transport(real_port_open, real_resolve) -> None:
    netcheck.port_open, netcheck.resolve_via = real_port_open, real_resolve


class TestAuthoritativeAnswerWins(unittest.TestCase):
    def probe(self, ctx: _Ctx, advisory_addrs=None):
        real = patch_transport(ctx, advisory_addrs=advisory_addrs)
        try:
            return p30_lb.is_done(ctx)
        finally:
            restore_transport(*real)

    def test_matching_dns_is_done(self):
        ctx = _Ctx(getent_addrs=[LB_IP])
        probe = self.probe(ctx)
        self.assertTrue(probe.done, probe.detail)
        self.assertIn("asked the bootstrap", probe.detail)

    def test_wrong_dns_is_not_done(self):
        ctx = _Ctx(getent_addrs=["10.10.50.99"])
        probe = self.probe(ctx)
        self.assertFalse(probe.done)

    def test_no_record_at_all_is_not_done(self):
        ctx = _Ctx(getent_addrs=None)
        probe = self.probe(ctx)
        self.assertFalse(probe.done)
        self.assertIn("(no answer)", probe.detail)

    def test_the_authoritative_answer_overrides_a_wrong_advisory_one(self):
        # If the laptop's view disagreed, it must not matter once the
        # bootstrap has spoken -- the whole point of the fix.
        ctx = _Ctx(getent_addrs=[LB_IP])
        probe = self.probe(ctx, advisory_addrs={"10.10.50.99"})
        self.assertTrue(probe.done, probe.detail)


class TestItActuallyAsksTheBootstrap(unittest.TestCase):
    """The whole point of B6: WHICH host gets asked. A mutant that queried a
    platform node, or a hardcoded IP, or the wrong fqdn would pass a suite
    that never looks at ctx.calls -- this class is what catches that."""

    def test_the_query_targets_the_bootstrap_ip_specifically(self):
        ctx = _Ctx(getent_addrs=[LB_IP])
        real = patch_transport(ctx)
        try:
            p30_lb.is_done(ctx)
        finally:
            restore_transport(*real)
        self.assertEqual([ip for ip, _cmd in ctx.calls], [ctx.bootstrap_ip])

    def test_the_query_names_the_tenant_fqdn(self):
        ctx = _Ctx(getent_addrs=[LB_IP])
        real = patch_transport(ctx)
        try:
            p30_lb.is_done(ctx)
        finally:
            restore_transport(*real)
        self.assertIn(FQDN, ctx.calls[0][1])

    def test_it_queries_ipv4_specifically_not_plain_hosts(self):
        # `getent hosts` prefers AAAA over A and would report only an IPv6
        # address for a dual-stack record, rejecting a correct IPv4 LB.
        # `ahostsv4` is the fix; pin the command so that regresses loudly.
        ctx = _Ctx(getent_addrs=[LB_IP])
        real = patch_transport(ctx)
        try:
            p30_lb.is_done(ctx)
        finally:
            restore_transport(*real)
        self.assertIn("ahostsv4", ctx.calls[0][1])
        self.assertNotIn("getent hosts ", ctx.calls[0][1])

    def test_the_command_survives_a_real_shell(self):
        # Not shlex-inspected -- run through an actual /bin/sh, the way this
        # repo checks quoting elsewhere (test_write_file, test_p80_tenant):
        # a broken quote can split cleanly under shlex and still fail on a
        # real shell.
        ctx = _Ctx(getent_addrs=[LB_IP])
        real = patch_transport(ctx)
        try:
            p30_lb.is_done(ctx)
        finally:
            restore_transport(*real)
        _ip, command = ctx.calls[0]
        replaced = command.replace("getent ahostsv4", "echo GETENT-WOULD-RUN")
        result = subprocess.run(["/bin/sh", "-c", replaced],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GETENT-WOULD-RUN", result.stdout)
        self.assertIn(p30_lb._FOUND, result.stdout)

    def test_an_fqdn_is_quoted_against_shell_interpretation(self):
        # FQDNs cannot really carry shell metacharacters, but the quoting
        # must not assume that -- prove it against a value that would inject
        # a second command if it ever reached a shell unquoted.
        #
        # Goes through the REAL _authoritative(), capturing whatever command
        # it actually builds via a fake node_run, then executes THAT command
        # in a real shell. An earlier version of this test hand-built its own
        # command string using shlex.quote directly, which meant deleting
        # quoting from the production code changed nothing it could detect.
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "should-not-exist")
            hostile = f"access.lab.example.com; touch {marker}"

            captured = {}

            class Capturing(_Ctx):
                def node_run(self, ip, command):
                    captured["command"] = command
                    return SshResult(0, p30_lb._NOTFOUND)

            ctx = Capturing()
            real = patch_transport(ctx)
            try:
                p30_lb._authoritative(ctx, hostile)
            finally:
                restore_transport(*real)

            self.assertIn("command", captured, "node_run was never called")
            result = subprocess.run(["/bin/sh", "-c", captured["command"]],
                                    capture_output=True, text=True)
            # Proper quoting: the semicolon is part of the (bogus) hostname
            # argument, not a command separator, so `touch` never ran and
            # getent -- failing on a bogus host -- reaches the || branch.
            self.assertFalse(os.path.exists(marker),
                             "the injected `touch` command ran")
            self.assertIn(p30_lb._NOTFOUND, result.stdout)


class TestAdvisoryCanNeverMarkItDone(unittest.TestCase):
    """The false accept this phase used to be capable of: a laptop-only
    view saying yes while the cluster's own view would say no."""

    def probe(self, ctx: _Ctx, advisory_addrs):
        real = patch_transport(ctx, advisory_addrs=advisory_addrs)
        try:
            return p30_lb.is_done(ctx)
        finally:
            restore_transport(*real)

    def test_bootstrap_unreachable_is_never_done_even_if_the_laptop_agrees(self):
        ctx = _Ctx(port_open=False)
        probe = self.probe(ctx, advisory_addrs={LB_IP})
        self.assertFalse(probe.done)

    def test_the_advisory_result_is_labelled_as_such(self):
        ctx = _Ctx(port_open=False)
        probe = self.probe(ctx, advisory_addrs={LB_IP})
        self.assertIn("ADVISORY", probe.detail)
        self.assertIn("not authoritative", probe.detail)

    def test_unreachable_bootstrap_does_not_attempt_ssh(self):
        # The whole reason for the cheap TCP probe first: no ~25s SSH
        # connect-timeout stack while the bootstrap does not exist yet.
        ctx = _Ctx(port_open=False)
        self.probe(ctx, advisory_addrs=set())
        self.assertEqual(ctx.calls, [])

    def test_unreachable_says_not_up_yet(self):
        ctx = _Ctx(port_open=False)
        probe = self.probe(ctx, advisory_addrs={LB_IP})
        self.assertIn("not answering on port 22 yet", probe.detail)


class TestAuthFailureIsNotBlamedOnDnsOrTheLb(unittest.TestCase):
    """Fable's finding: port 22 open but login refused used to be reported
    exactly like "bootstrap not up yet" -- 20 minutes of that, then a raise
    blaming DNS/the LB, for what is really an expired configuser password."""

    def probe(self, ctx: _Ctx, advisory_addrs):
        real = patch_transport(ctx, advisory_addrs=advisory_addrs)
        try:
            return p30_lb.is_done(ctx)
        finally:
            restore_transport(*real)

    def test_it_is_still_not_done(self):
        ctx = _Ctx(port_open=True, ssh_ok=False)
        probe = self.probe(ctx, advisory_addrs={LB_IP})
        self.assertFalse(probe.done)

    def test_it_does_not_say_not_reachable(self):
        # It IS reachable -- port 22 answered. Saying otherwise misdirects
        # straight at DNS/the LB instead of at the login.
        ctx = _Ctx(port_open=True, ssh_ok=False)
        probe = self.probe(ctx, advisory_addrs={LB_IP})
        self.assertNotIn("not answering on port 22", probe.detail)

    def test_it_blames_the_login_not_dns_or_the_lb(self):
        ctx = _Ctx(port_open=True, ssh_ok=False)
        probe = self.probe(ctx, advisory_addrs={LB_IP})
        self.assertIn("could not authenticate", probe.detail)
        self.assertIn("NOT a DNS or LB problem", probe.detail)
        self.assertIn("configuser password", probe.detail)

    def test_the_raise_after_the_deadline_also_blames_the_login(self):
        real_sleep = p30_lb.time.sleep
        p30_lb.time.sleep = lambda _s: None
        ctx = _Ctx(port_open=True, ssh_ok=False)
        real = patch_transport(ctx, advisory_addrs={LB_IP})
        try:
            with self.assertRaises(RuntimeError) as caught:
                p30_lb.run(ctx)
        finally:
            restore_transport(*real)
            p30_lb.time.sleep = real_sleep
        # Must not claim to have consulted "the bootstrap's own view" when it
        # never authenticated to it at all.
        self.assertNotIn("bootstrap's own view", str(caught.exception))
        self.assertIn("could not authenticate", str(caught.exception))


class TestNotFoundIsAnAnswerNotAFailureToAsk(unittest.TestCase):
    """getent exiting non-zero on a real "no record" must not be confused
    with the transport itself failing -- that is the whole reason for the
    marker-based command instead of trusting the raw exit code."""

    def test_a_genuine_not_found_is_authoritative(self):
        ctx = _Ctx(getent_addrs=None)
        real = patch_transport(ctx, advisory_addrs={LB_IP})
        try:
            addrs, why_not = p30_lb._authoritative(ctx, FQDN)
        finally:
            restore_transport(*real)
        self.assertEqual(addrs, set())            # asked, empty answer
        self.assertIsNotNone(addrs)                # NOT "could not ask"
        self.assertEqual(why_not, "")

    def test_ssh_failure_is_not_authoritative(self):
        ctx = _Ctx(ssh_ok=False)
        real = patch_transport(ctx)
        try:
            addrs, why_not = p30_lb._authoritative(ctx, FQDN)
        finally:
            restore_transport(*real)
        self.assertIsNone(addrs)
        self.assertTrue(why_not)

    def test_output_with_neither_marker_is_not_read_as_an_answer(self):
        # Some noise ate the marker (a banner, a chatty profile script). Not
        # a real answer either way -- must not be guessed at from whatever
        # text came back.
        class Garbled(_Ctx):
            def node_run(self, ip, command):
                self.calls.append((ip, command))
                return SshResult(0, "Last login: Tue Jul 28 ...\n")

        ctx = Garbled()
        real = patch_transport(ctx)
        try:
            addrs, why_not = p30_lb._authoritative(ctx, FQDN)
        finally:
            restore_transport(*real)
        self.assertIsNone(addrs)
        self.assertIn("could not be read", why_not)


class TestRunWaitsThenGivesUp(unittest.TestCase):
    def setUp(self):
        self.real_sleep = p30_lb.time.sleep
        p30_lb.time.sleep = lambda _s: None    # do not actually wait in tests

    def tearDown(self):
        p30_lb.time.sleep = self.real_sleep

    def test_it_returns_once_the_bootstrap_confirms(self):
        ctx = _Ctx(getent_addrs=[LB_IP])
        real = patch_transport(ctx)
        try:
            p30_lb.run(ctx)                    # must not raise
        finally:
            restore_transport(*real)

    def test_it_raises_after_the_deadline_with_the_last_detail(self):
        ctx = _Ctx(getent_addrs=["10.10.50.99"])
        real = patch_transport(ctx)
        try:
            with self.assertRaises(RuntimeError) as caught:
                p30_lb.run(ctx)
        finally:
            restore_transport(*real)
        self.assertIn("10.10.50.99", str(caught.exception))

    def test_it_reports_progress_while_waiting(self):
        ctx = _Ctx(getent_addrs=["10.10.50.99"])
        real = patch_transport(ctx)
        try:
            with self.assertRaises(RuntimeError):
                p30_lb.run(ctx)
        finally:
            restore_transport(*real)
        self.assertTrue(ctx.reports)
        self.assertIn("FAIL", ctx.reports[0])

    def test_it_stops_polling_the_instant_it_succeeds(self):
        # A ctx whose second call succeeds -- confirms run() does not sleep
        # through a deadline it already met.
        class ThenFound(_Ctx):
            def node_run(self, ip, command):
                self.calls.append((ip, command))
                if len(self.calls) < 2:
                    return SshResult(0, p30_lb._NOTFOUND)
                return SshResult(0, f"{LB_IP}    STREAM {FQDN}\n{p30_lb._FOUND}")

        ctx = ThenFound()
        real = patch_transport(ctx)
        try:
            p30_lb.run(ctx)
        finally:
            restore_transport(*real)
        self.assertEqual(len(ctx.calls), 2)

    def test_advisory_transitions_to_authoritative_mid_poll(self):
        # The exact scenario the advisory fallback exists for: the bootstrap
        # is not up on the first attempt (port closed) and comes up by the
        # third. Nothing must be cached from the earlier "not reachable"
        # answers -- confirms the transition, not just the two endpoints.
        ctx = _Ctx(getent_addrs=[LB_IP])
        attempts = {"n": 0}
        real_port_open, real_resolve = netcheck.port_open, netcheck.resolve_via

        def fake_port_open(host, port, timeout=4.0):
            attempts["n"] += 1
            return attempts["n"] >= 3

        netcheck.port_open = fake_port_open
        netcheck.resolve_via = lambda *a, **kw: set()
        try:
            p30_lb.run(ctx)
        finally:
            netcheck.port_open, netcheck.resolve_via = real_port_open, real_resolve
        self.assertGreaterEqual(attempts["n"], 3)
        # Two advisory ("pending") reports, then success -- and success came
        # from the bootstrap, not from a cached advisory result.
        self.assertEqual(len(ctx.reports), 2)
        self.assertTrue(all("pending" in r for r in ctx.reports))
        self.assertEqual(len(ctx.calls), 1)        # only the successful attempt asked


class TestAgreesWithIsDone(unittest.TestCase):
    """run() and is_done() must be judging the same fact -- the shared
    _probe() is the point, rather than two copies that could drift apart."""

    def test_run_succeeding_leaves_is_done_true(self):
        ctx = _Ctx(getent_addrs=[LB_IP])
        real = patch_transport(ctx)
        try:
            p30_lb.run(ctx)
            probe = p30_lb.is_done(ctx)
        finally:
            restore_transport(*real)
        self.assertTrue(probe.done, probe.detail)


if __name__ == "__main__":
    unittest.main()
