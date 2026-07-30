"""wso's answer never arrives alone -- and what surrounds it must not hide it.

Found on the operator's real cluster, 2026-07-29. `axs status` reported
`70_services OPEN  healthcheck: <unparseable healthcheck output>` while
`60_platform`, running the SAME command seconds earlier in the same run, parsed
it fine. Running the command by hand returned perfectly well-formed JSON.

Hunting that turned up a defect, since MEASURED against that cluster:

    stdout:  {"vault":{"reachable":true, ...     the answer
    stderr:  Checking Vault ......done ...       wso's own progress

`run_with_key` returns `stdout + stderr` CONCATENATED, so on the key path the
JSON comes first and the progress lands AFTER it -- and json.loads on
everything-from-the-first-brace fails with "Extra data: line 2 column 1". Not
intermittent there but permanent: phases 60 and 70 could never call the cluster
healthy again. It stayed hidden only because the operator had no key to the
bootstrap; the hour he installed one, it would have started.

(An earlier version of this text blamed the appliance's login banner. The
banner is on stderr too, but it does not even appear on a non-interactive
command -- the story was plausible and wrong, and the tests below still cover
it because noise on either side must be survived either way.)

The pty path escapes it because ssh writes both channels to the one terminal as
they arrive: the progress lines are printed while the work happens, so they
come first and the JSON last. That makes the intermittent failure above
plausible for the first time -- two channels, usually in order, occasionally
not -- but plausible is not proven, and it stays open.

The second half is the message. `<unparseable healthcheck output>` covers a
dropped connection, a wso error, an empty reply and a changed format alike --
one sentence for four causes. docs/08 A9 fixed exactly that for
check-service-readiness and it was never carried here.
"""

from __future__ import annotations

import unittest

from ws1access.health import (
    UNREADABLE,
    UNREADABLE_HEALTHCHECK,
    parse_healthcheck,
    parse_readiness,
    unreadable_message,
)

from ._fakes import healthcheck_json, readiness_json

# The appliance's real banner, verbatim.
BANNER = "Authorized users only. All activity may be monitored and reported."


class TestNoiseAroundTheAnswer(unittest.TestCase):
    def test_banner_before_the_answer(self):
        # The pty path: the client prints the banner during auth, so it comes
        # first. This always worked.
        ok, problems = parse_healthcheck(BANNER + "\n" + healthcheck_json())
        self.assertTrue(ok, problems)

    def test_banner_after_the_answer(self):
        # The key path: stdout + stderr concatenated. This never worked.
        ok, problems = parse_healthcheck(healthcheck_json() + "\n" + BANNER)
        self.assertTrue(ok, problems)

    def test_banner_on_both_sides(self):
        text = BANNER + "\n" + healthcheck_json() + "\n" + BANNER
        self.assertTrue(parse_healthcheck(text)[0])

    def test_readiness_survives_the_same_noise(self):
        # Readiness reads the same way and travels the same wire.
        ok, not_ready, missing = parse_readiness(readiness_json() + "\n" + BANNER)
        self.assertTrue(ok, (not_ready, missing))

    def test_a_stray_brace_before_the_answer_does_not_poison_it(self):
        # A motd with a brace in it would otherwise consume the one attempt.
        text = "Welcome {see /etc/motd}\n" + healthcheck_json()
        self.assertTrue(parse_healthcheck(text)[0])

    def test_trailing_ssh_warning(self):
        text = healthcheck_json() + "\nWarning: Permanently added a new host key."
        self.assertTrue(parse_healthcheck(text)[0])

    def test_genuinely_unreadable_output_is_still_unreadable(self):
        # Tolerating noise must not turn into tolerating nonsense.
        ok, problems = parse_healthcheck("wso: command not found")
        self.assertFalse(ok)
        self.assertEqual(problems, [UNREADABLE_HEALTHCHECK])

    def test_a_truncated_object_is_unreadable(self):
        ok, problems = parse_healthcheck('{"vault": {"reachable": true')
        self.assertFalse(ok)
        self.assertEqual(problems, [UNREADABLE_HEALTHCHECK])

    def test_a_truncated_large_answer_is_unreadable_not_misread(self):
        # The dangerous one. Cut the answer near its END and the outer object
        # fails while the first INNER object still parses -- so falling through
        # to the next candidate reports "vault: unreachable" about a reachable
        # Vault, and hides the transport failure that actually happened.
        full = healthcheck_json()
        ok, problems = parse_healthcheck(full[:-3])
        self.assertFalse(ok)
        self.assertEqual(problems, [UNREADABLE_HEALTHCHECK])
        self.assertFalse(any("unreachable" in p for p in problems), problems)

    def test_deeply_nested_input_does_not_escape_as_an_exception(self):
        # The old code caught this with a bare `except Exception`. An
        # exception out of a done-probe is read by the TUI as "not done" and
        # the phase RUNS.
        ok, problems = parse_healthcheck('{"a":' * 12000)
        self.assertFalse(ok)
        self.assertEqual(problems, [UNREADABLE_HEALTHCHECK])

    def test_a_json_array_is_not_an_answer(self):
        self.assertEqual(parse_healthcheck("[1, 2, 3]")[1],
                         [UNREADABLE_HEALTHCHECK])
        self.assertEqual(parse_readiness("[1, 2, 3]")[2], [UNREADABLE])


class TestTheMessageSaysWhatCameBack(unittest.TestCase):
    """One sentence for four causes was the whole problem."""

    def test_it_carries_the_ssh_exit_code(self):
        # 255 + a connection message is transport; non-zero + wso's own words
        # is wso; 0 + something unexpected is the answer having changed shape.
        message = unreadable_message(255, "ssh: connect to host: timed out")
        self.assertIn("255", message)

    def test_it_carries_what_came_back(self):
        message = unreadable_message(1, "wso: error: vault is sealed")
        self.assertIn("vault is sealed", message)

    def test_silence_is_said_plainly(self):
        self.assertIn("nothing at all", unreadable_message(0, ""))
        self.assertIn("nothing at all", unreadable_message(0, "   \n "))

    def test_it_is_bounded(self):
        self.assertLess(len(unreadable_message(0, "x" * 5000)), 400)


class TestBothPhasesExplain(unittest.TestCase):
    """p60 and p70 both show this string. A9 was carried to neither."""

    def probe_60(self, output: str, rc: int = 0):
        from ws1access.phases import p60_platform
        from ._fakes import FakeCtx
        ctx = FakeCtx({"healthcheck": (rc, output), "grep": (0, "Folder Hash: ab")})
        return p60_platform.is_done(ctx)

    def accept_70(self, output: str, rc: int = 0):
        from ws1access.phases.p70_services import _acceptance
        from ._fakes import FakeCtx
        ctx = FakeCtx({"check-service-readiness": (0, readiness_json()),
                       "healthcheck": (rc, output)})
        return _acceptance(ctx)

    def test_phase_60_shows_the_raw_answer_and_the_code(self):
        probe = self.probe_60("ssh: connect to host 10.10.50.30: timed out", rc=255)
        self.assertFalse(probe.done)
        self.assertIn("255", probe.detail)
        self.assertIn("timed out", probe.detail)
        self.assertNotIn(UNREADABLE_HEALTHCHECK, probe.detail)

    def test_phase_70_shows_the_raw_answer_and_the_code(self):
        ok, detail, _ = self.accept_70("wso: error: could not reach nomad", rc=1)
        self.assertFalse(ok)
        self.assertIn("could not reach nomad", detail)
        self.assertNotIn(UNREADABLE_HEALTHCHECK, detail)

    def test_the_raw_answer_is_redacted(self):
        # Whatever came back is by definition unknown, so it may carry a token.
        ok, detail, _ = self.accept_70("vault_token: s.leakedValue", rc=0)
        self.assertNotIn("s.leakedValue", detail)

    def test_phase_60_is_redacted_too(self):
        probe = self.probe_60("vault_token: s.leakedValue", rc=0)
        self.assertNotIn("s.leakedValue", probe.detail)

    def test_confirm_health_explains_too(self):
        # The THIRD place that shows this string, and the one the deploy path
        # goes through. is_done and _acceptance were covered; this was not,
        # and a mutation stripping it ran green.
        from ws1access.context import RemoteError
        from ws1access.phases import p60_platform
        from ._fakes import FakeCtx
        ctx = FakeCtx({"healthcheck": (255, "ssh: connect to host: timed out"),
                       "unseal": (0, "")})
        with self.assertRaises(RemoteError) as caught:
            p60_platform._confirm_health(ctx)
        message = caught.exception.result.output
        self.assertIn("255", message)
        self.assertIn("timed out", message)
        self.assertNotIn(UNREADABLE_HEALTHCHECK, message)

    def test_a_real_problem_is_still_reported_plainly(self):
        # Only the unreadable marker is replaced; genuine findings pass through.
        probe = self.probe_60(healthcheck_json(vault_sealed=True))
        self.assertFalse(probe.done)
        self.assertIn("SEALED", probe.detail)


if __name__ == "__main__":
    unittest.main()
