"""last_segment() and probe_alive() -- two answers that must not be guessed.

last_segment: phase 80's log holds the one-time admin reset link, deliberately
stored nowhere else. Since 2026-07-28 the log is APPENDED to instead of
overwritten, so a re-run no longer destroys it -- but then `onboarding_info`
must read only the newest run, or an expired link from an earlier attempt is
presented as the current one.

probe_alive: `bootstrap_run` returns the same "not ok" for pgrep finding nothing
(rc 1), a dropped connection (rc 255) and the SSH timeout (rc 124). Reading all
three as "the process is gone" is how one VPN blip announces a finished deploy
that is still running -- and starts a second one against the same cluster.
"""

from __future__ import annotations

import unittest

from ws1access.context import RUN_MARK, Context, last_segment
from ws1access.ssh import SshResult


class TestLastSegment(unittest.TestCase):
    def test_no_marker_returns_everything(self):
        # Logs written before the marker existed, or by wso itself.
        text = "Bootstrap already completed.\nCreating tenant ...\n"
        self.assertEqual(last_segment(text), text)

    def test_returns_only_the_newest_run(self):
        text = (f"{RUN_MARK} 2026-07-28 14:00 =====\n"
                "reset link: OLD\n"
                f"{RUN_MARK} 2026-07-28 16:22 =====\n"
                "reset link: NEW\n")
        out = last_segment(text)
        self.assertIn("NEW", out)
        self.assertNotIn("OLD", out)

    def test_marker_as_last_line_returns_empty(self):
        # A run that has started but written nothing yet. Returning the PREVIOUS
        # run's text here would hand the operator an expired link.
        text = f"reset link: OLD\n{RUN_MARK} 2026-07-28 16:22 ====="
        self.assertEqual(last_segment(text), "")

    def test_marker_as_last_line_with_trailing_newline_returns_empty(self):
        text = f"reset link: OLD\n{RUN_MARK} 2026-07-28 16:22 =====\n"
        self.assertEqual(last_segment(text), "")

    def test_three_runs_returns_the_third(self):
        text = "".join(f"{RUN_MARK} run{i} =====\nbody{i}\n" for i in (1, 2, 3))
        out = last_segment(text)
        self.assertIn("body3", out)
        self.assertNotIn("body2", out)
        self.assertNotIn("body1", out)

    def test_empty_input(self):
        self.assertEqual(last_segment(""), "")


class _Probe:
    """Just enough of a Context for probe_alive: it touches nothing else."""

    def __init__(self, rc: int, output: str) -> None:
        self.result = SshResult(rc, output)
        self.commands: list[str] = []

    def bootstrap_run(self, command: str, **_kw) -> SshResult:
        self.commands.append(command)
        return self.result


def probe(rc: int, output: str) -> tuple[str, _Probe]:
    p = _Probe(rc, output)
    return Context.probe_alive(p, "pgrep -f '[w]so cp deploy'"), p


class TestProbeAlive(unittest.TestCase):
    def test_alive(self):
        state, _ = probe(0, "AXS_ALIVE\n")
        self.assertEqual(state, "alive")

    def test_dead(self):
        # The remote shell ran and answered "no such process". rc is non-zero on
        # neither branch here -- the MARKER is the answer, not the exit code.
        state, _ = probe(0, "AXS_DEAD\n")
        self.assertEqual(state, "dead")

    def test_dead_is_reported_even_when_the_wrapper_exits_non_zero(self):
        state, _ = probe(1, "AXS_DEAD\n")
        self.assertEqual(state, "dead")

    def test_connection_refused_is_unknown_not_dead(self):
        # rc 255: the transport failed. This is the case that used to read as
        # "the process is gone".
        state, _ = probe(255, "ssh: connect to host 192.168.10.10 port 22: "
                              "Operation timed out")
        self.assertEqual(state, "unknown")

    def test_timeout_is_unknown_not_dead(self):
        state, _ = probe(124, "")          # rc 124: the SSH run timeout
        self.assertEqual(state, "unknown")

    def test_empty_answer_is_unknown(self):
        state, _ = probe(0, "")
        self.assertEqual(state, "unknown")

    def test_question_carries_both_markers(self):
        # The separation only works if the remote shell prints a marker on both
        # branches; a bare `pgrep` cannot distinguish transport from answer.
        _, p = probe(0, "AXS_ALIVE\n")
        self.assertIn("AXS_ALIVE", p.commands[0])
        self.assertIn("AXS_DEAD", p.commands[0])


if __name__ == "__main__":
    unittest.main()
