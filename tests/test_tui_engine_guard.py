"""The deploy engine must never die in silence -- and _done_line must resolve.

The hang that cost hours on 2026-07-30: `_done_line` was a function nested in
`_engine`, but called as `self._done_line(...)`. `ProgressScreen` had no such
attribute, so every call raised AttributeError -- caught by nothing, since
probe_of wraps only is_done -- and killed the engine thread on the FIRST done
phase. A daemon thread's exception is swallowed (Textual owns stderr), so the
board froze on 'probing' with no error, elapsed timer still ticking.

No test exercised the TUI engine loop, so nothing caught it. These do, without a
running Textual app: the methods are called on a stand-in `self`.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from ws1access.phases import Probe
from ws1access.tui_deploy import ProgressScreen


class Recorder:
    """A stand-in self: records what the methods under test do to the UI."""

    def __init__(self):
        self.logs: list[str] = []
        self.sets: list[tuple] = []
        self.outcomes: list[tuple[bool, str]] = []

    def _log(self, msg):
        self.logs.append(msg)

    def _set(self, name, status, detail=""):
        self.sets.append((name, status, detail))

    def _outcome(self, ok, text):
        self.outcomes.append((ok, text))


class TestDoneLineIsACallableMethod(unittest.TestCase):
    def test_it_exists_on_the_class(self):
        # The exact regression: a nested function is not an attribute of the
        # class, so `self._done_line` raised AttributeError.
        self.assertTrue(callable(getattr(ProgressScreen, "_done_line", None)))

    def test_it_marks_the_phase_done(self):
        rec = Recorder()
        ProgressScreen._done_line(rec, "00_preflight", Probe(True), ran=True)
        self.assertIn(("00_preflight", "done", ""), rec.sets)
        self.assertTrue(any("done" in m for m in rec.logs))

    def test_it_surfaces_a_probe_warning(self):
        rec = Recorder()
        ProgressScreen._done_line(
            rec, "50_cluster_init",
            Probe(True, warning="DRIFT: nfs_host differs\n  detail line"))
        # The warning's first line reaches the board; every line reaches the log.
        self.assertTrue(any("DRIFT" in d for _n, _s, d in rec.sets))
        self.assertTrue(any("detail line" in m for m in rec.logs))

    def test_a_done_phase_without_a_warning_says_already_done(self):
        rec = Recorder()
        ProgressScreen._done_line(rec, "10_vms", Probe(True))   # ran defaults False
        self.assertIn(("10_vms", "done", "already done"), rec.sets)


class TestTheEngineNeverDiesInSilence(unittest.TestCase):
    """The systemic fix: whatever escapes _engine is surfaced, not swallowed."""

    def guard_with(self, engine):
        rec = Recorder()
        rec._engine = engine
        # Run in a temp cwd so the error log does not land in the repo.
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                ProgressScreen._engine_guarded(rec)
                wrote = os.path.exists("deploy-engine-error.log")
                trace = (open("deploy-engine-error.log").read()
                         if wrote else "")
            finally:
                os.chdir(old)
        return rec, wrote, trace

    def test_an_attribute_error_becomes_a_visible_failure(self):
        # The very shape of the original bug.
        def boom():
            raise AttributeError("'ProgressScreen' object has no attribute '_x'")
        rec, wrote, trace = self.guard_with(boom)
        self.assertTrue(rec.outcomes, "no outcome surfaced -- it was swallowed")
        ok, text = rec.outcomes[0]
        self.assertFalse(ok)
        self.assertIn("AttributeError", text)
        self.assertIn("deploy-engine-error.log", text)
        self.assertTrue(wrote)
        self.assertIn("AttributeError", trace)

    def test_even_a_bare_baseexception_is_caught(self):
        # probe_of catches only Exception; the guard must catch more, or a
        # BaseException walks straight out of the thread again.
        class Weird(BaseException):
            pass

        def boom():
            raise Weird("not an Exception subclass")
        rec, _wrote, _trace = self.guard_with(boom)
        self.assertTrue(rec.outcomes)
        self.assertFalse(rec.outcomes[0][0])

    def test_a_clean_engine_run_surfaces_no_failure(self):
        rec, wrote, _trace = self.guard_with(lambda: None)
        self.assertEqual(rec.outcomes, [])
        self.assertFalse(wrote)


if __name__ == "__main__":
    unittest.main()
