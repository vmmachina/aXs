"""Probe.warning has to reach the operator -- from every place a phase can be
marked done.

This is a STRUCTURAL guard, and it says so. Whether a Textual widget actually
paints the text cannot be checked without a terminal and a cluster, so what is
checked here is the property that kept breaking instead: that no code path
marks a phase done while quietly dropping what its probe had to say.

It broke twice, the same way both times. `Probe.warning` was added for phase
50's config drift and rendered in the first probe round -- the one round a
phase SKIPS whenever an earlier phase is still open. So on an ordinary resume,
and again on the probe that runs right after a phase finishes, the warning was
collected and thrown away. Phase 80 then inherited it: a tenant whose login URL
the probe had just measured as dead was announced as done, and the completion
banner advertised that URL.
"""

from __future__ import annotations

import inspect
import unittest

from ws1access import cli, tui_deploy


class TestTuiMarksDoneInOneplace(unittest.TestCase):
    """Three call sites, one helper -- so there is no fourth place to forget."""

    def source(self) -> str:
        return inspect.getsource(tui_deploy)

    def test_the_helper_exists_and_reads_the_warning(self):
        source = self.source()
        self.assertIn("def _done_line(", source)
        start = source.index("def _done_line(")
        body = source[start:start + 1200]
        self.assertIn("warning", body)

    def test_every_done_marking_goes_through_the_helper(self):
        # `_set(name, "done", ...)` is how a phase is marked done on the board.
        # Outside the helper there must be none: each one is a place where a
        # warning can be dropped.
        source = self.source()
        marks = [ln.strip() for ln in source.splitlines()
                 if '_set(' in ln and '"done"' in ln]
        self.assertEqual(len(marks), 1,
                         "a phase is marked done outside _done_line: " + str(marks))

    def test_all_three_paths_call_it(self):
        # First probe round, the resume probe, and the probe after a run: each
        # done-path routes through the ONE helper, so no path forgets to render
        # the warning. Count the CALLS inside _engine, not module-wide -- the
        # helper is now a proper method (it was a function nested in _engine and
        # called as self._done_line, which raised AttributeError and froze the
        # board; test_tui_engine_guard covers that it now resolves).
        engine_src = inspect.getsource(tui_deploy.ProgressScreen._engine)
        self.assertEqual(engine_src.count("self._done_line("), 3,
                         "a done-path stopped calling _done_line")


class TestPlainPathPrintsWarnings(unittest.TestCase):
    def source(self) -> str:
        return inspect.getsource(cli._deploy_locked)

    def test_the_probe_round_prints_the_warning(self):
        self.assertIn("probe.warning", self.source())

    def test_the_probe_after_a_run_prints_it_too(self):
        # The run that just happened is where a warning matters most -- phase
        # 80 measuring its own tenant URL as unreachable, for instance.
        source = self.source()
        self.assertIn("final.warning", source)

    def test_the_post_run_probe_is_not_discarded(self):
        # It used to be `if not phase.is_done(ctx).done:` -- the Probe was
        # built, read for one boolean, and dropped.
        self.assertNotIn("if not phase.is_done(ctx).done:", self.source())


class TestStatusPrintsWarnings(unittest.TestCase):
    def test_status_renders_the_warning(self):
        # `axs status` has no progress sink at all, so Probe.warning is its
        # only channel for this.
        self.assertIn("warning", inspect.getsource(cli.cmd_status))


if __name__ == "__main__":
    unittest.main()
