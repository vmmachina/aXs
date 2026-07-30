"""B1, full design: a detected drift becomes an APPLIED one (docs/09 §5).

The gap this closes, and why a warning could not close it: phase 50 owns
profile.yml, phase 60 rolls it out, and `DEPS` only orders them -- it does not
cascade. So phase 50 rewriting the file left 60/70/80 green on their own
evidence (a healthy cluster IS healthy; it is just running yesterday's
settings), and the change was correct on disk and never deployed.

Three parts have to hold together, and each is tested separately below, because
any one of them failing silently restores the silent green:

  1. Phase 50 goes RED on drift it can apply -- red is what makes it run.
  2. It leaves a marker on the bootstrap BEFORE it patches the file.
  3. Phase 60 sees the marker, is red, rolls out, and only then clears it.

Plus the two that keep the mechanism from becoming the worse failure:

  4. A logging change never sets the marker -- `wso cp deploy` cannot apply it,
     so a red phase would never go green again (docs/09 §4).
  5. Every key the comparison can report is a key `patch` actually writes.
     Otherwise phase 50 is red, runs, is still red, and the engine aborts with
     "run finished but probe still reports not done" and no diagnosis.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from ws1access import pending, profile_yml
from ws1access.phases import Probe, dependents, p50_cluster_init, p60_platform
from ws1access.ssh import SshResult

from ._fakes import FakeCtx, healthcheck_json
from .test_profile_drift import NFS, WSO_TEMPLATE


class TestReadingTheMarker(unittest.TestCase):
    """Tri-state, and the third state is the one that matters."""

    def read(self, rc: int, out: str) -> pending.Pending:
        return pending.read(FakeCtx({pending.FILENAME: (rc, out)}))

    def test_no_marker_is_clean(self):
        self.assertEqual(self.read(0, "AXS_PENDING_NONE").state, "clean")

    def test_a_marker_is_pending_and_carries_its_keys(self):
        state = self.read(0, "ntp_server\nnfs_host\nAXS_PENDING_END")
        self.assertEqual(state.state, "pending")
        self.assertEqual(state.keys, ("ntp_server", "nfs_host"))

    def test_an_empty_marker_is_still_pending(self):
        # The marker's EXISTENCE is the obligation; the keys are only for the
        # message. An empty file must not read as "nothing owed" -- which is
        # exactly what a bare `list` return value would have done, since an
        # empty list is falsy.
        state = self.read(0, "AXS_PENDING_END")
        self.assertEqual(state.state, "pending")
        self.assertEqual(state.keys, ())

    def test_a_failed_ssh_call_is_unknown_not_clean(self):
        # docs/08 E1. Reading "no marker" out of a broken connection would
        # cancel a rollout that is genuinely owed -- and this marker exists
        # precisely to be harder to lose than a warning was.
        state = self.read(255, "connection closed")
        self.assertEqual(state.state, "unknown")
        self.assertIn("could not ask", state.reason)

    def test_noise_that_ate_both_markers_is_unknown(self):
        # A login banner or a chatty profile script. Not an answer either way.
        state = self.read(0, "Welcome to the appliance\nLast login: ...")
        self.assertEqual(state.state, "unknown")

    def test_the_marker_is_per_cluster_not_global(self):
        # Two clusters driven from one bootstrap would otherwise share one
        # marker and roll out each other's changes.
        a = pending.path(FakeCtx({}, cluster_dir="/root/alpha"))
        b = pending.path(FakeCtx({}, cluster_dir="/root/beta"))
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith("/root/alpha/"))

    def test_the_query_cannot_fail_on_a_missing_file(self):
        # `cat` of a missing file exits non-zero, which is indistinguishable
        # from ssh failing. The `&&`/`||` pair is what makes rc mean "could not
        # ask" and nothing else; without it every clean cluster reads unknown.
        ctx = FakeCtx({pending.FILENAME: (0, "AXS_PENDING_NONE")})
        pending.read(ctx)
        cmd = ctx.calls[-1]
        self.assertIn("&& echo", cmd)
        self.assertIn("|| echo", cmd)


class TestClearingTheMarker(unittest.TestCase):
    def test_removal_is_verified_not_assumed(self):
        # `rm -f` reports success for a file it never touched. A marker that
        # outlives its rollout makes phase 60 red on every future run.
        ctx = FakeCtx({"rm -rf": (0, "")})
        ok, why = pending.clear(ctx)
        self.assertFalse(ok)
        self.assertIn("rm -rf", why)
        self.assertIn("test ! -e", ctx.calls[-1])

    def test_a_confirmed_removal_succeeds(self):
        ok, why = pending.clear(FakeCtx({"rm -rf": (0, "AXS_PENDING_GONE")}))
        self.assertTrue(ok)
        self.assertEqual(why, "")

    def test_the_failure_message_names_the_manual_fix(self):
        # This is the only state that can make phase 60 permanently red, so the
        # operator has to be handed the exact command.
        _ok, why = pending.clear(FakeCtx({"rm -rf": (255, "closed")},
                                         cluster_dir="/root/cp"))
        self.assertIn("/root/cp/.axs-profile-pending", why)


class TestTheMarkerCommandsActuallyRun(unittest.TestCase):
    """Executed by a real /bin/sh against real files, not inspected as strings.

    The gap this closes was demonstrated, not imagined: swapping `echo _END` and
    `echo _NONE` in `pending.read` left all 416 tests green, because every fake
    answers with the output format the code expects no matter what shell the
    code actually generated. In production that swap means a missing marker
    reads as "pending" (a 30-60 minute platform deploy on every run) and a
    present one as "clean" (the rollout silently lost).

    The same lesson as the `trap 'rm -f ...'` defect: a command that splits
    cleanly can still do the opposite of what it says.
    """

    class _Sh:
        """Runs the generated command through /bin/sh, mimicking bootstrap_run.

        `in_cluster_dir` is honoured for real -- prefixing `cd <dir> &&` the way
        Context does -- because that prefix is precisely what made `|| echo
        NONE` fire for a failed `cd` and answer "clean" to a question that was
        never asked.
        """

        def __init__(self, cluster_dir: str):
            self.cluster_dir = cluster_dir
            self.commands: list[str] = []

        def bootstrap_run(self, command, *, become=True, in_cluster_dir=True,
                          stdin=None) -> SshResult:
            import shlex
            import subprocess
            if in_cluster_dir:
                command = f"cd {shlex.quote(self.cluster_dir)} && {command}"
            self.commands.append(command)
            p = subprocess.run(["/bin/sh", "-c", command], input=stdin,
                               capture_output=True, text=True)
            return SshResult(p.returncode, p.stdout + p.stderr)

    def read_in(self, directory: str, content: str | None,
                *, name: str | None = None, mode: int | None = None):
        import os
        if content is not None:
            target = os.path.join(directory, name or pending.FILENAME)
            with open(target, "w") as handle:
                handle.write(content)
            if mode is not None:
                os.chmod(target, mode)
        return pending.read(self._Sh(directory))

    def test_a_real_missing_file_reads_as_clean(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.read_in(d, None).state, "clean")

    def test_a_real_marker_reads_as_pending_with_its_keys(self):
        with tempfile.TemporaryDirectory() as d:
            state = self.read_in(d, "ntp_server\nnfs_host\n")
            self.assertEqual(state.state, "pending")
            self.assertEqual(state.keys, ("ntp_server", "nfs_host"))

    def test_a_real_empty_marker_reads_as_pending(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.read_in(d, "").state, "pending")

    def test_a_marker_without_a_trailing_newline_keeps_its_last_key(self):
        with tempfile.TemporaryDirectory() as d:
            state = self.read_in(d, "ntp_server")
            self.assertEqual(state.keys, ("ntp_server",))

    def test_a_marker_that_exists_but_cannot_be_read_is_unknown(self):
        # Not "clean". `cat` fails identically for missing and unreadable, and
        # a two-marker version cancelled the rollout over a permission problem.
        import os
        if os.geteuid() == 0:
            self.skipTest("root can read a mode-000 file")
        with tempfile.TemporaryDirectory() as d:
            state = self.read_in(d, "ntp_server\n", mode=0o000)
            self.assertEqual(state.state, "unknown")
            # The marker path, not just "could not be read": the generic
            # no-answer branch says that too, so asserting the phrase alone
            # passed even with the unreadable branch removed. The operator needs
            # to know it is a permission problem on a file that EXISTS.
            self.assertIn(pending.FILENAME, state.reason)
            self.assertIn("exists", state.reason)

    def test_a_directory_of_that_name_is_unknown_not_clean(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, pending.FILENAME))
            self.assertEqual(pending.read(self._Sh(d)).state, "unknown")

    def test_the_query_is_not_wrapped_in_a_cd(self):
        # `bootstrap_run`'s default prefixes `cd <cluster dir> &&`, and
        # `A && B || C` binds the `||` to the WHOLE chain -- so a `cd` that fails
        # answers through the `|| echo NONE` branch, reporting "no marker" for a
        # question that was never asked. The path here is absolute, so there was
        # never anything for the `cd` to do.
        #
        # Observed on the real call rather than read out of the source: what is
        # asserted is the command the fake actually received.
        with tempfile.TemporaryDirectory() as d:
            ctx = self._Sh(d)
            pending.read(ctx)
            self.assertFalse(ctx.commands[-1].startswith("cd "),
                             ctx.commands[-1])

    def test_clear_is_not_wrapped_in_a_cd_either(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self._Sh(d)
            pending.clear(ctx)
            self.assertFalse(ctx.commands[-1].startswith("cd "),
                             ctx.commands[-1])

    def test_a_marker_path_with_a_space_still_works(self):
        with tempfile.TemporaryDirectory() as d:
            spaced = os.path.join(d, "cluster with space")
            os.mkdir(spaced)
            state = self.read_in(spaced, "ntp_server\n")
            self.assertEqual(state.state, "pending")

    def test_a_key_that_looks_like_the_other_marker_is_not_misread(self):
        with tempfile.TemporaryDirectory() as d:
            state = self.read_in(d, "AXS_PENDING_NONE\nntp_server\n")
            self.assertEqual(state.state, "pending")

    def test_clear_really_removes_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, pending.FILENAME)
            with open(target, "w") as handle:
                handle.write("ntp_server\n")
            ok, why = pending.clear(self._Sh(d))
            self.assertTrue(ok, why)
            self.assertFalse(os.path.exists(target))

    def test_clear_succeeds_when_there_was_nothing_to_remove(self):
        with tempfile.TemporaryDirectory() as d:
            ok, _why = pending.clear(self._Sh(d))
            self.assertTrue(ok)

    def test_clear_removes_a_directory_of_that_name_too(self):
        # `rm -f` cannot, and a marker it cannot remove makes phase 60 red for
        # good.
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, pending.FILENAME))
            ok, why = pending.clear(self._Sh(d))
            self.assertTrue(ok, why)

    def test_marking_then_reading_round_trips(self):
        # The pair, end to end: what `mark` writes is what `read` gets back.
        with tempfile.TemporaryDirectory() as d:
            ctx = self._Sh(d)
            ctx.write_file = lambda p, c: open(p, "w").write(c)
            pending.mark(ctx, ["ntp_server", "nfs_host"])
            self.assertEqual(pending.read(ctx).keys, ("ntp_server", "nfs_host"))


class TestClassifyingWhatCanBeRetrofitted(unittest.TestCase):
    def test_the_scalars_are_retrofittable(self):
        apply_now, rebuild = profile_yml.classify(list(profile_yml.SCALARS))
        self.assertEqual(sorted(apply_now), sorted(profile_yml.SCALARS))
        self.assertEqual(rebuild, [])

    def test_logging_needs_a_rebuild(self):
        keys = ["logging.loki_server.url", "logging.syslog_servers[0].host"]
        apply_now, rebuild = profile_yml.classify(keys)
        self.assertEqual(apply_now, [])
        self.assertEqual(rebuild, keys)

    def test_an_unrecognised_key_is_treated_as_retrofittable(self):
        # Erring towards "try to apply it" fails VISIBLY -- the rollout runs,
        # the drift persists, and phase 50's own verification says so. Erring
        # the other way loses the setting with nothing to notice it.
        apply_now, rebuild = profile_yml.classify(["some_future_key"])
        self.assertEqual(apply_now, ["some_future_key"])
        self.assertEqual(rebuild, [])


class TestEveryReportableKeyIsAlsoWritable(unittest.TestCase):
    """The property that keeps phase 50 from being red forever.

    Phase 50 is now red when `drift_keys` names a retrofittable key, and it
    verifies after patching that the key is gone. If the comparison can report
    something `patch` does not write, that verification fails on every run and
    the phase can never complete. So: for a wide set of starting files, patching
    must eliminate ALL reported drift.
    """

    SETTINGS = dict(NFS, ntp_server="ntp.example.com",
                    bridge_network_subnet="172.26.64.0/20",
                    logging={"loki_server": {"url": "http://loki:3100",
                                             "user": "svc",
                                             "admin_password": "secret"},
                             "syslog_servers": [{"host": "log1",
                                                 "port": 601,
                                                 "protocol": "tcp"}]})

    STARTING_FILES = (
        WSO_TEMPLATE,                                     # freshly initialised
        "",                                               # empty
        "# everything commented out\n",
        "cluster_name: lab\n",                            # wso's keys only
        "ntp_server: wrong.example.com\n",                # one wrong scalar
        "nfs_host: 10.0.0.9\nnfs_path: /other\nnfs_version: 3\n",
        "logging:\n  loki_server:\n    url: http://old:3100\n",
        # aXs's own previous output, patched with different values.
        None,
    )

    # PARTIAL settings, and this is the hole the first version of this test had:
    # SETTINGS above sets every key aXs owns, so `want` was never None and the
    # "config.yml no longer sets this" case -- the one that made phase 50 red
    # forever -- could not occur in any of the eight files. A property test
    # whose fixture cannot express the failing case proves nothing about it.
    PARTIAL = ({"ntp_server": "ntp.example.com"},
               {"nfs_host": "10.0.0.9", "nfs_path": "/p", "nfs_version": 4},
               {"bridge_network_subnet": "172.26.64.0/20"})

    def cases(self):
        for start in self.STARTING_FILES:
            if start is None:
                start = profile_yml.patch(WSO_TEMPLATE, {"ntp_server": "old"})
            for settings in (self.SETTINGS,) + self.PARTIAL:
                yield start, settings
        # And the file aXs itself wrote for a FULLER config than the one now in
        # force -- the exact shape of the removed-setting case.
        yield profile_yml.patch(WSO_TEMPLATE, self.SETTINGS), self.PARTIAL[0]

    def test_patching_removes_every_key_it_promised_to_write(self):
        # `actionable_keys`, not `drift_keys`: the promise is over keys aXs can
        # write, and phase 50's verification is checked against exactly that set.
        for i, (start, settings) in enumerate(self.cases()):
            with self.subTest(case=i):
                before = profile_yml.actionable_keys(start, settings)
                self.assertIsNotNone(before)
                after = profile_yml.actionable_keys(
                    profile_yml.patch(start, settings), settings)
                self.assertEqual(after, [], f"still drifting: {after}")

    def test_a_key_config_no_longer_sets_is_never_promised(self):
        # The other half: it must be reported as a difference and excluded from
        # what the phase undertakes to fix.
        written = profile_yml.patch(WSO_TEMPLATE, self.SETTINGS)
        smaller = self.PARTIAL[0]
        self.assertTrue(profile_yml.orphan_keys(written, smaller))
        apply_now, _rebuild = profile_yml.classify(
            profile_yml.actionable_keys(written, smaller))
        self.assertEqual(apply_now, [])

    def test_patching_twice_changes_nothing(self):
        # Otherwise every run marks a rollout as owed and phase 60 redeploys
        # the platform forever.
        once = profile_yml.patch(WSO_TEMPLATE, self.SETTINGS)
        twice = profile_yml.patch(once, self.SETTINGS)
        self.assertEqual(profile_yml.drift_keys(twice, self.SETTINGS), [])


class TestTheFourWaysPhase50CouldHaveBeenRedForever(unittest.TestCase):
    """Found by review, not by the property test below -- whose fixture set
    every key and so could not contain the first of these at all.

    Each case is a real operator action that made `drift_keys` report a key
    `patch` cannot write. Phase 50 was then red, ran, verified its own write,
    failed, and repeated identically on every future run: a deploy that can
    never get past phase 50 again without hand-editing the bootstrap. docs/09 §4
    names exactly this as worse than the drift it reports.
    """

    def probe(self, remote: str, settings: dict):
        ctx = FakeCtx({"wso access validate": (0, "ok"), "cat ": (0, remote)})
        ctx.deployment_settings = settings
        return p50_cluster_init.is_done(ctx)

    def test_a_setting_removed_from_config_does_not_make_the_phase_red(self):
        # The operator deletes `ntp_server` from config.yml. It is still set on
        # the bootstrap. The two sides DO differ -- but aXs writes values, it
        # does not remove keys, so no run could ever close this.
        remote = "ntp_server: ntp.example.com\n"
        result = self.probe(remote, {"ntp_server": ""})
        self.assertTrue(result.done, result.detail)

    def test_that_leftover_is_still_reported_not_silently_ignored(self):
        # The operator may well believe deleting the line unset the setting.
        remote = ("ntp_server: ntp.example.com\nnfs_host: 10.0.0.9\n"
                  "nfs_path: /exports/cp\nnfs_version: '4'\n")
        settings = dict(NFS, nfs_host="10.0.0.9", nfs_path="/exports/cp")
        result = self.probe(remote, settings)
        self.assertIn("ntp_server", result.warning)
        self.assertIn("does NOT unset", result.warning)

    def test_actionable_keys_excludes_it_and_drift_keys_still_reports_it(self):
        # The two functions answer different questions and must not be confused
        # again: drift_keys is "what differs", actionable_keys is "what we could
        # write".
        remote = "ntp_server: old\n"
        settings = {"nfs_host": "10.0.0.9", "nfs_path": "/p", "nfs_version": 4}
        self.assertIn("ntp_server", profile_yml.drift_keys(remote, settings))
        self.assertNotIn("ntp_server",
                         profile_yml.actionable_keys(remote, settings))

    def test_a_hand_added_duplicate_key_is_actually_overridden(self):
        # YAML resolves a duplicate key to the LAST occurrence. Patching only
        # the first left the operator's old value winning, so the comparison
        # kept reporting drift no matter how often the phase ran.
        remote = WSO_TEMPLATE + "\nntp_server: 10.9.9.9\n"
        settings = {"ntp_server": "ntp.example.com"}
        patched = profile_yml.patch(remote, settings)
        self.assertEqual(profile_yml.actionable_keys(patched, settings), [])
        import yaml
        self.assertEqual(yaml.safe_load(patched)["ntp_server"],
                         "ntp.example.com")

    def test_a_commented_duplicate_is_left_alone(self):
        # It is the template's documentation and YAML never reads it, so
        # removing it would be destroying the operator's reference for nothing.
        remote = "ntp_server: old\n#ntp_server: us.pool.ntp.org\n"
        patched = profile_yml.patch(remote, {"ntp_server": "new"})
        self.assertIn("#ntp_server: us.pool.ntp.org", patched)

    def test_a_scalar_between_two_axs_blocks_does_not_win(self):
        remote = (WSO_TEMPLATE
                  + "\n# ---- set by aXs ----\nnfs_version: 4\n"
                  + "\nntp_server: 10.9.9.9\n"
                  + "\n# ---- set by aXs ----\nnfs_host: 1.2.3.4\n")
        settings = {"ntp_server": "ntp.example.com"}
        patched = profile_yml.patch(remote, settings)
        self.assertEqual(profile_yml.actionable_keys(patched, settings), [])

    def test_a_syslog_entry_without_a_host_does_not_drift_forever(self):
        # Found while constructing the case above. `_logging_block` skips an
        # entry with no host and writes the NEXT one at index 0; the comparison
        # counted the position in config.yml instead, so it held
        # `syslog_servers[1].*` against a file containing `syslog_servers[0].*`
        # -- three differences between aXs's own output and aXs's own config, on
        # every single run, that no amount of patching could clear.
        settings = {"logging": {"syslog_servers": [{"port": 514},
                                                   {"host": "log1"}]}}
        after = profile_yml.patch("", settings)
        self.assertEqual(profile_yml.drift_keys(after, settings), [])

    def test_hostile_logging_shapes_all_round_trip(self):
        # The property that keeps the verification from ever being fatal over a
        # logging key. Each of these is a plausible hand-edit of config.yml.
        shapes = (
            {"syslog_servers": [{"port": 514}, {"host": "log1"}]},
            {"syslog_servers": [{"host": "a"}, {"port": 1}, {"host": "c"}]},
            {"syslog_servers": ["notamapping", {"host": "b"}]},
            {"syslog_servers": [{"host": "a", "port": "notaport"}]},
            {"syslog_servers": [{"host": "a", "protocol": "tls"}]},
            {"loki_server": {"user": "svc"}},                    # no url
            {"loki_server": {"url": "", "user": "svc"}},          # empty url
            {"loki_server": {"url": "http://l", "custom": "x"}},
            {"opensearch": {"url": "http://o", "auth": {"u": "v"}}},
        )
        for i, logging in enumerate(shapes):
            with self.subTest(shape=i):
                settings = dict(NFS, logging=logging)
                after = profile_yml.patch("nfs_host: 1.1.1.1\n", settings)
                self.assertEqual(
                    profile_yml.actionable_keys(after, settings), [])

    def test_a_syslog_entry_that_is_not_a_mapping_cannot_crash_anything(self):
        # `- log1.example.com` instead of `- host: log1.example.com`. Every
        # `.get` on it raised AttributeError -- and `is_configured` calls the
        # writer from phase 50's done-probe, where the TUI reads an exception as
        # "not done" and runs the phase against a healthy cluster.
        settings = {"logging": {"syslog_servers": ["log1.example.com"]}}
        profile_yml.is_configured(settings)
        profile_yml.patch("", settings)
        profile_yml.summary(settings)

    def test_the_validator_names_that_mistake_instead_of_dying_on_it(self):
        from ws1access import validate
        errs = validate.validate_config({
            "cluster": {"name": "lab"},
            "deployment_settings": {
                "logging": {"syslog_servers": ["log1.example.com"]}}})
        self.assertTrue(any("syslog_servers" in e and "mapping" in e
                            for e in errs), errs)

    def test_a_logging_difference_cannot_fail_the_verification(self):
        # classify() guarantees logging never makes the phase red. Verifying
        # against every difference broke that guarantee from the other end: the
        # phase went red over NFS, patched NFS, and then raised over logging.
        remote = ("nfs_host: 10.0.0.9\n"
                  "logging:\n  loki_server:\n    url: http://old:3100\n")
        settings = dict(NFS, logging={"loki_server":
                                      {"url": "http://new:3100"}})
        after = profile_yml.patch(remote, settings)
        actionable = profile_yml.actionable_keys(after, settings)
        apply_now, _rebuild = profile_yml.classify(
            profile_yml.actionable_keys(remote, settings))
        self.assertEqual([k for k in apply_now if k in actionable], [])


class _ApplyCtx:
    """Enough Context for `_apply_profile`, recording the ORDER of its writes.

    The order is the thing under test: the marker has to be written before
    profile.yml, or a failed marker write is unrecoverable.
    """

    logging_passwords: dict = {}
    bootstrap_ip = "10.0.0.1"
    platform_ips: list[str] = []
    access_ips: list[str] = []

    def __init__(self, settings: dict, remote: str, *,
                 after: str | None = None, mark_fails: bool = False):
        self.deployment_settings = settings
        self.cluster_dir = "/root/lab"
        self.remote = remote
        # What a re-read returns; defaults to "the patch landed".
        self.after = after
        self.mark_fails = mark_fails
        self.events: list[str] = []
        self.reports: list[str] = []

    def bootstrap_run(self, command: str, **_kw) -> SshResult:
        if pending.FILENAME in command:
            self.events.append("read-marker")
            return SshResult(0, "AXS_PENDING_NONE")
        if command.startswith("cat "):
            self.events.append("read-profile")
            text = self.remote if "read-back" not in self.events else self.after
            if "read-profile" in self.events[:-1]:
                self.events.append("read-back")
                text = self.after
            return SshResult(0, text if text is not None else "")
        # Everything else is `_verify_nfs`, which runs after the write and is
        # deliberately non-fatal (it has its own tests in test_nfscheck_where).
        # Answering "could not reach it" keeps it from touching this test's
        # subject, which is the ORDER of the two writes.
        self.events.append("nfs-check")
        return SshResult(255, "not reachable in this test")

    def write_file(self, path: str, content: str) -> None:
        if path.endswith(pending.FILENAME):
            if self.mark_fails:
                raise RuntimeError("marker write failed")
            self.events.append("write-marker")
        else:
            self.events.append("write-profile")
            self.remote = content

    def report(self, message: str) -> None:
        self.reports.append(message)


class TestPhase50MarksBeforeItPatches(unittest.TestCase):
    def apply(self, **kw):
        ctx = _ApplyCtx(dict(NFS), WSO_TEMPLATE, **kw)
        ctx.after = profile_yml.patch(WSO_TEMPLATE, dict(NFS))
        p50_cluster_init._apply_profile(ctx)
        return ctx

    def test_the_marker_is_written_before_the_file(self):
        # Patch first and a failed marker write is unrecoverable: profile.yml
        # would be correct, so the next run finds no drift, and the rollout is
        # owed forever with nothing left to notice it. In this order the same
        # failure leaves the file stale and the next run retries everything.
        ctx = self.apply()
        self.assertIn("write-marker", ctx.events)
        self.assertIn("write-profile", ctx.events)
        self.assertLess(ctx.events.index("write-marker"),
                        ctx.events.index("write-profile"))

    def test_a_failed_marker_write_leaves_the_file_alone(self):
        ctx = _ApplyCtx(dict(NFS), WSO_TEMPLATE, mark_fails=True)
        with self.assertRaises(RuntimeError):
            p50_cluster_init._apply_profile(ctx)
        self.assertNotIn("write-profile", ctx.events)
        self.assertEqual(ctx.remote, WSO_TEMPLATE)

    def test_no_drift_means_no_marker(self):
        # A re-run against an in-sync cluster must not schedule a 30-60 minute
        # platform deploy.
        already = profile_yml.patch(WSO_TEMPLATE, dict(NFS))
        ctx = _ApplyCtx(dict(NFS), already, after=already)
        p50_cluster_init._apply_profile(ctx)
        self.assertNotIn("write-marker", ctx.events)


class TestPhase50VerifiesItsOwnWrite(unittest.TestCase):
    def test_a_patch_that_did_not_take_is_named_not_left_to_the_engine(self):
        # Without this the engine says only "run finished but probe still
        # reports not done" -- a fatal abort with no diagnosis, on every run.
        ctx = _ApplyCtx(dict(NFS), WSO_TEMPLATE, after=WSO_TEMPLATE)
        with self.assertRaises(Exception) as caught:
            p50_cluster_init._apply_profile(ctx)
        message = str(caught.exception) + str(getattr(caught.exception,
                                                     "result", ""))
        self.assertIn("nfs_host", message)

    def test_an_unreadable_read_back_is_not_taken_as_success(self):
        ctx = _ApplyCtx(dict(NFS), WSO_TEMPLATE, after="nfs_host: [unclosed\n")
        with self.assertRaises(Exception):
            p50_cluster_init._apply_profile(ctx)

    def test_a_logging_difference_cannot_fail_the_run(self):
        # Through the REAL `_apply_profile`, not through profile_yml alone: the
        # first version of this test called the comparison functions directly
        # and so passed even with the verification checking every difference
        # again -- the regression it was written to catch.
        #
        # A logging change cannot be applied by a re-run, so `classify` keeps it
        # out of what the phase undertakes. Verifying against every difference
        # broke that from the other end: red over NFS, patch NFS, raise over
        # logging, on every run forever.
        settings = dict(NFS, logging={"loki_server":
                                      {"url": "http://new:3100"}})
        remote = ("nfs_host: 1.1.1.1\n"
                  "logging:\n  loki_server:\n    url: http://old:3100\n")
        ctx = _ApplyCtx(settings, remote)
        # Whatever `patch` produces IS what the bootstrap would hold afterwards.
        ctx.after = profile_yml.patch(remote, settings)
        p50_cluster_init._apply_profile(ctx)          # must not raise
        self.assertIn("write-profile", ctx.events)

    def test_a_setting_removed_from_config_does_not_fail_the_run_either(self):
        # `ntp_server` still on the bootstrap, gone from config.yml. `patch`
        # cannot remove it, so it must never be something the phase promises.
        settings = dict(NFS)
        remote = "ntp_server: leftover\n"
        ctx = _ApplyCtx(settings, remote)
        ctx.after = profile_yml.patch(remote, settings)
        p50_cluster_init._apply_profile(ctx)          # must not raise


class TestItNeverWritesAFileWsoCannotRead(unittest.TestCase):
    """`patch` appends its block at the end of the file. A remote profile.yml
    containing a `...` document-end marker therefore got aXs's settings placed in
    a SECOND YAML document: valid text, unreadable configuration -- and wso reads
    this file too. It was written anyway, and only the read-back noticed, on
    every run, without ever saying that aXs had broken the file itself."""

    def test_it_refuses_rather_than_writing_broken_yaml(self):
        remote = "nfs_host: old\n...\n"
        ctx = _ApplyCtx(dict(NFS), remote)
        with self.assertRaises(Exception) as caught:
            p50_cluster_init._apply_profile(ctx)
        message = str(caught.exception) + str(getattr(caught.exception,
                                                     "result", ""))
        self.assertIn("NOT written", message)
        self.assertIn("...", message)          # names the known cause

    def test_the_bootstrap_file_is_left_untouched(self):
        ctx = _ApplyCtx(dict(NFS), "nfs_host: old\n...\n")
        with self.assertRaises(Exception):
            p50_cluster_init._apply_profile(ctx)
        self.assertNotIn("write-profile", ctx.events)
        self.assertEqual(ctx.remote, "nfs_host: old\n...\n")

    def test_a_normal_file_is_still_written(self):
        # The guard must not refuse the ordinary case.
        ctx = _ApplyCtx(dict(NFS), WSO_TEMPLATE)
        ctx.after = profile_yml.patch(WSO_TEMPLATE, dict(NFS))
        p50_cluster_init._apply_profile(ctx)
        self.assertIn("write-profile", ctx.events)


class TestEveryProbeCallSiteIsGuarded(unittest.TestCase):
    """The first version of this guard covered ONE of four probe call sites.

    That is this project's signature defect -- repaired in one place, not in the
    others -- and it was not hypothetical: a hand-edited config.yml really could
    make a probe raise (see test_hostile_config.py), so all four were reachable.

    Both readings of a raising probe are wrong. "Not done" runs a phase against a
    live cluster on the strength of a bug; "done" is the silent green.
    """

    def plain(self, *, raise_on: str):
        """Run the real `axs deploy` loop with one probe raising."""
        import sys
        from types import SimpleNamespace

        from ws1access import cli, config, phases, validate

        calls: list[str] = []

        def is_done(_ctx, name="50_cluster_init"):
            calls.append(name)
            if raise_on == "upfront" or (raise_on == "postrun"
                                         and len(calls) > 1):
                raise RuntimeError("probe exploded")
            return Probe(False)

        registry = {"50_cluster_init": SimpleNamespace(
            NAME="50_cluster_init", DEPS=(), is_done=is_done,
            run=lambda _c: calls.append("RAN"),
            explain_failure=lambda _c, exc: str(exc))}
        ctx = SimpleNamespace(progress=None, password_refused=lambda: False)
        saved = (phases.REGISTRY, config.context, config.load,
                 validate.validate_config, sys.stdout.isatty)
        phases.REGISTRY = registry
        config.context = lambda _c: ctx
        # _deploy_locked now validates the config first, before this stub logic.
        # These tests are about the probe/re-probe behaviour, not the gate, so
        # stub it out -- otherwise they read (and can be failed by) whatever real
        # clusters/lab/config.yml is on disk. That is exactly how the host caught
        # it while the Mac's happened to validate clean.
        config.load = lambda _c: {}
        validate.validate_config = lambda _c: []
        sys.stdout.isatty = lambda: False
        try:
            return cli._deploy_locked("lab", None), calls
        finally:
            (phases.REGISTRY, config.context, config.load,
             validate.validate_config, sys.stdout.isatty) = saved

    def test_the_up_front_round_stops_instead_of_crashing(self):
        rc, calls = self.plain(raise_on="upfront")
        self.assertEqual(rc, 1)
        # And nothing ran: a probe nobody could read is not a licence to act.
        self.assertNotIn("RAN", calls)

    def test_the_post_run_probe_stops_instead_of_crashing(self):
        # Worse than the others: the phase has already done its work, so a bare
        # traceback reads as "the deploy broke" when only the confirmation did.
        rc, calls = self.plain(raise_on="postrun")
        self.assertEqual(rc, 1)
        self.assertIn("RAN", calls)

    def test_the_tui_does_not_read_a_crashed_probe_as_not_done(self):
        """WEAKER THAN THE TESTS ABOVE, and deliberately labelled so.

        The claim: `probe_of` used to return a stand-in with `done=False`, which
        the run loop cannot tell from a genuine "not finished" -- so a crashed
        probe made the TUI RUN the phase against a live cluster.

        Both halves of the fix live in closures inside a Textual worker method
        (`probe_of` and the `broken` check in the run loop), so there is nothing
        importable to call: this asserts on the SOURCE, which cannot tell a call
        from a mention. A mutation that neutralises the check while leaving the
        text in place would survive it -- the exact weakness that let
        `(True, '')  # pending.clear(ctx)` pass earlier in this same change.

        Recorded in tests/README.md under what the suite does not cover. The
        plain path's equivalents ARE tested behaviourally, above.
        """
        import inspect

        from ws1access import tui_deploy
        source = inspect.getsource(tui_deploy)
        self.assertIn("broken[name]", source)
        # The stand-in class trick is what made the two indistinguishable.
        self.assertNotIn('type("P", (), {"done": False', source)


class TestPhase60ActsOnTheMarker(unittest.TestCase):
    def probe(self, marker: str | None, *, healthy: bool = True):
        answers = {
            "wso healthcheck": (0, healthcheck_json(vault_healthy=healthy)),
            "grep ": (0, "New Folder Hash: abc123"),
        }
        return p60_platform.is_done(FakeCtx(answers, pending=marker))

    def test_a_pending_marker_makes_the_healthy_platform_red(self):
        # The healthcheck is green and the folder hash is the hash of the LAST
        # deploy, so both agree the platform is fine -- and neither can see
        # that profile.yml changed since. The marker is the only witness.
        result = self.probe("ntp_server")
        self.assertFalse(result.done)
        self.assertIn("ntp_server", result.detail)
        self.assertIn("NOT been rolled out", result.detail)

    def test_no_marker_leaves_it_done(self):
        result = self.probe(None)
        self.assertTrue(result.done)
        self.assertEqual(result.warning, "")

    def test_an_unreadable_marker_is_done_with_a_warning(self):
        # Not red: being wrong here costs one run's delay, being red costs a
        # 30-60 minute deploy on every ssh hiccup -- and phase 50 says the same
        # thing from its side.
        answers = {"wso healthcheck": (0, healthcheck_json()),
                   "grep ": (0, "New Folder Hash: abc123"),
                   pending.FILENAME: (255, "closed")}
        result = p60_platform.is_done(FakeCtx(answers))
        self.assertTrue(result.done)
        self.assertIn("could not ask", result.warning)

    def test_an_empty_marker_still_blocks(self):
        result = self.probe("")
        self.assertFalse(result.done)

    def test_the_marker_is_not_read_when_the_platform_is_already_unhealthy(self):
        # One `cat` per probe, and on this branch it could not change the
        # verdict anyway.
        answers = {"wso healthcheck": (0, healthcheck_json(vault_healthy=False)),
                   "grep ": (0, "New Folder Hash: abc123")}
        ctx = FakeCtx(answers)
        result = p60_platform.is_done(ctx)
        self.assertFalse(result.done)
        self.assertFalse([c for c in ctx.calls if pending.FILENAME in c])


class _RunCtx:
    """Enough Context to drive `p60_platform.run` for real.

    Behaviour, not source text. The first version of these tests asserted that
    `"pending.clear"` appeared in `inspect.getsource(run)` -- and a mutation
    that replaced the call with `(True, '')  # pending.clear(ctx)` passed,
    because the string was still there in the comment. A test that cannot tell
    a call from a mention of a call is not a test.
    """

    local_name = "lab"

    def __init__(self, *, healthy: bool = True, clear_ok: bool = True,
                 hashes: tuple[int, int] = (1, 2)):
        self.cluster_dir = "/root/lab"
        self.healthy = healthy
        self.clear_ok = clear_ok
        self.hashes = list(hashes)
        self.reports: list[str] = []
        self.marker_cleared = False
        self.detached: list[str] = []

    def bootstrap_run(self, command: str, **_kw) -> SshResult:
        if command.startswith("rm -") and pending.FILENAME in command:
            self.marker_cleared = True
            return SshResult(0, "AXS_PENDING_GONE" if self.clear_ok else "")
        if pending.FILENAME in command:
            return SshResult(0, "ntp_server\nAXS_PENDING_END")
        if "wso healthcheck" in command:
            return SshResult(0, healthcheck_json(vault_healthy=self.healthy))
        if command.startswith("grep -c") or "| wc -l" in command:
            return SshResult(0, str(self.hashes.pop(0) if self.hashes else 2))
        if "grep " in command:
            return SshResult(0, "New Folder Hash: abc123")
        if "wso cp precheck" in command:
            return SshResult(0, "")
        return SshResult(0, "")

    def start_detached_once(self, *_a, **_kw) -> None:
        self.detached.append("wso cp deploy")

    def wait_while_running(self, *_a, **_kw) -> None:
        pass

    def report(self, message: str) -> None:
        self.reports.append(message)


class TestPhase60ClearsItOnlyAfterASuccessfulRollout(unittest.TestCase):
    def run_phase(self, **kw):
        import time
        ctx = _RunCtx(**kw)
        real_sleep = time.sleep
        time.sleep = lambda _s: None          # the 5s warm-up wait
        try:
            p60_platform.run(ctx)
        finally:
            time.sleep = real_sleep
        return ctx

    def test_a_successful_rollout_clears_the_marker(self):
        ctx = self.run_phase()
        self.assertTrue(ctx.marker_cleared)

    def test_it_names_the_keys_it_is_rolling_out(self):
        ctx = self.run_phase()
        self.assertTrue(any("ntp_server" in r for r in ctx.reports), ctx.reports)

    def test_a_deploy_that_fails_health_leaves_the_marker_in_place(self):
        # Clearing before health would forget the obligation on a deploy that
        # then failed -- and the next run would find nothing owed.
        import time
        ctx = _RunCtx(healthy=False)
        real_sleep, time.sleep = time.sleep, lambda _s: None
        try:
            with self.assertRaises(Exception):
                p60_platform.run(ctx)
        finally:
            time.sleep = real_sleep
        self.assertFalse(ctx.marker_cleared)

    def test_a_failed_removal_raises_instead_of_reporting_done(self):
        # An outliving marker makes this phase red on every future run. Raising
        # also beats the engine's own "run finished but probe still reports not
        # done", which is what would happen next and explains nothing.
        import time
        real_sleep, time.sleep = time.sleep, lambda _s: None
        try:
            with self.assertRaises(Exception) as caught:
                p60_platform.run(_RunCtx(clear_ok=False))
        finally:
            time.sleep = real_sleep
        message = str(caught.exception) + str(getattr(caught.exception,
                                                     "result", ""))
        self.assertIn(pending.FILENAME, message)


class TestTheEnginesReProbeWhatWentStale(unittest.TestCase):
    """The fourth part, which docs/09 §5 does not mention and without which the
    marker is invisible on the plain path.

    `axs deploy` probes EVERY phase up front, regardless of dependencies. So
    phase 60's "done" is taken seconds before phase 50 rewrites profile.yml,
    and the run loop then skips 60 on that stale answer -- the marker is never
    looked at. The TUI probes lazily (a phase whose dependency is not done is
    left unprobed until its turn), so it never had this hole.
    """

    def test_phase_50_has_dependents_to_invalidate(self):
        self.assertIn("60_platform", dependents("50_cluster_init"))

    def test_invalidation_is_transitive(self):
        # 70 depends on 60, 80 on 70. A stale 60 makes both stale.
        stale = dependents("50_cluster_init")
        self.assertIn("70_services", stale)
        self.assertIn("80_tenant", stale)

    def test_a_phase_is_not_its_own_dependent(self):
        self.assertNotIn("50_cluster_init", dependents("50_cluster_init"))

    def test_the_last_phase_invalidates_nothing(self):
        self.assertEqual(dependents("80_tenant"), set())

    def engine(self, second_probe_done: bool):
        """Drive the real `axs deploy` loop over two stub phases.

        Behaviour, not source text: the first version of this asserted that
        `"stale |= dependents(name)"` appeared in cli.py, and a mutation that
        commented the line out -- `pass  # stale |= dependents(name)` -- passed,
        because the string was still in the comment.

        Phase 50 is not done and will run. Phase 60's FIRST probe says done,
        which is what the up-front round records; whether it runs afterwards
        depends entirely on being asked a second time.
        """
        import sys
        from types import SimpleNamespace

        from ws1access import cli, config, phases, validate

        ran: list[str] = []
        probes: list[str] = []

        def phase(name, deps, answers):
            answers = list(answers)

            def is_done(_ctx):
                probes.append(name)
                answer = answers.pop(0) if answers else True
                if isinstance(answer, Exception):
                    raise answer
                return Probe(answer)

            return SimpleNamespace(
                NAME=name, DEPS=deps, is_done=is_done,
                run=lambda _ctx, _n=name: ran.append(_n),
                explain_failure=lambda _ctx, exc: str(exc))

        registry = {
            "50_cluster_init": phase("50_cluster_init", (), [False, True]),
            # done up front; the second answer is the one under test
            "60_platform": phase("60_platform", ("50_cluster_init",),
                                 [True, second_probe_done, True]),
        }
        ctx = SimpleNamespace(progress=None, password_refused=lambda: False)

        saved = (phases.REGISTRY, config.context, config.load,
                 validate.validate_config, sys.stdout.isatty)
        phases.REGISTRY = registry
        config.context = lambda _c: ctx
        # _deploy_locked now validates the config first, before this stub logic.
        # These tests are about the probe/re-probe behaviour, not the gate, so
        # stub it out -- otherwise they read (and can be failed by) whatever real
        # clusters/lab/config.yml is on disk. That is exactly how the host caught
        # it while the Mac's happened to validate clean.
        config.load = lambda _c: {}
        validate.validate_config = lambda _c: []
        sys.stdout.isatty = lambda: False
        try:
            rc = cli._deploy_locked("lab", None)
        finally:
            (phases.REGISTRY, config.context, config.load,
             validate.validate_config, sys.stdout.isatty) = saved
        return rc, ran, probes

    def test_a_dependent_that_went_stale_is_re_probed_and_runs(self):
        # Without the invalidation, phase 60's up-front "done" -- taken before
        # phase 50 rewrote profile.yml -- stands, the loop skips it, and the
        # pending marker is never looked at. This is the whole hole.
        rc, ran, probes = self.engine(second_probe_done=False)
        self.assertEqual(rc, 0)
        self.assertIn("60_platform", ran)
        self.assertGreaterEqual(probes.count("60_platform"), 2)

    def test_a_re_probe_that_raises_stops_the_deploy_instead_of_crashing(self):
        # A probe is not supposed to raise, and both readings of one that does
        # are wrong: "not done" runs a phase against a live cluster on the
        # strength of a bug, "done" is the silent green. Without the guard the
        # exception propagated through `main` (which catches only
        # KeyboardInterrupt) as a bare traceback in the middle of a deploy.
        rc, ran, _probes = self.engine(
            second_probe_done=RuntimeError("probe exploded"))
        self.assertEqual(rc, 1)
        self.assertNotIn("60_platform", ran)

    def test_a_dependent_that_is_still_done_stays_skipped(self):
        # The other half, and the reason this re-PROBES instead of just
        # re-running: phase 70 does not get an hour of needless work because
        # phase 50 touched a file.
        rc, ran, _probes = self.engine(second_probe_done=True)
        self.assertEqual(rc, 0)
        self.assertNotIn("60_platform", ran)


if __name__ == "__main__":
    unittest.main()
