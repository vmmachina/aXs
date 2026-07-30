"""Refuse a 13.5 GB upload that cannot land -- before starting it.

docs/08 B10: there was no space check before phase 40. Running out partway
through costs the whole transfer, and the failure arrives as whatever scp says
about a broken write -- nowhere near "the bootstrap is out of space".

The split matters. The archive fitting where it lands is CERTAIN, so that
refuses. The unpacked size is an estimate (phase 40's own failure text has
always said ~26 GB, and nothing states whether that includes the archive), so
that WARNS -- over-stating the need would block a deploy that would have
worked, which is the same class of harm as not checking at all.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ws1access.context import Context, RemoteError
from ws1access.ssh import SshResult

GB = 1000 ** 3
BUNDLE = 14 * GB


def df_output(free_bytes: int, device: str = "/dev/mapper/almalinux-root") -> str:
    """`df -Pk` as the bootstrap prints it: header, then one line, 1K blocks."""
    blocks = free_bytes // 1024
    return ("Filesystem     1024-blocks      Used Available Capacity Mounted on\n"
            f"{device}   100000000  50000000 {blocks}      34% /\n")


class _Ctx:
    """A Context stand-in: only bootstrap_run and report are used."""

    user = "configuser"
    cluster_name = "lab"

    def __init__(self, free: dict[str, int | None]) -> None:
        self.free = free
        self.reports: list[str] = []
        self.calls: list[str] = []

    def __getattr__(self, name):
        # Bind Context's methods to this stand-in -- but pass its class
        # ATTRIBUTES (like _UNPACKED_BYTES) straight through, or the descriptor
        # protocol is applied to an int.
        attr = getattr(Context, name, None)
        if attr is None:
            raise AttributeError(name)
        return attr.__get__(self, type(self)) if hasattr(attr, "__get__") else attr

    def bootstrap_run(self, command: str, **_kw):
        self.calls.append(command)
        for path, free in self.free.items():
            if path in command:
                if free is None:
                    return SshResult(1, "df: /nope: No such file or directory")
                return SshResult(0, df_output(free))
        raise AssertionError(f"unexpected command: {command!r}")

    def report(self, message: str) -> None:
        self.reports.append(message)


def check(home_free, assets_free, bundle_bytes: int = BUNDLE):
    """Run the real check against a bundle of a given size."""
    with tempfile.TemporaryDirectory() as d:
        local = Path(d) / "Access-asset-bundle-26.07.zip"
        with open(local, "wb") as f:      # sparse: no 14 GB is actually written
            f.truncate(bundle_bytes)
        ctx = _Ctx({"/home/configuser": home_free, "/root/lab/assets": assets_free})
        Context._check_space(ctx, str(local),
                             "/home/configuser/Access-asset-bundle-26.07.zip",
                             "/root/lab/assets")
        return ctx


class TestRefusesWhatCannotLand(unittest.TestCase):
    def test_a_full_staging_directory_refuses(self):
        with self.assertRaises(RemoteError) as caught:
            check(home_free=2 * GB, assets_free=100 * GB)
        self.assertIn("staging directory", caught.exception.result.output)

    def test_a_full_cluster_directory_refuses(self):
        with self.assertRaises(RemoteError) as caught:
            check(home_free=100 * GB, assets_free=2 * GB)
        self.assertIn("cluster directory", caught.exception.result.output)

    def test_the_message_names_both_numbers(self):
        with self.assertRaises(RemoteError) as caught:
            check(home_free=2 * GB, assets_free=100 * GB)
        out = caught.exception.result.output
        self.assertIn("2.0 GB free", out)          # what is there
        self.assertIn("14.0 GB", out)              # what is needed
        self.assertIn("nothing has been uploaded yet", out)

    def test_exactly_enough_for_the_archive_is_not_refused(self):
        # Refusing a deploy that would have worked is the same class of harm as
        # not checking. The boundary belongs to the operator, not to a margin
        # nobody can justify.
        ctx = check(home_free=BUNDLE, assets_free=BUNDLE + 26 * GB)
        self.assertEqual(ctx.reports, [])


class TestWarnsAboutTheUnpack(unittest.TestCase):
    def test_room_for_the_archive_but_not_for_what_follows_warns(self):
        ctx = check(home_free=100 * GB, assets_free=20 * GB)
        self.assertTrue(any("needs roughly" in r for r in ctx.reports), ctx.reports)

    def test_the_warning_does_not_stop_the_deploy(self):
        check(home_free=100 * GB, assets_free=20 * GB)   # must not raise

    def test_the_warning_separates_what_is_measured_from_what_is_estimated(self):
        # The upload fitting is measured. What comes after it -- the unpack and
        # the image load -- rests on a figure whose origin is phase 40's own
        # failure text, and nothing says whether it counts the archive. The
        # first version of this text said "the upload will work; the unpack may
        # not", which claims a precision the number does not have.
        ctx = check(home_free=100 * GB, assets_free=20 * GB)
        warning = " ".join(ctx.reports)
        self.assertIn("room for the upload", warning)
        self.assertIn("estimate", warning)
        self.assertIn("loading the images", warning)

    def test_plenty_of_room_says_nothing(self):
        ctx = check(home_free=500 * GB, assets_free=500 * GB)
        self.assertEqual(ctx.reports, [])


class TestUnreadable(unittest.TestCase):
    """"I could not tell" is not "there is plenty" -- the same rule as
    everywhere else in this tool."""

    def test_an_unreadable_path_warns_and_continues(self):
        ctx = check(home_free=None, assets_free=100 * GB)
        self.assertTrue(any("could not read free space" in r for r in ctx.reports),
                        ctx.reports)

    def test_an_unreadable_path_does_not_refuse(self):
        check(home_free=None, assets_free=100 * GB)      # must not raise

    def test_an_unreadable_path_does_not_count_as_enough(self):
        # The other half: it must not silently satisfy the unpack estimate
        # either, or "df broke" would read as "26 GB free".
        ctx = check(home_free=100 * GB, assets_free=None)
        self.assertTrue(any("could not read free space" in r for r in ctx.reports))
        self.assertFalse(any("needs roughly" in r for r in ctx.reports))


class TestStageBundleAsksBeforeUploading(unittest.TestCase):
    """The promise the refusal makes is "nothing has been uploaded yet".

    Testing _check_space proves _check_space. It does not prove stage_bundle
    calls it, let alone that it calls it BEFORE the 13.5 GB goes out -- and a
    check that runs after the upload is worth nothing at all.
    """

    def run_stage(self, free: int):
        import ws1access.context as mod

        uploaded = []

        class Staging(_Ctx):
            cluster_dir = "/root/lab"
            bootstrap_ip = "192.168.10.10"
            configuser_password = "pw"

            def bootstrap_step(self, _step, command, **kw):
                self.calls.append(command)
                return SshResult(0, "")

        ctx = Staging({"/home/configuser": free, "/root/lab/assets": free})
        real_scp = mod.scp_to
        mod.scp_to = lambda *a, **kw: (uploaded.append(a), SshResult(0, ""))[1]
        try:
            with tempfile.TemporaryDirectory() as d:
                local = Path(d) / "Access-asset-bundle-26.07.zip"
                with open(local, "wb") as f:
                    f.truncate(BUNDLE)
                raised = None
                try:
                    Context.stage_bundle(ctx, str(local))
                except RemoteError as exc:
                    raised = exc
        finally:
            mod.scp_to = real_scp
        return raised, uploaded

    def test_a_full_disk_stops_it_before_the_upload(self):
        raised, uploaded = self.run_stage(2 * GB)
        self.assertIsNotNone(raised, "stage_bundle uploaded onto a full disk")
        self.assertEqual(uploaded, [], "the upload started anyway")

    def test_enough_space_uploads(self):
        raised, uploaded = self.run_stage(500 * GB)
        self.assertIsNone(raised)
        self.assertEqual(len(uploaded), 1)

    def test_the_assets_directory_is_created_before_it_is_measured(self):
        # On a fresh bootstrap <cluster>/assets does not exist yet, so a check
        # that ran before the mkdir would get "no such directory" from df,
        # read it as "could not tell", and skip both the refusal AND the
        # estimate for exactly the directory that matters.
        ordered = self.ordered_calls(500 * GB)
        mkdir = next(i for i, c in enumerate(ordered) if "mkdir" in c)
        measure = next(i for i, c in enumerate(ordered)
                       if "df" in c and "assets" in c)
        self.assertLess(mkdir, measure,
                        "the assets directory is measured before it exists")

    def ordered_calls(self, free: int) -> list[str]:
        import ws1access.context as mod

        class Staging(_Ctx):
            cluster_dir = "/root/lab"
            bootstrap_ip = "192.168.10.10"
            configuser_password = "pw"

            def bootstrap_step(self, _step, command, **kw):
                self.calls.append(command)
                return SshResult(0, "")

        ctx = Staging({"/home/configuser": free, "/root/lab/assets": free})
        real_scp = mod.scp_to
        mod.scp_to = lambda *a, **kw: SshResult(0, "")
        try:
            with tempfile.TemporaryDirectory() as d:
                local = Path(d) / "bundle.zip"
                with open(local, "wb") as f:
                    f.truncate(BUNDLE)
                Context.stage_bundle(ctx, str(local))
        finally:
            mod.scp_to = real_scp
        return ctx.calls


class TestFreeBytesParsing(unittest.TestCase):
    def parse(self, output: str, rc: int = 0):
        class Once:
            def bootstrap_run(_self, _command, **_kw):
                return SshResult(rc, output)
        return Context.free_bytes(Once(), "/root/lab/assets")

    def test_the_query_is_posix_df(self):
        # `-P` is what guarantees one line per filesystem: plain `df` wraps a
        # long device name onto a second line, and the parser would then read
        # the wrong fields. `-k` fixes the block size to 1K.
        seen = []

        class Recording:
            def bootstrap_run(_self, command, **_kw):
                seen.append(command)
                return SshResult(0, df_output(50 * GB))

        Context.free_bytes(Recording(), "/root/lab/assets")
        # The exact flags, not a substring: "df -Pkh" would contain "df -Pk"
        # and print human-readable sizes the parser cannot read.
        self.assertRegex(seen[0], r"\bdf -Pk\s")

    def test_a_normal_answer(self):
        self.assertEqual(self.parse(df_output(50 * GB)), (50 * GB // 1024) * 1024)

    def test_a_chatty_login_shell_does_not_disable_the_check(self):
        # bootstrap_run goes through a LOGIN shell and ssh hands back stdout
        # and stderr concatenated, so a profile script can append a line after
        # df's. Taking the last line blindly turned that into "could not tell"
        # and switched the check off for good on such a machine.
        noisy = df_output(50 * GB) + "Last login: Tue Jul 28 18:07:11 2026\n"
        self.assertEqual(self.parse(noisy), (50 * GB // 1024) * 1024)

    def test_a_banner_before_the_output_is_ignored(self):
        noisy = "=== Company XY -- authorised use only ===\n" + df_output(50 * GB)
        self.assertEqual(self.parse(noisy), (50 * GB // 1024) * 1024)

    def test_a_failed_command_is_unknown(self):
        self.assertIsNone(self.parse("df: /nope: No such file", rc=1))

    def test_empty_output_is_unknown(self):
        self.assertIsNone(self.parse(""))

    def test_a_header_without_data_is_unknown(self):
        self.assertIsNone(self.parse("Filesystem 1024-blocks Used Available\n"))

    def test_a_non_numeric_field_is_unknown(self):
        self.assertIsNone(self.parse(
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "tmpfs - - - - /run\n"))


if __name__ == "__main__":
    unittest.main()
