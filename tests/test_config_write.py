"""configure._write -- config.yml is written whole, or not at all.

docs/08 B10: it was a plain `write_text`, which truncates first and then
writes. A Ctrl-C, a full disk or a crash in that window left a HALF file -- and
truncated YAML usually still parses. It just silently lacks the last nodes, or
the whole deployment_settings block. The next run would deploy something the
operator never configured, and the dialog is the last place they would look.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import yaml

from ws1access import configure

CFG = {
    "cluster": {"name": "lab", "size": "small"},
    "nodes": {"platform": [{"hostname": f"platform{i}"} for i in (1, 2, 3)]},
    "deployment_settings": {"nfs_host": "10.0.0.9", "nfs_path": "/exports/cp"},
}


class _Cwd:
    """Run inside a scratch directory -- _write builds a relative path."""

    def __enter__(self):
        self.previous = os.getcwd()
        self.dir = tempfile.mkdtemp()
        os.chdir(self.dir)
        return Path(self.dir)

    def __exit__(self, *exc):
        os.chdir(self.previous)


class TestWritesCorrectly(unittest.TestCase):
    def test_the_file_round_trips(self):
        with _Cwd():
            path = configure._write("lab", CFG)
            self.assertEqual(yaml.safe_load(path.read_text()), CFG)

    def test_it_overwrites_an_existing_file(self):
        with _Cwd():
            configure._write("lab", {"cluster": {"name": "old"}})
            path = configure._write("lab", CFG)
            self.assertEqual(yaml.safe_load(path.read_text()), CFG)

    def test_it_creates_the_cluster_directory(self):
        with _Cwd() as root:
            configure._write("brandnew", CFG)
            self.assertTrue((root / "clusters" / "brandnew" / "config.yml").exists())

    def test_no_temp_file_is_left_behind(self):
        with _Cwd() as root:
            configure._write("lab", CFG)
            leftovers = [p.name for p in (root / "clusters" / "lab").iterdir()
                         if p.name != "config.yml"]
            self.assertEqual(leftovers, [])


class TestInterruptedWrite(unittest.TestCase):
    """The defect itself: what the operator is left with when it goes wrong.

    The failure is injected DURING the byte write -- at the fsync, after the
    content has gone out. An earlier version of these tests raised from
    `yaml.safe_dump` instead, and they passed against the old `write_text` code
    too: the argument is evaluated before the file is opened, so that window
    never touched the target at all. They proved nothing. This one fails
    against `write_text` and passes here, which is the whole point.
    """

    def interrupt_during_write(self, exc, existing=None):
        """Write with the transfer blowing up after the bytes are out, and
        report what the cluster folder looks like afterwards."""
        with _Cwd() as root:
            folder = root / "clusters" / "lab"
            folder.mkdir(parents=True, exist_ok=True)
            if existing is not None:
                (folder / "config.yml").write_text(yaml.safe_dump(existing))

            real_fsync = configure.os.fsync

            def exploding_fsync(fd):
                raise exc

            configure.os.fsync = exploding_fsync
            try:
                with self.assertRaises(type(exc)):
                    configure._write("lab", CFG)
            finally:
                configure.os.fsync = real_fsync

            target = folder / "config.yml"
            return (target.read_text() if target.exists() else None,
                    [p.name for p in folder.iterdir()])

    def test_ctrl_c_leaves_the_previous_config_intact(self):
        previous = {"cluster": {"name": "still-here"}}
        content, files = self.interrupt_during_write(KeyboardInterrupt(),
                                                     existing=previous)
        self.assertIsNotNone(content, "the old config.yml was destroyed")
        self.assertEqual(yaml.safe_load(content), previous)
        self.assertEqual(files, ["config.yml"], "a temp file was left behind")

    def test_ctrl_c_on_a_first_run_leaves_no_half_file(self):
        content, files = self.interrupt_during_write(KeyboardInterrupt())
        self.assertIsNone(content)
        self.assertEqual(files, [])

    def test_a_disk_error_leaves_the_previous_config_intact(self):
        previous = {"cluster": {"name": "still-here"}}
        content, _ = self.interrupt_during_write(
            OSError(28, "No space left on device"), existing=previous)
        self.assertEqual(yaml.safe_load(content), previous)

    def test_a_failure_while_serialising_touches_nothing(self):
        # The other window, kept because it is a real failure mode -- but named
        # for what it actually proves, which is much less.
        with _Cwd() as root:
            folder = root / "clusters" / "lab"
            folder.mkdir(parents=True)
            (folder / "config.yml").write_text("cluster: {name: still-here}\n")
            real_dump = configure.yaml.safe_dump
            configure.yaml.safe_dump = lambda *a, **kw: (_ for _ in ()).throw(
                KeyboardInterrupt())
            try:
                with self.assertRaises(KeyboardInterrupt):
                    configure._write("lab", CFG)
            finally:
                configure.yaml.safe_dump = real_dump
            self.assertEqual([p.name for p in folder.iterdir()], ["config.yml"])


class TestFailureDuringTheWriteItself(unittest.TestCase):
    """Not just while serialising -- while the bytes are going out."""

    def test_a_failing_write_leaves_no_temp_file(self):
        with _Cwd() as root:
            real_replace = configure.os.replace

            def exploding_replace(*a, **kw):
                raise KeyboardInterrupt()

            configure.os.replace = exploding_replace
            try:
                with self.assertRaises(KeyboardInterrupt):
                    configure._write("lab", CFG)
            finally:
                configure.os.replace = real_replace

            folder = root / "clusters" / "lab"
            # A .config.yml.*.tmp sitting in the operator's cluster folder is
            # its own small mess -- docs/08 A16 was exactly this shape.
            self.assertEqual([p.name for p in folder.iterdir()], [])


class TestAtomicity(unittest.TestCase):
    def test_the_temp_file_lives_in_the_target_directory(self):
        # os.replace is only atomic within ONE filesystem. A temp file in
        # /tmp would make the rename a copy across devices -- and a copy has
        # the same half-written window this fix exists to remove.
        seen = {}
        real_mkstemp = configure.tempfile.mkstemp

        def recording_mkstemp(*a, **kw):
            seen["dir"] = kw.get("dir")
            return real_mkstemp(*a, **kw)

        with _Cwd() as root:
            configure.tempfile.mkstemp = recording_mkstemp
            try:
                configure._write("lab", CFG)
            finally:
                configure.tempfile.mkstemp = real_mkstemp
            self.assertEqual(Path(seen["dir"]).resolve(),
                             (root / "clusters" / "lab").resolve())

    def test_the_file_is_not_world_readable(self):
        # A change from the old 0644, made deliberately: config.yml holds no
        # passwords, but it describes the customer's network in full.
        with _Cwd():
            path = configure._write("lab", CFG)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_the_buffer_is_flushed_before_it_is_synced(self):
        # fsync on an unflushed buffer synchronises nothing, so the durability
        # the docstring promises would quietly not exist.
        order = []
        real_fdopen, real_fsync = configure.os.fdopen, configure.os.fsync

        def recording_fdopen(fd, mode):
            handle = real_fdopen(fd, mode)
            real_flush = handle.flush

            def flush():
                order.append("flush")
                return real_flush()

            handle.flush = flush
            return handle

        configure.os.fdopen = recording_fdopen
        configure.os.fsync = lambda fd: order.append("fsync")
        try:
            with _Cwd():
                configure._write("lab", CFG)
        finally:
            configure.os.fdopen, configure.os.fsync = real_fdopen, real_fsync
        self.assertEqual(order[:2], ["flush", "fsync"], order)

    def test_a_failing_fdopen_does_not_leak_the_descriptor(self):
        # The temp file is cleaned up by the handler; the raw fd was not.
        import os as real_os

        before = len(real_os.listdir(f"/dev/fd")) if os.path.isdir("/dev/fd") else None
        if before is None:
            self.skipTest("no /dev/fd on this platform")
        real_fdopen = configure.os.fdopen

        def exploding_fdopen(fd, mode):
            raise KeyboardInterrupt()

        configure.os.fdopen = exploding_fdopen
        try:
            with _Cwd():
                with self.assertRaises(KeyboardInterrupt):
                    configure._write("lab", CFG)
        finally:
            configure.os.fdopen = real_fdopen
        self.assertLessEqual(len(real_os.listdir("/dev/fd")), before,
                             "an open descriptor was left behind")

    def test_the_content_is_flushed_before_the_rename(self):
        # An atomic rename over unflushed data can leave the new name pointing
        # at an empty file after a power cut -- the same failure in a hat.
        order = []
        real_fsync, real_replace = configure.os.fsync, configure.os.replace
        configure.os.fsync = lambda fd: order.append("fsync")
        configure.os.replace = lambda *a: order.append("replace")
        try:
            with _Cwd():
                configure._write("lab", CFG)
        finally:
            configure.os.fsync, configure.os.replace = real_fsync, real_replace
        self.assertEqual(order, ["fsync", "replace"])


if __name__ == "__main__":
    unittest.main()
