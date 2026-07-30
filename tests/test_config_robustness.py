"""A malformed config.yml gets a named error, never a Python traceback.

main() catches only KeyboardInterrupt, so anything validate_config or config.load
raises reaches the operator as a raw traceback -- from the very code whose job is
to explain the mistake. Found by asking "what happens if I put garbage in the
config": broken YAML, a top-level list, a section that is a string all produced
tracebacks. Now each is a sentence.
"""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stderr

from ws1access import cli, config, validate


class TestValidateConfigNeverCrashesOnShape(unittest.TestCase):
    """It reports the wrong shape; it does not die on it."""

    def errs(self, cfg):
        return validate.validate_config(cfg)   # must not raise

    def test_a_top_level_non_mapping_is_named(self):
        for bad in (["a", "b"], "kaputt", None, 7):
            with self.subTest(bad=bad):
                errs = self.errs(bad)
                self.assertTrue(errs)
                self.assertIn("mapping at the top level", errs[0])

    def test_deployment_settings_as_a_string_is_named(self):
        errs = self.errs({"cluster": {"name": "x", "size": "small"},
                          "deployment_settings": "kaputt"})
        self.assertTrue(any("deployment_settings must be a mapping" in e
                            for e in errs), errs)

    def test_nodes_platform_as_a_string_is_named(self):
        errs = self.errs({"cluster": {"name": "x", "size": "small"},
                          "nodes": {"platform": "nope"}})
        self.assertTrue(any("nodes.platform must be a list" in e for e in errs),
                        errs)

    def test_a_node_entry_that_is_not_a_mapping_is_named(self):
        errs = self.errs({"cluster": {"name": "x", "size": "small"},
                          "nodes": {"platform": ["justastring",
                                                 {"hostname": "a", "ip": "1.2.3.4"}]}})
        self.assertTrue(any("not a mapping" in e for e in errs), errs)

    def test_a_string_section_does_not_crash_and_still_reports(self):
        # cluster/network/access as strings: coerced to {} so the reads cannot
        # raise, and the ordinary "missing" errors come out instead of a crash.
        for section in ("cluster", "network", "access", "loadbalancer"):
            with self.subTest(section=section):
                cfg = {"cluster": {"name": "x", "size": "small"},
                       section: "kaputt"}
                self.assertIsInstance(self.errs(cfg), list)   # no exception

    def test_reverse_proxies_as_a_string_is_named_not_iterated_char_by_char(self):
        errs = self.errs({"cluster": {"name": "x", "size": "small"},
                          "reverse_proxies": "10.0.0.1"})
        self.assertTrue(any("reverse_proxies must be a list" in e for e in errs),
                        errs)

    def test_a_valid_config_is_unaffected(self):
        # The hardening must not start flagging a good config. config.example.yml
        # is the canonical valid one.
        import pathlib

        import yaml
        example = pathlib.Path("config.example.yml")
        if not example.exists():
            self.skipTest("config.example.yml not present")
        cfg = yaml.safe_load(example.read_text())
        # It may have placeholder values that flag, but it must not raise and
        # must not be rejected for its SHAPE.
        errs = self.errs(cfg)
        self.assertFalse(any("mapping at the top level" in e for e in errs), errs)


class TestLoadingErrorsAreNamedNotThrown(unittest.TestCase):
    def test_broken_yaml_is_reported(self):
        real = config.load
        config.load = lambda _c: (_ for _ in ()).throw(
            __import__("yaml").YAMLError("mapping values are not allowed here"))
        try:
            cfg, err = cli._load_config("lab")
        finally:
            config.load = real
        self.assertIsNone(cfg)
        self.assertIn("not valid YAML", err)

    def test_a_missing_file_is_reported(self):
        real = config.load
        config.load = lambda _c: (_ for _ in ()).throw(
            FileNotFoundError("No config for cluster 'lab' (looked in ...)."))
        try:
            cfg, err = cli._load_config("lab")
        finally:
            config.load = real
        self.assertIsNone(cfg)
        self.assertIn("No config", err)

    def test_a_good_config_passes_through(self):
        real = config.load
        config.load = lambda _c: {"cluster": {"name": "x"}}
        try:
            cfg, err = cli._load_config("lab")
        finally:
            config.load = real
        self.assertIsNone(err)
        self.assertEqual(cfg, {"cluster": {"name": "x"}})


class TestDeployRefusesGarbageWithoutTraceback(unittest.TestCase):
    """End to end through the real gate: a broken file returns 1 with a message,
    never a traceback, and before any password or network."""

    def deploy(self, *, load):
        saved_load, saved_isatty = config.load, sys.stdout.isatty
        config.load = load
        sys.stdout.isatty = lambda: False
        err = io.StringIO()
        try:
            with redirect_stderr(err):
                rc = cli._deploy_locked("lab", None)
        finally:
            config.load, sys.stdout.isatty = saved_load, saved_isatty
        return rc, err.getvalue()

    def test_broken_yaml_returns_one_cleanly(self):
        import yaml

        def boom(_c):
            raise yaml.YAMLError("bad indent")
        rc, err = self.deploy(load=boom)
        self.assertEqual(rc, 1)
        self.assertIn("not valid YAML", err)

    def test_a_non_dict_config_returns_one_cleanly(self):
        rc, err = self.deploy(load=lambda _c: ["a", "b"])
        self.assertEqual(rc, 1)
        self.assertIn("mapping at the top level", err)


if __name__ == "__main__":
    unittest.main()
