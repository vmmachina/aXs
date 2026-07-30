"""`-c` names the cluster, and every command that acts on one requires it.

It used to be required for deploy/status/validate but OPTIONAL for configure,
which fell back to a 'default' cluster. So you could configure without naming a
cluster but not deploy without one, and a forgotten -c wrote
clusters/default/config.yml by surprise. Now all four require it; nothing acts
on an unnamed 'default'.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr

from ws1access.cli import build_parser

COMMANDS = ("configure", "deploy", "status", "validate")


class TestClusterFlagIsRequiredEverywhere(unittest.TestCase):
    def parse(self, argv):
        # argparse prints a usage error to stderr on a missing required arg;
        # swallow it so the suite output stays clean.
        with redirect_stderr(io.StringIO()):
            return build_parser().parse_args(argv)

    def test_each_command_refuses_to_run_without_c(self):
        for cmd in COMMANDS:
            with self.subTest(command=cmd):
                with self.assertRaises(SystemExit):   # argparse exits on missing -c
                    self.parse([cmd])

    def test_each_command_takes_the_named_cluster(self):
        for cmd in COMMANDS:
            with self.subTest(command=cmd):
                self.assertEqual(self.parse([cmd, "-c", "lab"]).cluster, "lab")

    def test_configure_specifically_no_longer_defaults(self):
        # The exact regression: configure was the odd one out.
        with self.assertRaises(SystemExit):
            self.parse(["configure"])
        self.assertEqual(self.parse(["configure", "-c", "prod"]).cluster, "prod")

    def test_phases_needs_no_cluster(self):
        # `phases` just lists the phase graph -- it acts on no cluster, so it
        # must NOT demand one.
        args = self.parse(["phases"])
        self.assertEqual(args.command, "phases")


if __name__ == "__main__":
    unittest.main()
