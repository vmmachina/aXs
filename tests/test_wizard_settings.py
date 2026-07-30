"""The optional profile.yml settings (page 6) honour "empty means off" -- and a
deploy no longer accepts a config it would choke on.

Two problems, found live on 2026-07-30:

1. The NFS-version field's default was "4". `fields_for` applies a field's
   default ON SUBMIT when the field is left empty, so leaving NTP, NFS host and
   path blank still wrote `deployment_settings: {nfs_version: '4'}` -- a version
   for a backup that does not exist. That lone key makes
   profile_yml.is_configured True, so phase 50 patches profile.yml and marks a
   rollout for a setting that configures nothing. The field default is now "";
   the "4" is supplied in build_config instead, and only when NFS is actually
   configured (host + path present).

2. `axs deploy` never ran the static checks -- only `axs validate` did. So an
   accidental entry (half-configured NFS, a leading colon in nfs_path, a bad
   version) flowed straight into the deploy and surfaced an hour later, or hung
   on an NFS mount to a wrong host. Deploy now validates first, for BOTH the TUI
   and the plain path, before any password or network.
"""

from __future__ import annotations

import unittest

from ws1access import configure, profile_yml
from ws1access.tui import fields_for


class TestTheNfsVersionFieldHasNoDefault(unittest.TestCase):
    def field(self, key: str):
        for f in fields_for("Time and backup", {}):
            if f.key == key:
                return f
        self.fail(f"no field {key!r} on the Time-and-backup page")

    def test_nfs_version_default_is_empty(self):
        # The regression guard: a non-empty default here is applied on submit
        # and leaks into a no-NFS deploy.
        self.assertEqual(self.field("nfs_version").default, "")

    def test_the_other_optional_fields_are_also_empty(self):
        # So "leave it empty and you get exactly the deployment you get today"
        # holds uniformly -- nfs_version was the sole violator.
        for key in ("ntp_server", "nfs_host", "nfs_path"):
            self.assertEqual(self.field(key).default, "", key)


class TestEmptyMeansOff(unittest.TestCase):
    """The block content is built by `_deployment_settings`; test it directly so
    the case does not need a whole answers dict."""

    def build(self, **answers):
        return configure._deployment_settings(answers)

    def test_all_blank_produces_no_block(self):
        # Every field left at its (now empty) default.
        blank = {f.key: (f.default or "")
                 for f in fields_for("Time and backup", {})}
        self.assertEqual(self.build(**blank), {})

    def test_nothing_at_all_produces_no_block(self):
        self.assertEqual(self.build(), {})

    def test_ntp_alone_is_written(self):
        self.assertEqual(self.build(ntp_server="ntp.example.com"),
                         {"ntp_server": "ntp.example.com"})

    def test_a_configured_nfs_keeps_the_version_given(self):
        self.assertEqual(
            self.build(nfs_host="10.0.0.9", nfs_path="/exports/cp",
                       nfs_version="3"),
            {"nfs_host": "10.0.0.9", "nfs_path": "/exports/cp",
             "nfs_version": "3"})

    def test_a_configured_nfs_without_a_version_gets_the_default(self):
        # The field is empty now, so this is the ordinary wizard case: host and
        # path filled, version left blank. It must NOT reach wso bare.
        out = self.build(nfs_host="10.0.0.9", nfs_path="/exports/cp")
        self.assertEqual(out["nfs_version"], "4")

    def test_no_nfs_gets_no_version_default(self):
        # The default must be gated on a real target, or we are back to the leak.
        self.assertNotIn("nfs_version", self.build(ntp_server="x"))


class TestLoggingDoesNotHaveTheSameLeak(unittest.TestCase):
    """Two logging fields DO carry non-empty defaults -- syslog protocol 'udp'
    and port '514' -- so the obvious worry is whether they leak the way
    nfs_version did. They do not, and this pins WHY: every logging setting is a
    GROUP gated on its key field (syslog on a host, loki/opensearch on a url),
    where nfs_version was a flat independent scalar answerable to nothing. If a
    future change moves a logging default out of its group, this goes red."""

    def blank_page7(self):
        return {f.key: (f.default or "")
                for f in fields_for("Central logging", {})}

    def test_the_whole_page_left_at_defaults_writes_no_logging(self):
        out = configure._deployment_settings(self.blank_page7())
        self.assertNotIn("logging", out)

    def test_the_syslog_defaults_apply_only_with_a_host(self):
        page = dict(self.blank_page7(), syslog1_host="log1.example.com")
        server = configure._deployment_settings(page)["logging"]["syslog_servers"][0]
        self.assertEqual(server["protocol"], "udp")
        self.assertEqual(server["port"], 514)

    def test_a_loki_user_without_a_url_is_dropped(self):
        # The same coherence one level over: credentials without a backend URL
        # configure nothing and must not be written.
        out = configure._deployment_settings({"loki_user": "svc"})
        self.assertNotIn("logging", out)


class TestDeployValidatesBeforeTouchingAnything(unittest.TestCase):
    """The gate that turns accidental input into a fast, named error instead of a
    stuck deploy. One place -- above the TUI/plain split -- so both engines are
    covered, and it runs before config.context prompts for a password."""

    def deploy(self, cfg: dict):
        import io
        import sys
        from contextlib import redirect_stderr

        from ws1access import cli, config

        saved_load, saved_isatty = config.load, sys.stdout.isatty
        config.load = lambda _c: cfg
        sys.stdout.isatty = lambda: False           # force the plain path
        err = io.StringIO()
        try:
            with redirect_stderr(err):
                # If validation were skipped this would block on getpass instead
                # of returning -- so a regression surfaces as a hang, which the
                # bad-config cases below would catch by never returning.
                rc = cli._deploy_locked("lab", None)
        finally:
            config.load, sys.stdout.isatty = saved_load, saved_isatty
        return rc, err.getvalue()

    GOODISH = {"cluster": {"name": "lab", "size": "small"}}

    def test_a_leading_colon_nfs_path_is_refused_before_any_work(self):
        cfg = dict(self.GOODISH,
                   deployment_settings={"nfs_host": "10.0.0.9",
                                        "nfs_path": ":/exports/cp",
                                        "nfs_version": "4"})
        rc, err = self.deploy(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("nfs_path", err)
        self.assertIn("nothing was changed", err.lower())

    def test_a_half_configured_nfs_is_refused(self):
        cfg = dict(self.GOODISH,
                   deployment_settings={"nfs_host": "10.0.0.9"})  # no path
        rc, err = self.deploy(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("nfs_host and nfs_path", err)

    def test_a_bad_nfs_version_is_refused(self):
        cfg = dict(self.GOODISH,
                   deployment_settings={"nfs_host": "10.0.0.9",
                                        "nfs_path": "/exports/cp",
                                        "nfs_version": "5"})
        rc, err = self.deploy(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("3 or 4", err)

    def test_an_accidentally_typed_lone_version_is_refused(self):
        # The exact "someone fills a field by accident and it hangs" worry: a
        # version typed into an otherwise-empty NFS section. Refused up front.
        cfg = dict(self.GOODISH,
                   deployment_settings={"nfs_version": "4"})
        rc, err = self.deploy(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("no NFS target", err)


if __name__ == "__main__":
    unittest.main()
