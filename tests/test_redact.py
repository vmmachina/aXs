"""redact() -- both directions.

Masking too little leaks a credential onto a screen or into a log. Masking too
much destroys the very output the operator diagnoses with: an Access service is
literally named `token`, so a rule that swallowed `"token": "READY"` would blind
phase 70's readiness report. Both failures happened during the 2026-07-28
review, which is why the preservations are tested as hard as the masks.
"""

from __future__ import annotations

import unittest

from ws1access.context import redact

MASK = "••••••••"


class TestRedactMasks(unittest.TestCase):
    """Inputs that MUST NOT survive intact."""

    def assert_masked(self, text: str, secret: str) -> None:
        out = redact(text)
        self.assertNotIn(secret, out, f"secret survived redact(): {out!r}")
        self.assertIn(MASK, out, f"nothing was masked in: {out!r}")

    def test_ansible_password_with_space(self):
        # Stopping at the first whitespace masked `Str0ng` and printed ` Pass!word`.
        # Nothing forbids a space in these passwords.
        self.assert_masked("ansible_password=Str0ng Pass!word", "Pass!word")

    def test_yaml_colon_form(self):
        # profile.yml is written by yaml.safe_dump, so its secrets appear in the
        # colon form -- which was not matched at all before 2026-07-28.
        self.assert_masked("password: geheim", "geheim")

    def test_yaml_colon_form_indented(self):
        self.assert_masked("  root_token: hvs.ABCDEF", "hvs.ABCDEF")

    def test_prefixed_vault_token_colon(self):
        # The asymmetry's other half: a PREFIXED token key is always a
        # credential, and wso prints these while initialising Vault straight
        # into the log we tail.
        self.assert_masked("vault_token: s.7Xy9QqAbC", "s.7Xy9QqAbC")

    def test_prefixed_token_header_form(self):
        self.assert_masked("x-vault-token: s.headerValue", "s.headerValue")

    def test_env_token_assignment(self):
        # The `=` form keeps bare `token` -- NOMAD_TOKEN=, CONSUL_TOKEN=.
        self.assert_masked("NOMAD_TOKEN=8f3c1e22-dead-beef", "8f3c1e22-dead-beef")

    def test_env_secret_assignment(self):
        self.assert_masked("client_secret=shhh", "shhh")

    def test_reset_password_link(self):
        # The single-use admin link from phase 80. report_log passed raw tails
        # through until 2026-07-28, and phase 80 tails exactly this file.
        self.assert_masked(
            "Reset password link: https://acc.example.com/reset?code=DEADBEEF",
            "DEADBEEF")

    def test_single_line_json_object(self):
        # `[{,]?` in the pattern: without it the `{` anchor broke the match.
        self.assert_masked('{"password": "hunter2"}', "hunter2")

    def test_vi_url_credential(self):
        # ovftool.render() masks on its way to argv logging; any OTHER path that
        # quotes a vi:// target -- an error tail, a traceback -- needs this.
        self.assert_masked("deploying to vi://user:s3cret@vc.example.com/dc",
                           "s3cret")

    def test_vi_url_urlencoded_user(self):
        # What aXs itself builds: VCenter.locator URL-encodes the user, so the
        # real vCenter account administrator@vsphere.local arrives as
        # administrator%40vsphere.local and the pattern holds.
        self.assert_masked(
            "vi://administrator%40vsphere.local:s3cret@vc.example.com/dc",
            "s3cret")

    def test_masks_per_line_not_only_first(self):
        # re.M with a `^` anchor: a secret on line two of a tail must not be
        # spared because line one was clean.
        out = redact("Starting deploy\nansible_password=p w\nDone")
        self.assertNotIn("p w", out)
        self.assertIn("Starting deploy", out)
        self.assertIn("Done", out)


class TestRedactPreserves(unittest.TestCase):
    """Inputs that MUST survive untouched. A mask here is a lost diagnosis."""

    def assert_unchanged(self, text: str) -> None:
        self.assertEqual(redact(text), text)

    def test_token_service_readiness(self):
        # An Access core service is named `token`. Masking this line would
        # destroy the readiness output phase 70 reports from.
        self.assert_unchanged('  "token": "READY",')

    def test_password_authentication_failed(self):
        # A reason, not a credential. No separator at all.
        self.assert_unchanged("password authentication failed")

    def test_prose_with_password_colon(self):
        # The colon rule requires the key at the start of the line precisely so
        # a sentence keeps its reason instead of ending in a mask.
        self.assert_unchanged("could not read password: permission denied")

    def test_keyword_must_end_the_key(self):
        # `secretsmanager=` is a setting, not a credential assignment.
        self.assert_unchanged("secretsmanager=on")

    def test_ordinary_readiness_line(self):
        self.assert_unchanged("usergroup: READY")


class TestRedactBehindAPrefix(unittest.TestCase):
    """Both gaps found while writing this suite, both now closed.

    The colon rule anchors the key at the start of the line on purpose, so
    prose keeps its reason. But wso stamps every control_plane.log line with a
    logger prefix, and phase 60 hands a raw tail of that file to a RemoteError
    which tui_deploy writes to clusters/<name>/deploy.log -- so the secret
    reached disk, not just the screen.
    """

    def test_secret_behind_a_cp_logger_prefix(self):
        out = redact("2026-07-23 05:11:54,499 p=184 u=root n=ansible INFO| "
                     "vault_token: s.leakedValue")
        self.assertNotIn("s.leakedValue", out)

    def test_the_prefix_itself_survives(self):
        # Masking the timestamp would take the diagnosis with it.
        out = redact("2026-07-23 05:11:54,499 p=184 u=root n=ansible INFO| "
                     "root_token: s.X")
        self.assertIn("2026-07-23 05:11:54,499 p=184 u=root n=ansible INFO|", out)

    def test_prose_behind_a_prefix_still_keeps_its_reason(self):
        # Allowing ONE measured prefix shape, not "anything before the key" --
        # otherwise the preservation cases come back as failures.
        text = ("2026-07-23 05:11:54,499 p=184 u=root n=ansible INFO| "
                "could not read password: permission denied")
        self.assertEqual(redact(text), text)

    def test_readiness_output_behind_a_prefix_survives(self):
        text = ('2026-07-23 05:11:54,499 p=184 u=root n=ansible INFO| '
                '"token": "READY"')
        self.assertEqual(redact(text), text)

    def test_vi_url_with_unencoded_at_in_user(self):
        # administrator@vsphere.local is THE standard vCenter SSO account.
        # aXs's own targets were covered only because VCenter.locator
        # URL-encodes the user; a hand-typed one was not.
        out = redact("vi://administrator@vsphere.local:s3cret@vc.example.com/dc")
        self.assertNotIn("s3cret", out)

    def test_vi_url_without_credentials_is_untouched(self):
        self.assertEqual(redact("vi://vc.example.com/dc"), "vi://vc.example.com/dc")

    def test_vi_url_with_a_port_but_no_password_is_untouched(self):
        # Widening the user part to cross '@' put this right next door: the
        # port then looked like a password. Masking it takes the diagnosis.
        text = "vi://administrator@vsphere.local:443/DC/host/esx"
        self.assertEqual(redact(text), text)

    def test_vi_url_with_a_later_at_sign_in_the_path_is_untouched(self):
        # vSphere inventory names may contain '@'. Without the password part
        # stopping at '/', this matched from the port to that '@' and masked
        # port and path both. Found by the Fable review of the widening.
        text = "vi://admin@vc.local:443/dc/host@cluster"
        self.assertEqual(redact(text), text)


class TestRedactStaysLinear(unittest.TestCase):
    """redact() runs over remote log tails, on the UI thread.

    The optional prefix sat in front of `\\s*[{,]?\\s*` -- two whitespace runs
    either side of an optional character. On a prefixed line followed by a long
    run of spaces the engine tried every way of splitting that run between
    them: 10.7 s for 1200 spaces, measured, up from ~0. A tail like that fits
    inside the 1500-character slice phase 80 already passes through here, so it
    was reachable, and it would have frozen the deploy UI.
    """

    PREFIX = "2026-07-23 05:11:54,499 p=184 u=root n=ansible INFO| "

    # Both sizes come from a measurement, not a guess. A timing test cannot
    # interrupt the call it measures, so a regression does not fail here -- it
    # BLOCKS here. Each input therefore has to be big enough to expose the
    # quadratic form and small enough that a regression costs seconds:
    #
    #   one line, n spaces        reverted    fixed
    #    5000                      0.48 s     0.0003 s
    #   15000                      4.17 s     0.0008 s   <- chosen
    #
    #   n lines x 60 spaces       reverted    fixed
    #   20  (1273 chars)           0.23 s     0.0006 s
    #   40  (2493 chars)           1.66 s     0.0020 s   <- chosen
    #   60  (3713 chars)           5.37 s     0.0044 s
    #
    # The multi-line case is far the worse per character: re.M retries the
    # pattern at EVERY line start, so the quadratic cost is paid once per line.
    # 40 lines is not a stress input -- it is exactly the `tail -n 40` phase 60
    # already passes through here.
    #
    # Caveat worth stating: this bounds the QUADRATIC form. Putting the trailing
    # `\\s*` back into _CP_PREFIX as well makes it cubic, and then these tests
    # hang rather than fail. Two separately documented edits would have to be
    # undone for that.
    SIZE = 15000
    LINES = 40
    LIMIT = 0.5

    def elapsed(self, text: str) -> float:
        import time
        start = time.perf_counter()
        redact(text)
        return time.perf_counter() - start

    def test_long_whitespace_run_behind_a_prefix(self):
        took = self.elapsed(self.PREFIX + " " * self.SIZE + "x")
        self.assertLess(took, self.LIMIT, f"redact took {took:.2f}s")

    def test_whitespace_spread_over_a_realistic_log_tail(self):
        # `\\s` matches newlines, so the run does not have to sit on one line.
        text = "\n".join([self.PREFIX] + [" " * 60] * self.LINES)
        took = self.elapsed(text)
        self.assertLess(took, self.LIMIT, f"redact took {took:.2f}s")


if __name__ == "__main__":
    unittest.main()
