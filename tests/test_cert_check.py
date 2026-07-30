"""`certs.validate_cluster` -- the cross-check the configure wizard runs at four
call sites before a single asset is uploaded.

It had NO tests. That surfaced when a dead-code removal deleted `validate_for`
(0 callers) on the claim that validate_cluster was a strict superset, and the
review found it was not: validate_cluster added the certificate's CN to the
match pool unconditionally, so a cert whose CN covered the tenant but whose SANs
did not was reported green -- while every current TLS client, which ignores the
CN once a SAN extension is present (RFC 6125 §6.4.4), would refuse it. A check
friendlier than the system it vouches for (docs/08 E1).

These pin the fix -- CN counts only when there is no SAN at all -- and the two
verdicts that had lived in the data and reached no screen: the no-SAN warning
and the <30-day expiry warning.
"""

from __future__ import annotations

import datetime as _dt
import unittest

from ws1access import certs


def cert(sans=(), cn=None, days_left=None):
    info = certs.CertInfo(sans=sorted(s.lower() for s in sans), subject_cn=cn)
    if days_left is not None:
        info.not_after = (_dt.datetime.now(_dt.timezone.utc)
                          + _dt.timedelta(days=days_left))
    return info


def check(info, tenant="access", domain="lab.example", hosts=(), **kw):
    return certs.validate_cluster(info, tenant, domain, list(hosts), **kw)


class TestTheCnIsNotTrustedOverASan(unittest.TestCase):
    def test_cn_covers_the_tenant_but_sans_do_not_is_NOT_ok(self):
        # The exact case the review found. Browsers ignore the CN here, so a
        # green verdict would send the operator into a deploy that fails at the
        # first TLS handshake.
        info = cert(sans=["other.lab.example"], cn="access.lab.example")
        result = check(info)
        self.assertFalse(result.ok)
        tenant_name = next(n for n in result.names if n.role == "tenant")
        self.assertFalse(tenant_name.covered)

    def test_a_matching_san_is_ok_regardless_of_cn(self):
        info = cert(sans=["access.lab.example"], cn="something.else")
        self.assertTrue(check(info).ok)

    def test_a_cert_with_no_sans_falls_back_to_the_cn(self):
        # There the CN is all a client has, so it is honoured -- but flagged,
        # because a SAN-less certificate is a problem of its own.
        info = cert(sans=[], cn="access.lab.example")
        result = check(info)
        self.assertTrue(result.ok)
        self.assertTrue(any("no subject-alternative-name" in n.lower()
                            for n in result.notes), result.notes)

    def test_a_cert_with_sans_gets_no_such_note(self):
        info = cert(sans=["access.lab.example"], cn="access.lab.example")
        self.assertFalse(any("subject-alternative-name" in n.lower()
                             for n in check(info).notes))

    def test_a_wildcard_san_still_covers_the_tenant(self):
        self.assertTrue(check(cert(sans=["*.lab.example"])).ok)


class TestHelperNamesFollowTheEnabledAuth(unittest.TestCase):
    def test_helpers_are_not_required_when_their_auth_is_off(self):
        info = cert(sans=["access.lab.example"])
        result = check(info, cert_auth=False, sso=False)
        self.assertTrue(result.ok)
        helpers = [n for n in result.names if n.role in ("cert-helper",
                                                        "sso-helper")]
        self.assertTrue(helpers and not any(n.required for n in helpers))

    def test_a_missing_cert_helper_fails_only_when_cert_auth_is_on(self):
        info = cert(sans=["access.lab.example"])          # no -cert SAN
        self.assertTrue(check(info, cert_auth=False).ok)
        self.assertFalse(check(info, cert_auth=True).ok)

    def test_sso_helper_is_independent_of_cert_auth(self):
        info = cert(sans=["access.lab.example", "access-cert.lab.example"])
        # -amsso missing: fine unless sso is on, and cert_auth being on must not
        # drag it in.
        self.assertTrue(check(info, cert_auth=True, sso=False).ok)
        self.assertFalse(check(info, cert_auth=True, sso=True).ok)


class TestTheExpiryWarningReachesAScreen(unittest.TestCase):
    def test_a_cert_near_expiry_is_ok_but_carries_a_note(self):
        # 10 whole days after subtracting the time-of-day from timedelta(days=11).
        info = cert(sans=["access.lab.example"], days_left=11)
        result = check(info)
        self.assertTrue(result.ok)                        # still usable now
        self.assertTrue(any("expires in" in n and "days" in n
                            for n in result.notes), result.notes)

    def test_a_cert_with_plenty_of_time_has_no_expiry_note(self):
        info = cert(sans=["access.lab.example"], days_left=200)
        self.assertFalse(any("expires in" in n for n in check(info).notes))

    def test_an_expired_cert_is_not_ok(self):
        info = cert(sans=["access.lab.example"], days_left=-1)
        self.assertFalse(check(info).ok)


class TestBothWizardPagesRenderTheNotes(unittest.TestCase):
    """WEAKER than the tests above, and labelled so.

    The two render loops live in Textual worker methods (the review page and the
    final check before writing), so there is nothing importable to call: this
    asserts on SOURCE and cannot tell a real loop from a mention of one. It is
    here only to guard the specific defect the review named -- a note shown on
    one page and not the other, invisible on whichever path the operator takes.
    The verdict logic itself IS tested behaviourally above; only the rendering
    is source-checked. Recorded in tests/README.md under what the suite does not
    cover.
    """

    def test_neither_page_drops_the_notes(self):
        import inspect

        from ws1access import tui
        source = inspect.getsource(tui)
        # Both the review page (`r.notes`) and the write page (`cert.notes`).
        self.assertIn("r.notes", source)
        self.assertIn("cert.notes", source)
        # And not the empty-iterable trick that would render nothing.
        self.assertNotIn("for note in []:", source)


class TestAccessNodeNamesAreCheckedToo(unittest.TestCase):
    def test_every_access_node_fqdn_must_be_covered(self):
        info = cert(sans=["access.lab.example"])          # tenant only
        result = check(info, hosts=["wsa-acc-01"])
        self.assertFalse(result.ok)                       # node fqdn missing
        node = next(n for n in result.names if n.fqdn == "wsa-acc-01.lab.example")
        self.assertTrue(node.required and not node.covered)

    def test_a_wildcard_covers_the_nodes(self):
        info = cert(sans=["*.lab.example"])
        self.assertTrue(check(info, hosts=["wsa-acc-01", "wsa-acc-02"]).ok)


if __name__ == "__main__":
    unittest.main()
