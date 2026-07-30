"""Certificate handling -- normalisation and the tenant/domain cross-check.

The certificate is the anchor. The tenant and domain a user later puts into
access-profile.yml must be covered by the certificate's SANs, or the access
services deploy fails 40 minutes in. This module reads the SANs, proposes
tenant/domain from them so the values come from the cert rather than from
memory, and cross-checks a given tenant/domain against them.

Everything runs through the system `openssl` binary -- no compiled dependency
(see pyproject.toml). PFX is converted, never generated: no CSR, no self-signing,
no CA.
"""

from __future__ import annotations

import datetime as _dt
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


class CertError(Exception):
    pass


@dataclass
class CertInfo:
    sans: list[str] = field(default_factory=list)   # DNS SANs, lower-cased
    subject_cn: str | None = None
    not_after: _dt.datetime | None = None

    @property
    def expired(self) -> bool:
        if not self.not_after:
            return False
        return self.not_after < _dt.datetime.now(_dt.timezone.utc)

    @property
    def days_left(self) -> int | None:
        if not self.not_after:
            return None
        return (self.not_after - _dt.datetime.now(_dt.timezone.utc)).days


def _openssl(args: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["openssl", *args], input=stdin, capture_output=True
    )


_PEM_BLOCK = re.compile(rb"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL)


def _clean_pem(data: bytes) -> bytes:
    """Keep only the PEM blocks, dropping openssl's 'Bag Attributes' preamble.

    `openssl pkcs12` prefixes each object with friendlyName/localKeyID metadata;
    OpenSSL tolerates it, but stricter parsers on the appliance are happier with
    clean PEM. Returns the blocks joined with newlines, or the input unchanged if
    no block is found (so nothing is silently emptied)."""
    blocks = _PEM_BLOCK.findall(data)
    return b"\n".join(blocks) + b"\n" if blocks else data


def pem_from_pfx(pfx: Path, password: str) -> bytes:
    """Extract the certificate chain (no key) from a PFX as PEM.

    Retries with -legacy because PFX from older Windows CAs uses RC2/3DES, which
    OpenSSL 3.x moved to the legacy provider. Without the retry the error reads
    'digital envelope routines::unsupported', which looks like a broken cert but
    is a missing flag. The password goes via stdin, never on the command line.
    """
    base = ["pkcs12", "-in", str(pfx), "-clcerts", "-nokeys", "-passin", "stdin"]
    r = _openssl(base, stdin=(password + "\n").encode())
    if r.returncode != 0 and b"unsupported" in r.stderr.lower():
        r = _openssl([*base, "-legacy"], stdin=(password + "\n").encode())
        if r.returncode == 0:
            # Signal upward that the PFX uses outdated encryption.
            pass
    if r.returncode != 0:
        msg = r.stderr.decode(errors="replace").strip()
        if "mac verify failure" in msg.lower() or "invalid password" in msg.lower():
            raise CertError("The PFX password is wrong.")
        raise CertError(f"Could not read the PFX: {msg}")
    return r.stdout


def chain_pem_from_pfx(pfx: Path, password: str) -> bytes:
    """Leaf certificate PLUS the intermediate chain, as PEM.

    For SSL passthrough the appliance terminates TLS and must present the full
    chain to the browser, or clients see a trust error. Unlike pem_from_pfx
    (which uses -clcerts to isolate the leaf for SAN reading), this emits every
    certificate in the PFX (leaf first, then intermediates/root), which is what
    the appliance's custom_cert_file expects. Same -legacy retry; password via
    stdin, never on the argv.
    """
    base = ["pkcs12", "-in", str(pfx), "-nokeys", "-passin", "stdin"]
    r = _openssl(base, stdin=(password + "\n").encode())
    if r.returncode != 0 and b"unsupported" in r.stderr.lower():
        r = _openssl([*base, "-legacy"], stdin=(password + "\n").encode())
    if r.returncode != 0:
        msg = r.stderr.decode(errors="replace").strip()
        if "mac verify failure" in msg.lower() or "invalid password" in msg.lower():
            raise CertError("The PFX password is wrong.")
        raise CertError(f"Could not read the PFX chain: {msg}")
    return _clean_pem(r.stdout)


def key_from_pfx(pfx: Path, password: str) -> bytes:
    """Extract the private key from a PFX as unencrypted PEM.

    Used for SSL passthrough: the appliance presents the real certificate, so
    the cert and key are taken straight from the operator's PFX (the same anchor
    the whole dialog validates) and written as custom_cert_file/keyfile. Same
    -legacy retry as pem_from_pfx; password via stdin, never on the argv.
    """
    base = ["pkcs12", "-in", str(pfx), "-nocerts", "-nodes", "-passin", "stdin"]
    r = _openssl(base, stdin=(password + "\n").encode())
    if r.returncode != 0 and b"unsupported" in r.stderr.lower():
        r = _openssl([*base, "-legacy"], stdin=(password + "\n").encode())
    if r.returncode != 0:
        msg = r.stderr.decode(errors="replace").strip()
        if "mac verify failure" in msg.lower() or "invalid password" in msg.lower():
            raise CertError("The PFX password is wrong.")
        raise CertError(f"Could not read the PFX key: {msg}")
    return _clean_pem(r.stdout)


def read_cert(pem: bytes) -> CertInfo:
    """Parse SANs, CN and expiry out of a PEM certificate."""
    text = _openssl(
        ["x509", "-noout", "-subject", "-enddate", "-ext", "subjectAltName"],
        stdin=pem,
    )
    if text.returncode != 0:
        raise CertError(
            "The file is not a readable certificate: "
            + text.stderr.decode(errors="replace").strip()
        )
    out = text.stdout.decode(errors="replace")
    info = CertInfo()

    info.sans = sorted({m.lower() for m in re.findall(r"DNS:([^,\s]+)", out)})

    if m := re.search(r"CN\s*=\s*([^,/\n]+)", out):
        info.subject_cn = m.group(1).strip()

    if m := re.search(r"notAfter=(.+)", out):
        # e.g. "Mar 14 12:00:00 2027 GMT"
        try:
            info.not_after = _dt.datetime.strptime(
                m.group(1).strip(), "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            pass
    return info


def _san_covers(san: str, host: str) -> bool:
    """Does a single SAN cover a hostname, exact or single-label wildcard?"""
    san, host = san.lower(), host.lower()
    if san == host:
        return True
    if san.startswith("*."):
        # *.a.b covers x.a.b but not a.b itself and not x.y.a.b
        suffix = san[1:]                      # ".a.b"
        return host.endswith(suffix) and host[: -len(suffix)].count(".") == 0
    return False


def propose_tenant_domain(info: CertInfo) -> list[tuple[str | None, str]]:
    """Derive candidate (tenant, domain) pairs from the SANs.

    So the values come from the cert, not from the user's memory -- which is what
    kills the access.access.<domain> mistake at the root.

      *.lab.vmguru.io       -> (None, lab.vmguru.io)   ask for the tenant
      access.lab.vmguru.io  -> (access, lab.vmguru.io)
    """
    out: list[tuple[str | None, str]] = []
    seen = set()
    # Domains that have a wildcard SAN. A bare SAN equal to one of these is the
    # apex (e.g. lab.vmguru.io next to *.lab.vmguru.io) -- it is NOT a tenant, so
    # it must not be proposed as (lab, vmguru.io).
    wildcard_domains = {s[2:] for s in info.sans if s.startswith("*.")}
    for san in info.sans:
        if san.startswith("*."):
            pair = (None, san[2:])
        elif san in wildcard_domains:
            continue                      # apex of a wildcard -- skip
        else:
            head, _, rest = san.partition(".")
            # Skip the -cert / -amsso helper SANs when proposing the tenant.
            if head.endswith("-cert") or head.endswith("-amsso"):
                stripped = head.rsplit("-", 1)[0]
                if not rest or not stripped:
                    continue          # e.g. "-cert.d" or "host-cert" (no domain)
                pair = (stripped, rest)
            elif rest:
                pair = (head, rest)
            else:
                continue
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    return out


@dataclass
class NameCheck:
    """One required hostname and whether the certificate covers it."""
    fqdn: str
    role: str                 # tenant | access | cert-helper | sso-helper
    covered: bool
    via: str | None           # the SAN (or CN) that matched, if any
    required: bool = True


@dataclass
class ClusterCertCheck:
    """The full per-name verdict shown on the review page (step 3)."""
    cn: str | None
    sans: list[str]
    names: list[NameCheck]
    not_after: _dt.datetime | None
    expired: bool
    days_left: int | None
    ok: bool
    # Things the per-name table cannot say. Rendered by every caller -- the
    # review page and the final check before writing -- because a note only one
    # of them shows is a note the operator may never see.
    notes: list[str] = field(default_factory=list)


def _match(candidates: list[str], host: str) -> str | None:
    """First candidate SAN/CN that covers host (exact or wildcard), else None."""
    for c in candidates:
        if _san_covers(c, host):
            return c
    return None


def validate_cluster(
    info: CertInfo,
    tenant: str,
    domain: str,
    access_hostnames: list[str],
    *,
    cert_auth: bool = False,
    sso: bool = False,
) -> ClusterCertCheck:
    """Validate the delivered certificate against the REAL entered values.

    CN and SANs are matched (both count) against every name the cluster serves
    TLS on: the tenant FQDN and each access node's FQDN. The -cert / -amsso
    helper names are only *required* when the matching auth is enabled
    (certificate-based auth / SSO); otherwise they are shown but not required.
    A wildcard SAN covers them all in one go.
    """
    # The CN counts ONLY when there is no SAN extension at all.
    #
    # This used to add the CN to the pool unconditionally, and that made the
    # check friendlier than the thing it vouches for: every current TLS client
    # -- browsers since Chrome 58, and the Go and OpenSSL defaults -- ignores the
    # CN outright once a SAN extension is present (RFC 6125 §6.4.4). So a
    # certificate with CN=access.lab.example and SANs=[other.lab.example] was
    # reported as covering the cluster, and the first browser to reach the
    # tenant URL would refuse it. docs/08 E1 is exactly this rule.
    #
    # A certificate with NO SANs is a different case: there the CN is all a
    # client has, so it is used -- and said out loud, because such a certificate
    # is old enough to be a problem of its own.
    pool = list(info.sans)
    cn_only = not info.sans and bool(info.subject_cn)
    if cn_only:
        pool.append(info.subject_cn.lower())

    names: list[NameCheck] = []

    host = f"{tenant}.{domain}"
    via = _match(pool, host)
    names.append(NameCheck(host, "tenant", via is not None, via, required=True))

    for h in access_hostnames:
        fqdn = f"{h}.{domain}"
        via = _match(pool, fqdn)
        names.append(NameCheck(fqdn, "access", via is not None, via, required=True))

    for enabled, suffix, role in (
        (cert_auth, "cert", "cert-helper"),
        (sso, "amsso", "sso-helper"),
    ):
        fqdn = f"{tenant}-{suffix}.{domain}"
        via = _match(pool, fqdn)
        names.append(NameCheck(fqdn, role, via is not None, via, required=enabled))

    notes: list[str] = []
    if cn_only:
        notes.append(
            "This certificate carries NO subject-alternative-name extension, so "
            f"it was matched on its Common Name ({info.subject_cn}). Current TLS "
            "clients require SANs -- browsers have ignored the CN since 2017 -- "
            "so expect them to reject it even where this check passes.")
    if not info.expired and info.days_left is not None and info.days_left < 30:
        # Nothing read `days_left` before, so this warning existed in the data
        # and nowhere else: a certificate three weeks from expiry was accepted
        # in silence.
        notes.append(
            f"This certificate expires in {info.days_left} days "
            f"({info.not_after:%Y-%m-%d}). Replacing it means re-running the "
            "certificate steps on the cluster, so plan it before then.")

    required_ok = all(n.covered for n in names if n.required)
    return ClusterCertCheck(
        cn=info.subject_cn,
        sans=info.sans,
        names=names,
        not_after=info.not_after,
        expired=info.expired,
        days_left=info.days_left,
        ok=required_ok and not info.expired,
        notes=notes,
    )
