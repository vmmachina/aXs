"""Builds ovftool invocations for phase 10.

Everything here is pure construction -- nothing is executed. The command is
built, shown, and only then run, so `--dry-run` and the real deploy differ in
exactly one step. That is deliberate: a 3.7 GB upload aimed at the wrong
datastore is expensive, and the command is the thing worth reviewing.

Key facts encoded here, all verified against the OVA descriptor and against
`ovftool --machineOutput` (see ova_profiles/26.07.yml):

  * Role and size are expressed ONCE, via --deploymentOption. The
    deploymentProfile property is userConfigurable="false" and follows
    automatically -- passing it with --prop: is an error.
  * The VM name comes from --name, not from the vm.vmname property, which is
    likewise not configurable.
  * Exactly nine properties are settable. DNS and dnsSearch are SPACE separated.
  * The OVA's signature cannot be verified against ovftool's trust store, but
    the manifest is valid and ovftool exits 0 without prompting, so no
    signature-related flag is needed.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import quote

import yaml

# Masks the password in a vi://user:pw@host target, whatever its encoding.
_VI_CRED = re.compile(r"(vi://[^:/@\s]+:)[^@/\s]+(@)")

# Where the operator extracts the ovftool package, and the version floor: 4.6.3
# breaks streamOptimized upload on ESXi 8.0.3, 5.1.0 is the verified minimum.
BINARY = "input/ovftool/ovftool"
MIN_VERSION = (5, 1, 0)


# Launching ovftool costs ~150 ms, and the requirements scan runs on every
# render of the first page (and once more from the CLI). Cache the answer per
# BINARY IDENTITY -- path, mtime, size and mode. Any of those changing means a
# different binary, so the cache expires exactly when it must: replacing the
# file (mtime/size) or making it executable (mode) forces a fresh run, which is
# what "Re-check" is for. No manual invalidation, no stale verdict.
_VERSION_CACHE: dict[tuple, tuple[int, ...] | None] = {}


def installed_version(binary: str = BINARY) -> tuple[int, ...] | None:
    """Run `ovftool --version` and parse (major, minor, patch). Returns None if
    the binary is missing or not runnable (e.g. not chmod +x). This is the ONE
    place that executes ovftool just to read its version -- shared by the
    requirements page (fail-fast) and by preflight so both agree on 5.1.0+."""
    try:
        st = os.stat(binary)
        key = (os.path.abspath(binary), st.st_mtime_ns, st.st_size, st.st_mode)
    except OSError:
        return None                      # missing -> nothing to cache
    if key in _VERSION_CACHE:
        return _VERSION_CACHE[key]
    try:
        out = subprocess.run([binary, "--version"],
                             capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        _VERSION_CACHE[key] = None
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    ver = tuple(int(x) for x in m.groups()) if m else None
    _VERSION_CACHE[key] = ver
    return ver

Role = Literal["bootstrap", "platform", "access"]
Size = Literal["small", "medium", "large"]

# Substituted for secret values when a command is displayed or logged.
REDACTED = "••••••••"


def load_profile(release: str = "26.07") -> dict:
    path = Path(__file__).parent / "ova_profiles" / f"{release}.yml"
    if not path.exists():
        raise FileNotFoundError(
            f"No OVA profile for release {release!r} (looked in {path}).\n"
            f"Available: {', '.join(sorted(p.stem for p in path.parent.glob('*.yml'))) or 'none'}"
        )
    return yaml.safe_load(path.read_text())


@dataclass
class VCenter:
    """Target vCenter. The password is never stored on this object."""

    host: str                       # vc01.lab.vmguru.io -- scheme stripped
    user: str                       # administrator@vsphere.local
    datacenter: str                 # DC01
    compute: str                    # CL01 -- a CLUSTER or a standalone HOST
    datastore: str
    network: str                    # portgroup mapped to the OVA's "Internet"
    folder: str | None = None       # VM folder; name or inventory path; None = root
    resource_pool: str | None = None  # pool under the cluster; "p" or "p/sub"; None = root pool

    def __post_init__(self) -> None:
        # Accept a pasted URL and reduce it to a bare host.
        h = self.host.strip()
        for prefix in ("https://", "http://", "vi://"):
            if h.startswith(prefix):
                h = h[len(prefix):]
        self.host = h.rstrip("/")

    def locator(self, password: str) -> str:
        """The vi:// target ovftool deploys into, credentials URL-encoded.

        ovftool 5.x does NOT read the password from stdin -- it loops forever
        (verified: a 645 MB log). The password must be embedded in the vi://
        target. User and password are percent-encoded so that '@', ':' or '/'
        in either survive. This does put the password in the process argument
        list for the duration of the run -- unavoidable with 5.x -- but
        `render()` masks it in everything shown or logged.
        """
        user = quote(self.user, safe="")
        pw = quote(password, safe="")
        target = f"vi://{user}:{pw}@{self.host}/{self.datacenter}/host/{self.compute}"
        if self.resource_pool:
            # Resource pools live under the cluster's "Resources"; nested pools
            # are slash-separated (Resources/parent/child). Empty = the cluster
            # root pool.
            target += "/Resources/" + self.resource_pool.strip("/")
        return target


@dataclass
class Node:
    """One VM to deploy."""

    role: Role
    vm_name: str                    # what the VM is called in vCenter
    hostname: str                   # short name written into the guest
    ip: str


@dataclass
class Network:
    netmask: str
    gateway: str
    dns: list[str]                  # joined with spaces for the DNS property
    search_domains: list[str]       # joined with spaces for dnsSearch
    docker_cidr: str | None = None  # omitted unless a subnet collision forces it


@dataclass
class Secrets:
    """Held only for the duration of a run; never written to config.yml."""

    root_password: str = field(repr=False, default="")
    configuser_password: str = field(repr=False, default="")

    def values(self) -> list[str]:
        return [v for v in (self.root_password, self.configuser_password) if v]


class PasswordPolicyError(ValueError):
    pass


def check_password(value: str, policy: dict, label: str) -> None:
    """Enforce the OVA's own policy before ovftool ever runs.

    The descriptor declares MinLen(15); the remaining rules come from the
    property description. Checking here means a bad password is rejected while
    the user types rather than after a 3.7 GB upload.
    """
    problems = []
    if len(value) < policy["min_length"]:
        problems.append(f"at least {policy['min_length']} characters (has {len(value)})")
    if policy.get("require_digit") and not any(c.isdigit() for c in value):
        problems.append("at least one digit (0-9)")
    if policy.get("require_uppercase") and not any(c.isupper() for c in value):
        problems.append("at least one uppercase letter (A-Z)")
    if policy.get("require_special") and value.isalnum():
        problems.append("at least one special character")
    if problems:
        raise PasswordPolicyError(
            f"{label} does not meet the appliance's requirements -- it needs "
            + "; ".join(problems)
            + ".\nThis policy comes from the OVA itself, not from this tool."
        )


def build(
    *,
    ova: Path,
    vcenter: VCenter,
    vcenter_password: str,
    node: Node,
    network: Network,
    secrets: Secrets,
    size: Size,
    profile: dict,
    power_on: bool = True,
    disk_mode: str = "thin",
) -> list[str]:
    """Assemble the argv for deploying one node.

    `vcenter_password` is passed in per call, never stored on VCenter, and ends
    up URL-encoded inside the vi:// target (see VCenter.locator). Feed the argv
    to `render()` before printing or logging so it gets masked.
    """
    if node.role == "bootstrap":
        # Bootstrap has no size variant: always 8 vCPU / 32 GB, per the OVA and
        # the install guide.
        option = profile["deployment_options"]["bootstrap"]
    else:
        option = profile["deployment_options"][node.role][size]

    p = profile["properties"]
    policy = profile["constraints"]
    check_password(secrets.root_password, policy["root_password"], "Root password")
    check_password(secrets.configuser_password, policy["configuser_password"],
                   "Configuser password")

    argv = [
        "ovftool",
        "--acceptAllEulas",
        "--noSSLVerify",
        f"--diskMode={disk_mode}",
        f"--name={node.vm_name}",
        f"--deploymentOption={option}",   # role + size, expressed once
        f"--datastore={vcenter.datastore}",
        f"--net:{profile['network']['name']}={vcenter.network}",
    ]
    if power_on:
        argv.append("--powerOn")
    if vcenter.folder:
        argv.append(f"--vmFolder={vcenter.folder}")

    props = {
        p["hostname"]: node.hostname,
        p["ip"]: node.ip,
        p["netmask"]: network.netmask,
        p["gateway"]: network.gateway,
        p["dns"]: " ".join(network.dns),                    # space separated
        p["dns_search"]: " ".join(network.search_domains),  # space separated
        p["root_password"]: secrets.root_password,
        p["configuser_password"]: secrets.configuser_password,
    }
    if network.docker_cidr:
        props[p["docker_cidr"]] = network.docker_cidr

    argv += [f"--prop:{k}={v}" for k, v in props.items()]
    argv += [str(ova), vcenter.locator(vcenter_password)]
    return argv


def render(argv: list[str], secrets: Secrets | None = None, wrap: bool = True) -> str:
    """Shell-quoted command with secrets masked -- safe to print and to log."""
    hidden = set(secrets.values()) if secrets else set()

    parts = []
    for arg in argv:
        for secret in hidden:
            if secret and secret in arg:
                arg = arg.replace(secret, REDACTED)
        # Mask the password in the vi://user:pw@host target regardless of how it
        # was percent-encoded -- the appliance passwords above are matched by
        # value, but the vCenter password only lives here.
        arg = _VI_CRED.sub(rf"\g<1>{REDACTED}\g<2>", arg)
        parts.append(shlex.quote(arg) if arg != REDACTED else arg)

    if not wrap:
        return " ".join(parts)
    # One argument per line: the point of showing the command is that a human
    # can check it, and a 900-character single line defeats that.
    head, *rest = parts
    return head + " \\\n" + " \\\n".join(f"    {x}" for x in rest)
