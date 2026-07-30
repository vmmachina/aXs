"""The data behind the `configure` dialog -- pure, testable, no I/O layer.

This module owns WHAT is asked and what is written; the TUI in tui.py owns HOW
it is asked. Everything here is a pure function or a constant, so the dialog's
logic can be tested without a terminal:

  * PREREQS / prerequisites()  -- the files to stage, live-scanned (and for
    ovftool the version is actually read, so a too-old build fails fast).
  * ENV_NOTE / CERT_NOTE       -- the teaching blocks on the requirements page.
  * derive_defaults()          -- node hostnames/IPs proposed from the subnet.
  * build_config() / _write()  -- assemble and persist clusters/<name>/config.yml.

There used to be a second, questionary-based dialog in here that duplicated the
TUI. It had drifted (different defaults, its own texts referring to "step 2/3")
and was the source of several claims the TUI did not honour, so it is gone --
tui.py is the single path.
"""

from __future__ import annotations

import glob
import ipaddress
import os
import tempfile
from pathlib import Path

import yaml

from . import ovftool

ACCESS_COUNT = {"small": 2, "medium": 2, "large": 3}   # platform is always 3

# Where to obtain the staged files. The Access download page carries BOTH the
# node OVA and the asset bundle for 26.07; ovftool comes from Broadcom.
_DL_ACCESS = ("https://customerconnect.omnissa.com/downloads/info/slug/"
              "security_and_compliance/omnissa_workspace_one_access_vidm/26_07")
_DL_OVFTOOL = ("https://developer.broadcom.com/tools/"
               "open-virtualization-format-ovf-tool/latest")

# Files the operator stages under input/ before configuring. Each: key, label,
# glob, whether it blocks `configure`, a specific instruction, and where to get
# it (download URL, or None for the operator's own file).
PREREQS = [
    ("ovftool", "ovftool 5.1+  (whole package)", "input/ovftool/ovftool", True,
     "ovftool is not 'installed' -- it is EXTRACTED here so the tool can run it. "
     "Unpack the Broadcom download (Linux .zip / macOS .dmg) into input/ovftool/ "
     "so that input/ovftool/ovftool is the runnable binary WITH its runtime next "
     "to it (lib/ schemas/ env/ icudt44l.dat ...) -- not just the binary, not the "
     ".zip. Make it executable (chmod +x input/ovftool/ovftool). Use the build "
     "for THIS machine (the one that runs axs). preflight then runs "
     "'ovftool --version' and requires >= 5.1.0 (4.6.3 fails on ESXi 8.0.3).",
     _DL_OVFTOOL),
    ("ova", "node OVA (AlmaLinux base)", "input/ova/*.ova", True,
     "The AlmaLinux base .ova (e.g. alma-minimal-9.6-*-minimal.ova) in input/ova/.",
     _DL_ACCESS),
    ("bundle", "Access asset bundle 26.07", "input/assets/*.zip", True,
     "The Access asset bundle .zip (e.g. Access-asset-bundle-26.07.*.zip) in input/assets/.",
     _DL_ACCESS),
    ("cert", "TLS certificate (.pfx)", "input/certs/*.pfx", True,
     "Your PKCS#12 (.pfx) TLS certificate in input/certs/ -- see the note below.",
     None),
]

# Environment prerequisites -- everything that must be READY before configure,
# but is NOT a file to stage. Straight from the guide's "Voraussetzungen"
# (docs/03); listed so nothing bites later (LB missing -> phase 70 fails, DNS
# missing -> tenant unreachable). Info only, no values asked here.
ENV_NOTE = """\
ENVIRONMENT  -- must be in place BEFORE you deploy (not files -- your infra)

   [ ] vSphere / ESXi with capacity for the cluster VMs
          small/medium = 6 VMs, large = 7  (bootstrap is always 8 vCPU)
   [ ] vCenter reachable, with an account allowed to deploy OVAs
          datacenter, cluster, datastore and the VM port group ready
   [ ] Static IPs + gateway/netmask for every node, and node FQDNs in DNS
   [ ] DNS:  <tenant>.<domain>  must resolve to the LOAD BALANCER IP
   [ ] Load Balancer standing in front of the access nodes BEFORE deploy
          (access-profile.yml needs the LB IP + the certificate)
   [ ] configuser password -- identical on all nodes; it EXPIRES 60 days
          after the OVA deploy, so deploy within that window"""

def access_hostnames(n_access: int = 2, prefix: str = "wsa",
                     override: list[str] | None = None) -> list[str]:
    """The access node SHORT names, either from the naming scheme or given
    explicitly. A prefix covers the common case (<prefix>-acc-01, -02, ...);
    the override exists because plenty of sites have their own convention
    (dmz-auth-a, ...) and would otherwise order the wrong SANs. Explicit names
    win position by position; anything missing falls back to the scheme."""
    gen = [f"{prefix}-acc-{i:02d}" for i in range(1, max(1, n_access) + 1)]
    if not override:
        return gen
    return [(override[i] if i < len(override) else gen[i])
            for i in range(max(1, n_access))]


def cert_coverage(tenant: str = "access", domain: str = "lab.vmguru.io",
                  n_access: int = 2, prefix: str = "wsa",
                  access_override: list[str] | None = None) -> str:
    """The exact names a PFX must cover, for a given tenant/domain.

    The certificate usually has to be ORDERED before anything can be deployed,
    so the operator needs this list up front -- on the requirements page, long
    before the PFX exists. Feeding in the real domain turns the teaching example
    into the actual SAN list to request.

    The names mirror certs.validate_cluster exactly (tenant FQDN, one per access
    node, and the -cert/-amsso helpers), so what is promised here is what is
    checked later.
    """
    t = tenant or "access"
    d = domain or "lab.vmguru.io"
    nodes = [f"{h}.{d}" for h in
             access_hostnames(n_access, prefix, access_override)]
    pad = "\n" + " " * 36
    lines = [
        "CERTIFICATE  -- what your PFX must cover",
        "",
        f"   Clients reach the tenant at      {t}.{d}",
        f"   Each access node serves TLS on   {pad.join(nodes)}",
        "",
        "   The PFX must cover ALL of these -- in ONE of two forms:",
        "",
        "     wildcard",
        f"        CN  = *.{d}",
        f"        SAN = *.{d}",
        "        -> covers the tenant, every access node, and both helpers below",
        "",
        "     exact",
        f"        CN  = {t}.{d}",
        f"        SAN = {t}.{d}",
    ]
    lines += [f"        SAN = {n}" for n in nodes]
    lines += [
        "        plus, depending on the auth you enable:",
        f"        SAN = {t}-cert.{d}     only if you use certificate-based auth",
        f"        SAN = {t}-amsso.{d}    only if you use SSO",
    ]
    return "\n".join(lines)


# The teaching block on the requirements page. EXAMPLE values -- at this point
# the tool does not know the operator's real names; they are read from the PFX
# on the last page and validated there. The requirements page lets the operator
# type their own domain, which re-renders this same block with real names.
CERT_NOTE = cert_coverage()


def prerequisites(root: str = ".", *, check_version: bool = True) -> list[dict]:
    """Scan input/ for the staged files. Mostly a filesystem scan -- but for
    ovftool it also RUNS `ovftool --version`, so a too-old build (4.6.3) is
    caught HERE (fail-fast) instead of 20 min into the deploy. `satisfied` folds
    presence and the version gate into one flag the caller loops on.

    check_version=False skips launching ovftool (~150 ms) and marks the item
    `version_pending`. The UI uses that to paint the page immediately and fill
    the version in afterwards, instead of holding the first frame hostage to a
    subprocess.
    """
    out = []
    for key, label, pattern, required, instr, source in PREREQS:
        matches = sorted(glob.glob(str(Path(root) / pattern)))
        found = matches[0] if matches else None
        item = {
            "key": key, "label": label, "pattern": pattern,
            "required": required, "instruction": instr, "source": source,
            "found": found,
        }
        if key == "ovftool" and found:
            if check_version:
                ver = ovftool.installed_version(found)
                item["version"] = ".".join(map(str, ver)) if ver else None
                item["version_ok"] = ver is not None and ver >= ovftool.MIN_VERSION
            else:
                item["version_pending"] = True
        item["satisfied"] = bool(found) and item.get("version_ok", True)
        out.append(item)
    return out






def derive_defaults(
    *, gateway: str, netmask: str, domain: str, cluster_name: str,
    size: str, prefix: str = "wsa",
) -> dict:
    """Logical defaults from a few anchors -- orientation, each overridable.

    Node IPs/hostnames follow a scheme within the gateway's subnet (bootstrap
    .30, platform .1/.2/.3, access .11/.12[/.13]). These feed the dialog defaults
    and the node-layout table the user confirms in one go.
    """
    net = ipaddress.ip_network(f"{gateway}/{netmask}", strict=False)
    base = net.network_address
    n_access = ACCESS_COUNT.get(size, 2)

    def ip(offset: int) -> str:
        return str(base + offset)

    return {
        "netmask": netmask,
        "search_domains": [domain],
        "boot_host": f"{prefix}-boot-01",
        "boot_ip": ip(30),
        "platform": [{"hostname": f"{prefix}-platform-0{i}", "ip": ip(i)}
                     for i in (1, 2, 3)],
        "access": [{"hostname": f"{prefix}-acc-0{i}", "ip": ip(10 + i)}
                   for i in range(1, n_access + 1)],
        "folder": cluster_name,
        "admin_user": "admin",
        "port": 443,
    }


def build_config(a: dict) -> dict:
    """Assemble the config.yml dict from a flat answers dict. Pure.

    loadbalancer.mode is the TLS topology: termination (appliance self-signed) or
    passthrough (appliance presents the real cert). The tool never generates LB
    config -- it only records the mode, which drives is_self_signed.
    """
    size = a["size"]
    sc: dict = {"is_self_signed": a["is_self_signed"]}
    if not a["is_self_signed"]:
        sc["custom_cert_file"] = a["custom_cert_file"]
        sc["custom_cert_keyfile"] = a["custom_cert_keyfile"]

    cp: dict = {"enabled": a.get("cert_proxy_enabled", False)}
    if cp["enabled"]:
        cp["ssl_certificate_type"] = a.get("cert_proxy_type", "FQDN_CERT")
        if cp["ssl_certificate_type"] == "CUSTOM_CERT":
            cp["ssl_certificate_path"] = a.get("cert_proxy_path")
            cp["ssl_certificate_key"] = a.get("cert_proxy_key")

    cfg = {
        "version": 1,
        "cluster": {"name": a["cluster_name"], "size": size, "auth": a["auth"]},
        "loadbalancer": {"mode": a["lb_mode"]},
        "vcenter": {
            "host": a["vc_host"], "user": a["vc_user"],
            "datacenter": a["vc_datacenter"], "compute": a["vc_compute"],
            "datastore": a["vc_datastore"], "network": a["vc_network"],
            "folder": a.get("vc_folder"),
            "resource_pool": a.get("vc_resource_pool"),
        },
        "ova": {"path": a["ova_path"]},
        "reverse_proxies": a.get("reverse_proxies", []),
        "assets": {"bundle": a["bundle"]},
        "network": {
            "netmask": a["netmask"], "gateway": a["gateway"],
            "dns": a["dns"], "search_domains": a["search_domains"],
        },
        "access": {
            "domain": a["domain"], "lb_ip": a["lb_ip"], "port": a.get("port", 443),
            "server_certificate": sc,
            "first_tenant": {
                "tenant_name": a["tenant_name"],
                "admin_user_name": a["admin_user"],
                "admin_email": a["admin_email"],
                "admin_first_name": a["admin_first"],
                "admin_last_name": a["admin_last"],
            },
            "cert_proxy": cp,
            "smtp": a.get("smtp", {"enabled": False}),
        },
        "nodes": {
            "bootstrap": {"hostname": a["boot_host"], "ip": a["boot_ip"]},
            "platform": a["platform"],
            "access": a["access"],
        },
    }
    # Operational settings for profile.yml (NTP / NFS / logging / Nomad bridge).
    # Entirely optional: the key is only written when something is set, so a
    # config from before this existed stays byte-identical in meaning and phase
    # 50 leaves the file wso generated untouched.
    ops = _deployment_settings(a)
    if ops:
        cfg["deployment_settings"] = ops
    return cfg


def _deployment_settings(a: dict) -> dict:
    """The `deployment_settings` block -- only the parts the operator filled in.

    Empty backends are dropped rather than written as empty mappings: an empty
    `loki_server:` would look configured to wso while carrying nothing.
    """
    out: dict = {}
    for key in ("ntp_server", "nfs_host", "nfs_path", "nfs_version",
                "bridge_network_subnet"):
        if v := str(a.get(key) or "").strip():
            out[key] = v

    # The NFS-version field no longer defaults to "4" -- that default was applied
    # on submit even for a no-NFS deploy and leaked `nfs_version: '4'` into a
    # config the operator meant to leave empty. So supply the default HERE
    # instead, and only when NFS is actually configured: an operator who filled
    # in a host and path should not have to know 4 is the current version, but a
    # deploy with no NFS at all must carry no NFS keys. Matches Omnissa's own
    # example (nfs_version: 4).
    if out.get("nfs_host") and out.get("nfs_path") and "nfs_version" not in out:
        out["nfs_version"] = "4"

    # NOTE ON PASSWORDS. Loki/OpenSearch credentials are NOT stored here. They
    # would sit in clear text in clusters/<name>/config.yml on the operator's
    # machine, which contradicts what this project promises everywhere else
    # ("config.yml never contains secrets"). Instead the config records THAT a
    # password is needed, and `axs deploy` asks for it -- the same treatment the
    # vCenter and configuser passwords get. On the bootstrap the value does end
    # up in clear text inside profile.yml, because the vendor's format requires
    # it; that part is unavoidable and documented.
    logging: dict = {}
    if url := str(a.get("loki_url") or "").strip():
        loki = {"url": url}
        if u := str(a.get("loki_user") or "").strip():
            loki["username"] = u
            loki["password_prompt"] = True
        logging["loki_server"] = loki
    if url := str(a.get("os_url") or "").strip():
        osd = {"url": url}
        for src, dst in (("os_user", "username"),
                         ("os_index_prefix", "index_prefix")):
            if v := str(a.get(src) or "").strip():
                osd[dst] = v
        if osd.get("username"):
            osd["password_prompt"] = True
        logging["opensearch"] = osd
    # The template allows at most two syslog servers.
    servers = []
    for i in (1, 2):
        if host := str(a.get(f"syslog{i}_host") or "").strip():
            # A non-numeric port used to raise an uncaught ValueError right at
            # the moment the operator pressed Write. The dialog validates the
            # field now; this stays defensive for a hand-edited answers dict.
            raw = str(a.get(f"syslog{i}_port") or "").strip()
            servers.append({
                "host": host,
                "protocol": str(a.get(f"syslog{i}_protocol") or "udp").strip(),
                "port": int(raw) if raw.isdigit() else 514,
            })
    if servers:
        logging["syslog_servers"] = servers
    if logging:
        out["logging"] = logging
    return out






def _write(cluster: str, cfg: dict) -> Path:
    """Write config.yml atomically -- either the whole new file or the old one.

    `write_text` truncates first and then writes. A Ctrl-C, a full disk or a
    crash in that window left a HALF config.yml, and a truncated YAML file
    usually still parses -- it just silently lacks the last nodes, or the whole
    deployment_settings block. The next run would then deploy something the
    operator never configured, and the dialog is where they would look last.

    Write to a temp file in the SAME directory (os.replace is only atomic
    within one filesystem) and rename over the target. On POSIX that rename is
    atomic, so a reader sees one version or the other, never a half one.

    Two behaviour changes worth knowing, neither accidental:

      * The file ends up 0600, not the 0644 `write_text` produced -- mkstemp
        creates it that way and the rename keeps the mode. config.yml holds no
        passwords by design, but it does describe the customer's network in
        full, and no other account needs to read it. Pinned by a test, so it
        stays a decision rather than a side effect.
      * A `chmod 444` on config.yml no longer stops a rewrite: rename only
        needs write permission on the DIRECTORY. If freezing a config that way
        was ever load-bearing for someone, it has stopped working.
    """
    path = Path("clusters") / cluster / "config.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    body = yaml.safe_dump(cfg, sort_keys=False)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".config.yml.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            # The file object owns the descriptor from here on. Without this,
            # an os.fdopen that RAISES would leak the raw fd: the handler below
            # only removes the temp file.
            fd = -1
            f.write(body)
            # The rename is atomic, but the CONTENT still has to be on disk
            # behind it -- otherwise a power cut can leave the new name
            # pointing at an empty file, which is the failure this guards
            # against wearing a different hat. flush() first: fsync on an
            # unflushed buffer synchronises nothing.
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        # BaseException, not Exception: KeyboardInterrupt is the case named in
        # the defect. Leaving a .config.yml.*.tmp behind in the operator's
        # cluster folder would be its own small mess.
        if fd >= 0:
            os.close(fd)
        Path(tmp).unlink(missing_ok=True)
        raise
    return path




