"""aXs Textual TUI for `configure` -- a five-page form. The only configure path.

Page 1  Requirements      : staged files (live-scanned, ovftool version really
                            read), the environment checklist, what the cert must
                            cover. Read-only; Next is blocked until it is met.
Page 2  Cluster & network : cluster name, size, SSH auth, subnet and DNS
Page 3  Nodes             : hostnames/IPs, proposed from the subnet on page 2
Page 4  Environment       : vCenter, Load balancer, Admin
Page 5  Certificate       : open the PFX, tenant/domain from its SANs, TLS
                            topology, full validation, then write config.yml.

Cluster/network and the nodes are separate pages on purpose: together they ran
to ~75 rows and always had to be scrolled, and this order lets the node defaults
derive from the subnet the user just entered.

Each page shows its sections as bordered boxes with room to breathe and a
description under every field. An existing config.yml is loaded so a restart
continues from the saved values. The form collects a flat answers dict and
hands it to configure.build_config -- the pure, tested assembly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.theme import Theme
from textual.widgets import Button, Footer, Header, Input, Label, Select, Static

from . import certs, configure, netcheck, profile_yml, validate
from .configure import ACCESS_COUNT, build_config, derive_defaults, _write

# Near-black neutral background (no blue cast); purple lives in the accents.
WS1_THEME = Theme(
    name="ws1purple", primary="#b98cff", secondary="#d6bcff", accent="#c084fc",
    foreground="#e8e6ee", background="#0b0b0e", surface="#111015", panel="#1c1a22",
    success="#34d399", warning="#fbbf24", error="#f87171", dark=True,
)

# The credit used to sit ABOVE the logo ("... presents..." plus a blank line):
# two rows of pure chrome on every page. The logo is five rows tall and the
# space to its right was empty, so the credit and the tagline both live there
# now -- same information, zero extra rows, identical on every page.
BANNER = r"""         __  __
   __ _  \ \/ /  ___
  / _` |  \  /  / __|
 | (_| |  /  \  \__ \   [dim]by Stefan Gourguis (Omnissa Tech Insider)[/dim]
  \__,_| /_/\_\ |___/   [b]— Omnissa Access Microservices Configuration and Deployment Toolkit[/b]"""

# Page title -> (subtitle, sections). The first page (requirements) and the last
# page (certificate) carry no form sections -- both are built specially.
PAGES = [
    ("Requirements",
     "What must be staged and ready before you configure. Nothing to fill in "
     "here -- read it, then press Next.",
     []),
    # The certificate gets its own page: the SAN list plus the early check ran
    # the requirements page past 80 rows, and planning/verifying the certificate
    # is a task of its own anyway -- usually done days before the deploy.
    ("Certificate plan",
     "Which names your certificate must carry -- and, if it is already staged, "
     "whether it really does. Preview only; nothing is saved here.",
     []),
    # Cluster/network and the node list used to share one page, which ran to
    # ~75 rows and always had to be scrolled. Split in two: each half now fits a
    # normal terminal, and the node defaults derive from the subnet entered on
    # the page before -- so the order also reads better.
    ("Cluster & network",
     "Name the cluster and define the subnet the cluster nodes live in.",
     ["Cluster", "Network"]),
    ("Nodes",
     "Hostnames and IPs for the cluster nodes (6 for small/medium, 7 for "
     "large). The suggestions follow the subnet above -- accept them or type "
     "your own.",
     ["Infra nodes", "Access nodes"]),
    # Load balancer and Admin share a box: two short sections cost two box
    # borders for six fields, and the page was the only one still scrolling.
    ("Environment",
     "Where the VMs are deployed and who administers the first tenant.",
     ["vCenter", "Load balancer and admin"]),
    # profile.yml, split over two pages: the three logging backends alone are
    # eleven fields and pushed a combined page to 70 rows. Both are optional --
    # each says so in its subtitle, because an operator who fills in nothing
    # gets the documented default deployment, not a lesser one.
    ("Time and backup",
     "What wso writes to profile.yml. ALL OPTIONAL — leave it empty and you get "
     "exactly the deployment you get today.",
     ["Time and backup", "Nomad network"]),
    ("Central logging",
     "Where the cluster ships its logs. ALSO OPTIONAL — but the one setting "
     "that cannot be changed later without a full redeployment.",
     ["Central logging"]),
    ("Certificate & validation",
     "Open your PFX, confirm tenant/domain from its names, pick the TLS "
     "topology, validate everything, then write the configuration.",
     []),
]


@dataclass
class F:
    key: str
    label: str
    kind: str = "text"            # text | ip | select
    default: str = ""
    choices: list | None = None
    optional: bool = False
    help: str = ""
    # kind="ip" fields are checked against the node subnet by default. The load
    # balancer VIP is the exception: it legitimately lives in another segment
    # (DMZ, dedicated LB network) -- the guide only requires that
    # <tenant>.<domain> resolves to it, never that it shares the node subnet.
    subnet_check: bool = True


# Facts that apply to a WHOLE section. Stating them once beats repeating the
# same sentence under every node field -- it reads better and saves the rows
# that used to force scrolling.
SECTION_HINTS = {
    # Detail that used to sit in per-field help lives here instead: a help text
    # long enough to wrap makes its cell taller, and the input then no longer
    # lines up with the one beside it. Section hints are full-width and cannot
    # do that -- so anything longer than a line belongs here.
    "Cluster":
        "Size commits real capacity: per access node small is 24 vCPU / 48 GB, "
        "medium 48/64, large 64/96. The OVA always ships a 200 GB disk, but the "
        "guide wants 300 GB (medium) or 400 GB (large) on the infra nodes — "
        "expand it after deployment, aXs cannot. On authentication: the "
        "configuser password is asked at the start of every 'axs deploy' either "
        "way and is never stored in this configuration, but with 'password' it "
        "is written into cp-cluster.ini on the bootstrap, as the guide's "
        "inventory requires.",
    "Infra nodes":
        "The bootstrap orchestrates the deployment (it runs the wso container). "
        "The three platform nodes are the internal control plane and need no "
        "tenant certificate. Every IP must be inside the subnet from the "
        "previous page, and hostnames must be unique DNS labels.",
    # The two warnings below are what `wso cp deploy` itself prints when these
    # are unset (verbatim, cp-deploy.log). They are quoted rather than
    # paraphrased because their weight differs: NTP is "recommended", NFS is
    # "required for disaster recovery" -- and the operator should read Omnissa's
    # words, not mine.
    "Time and backup":
        "Omnissa's deploy warns about both when unset. NTP: \"For production "
        "deployments, NTP server is highly recommended to prevent time drift.\" "
        "NFS: \"For production deployments, NFS is required for disaster "
        "recovery.\" Access is an identity provider — drifting clocks break "
        "SAML assertion windows and TOTP codes intermittently, on whichever "
        "node happens to answer. Write the NFS path plainly: Omnissa's example "
        "shows a leading colon, wso prepends one of its own, and the doubled "
        "'::' fails the deploy.\n"
        "The export must also let root stay root. Docker chowns a volume's "
        "directory when it creates the container, so an export that squashes "
        "root fails every service that uses the target — postgres first, and "
        "with no usable error in the deploy log. Linux: "
        "\"/srv/cpbackup 10.10.50.0/24(rw,sync,no_root_squash,no_subtree_check)\". "
        "macOS: \"-maproot=root\", never \"-mapall=<user>\". aXs mounts the "
        "target and tries exactly this chown before the deploy continues.",
    "Central logging":
        "Optional — but the one setting with a deadline: Omnissa's own note "
        "says changing it after the first deployment \"would require a full "
        "redeployment/upgrade of the cluster to take effect\". Decide now or "
        "redeploy later. A WRONG target is worse than none: an unreachable "
        "logging server is a documented cause of stuck service deploys. "
        "Passwords are not asked here and never stored in config.yml — if you "
        "name a user, 'axs deploy' asks for its password each run.",
    "Nomad network":
        "Only if Nomad's default bridge subnet collides with something you "
        "already run. Leave empty otherwise.",
    "vCenter":
        "Existing vCenter objects, spelled as they appear there. The password is "
        "asked at 'axs deploy' and never stored.",
    "Load balancer and admin":
        "aXs never configures the LB -- it only verifies <tenant>.<domain> "
        "resolves to this VIP, which may live in another segment. The admin is "
        "the first tenant's; its password is set via the reset link at the end.",
    "Access nodes":
        "These serve TLS behind the load balancer, so each node's FQDN "
        "(<hostname>.<domain>) must be covered by your certificate -- EITHER by "
        "its own SAN entry, OR by a wildcard SAN such as *.<domain>, which "
        "covers one level (wsa-acc-01.<domain>, but not a deeper subdomain). "
        "The certificate's CN counts as well. This is checked for real on the "
        "last page, against the PFX you open there.",
}


def _nodes_defaults(ans: dict) -> dict:
    # The prefix comes from the certificate-plan page. It must flow through
    # here as well: the SAN list the operator ORDERS from is built with it, so
    # the node hostnames proposed later have to match, or the certificate would
    # cover names the cluster never uses.
    return derive_defaults(
        gateway=ans.get("gateway") or "0.0.0.0",
        netmask=ans.get("netmask") or "255.255.255.0",
        domain="", cluster_name=ans.get("cluster_name") or "cp-cluster",
        size=ans.get("size") or "small",
        prefix=ans.get("prefix") or "wsa",
    )


def fields_for(name: str, ans: dict) -> list[F]:
    """Field definitions. F.default is a SUGGESTION only (shown as a placeholder,
    never pre-filled); it is applied on submit if the field is left empty."""
    if name == "Cluster":
        return [
            F("cluster_name", "Cluster name", "text", "cp-cluster",
              help="Working directory /root/<name> on the bootstrap. "
                   "Nothing to do with vCenter."),
            # vCPU/RAM and the disk gap are read from ova_profiles/26.07.yml
            # (the OVA's own VirtualHardwareSection) -- picking a size commits
            # real capacity, so it belongs here, not in a surprise later.
            F("size", "Deployment size", "select", "small",
              ["small", "medium", "large"],
              help="Access nodes: 2 (small/medium) or 3 (large). "
                   "Platform tier is always 3."),
            F("auth", "SSH authentication", "select", "key", ["key", "password"],
              help="How the bootstrap reaches the other nodes. "
                   "Key is recommended -- see the note above."),
        ]
    if name == "Network":
        return [
            F("gateway", "Gateway", "ip", "",
              help="Default gateway of the node subnet, e.g. 10.10.50.254."),
            F("netmask", "Netmask", "text", "255.255.255.0",
              help="Subnet mask shared by all cluster nodes."),
            F("dns", "DNS servers", "text", "",
              help="Space-separated. Also used to verify the tenant name "
                   "resolves to the LB."),
            F("search_domains", "Search domains", "text", "",
              help="Space-separated DNS search domains for the nodes, "
                   "e.g. lab.vmguru.io."),
        ]
    if name == "Infra nodes":
        # No per-field help here: it was the same sentence under every platform
        # node. The shared facts live in SECTION_HINTS once, which reads better
        # and costs a lot fewer rows.
        d = _nodes_defaults(ans)
        fs = [F("boot_host", "Bootstrap hostname", "text", d["boot_host"],
                help="Short DNS label, e.g. wsa-boot-01."),
              F("boot_ip", "Bootstrap IP", "ip", d["boot_ip"],
                help="Must be inside the subnet from the previous page.")]
        for i, n in enumerate(d["platform"]):
            fs.append(F(f"platform_{i}_host", f"Platform-{i+1} hostname", "text",
                        n["hostname"]))
            fs.append(F(f"platform_{i}_ip", f"Platform-{i+1} IP", "ip", n["ip"]))
        return fs
    if name == "Access nodes":
        # Same as above: the certificate rule is identical for every access node,
        # so it is stated once in SECTION_HINTS instead of under each field.
        d = _nodes_defaults(ans)
        # Names typed on the certificate-plan page win: the certificate was
        # ordered for THEM, so proposing the scheme here would invite a mismatch.
        override = (ans.get("access_override", "") or "").split()
        fs = []
        for i, n in enumerate(d["access"]):
            host = override[i] if i < len(override) else n["hostname"]
            fs.append(F(f"access_{i}_host", f"Access-{i+1} hostname", "text", host))
            fs.append(F(f"access_{i}_ip", f"Access-{i+1} IP", "ip", n["ip"]))
        return fs
    # --- profile.yml, all optional (see profile_yml.py) ------------------
    if name == "Time and backup":
        return [
            F("ntp_server", "NTP server", "text", "", optional=True,
              help="e.g. ntp.example.com or an IP."),
            F("nfs_host", "NFS host", "text", "", optional=True,
              help="Backup target, e.g. 10.10.50.200."),
            F("nfs_path", "NFS path", "text", "", optional=True,
              # Red on purpose: Omnissa's own example carries a leading colon,
              # and copying it kills the services deploy an hour later without
              # a usable error. This is the one field where the warning has to
              # win the eye.
              help="Plainly — [b #f87171]NO leading colon[/b #f87171]: "
                   "/controlplanenfs/us04pA"),
            # No default: this field's "suggestion" was applied on submit when
            # left empty (see fields_for), so a "4" here wrote
            # deployment_settings: {nfs_version: '4'} for a deploy the operator
            # meant to have NO NFS. Empty means empty, like every other field on
            # this page. When NFS IS configured, validate_config requires 3/4,
            # so a forgotten version fails fast rather than reaching wso bare.
            F("nfs_version", "NFS version", "text", "", optional=True,
              help="3 or 4 (required once an NFS host/path is set)."),
        ]
    if name == "Central logging":
        return [
            F("syslog1_host", "Syslog host", "text", "", optional=True,
              help="Leave empty if you do not use syslog."),
            F("syslog1_protocol", "Syslog protocol", "select", "udp",
              ["udp", "tcp", "tls"], optional=True,
              help="Transport to the syslog server."),
            F("syslog1_port", "Syslog port", "text", "514", optional=True,
              help="514 for udp/tcp, usually 6514 for tls."),
            F("syslog2_host", "Second syslog host", "text", "", optional=True,
              help="Optional. Omnissa allows at most two."),
            # No password fields here on purpose -- see the section hint.
            F("loki_url", "Loki URL", "text", "", optional=True,
              help="Base or push URL."),
            F("loki_user", "Loki user", "text", "", optional=True,
              help="Password is asked at deploy time."),
            F("os_url", "OpenSearch URL", "text", "", optional=True,
              help="Full HTTPS URL, e.g. https://search.example.com:9200"),
            F("os_user", "OpenSearch user", "text", "", optional=True,
              help="Password is asked at deploy time."),
            F("os_index_prefix", "Index prefix", "text", "", optional=True,
              help="Prefix for the OpenSearch indices."),
        ]
    if name == "Nomad network":
        return [
            F("bridge_network_subnet", "Nomad bridge subnet", "text", "",
              optional=True,
              help="CIDR, e.g. 10.90.0.0/24. Only needed if Nomad's default "
                   "collides with a network you already use."),
        ]
    if name == "vCenter":
        # Where these objects come from is one story, told once in SECTION_HINTS.
        # Only the genuinely field-specific notes stay here.
        return [
            F("vc_host", "vCenter host", "text", "", help="FQDN or IP."),
            F("vc_user", "vCenter user", "text", "",
              help="e.g. administrator@vsphere.local"),
            F("vc_datacenter", "Datacenter", "text", "",
              help="vSphere datacenter, e.g. DC01."),
            F("vc_compute", "Compute", "text", "",
              help="vSphere cluster (e.g. CL01) or a standalone ESXi host."),
            F("vc_resource_pool", "Resource pool", "text", "", optional=True,
              help="Empty = the cluster root pool."),
            F("vc_datastore", "Datastore", "text", "",
              help="Holds the VM disks -- needs room for every node."),
            F("vc_network", "Port group", "text", "",
              help="Mapped to the OVA's network, e.g. DMZ."),
            F("vc_folder", "VM folder", "text", "", optional=True,
              help="Empty = none."),
        ]
    if name == "Load balancer and admin":
        return [
            F("lb_ip", "Load balancer IP", "ip", "", subnet_check=False,
              help="The VIP clients connect to."),
            F("reverse_raw", "Reverse proxy IPs", "text", "", optional=True,
              help="Space-separated (UAG/F5). Empty = none."),
            F("admin_user", "Admin user", "text", "admin",
              help="Local admin account created in the first tenant."),
            F("admin_email", "Admin email", "text", "",
              help="Contact address of the tenant admin."),
            F("admin_first", "Admin first name", "text", "",
              help="Shown in the tenant console."),
            F("admin_last", "Admin last name", "text", "",
              help="Shown in the tenant console."),
        ]
    return []


def assemble(ans: dict, found: dict) -> dict:
    """Flat form answers -> the answers dict build_config expects."""
    d = _nodes_defaults(ans)
    a = dict(ans)
    a["dns"] = (ans.get("dns") or "").split()
    a["search_domains"] = (ans.get("search_domains") or "").split()
    a["platform"] = [
        {"hostname": ans.get(f"platform_{i}_host") or d["platform"][i]["hostname"],
         "ip": ans.get(f"platform_{i}_ip") or d["platform"][i]["ip"]}
        for i in range(3)
    ]
    a["access"] = [
        {"hostname": ans.get(f"access_{i}_host") or n["hostname"],
         "ip": ans.get(f"access_{i}_ip") or n["ip"]}
        for i, n in enumerate(d["access"])
    ]
    a["vc_resource_pool"] = ans.get("vc_resource_pool") or None
    a["vc_folder"] = ans.get("vc_folder") or None
    a["reverse_proxies"] = (ans.get("reverse_raw") or "").split()
    a["ova_path"] = found["ova"]
    a["bundle"] = found["bundle"]
    a["cert_pfx"] = found["cert"]
    return a


def answers_from_config(cfg: dict) -> dict:
    """Reverse of build_config: an existing config.yml -> flat form answers."""
    a: dict = {}
    c = cfg.get("cluster", {})
    a["cluster_name"] = c.get("name", "")
    a["size"] = c.get("size", "small")
    a["auth"] = c.get("auth", "key")
    a["lb_mode"] = cfg.get("loadbalancer", {}).get("mode", "termination")
    # Operational settings (profile.yml). Absent in configs written before this
    # existed -- everything stays empty then, which is the correct answer.
    ops = cfg.get("deployment_settings", {}) or {}
    for key in ("ntp_server", "nfs_host", "nfs_path", "nfs_version",
                "bridge_network_subnet"):
        a[key] = ops.get(key, "")
    # `logging: enabled` or `syslog_servers: {host: x}` in a hand-edited
    # config.yml used to crash this on load -- and this is `axs configure`, the
    # tool the operator would use to REPAIR that config.
    log = profile_yml.mapping(ops.get("logging"))
    loki = profile_yml.mapping(log.get("loki_server"))
    a["loki_url"], a["loki_user"] = loki.get("url", ""), loki.get("username", "")
    osd = profile_yml.mapping(log.get("opensearch"))
    a["os_url"], a["os_user"] = osd.get("url", ""), osd.get("username", "")
    a["os_index_prefix"] = osd.get("index_prefix", "")
    for i, s in enumerate(profile_yml.syslog_entries(log), start=1):
        a[f"syslog{i}_host"] = s.get("host", "")
        a[f"syslog{i}_protocol"] = s.get("protocol", "udp")
        a[f"syslog{i}_port"] = str(s.get("port", 514))
    vc = cfg.get("vcenter", {})
    a["vc_host"] = vc.get("host", "")
    a["vc_user"] = vc.get("user", "")
    a["vc_datacenter"] = vc.get("datacenter", "")
    a["vc_compute"] = vc.get("compute", "")
    a["vc_resource_pool"] = vc.get("resource_pool") or ""
    a["vc_datastore"] = vc.get("datastore", "")
    a["vc_network"] = vc.get("network", "")
    a["vc_folder"] = vc.get("folder") or ""
    net = cfg.get("network", {})
    a["netmask"] = net.get("netmask", "")
    a["gateway"] = net.get("gateway", "")
    a["dns"] = " ".join(net.get("dns", []) or [])
    a["search_domains"] = " ".join(net.get("search_domains", []) or [])
    acc = cfg.get("access", {})
    a["domain"] = acc.get("domain", "")
    a["lb_ip"] = acc.get("lb_ip", "")
    ft = acc.get("first_tenant", {})
    a["tenant_name"] = ft.get("tenant_name", "")
    a["admin_user"] = ft.get("admin_user_name", "admin")
    a["admin_email"] = ft.get("admin_email", "")
    a["admin_first"] = ft.get("admin_first_name", "")
    a["admin_last"] = ft.get("admin_last_name", "")
    a["is_self_signed"] = acc.get("server_certificate", {}).get("is_self_signed", True)
    a["cert_proxy_enabled"] = acc.get("cert_proxy", {}).get("enabled", False)
    a["reverse_raw"] = " ".join(cfg.get("reverse_proxies", []) or [])
    nodes = cfg.get("nodes", {})
    b = nodes.get("bootstrap", {})
    a["boot_host"] = b.get("hostname", "")
    a["boot_ip"] = b.get("ip", "")
    for i, n in enumerate(nodes.get("platform", [])):
        a[f"platform_{i}_host"] = n.get("hostname", "")
        a[f"platform_{i}_ip"] = n.get("ip", "")
    for i, n in enumerate(nodes.get("access", [])):
        a[f"access_{i}_host"] = n.get("hostname", "")
        a[f"access_{i}_ip"] = n.get("ip", "")
    return a


def _sid(name: str) -> str:
    return name.replace(" ", "_").lower()


CSS = """
Screen { background: $surface; }
Header { background: $primary; color: $background; text-style: bold; }
#form { padding: 0 3 1 3; }
#banner { color: $primary; text-style: bold; height: auto; }
/* The shared splash (see _splash.py) -- same look in configure and deploy. */
#axe { color: $primary; height: auto; content-align: center top; }
#splash_ctx { color: $text-muted; height: auto; content-align: center top;
              padding: 1 0 0 0; }
#welcome_tag { color: $text-muted; text-style: italic; height: auto;
               content-align: center top; }
#body { padding: 1 3 1 3; }
#pagetitle { color: $secondary; text-style: bold; height: auto; margin: 1 0 0 0; }
#pagesub { color: $text-muted; text-style: italic; height: auto; }
#steps { height: auto; margin: 0 0 1 0; color: $text-muted; }

/* Bordered section boxes. height:auto everywhere -- Vertical defaults to 1fr,
   which CLIPS rows (fields would vanish). */
.secbox { border: round $primary 40%; border-title-color: $primary;
          border-title-style: bold; padding: 1 2; margin: 1 0 0 0; height: auto; }
.secbox:focus-within { border: round $primary; }
#pagebody { height: auto; }
#afteropen { height: auto; }
#naming_box { height: auto; }
.row { height: auto; }
.cell { width: 1fr; padding: 0 2 1 0; height: auto; }
.cell Label { color: $secondary; text-style: bold; }
.help { color: $text-muted; height: auto; min-height: 1; }
.hint { color: $text-muted; text-style: italic; height: auto; }

Input { border: none; height: 1; background: $panel; padding: 0 1; }
Input:focus { background: $boost; }
Select { height: 3; }

#nav { height: 3; align: center middle; background: $panel; }
#nav Button { margin: 0 2; }
#go { min-width: 26; }
#formerror { color: $error; text-style: bold; padding: 0 3; height: auto; }
#result { padding: 0 1; height: auto; }
"""


class FormScreen(Screen):
    BINDINGS = [("escape", "quit_app", "Exit")]

    def __init__(self, app_ref: "ConfigureApp") -> None:
        super().__init__()
        self._app = app_ref
        self.page = 0
        self.info = None
        self.props: list = []
        self.state = "validate"   # validate -> write (two explicit presses)
        self._req_items: list = []   # last requirements scan (page 1 gate)

    # -- layout -----------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="form"):
            yield Static(BANNER, id="banner")
            yield Static("", id="steps")
            yield Static("", id="pagetitle")
            yield Static("", id="pagesub")
            yield Vertical(id="pagebody")
            yield Static("", id="result")
        yield Static("", id="formerror")
        with Horizontal(id="nav"):
            yield Button("Exit", id="quit", variant="error")
            yield Button("< Back", id="back")
            yield Button("Next >", id="next", variant="primary")
            yield Button("Validate", id="go", variant="primary")
        yield Footer()

    async def on_mount(self) -> None:
        await self.render_page()

    def _steps_line(self) -> str:
        parts = []
        for i, (title, _, _) in enumerate(PAGES):
            n = f"{i+1}. {title}"
            parts.append(f"[reverse b] {n} [/]" if i == self.page
                         else (f"[green]{n}[/]" if i < self.page else f"[dim]{n}[/]"))
        return "   ".join(parts)

    async def render_page(self) -> None:
        title, sub, sections = PAGES[self.page]
        first = self.page == 0
        self.query_one("#steps", Static).update(self._steps_line())
        self.query_one("#pagetitle", Static).update(
            f"Page {self.page+1} of {len(PAGES)} — {title}")
        self.query_one("#pagesub", Static).update(sub)
        self.query_one("#result", Static).update("")
        self.query_one("#formerror", Static).update("")
        body = self.query_one("#pagebody", Vertical)
        await body.remove_children()
        last = self.page == len(PAGES) - 1
        self.query_one("#back", Button).display = self.page > 0
        self.query_one("#next", Button).display = not last
        go = self.query_one("#go", Button)
        go.display = last
        self._reset_go()
        if first:
            await self._render_requirements_page(body)
        elif self.page == 1:
            await self._render_certplan_page(body)
        elif not last:
            for name in sections:
                box = Vertical(id=f"sec_{_sid(name)}", classes="secbox")
                box.border_title = f" {name.upper()} "
                await body.mount(box)
                await self._render_section(name, box)
        else:
            await self._render_cert_page(body)
        self.query_one("#form", VerticalScroll).scroll_home(animate=False)

    async def _render_section(self, name: str, box: Vertical) -> None:
        fields = fields_for(name, self._app.answers)
        if hint := SECTION_HINTS.get(name):
            await box.mount(Static(hint, classes="hint"))
        for i in range(0, len(fields), 2):
            row = Horizontal(classes="row")
            await box.mount(row)
            for f in fields[i:i + 2]:
                cell = Vertical(classes="cell")
                await row.mount(cell)
                await cell.mount(Label(f.label + ("  (optional)" if f.optional else "")))
                # Mount the help row ALWAYS, even when there is nothing to say.
                # A cell without it is one line shorter than the cell beside it,
                # and its input stops lining up -- which is how the columns
                # drifted apart on the vCenter page. Every field now carries a
                # one-liner; this keeps the layout honest if one ever does not.
                await cell.mount(Static(f.help or " ", classes="help"))
                value = self._app.answers.get(f.key, "")
                if f.kind == "select":
                    await cell.mount(Select(
                        [(c, c) for c in (f.choices or [])], value=value or f.default,
                        allow_blank=False, id=f"w_{f.key}"))
                else:
                    await cell.mount(Input(value=value, placeholder=f.default,
                                           id=f"w_{f.key}"))
        if name == "Access nodes":
            # These names are the ones the certificate has to cover. The plan
            # page built the SAN list from a prefix, but here each hostname can
            # be typed freely -- so say immediately whether the result still
            # matches, instead of letting it surface two pages later.
            await box.mount(Static(self._access_cert_note(), id="acc_cert_note",
                                   classes="help"))

    def _access_cert_note(self) -> str:
        """One line: do the access hostnames entered here still match the
        certificate? Only possible once the PFX has been opened (plan page);
        otherwise it says where it will be checked."""
        ans = self._app.answers
        domain = ans.get("domain", "")
        try:
            hosts = [str(w.value or w.placeholder or "").strip()
                     for w in (self.query_one(f"#w_access_{i}_host", Input)
                               for i in range(ACCESS_COUNT.get(
                                   ans.get("size", "small"), 2)))]
        except Exception:
            return ""
        if not domain:
            return ("Certificate coverage is checked on the last page, once the "
                    "domain is known.")
        if self.info is None:
            names = ", ".join(f"{h}.{domain}" for h in hosts if h)
            return (f"These become {names}. The certificate is checked against "
                    "them on the last page.")
        bad = [f"{h}.{domain}" for h in hosts
               if h and not certs.validate_cluster(
                   self.info, ans.get("tenant_name") or "access", domain, [h]
               ).names[1].covered]
        if bad:
            return ("NOT covered by the certificate you checked: "
                    + ", ".join(bad) + " -- rename them back, or get a "
                    "certificate that includes these names.")
        return "All these names are covered by the certificate you checked. ✔"

    def _coverage_text(self) -> str:
        """The SAN list for the tenant/domain typed on the requirements page.

        Falls back to the documented example while the fields are empty. The
        node count follows the chosen size if one is already known (a reloaded
        config), otherwise small -- the list is a preview, and the last page
        validates the real certificate anyway."""
        ans = self._app.answers
        kw = {}
        size = ans.get("size", "small")
        try:
            tenant = self.query_one("#w_req_tenant", Input).value.strip()
            domain = self.query_one("#w_req_domain", Input).value.strip()
            size = self.query_one("#w_req_size", Select).value or size
        except Exception:                      # first render: widgets not mounted
            tenant, domain = ans.get("tenant_name", ""), ans.get("domain", "")
        prefix, override = self._naming_values()
        if tenant:
            kw["tenant"] = tenant
        if domain:
            kw["domain"] = domain
        if prefix:
            kw["prefix"] = prefix
        if override:
            kw["access_override"] = override
        # large deploys THREE access nodes, so its certificate needs a third
        # node SAN. The size is picked on a later page, so ask for it here too --
        # otherwise the list would silently under-report for large.
        kw["n_access"] = ACCESS_COUNT.get(size, 2)
        text = configure.cert_coverage(**kw)
        return text.split("\n", 1)[1].lstrip("\n")     # heading is the box title

    async def _render_requirements_page(self, body: Vertical) -> None:
        """Read-only overview shown FIRST: the staged files (live-checked, incl.
        the real ovftool version), the environment that must exist before deploy,
        and what the certificate must cover. A dedicated page, so it can be
        explicit -- nothing to fill in, just 'do I have everything?' before the
        questions begin."""
        from rich.text import Text
        ans = self._app.answers
        # Paint first, probe second: the file scan is a glob and instant, but
        # `ovftool --version` launches a process (~150 ms). Skip it here, show
        # the line as "checking", and fill it in from a worker -- the page is up
        # immediately instead of waiting on a subprocess.
        items = configure.prerequisites(".", check_version=False)
        # Keep the scan so Next can gate on it, and let the rest of the app use
        # the paths found HERE (the user may have staged a file since launch).
        self._req_items = items
        self._app.found = {it["key"]: it["found"] for it in items}

        fbox = Vertical(id="sec_req_files", classes="secbox")
        fbox.border_title = " FILES  (staged under input/) "
        await body.mount(fbox)
        await fbox.mount(Static(
            "Checked live every time this page opens -- ovftool is actually run "
            "to read its version. Stage a missing file, then press Re-check.",
            classes="hint"))
        await fbox.mount(Static(self._files_lines(), id="req_files"))
        await fbox.mount(Button("Re-check", id="recheck"))
        self._sync_recheck_button()

        ebox = Vertical(id="sec_req_env", classes="secbox")
        ebox.border_title = " ENVIRONMENT "
        await body.mount(ebox)
        await ebox.mount(Static(
            "aXs cannot create these for you -- have them ready before deploy:",
            classes="hint"))
        # ENV_NOTE / CERT_NOTE are pre-formatted and contain literal '[ ]' -- render
        # as plain Text so Rich does not try to parse them as markup.
        await ebox.mount(Static(Text(configure.ENV_NOTE.split("\n\n", 1)[1])))

        # Page is complete and on screen. NOW ask ovftool for its version, off
        # the UI thread, and fill the line in when the answer arrives.
        if any(it.get("version_pending") for it in items):
            self.run_worker(self._probe_versions, thread=True,
                            group="reqscan", exclusive=True)

    def _files_lines(self) -> str:
        """The FILES block. Rebuilt in place once the version probe returns, so
        the page never waits for a subprocess to show what it already knows."""
        lines: list[str] = []
        for it in self._req_items:
            if it.get("version_pending"):
                mark = "[dim]····[/dim]"
            elif it["satisfied"]:
                mark = "[green] ok [/green]"
            elif it["found"]:
                mark = "[yellow]OLD [/yellow]"
            else:
                mark = "[red]MISS[/red]"
            where = it["found"] or it["pattern"]
            if it.get("version_pending"):
                where += "   [dim](checking version ...)[/dim]"
            elif it.get("version"):
                where += f"   [dim](v{it['version']})[/dim]"
            elif it["key"] == "ovftool" and it["found"]:
                where += "   [dim](version unreadable — chmod +x?)[/dim]"
            lines.append(f"  {mark}  {it['label']:<30} {where}")
            if not it["satisfied"] and not it.get("version_pending"):
                lines.append(f"        [dim]{it['instruction']}[/dim]")
                if it.get("source"):
                    lines.append(f"        [b]download:[/b] {it['source']}")
        return "\n".join(lines)

    def _sync_recheck_button(self) -> None:
        """Re-check is only useful while something is actually unmet."""
        try:
            btn = self.query_one("#recheck", Button)
        except Exception:
            return
        btn.display = any(it["required"] and not it["satisfied"]
                          and not it.get("version_pending")
                          for it in self._req_items)

    def _probe_versions(self) -> None:
        """Worker thread: run the slow probe, then hand the result back."""
        fresh = configure.prerequisites(".")
        self._app.call_from_thread(self._versions_done, fresh)

    def _versions_done(self, fresh: list[dict]) -> None:
        self._req_items = fresh
        self._app.found = {it["key"]: it["found"] for it in fresh}
        if self.page != 0:
            return                     # user moved on; state is updated anyway
        try:
            self.query_one("#req_files", Static).update(self._files_lines())
        except Exception:
            return
        self._sync_recheck_button()

    def _check_cert_now(self) -> None:
        """Early certificate check on the plan page.

        Opens the staged PFX and runs certs.validate_cluster -- the very same
        function the final page uses, so the two can never disagree. Empty
        tenant/domain are filled from the certificate's own SANs first, which
        makes this usable as "what does this certificate actually cover?".
        The opened certificate is kept, so the last page does not ask for the
        password a second time.
        """
        out = self.query_one("#req_val_result", Static)
        pfx = self._app.found.get("cert")
        if not pfx:
            out.update("[yellow]No .pfx staged yet[/yellow] -- put it in "
                       "input/certs/ and press Re-check on the previous page.")
            return
        pw = self.query_one("#w_req_pw", Input).value
        try:
            info = certs.read_cert(certs.pem_from_pfx(Path(pfx), pw))
        except certs.CertError as e:
            out.update(f"[red]Could not open the certificate:[/red] {e}")
            return

        t_in = self.query_one("#w_req_tenant", Input)
        d_in = self.query_one("#w_req_domain", Input)
        tenant, domain = t_in.value.strip(), d_in.value.strip()
        note = ""
        if not tenant or not domain:
            props = certs.propose_tenant_domain(info)
            if props:
                p_t, p_d = props[0]
                tenant = tenant or (p_t or "access")
                domain = domain or p_d
                t_in.value, d_in.value = tenant, domain
                note = "  [dim](tenant/domain taken from the certificate)[/dim]"
                self._refresh_coverage()
            else:
                out.update("[yellow]The certificate has no usable SANs[/yellow] "
                           "-- type tenant and domain yourself.")
                return

        size = self.query_one("#w_req_size", Select).value or "small"
        prefix, override = self._naming_values()
        hosts = configure.access_hostnames(ACCESS_COUNT.get(size, 2),
                                           prefix or "wsa", override)
        r = certs.validate_cluster(info, tenant, domain, hosts)

        L = [f"[b]Certificate check[/b]{note}",
             f"  CN = {info.subject_cn or '(none)'}"]
        for nm in r.names:
            if nm.covered:
                L.append(f"  [green]ok[/green]   {nm.fqdn}  via {nm.via}")
            elif nm.required:
                L.append(f"  [red]MISSING[/red] {nm.fqdn}")
            else:
                L.append(f"  [dim]--   {nm.fqdn} ({nm.role}) -- only needed if "
                         f"you enable that auth[/dim]")
        if info.expired:
            L.append("  [red]FAIL[/red] the certificate has expired")
        for note in r.notes:
            L.append(f"  [yellow]![/yellow] {note}")
        L.append("")
        L.append("[green]This certificate covers the cluster.[/green]"
                 if r.ok and not info.expired else
                 "[yellow]Not sufficient yet[/yellow] -- request the missing "
                 "names, or use a wildcard certificate for the domain.")
        # Say what this verdict is worth: it used the PLANNED node names. The
        # operator may still rename individual nodes on the Nodes page, and only
        # the last page checks the names actually configured. With a wildcard
        # certificate that distinction does not matter at all.
        L.append("[dim]Checked against the planned node names "
                 f"({', '.join(h + '.' + domain for h in hosts)}). If you rename "
                 "nodes later, the last page is what counts -- a wildcard "
                 "certificate is unaffected either way.[/dim]")
        out.update("\n".join(L))
        # Carry it forward: the last page reuses this instead of re-asking.
        # props feeds its tenant/domain picker, so fill it here too.
        self.info = info
        self.props = certs.propose_tenant_domain(info)
        self._app.answers["_pw"] = pw

    def _naming_values(self) -> tuple[str, list[str]]:
        """(prefix, explicit access hostnames) as currently entered.

        Exactly one of the two is in use; the other stays empty. Falls back to
        the saved answers when the widgets are not mounted (other pages)."""
        ans = self._app.answers
        if self._naming_mode() == "custom":
            hosts = []
            for i in range(ACCESS_COUNT.get(self._planned_size(), 2)):
                try:
                    hosts.append(
                        self.query_one(f"#w_req_host_{i}", Input).value.strip())
                except Exception:
                    hosts = (ans.get("access_override", "") or "").split()
                    break
            return ans.get("prefix", ""), [h for h in hosts if h]
        try:
            return self.query_one("#w_req_prefix", Input).value.strip(), []
        except Exception:
            return ans.get("prefix", ""), []

    def _naming_mode(self) -> str:
        try:
            return self.query_one("#w_req_naming", Select).value or "scheme"
        except Exception:
            return self._app.answers.get("naming", "scheme")

    def _planned_size(self) -> str:
        try:
            return self.query_one("#w_req_size", Select).value or "small"
        except Exception:
            return self._app.answers.get("size", "small")

    async def _render_naming(self, box: Vertical) -> None:
        """Either the single prefix field, or one field per access node.

        Custom naming is not exotic -- plenty of sites have their own scheme, and
        with an exact-SAN certificate the names must be known BEFORE ordering.
        So they can be typed right here, and the SAN list follows them."""
        await box.remove_children()
        ans = self._app.answers
        n = ACCESS_COUNT.get(self._planned_size(), 2)
        if self._naming_mode() == "custom":
            saved = (ans.get("access_override", "") or "").split()
            gen = configure.access_hostnames(n, ans.get("prefix") or "wsa")
            row = Horizontal(classes="row")
            await box.mount(row)
            for i in range(n):
                cell = Vertical(classes="cell"); await row.mount(cell)
                await cell.mount(Label(f"Access-{i+1} hostname"))
                await cell.mount(Input(
                    value=saved[i] if i < len(saved) else "",
                    placeholder=gen[i], id=f"w_req_host_{i}"))
            return
        row = Horizontal(classes="row")
        await box.mount(row)
        cell = Vertical(classes="cell"); await row.mount(cell)
        await cell.mount(Label("Hostname prefix"))
        await cell.mount(Static("All node names follow it and are proposed later.",
                                classes="help"))
        await cell.mount(Input(value=ans.get("prefix", "") or "",
                               placeholder="wsa", id="w_req_prefix"))

    async def _render_certplan_page(self, body: Vertical) -> None:
        """Page 2: which names the certificate must carry, and -- if the PFX is
        already staged -- whether it actually does. Its own page because the SAN
        list plus the check pushed the requirements page past 80 rows."""
        from rich.text import Text
        ans = self._app.answers
        cbox = Vertical(id="sec_req_cert", classes="secbox")
        cbox.border_title = " CERTIFICATE COVERAGE "
        await body.mount(cbox)
        await cbox.mount(Static(
            "The certificate normally has to be ORDERED before you can deploy, "
            "so here is exactly which names it must carry. Fill these in and the "
            "list below is the one to request -- they carry over as suggestions; "
            "the last page reads the truth from the PFX.", classes="hint"))
        row = Horizontal(classes="row")
        await cbox.mount(row)
        ct = Vertical(classes="cell"); await row.mount(ct)
        await ct.mount(Label("Tenant name"))
        await ct.mount(Static("First tenant label, e.g. 'access'.", classes="help"))
        await ct.mount(Input(value=ans.get("tenant_name", "") or "",
                             placeholder="access", id="w_req_tenant"))
        cd = Vertical(classes="cell"); await row.mount(cd)
        await cd.mount(Label("Your domain"))
        await cd.mount(Static("DNS zone the tenant lives under.", classes="help"))
        await cd.mount(Input(value=ans.get("domain", "") or "",
                             placeholder="lab.vmguru.io", id="w_req_domain"))
        row2 = Horizontal(classes="row")
        await cbox.mount(row2)
        cnm = Vertical(classes="cell"); await row2.mount(cnm)
        await cnm.mount(Label("Access node naming"))
        await cnm.mount(Static("A prefix builds them, or name each node yourself.",
                               classes="help"))
        await cnm.mount(Select(
            [("prefix scheme  (<prefix>-acc-01 ...)", "scheme"),
             ("own names per node", "custom")],
            value=ans.get("naming", "scheme"), allow_blank=False,
            id="w_req_naming"))
        csz = Vertical(classes="cell"); await row2.mount(csz)
        await csz.mount(Label("Deployment size"))
        await csz.mount(Static("large has 3 access nodes -- one SAN more.",
                               classes="help"))
        await csz.mount(Select([(s, s) for s in ("small", "medium", "large")],
                               value=ans.get("size", "small"), allow_blank=False,
                               id="w_req_size"))
        # Either ONE prefix field or one field per access node -- swapped in
        # place when the selector above changes, so the SAN list always shows
        # the names this cluster will really use.
        nbox = Vertical(id="naming_box")
        await cbox.mount(nbox)
        await self._render_naming(nbox)
        # Drop the heading line -- the box title already says it.
        await cbox.mount(Static(Text(self._coverage_text()), id="req_cov"))

        # Optional early check: if the PFX is already staged, the operator can
        # verify HERE that the delivered certificate really covers the names
        # above -- before filling in the rest of the form. Same function that
        # decides it on the last page, so the verdicts cannot disagree.
        await cbox.mount(Static(
            "Already have the certificate? Check it against the names above -- "
            "the same test the last page runs. Leave tenant/domain empty to read "
            "them from the certificate.", classes="hint"))
        vrow = Horizontal(classes="row")
        await cbox.mount(vrow)
        vp = Vertical(classes="cell"); await vrow.mount(vp)
        await vp.mount(Label("PFX password"))
        await vp.mount(Static("Used in memory only, never stored.", classes="help"))
        await vp.mount(Input(password=True, id="w_req_pw"))
        vb = Vertical(classes="cell"); await vrow.mount(vb)
        await vb.mount(Label(" "))
        await vb.mount(Button("Check certificate", id="req_validate"))
        await cbox.mount(Static("", id="req_val_result"))

    async def _render_cert_page(self, body: Vertical) -> None:
        box = Vertical(id="sec_certificate", classes="secbox")
        box.border_title = " CERTIFICATE "
        await body.mount(box)
        if self.info is None:
            # Not opened yet (the check on the plan page was skipped).
            await box.mount(Static(
                "The certificate anchors the tenant: enter the PFX password and "
                "open it -- tenant and domain are then proposed from its SANs, "
                "and everything you configured is validated against it (CN "
                "included).", classes="hint"))
            row = Horizontal(classes="row")
            await box.mount(row)
            c1 = Vertical(classes="cell"); await row.mount(c1)
            await c1.mount(Label("PFX password"))
            await c1.mount(Static("The password set when the .pfx was exported.",
                                  classes="help"))
            await c1.mount(Input(password=True, id="w_pw"))
            c2 = Vertical(classes="cell"); await row.mount(c2)
            await c2.mount(Label(" "))
            await c2.mount(Button("Open certificate", id="open", variant="primary"))
        else:
            # Already opened on the certificate-plan page -- do not ask for the
            # same password twice; go straight to the decisions and validation.
            await box.mount(Static(
                f"Certificate already open (CN {self.info.subject_cn or '(none)'}). "
                "Confirm tenant and domain, pick the TLS topology, then Validate.",
                classes="hint"))
        await box.mount(Vertical(id="afteropen"))
        if self.info is not None:
            await self._mount_cert_fields()

    async def _mount_cert_fields(self) -> None:
        ans = self._app.answers
        box = self.query_one("#afteropen", Vertical)
        await box.remove_children()
        await box.mount(Static(
            f"[green]CN:[/]   {self.info.subject_cn or '(none)'}\n"
            f"[green]SANs:[/] {', '.join(self.info.sans) or '(none)'}"))
        opts = [(f"{t}.{d}" if t else f"(choose tenant) . {d}", i)
                for i, (t, d) in enumerate(self.props)] + [("enter manually", -1)]
        init_t = ans.get("tenant_name") or (self.props[0][0] if self.props else None)
        init_d = ans.get("domain") or (self.props[0][1] if self.props else "")
        await box.mount(Label("Tenant / domain (from the certificate)"))
        await box.mount(Static("Pick the pair the certificate stands for; the two "
                               "fields below can still be edited.", classes="help"))
        await box.mount(Select(opts, allow_blank=False, id="w_td"))
        row = Horizontal(classes="row"); await box.mount(row)
        ct = Vertical(classes="cell"); await row.mount(ct)
        await ct.mount(Label("Tenant name"))
        await ct.mount(Static("First tenant label, e.g. 'access' -> "
                              "https://access.<domain>", classes="help"))
        await ct.mount(Input(value=init_t or "", id="w_tenant"))
        cd = Vertical(classes="cell"); await row.mount(cd)
        await cd.mount(Label("Domain"))
        await cd.mount(Static("DNS zone under which the tenant lives.", classes="help"))
        await cd.mount(Input(value=init_d or "", id="w_domain"))
        await box.mount(Label("TLS topology at the load balancer"))
        await box.mount(Static("termination: the LB holds the real cert, the "
                               "appliance stays self-signed.  passthrough: the LB "
                               "passes TLS through, the appliance presents the real "
                               "cert (aXs places cert+key from this PFX).",
                               classes="help"))
        await box.mount(Select(
            [("termination  (LB terminates; appliance self-signed)", "termination"),
             ("passthrough  (appliance presents the real cert)", "passthrough")],
            value=ans.get("lb_mode", "termination"), allow_blank=False, id="w_mode"))
        row2 = Horizontal(classes="row"); await box.mount(row2)
        ca = Vertical(classes="cell"); await row2.mount(ca)
        await ca.mount(Label("Certificate-based auth"))
        await ca.mount(Static("Enables the cert proxy in access-profile.yml and "
                              "requires a <tenant>-cert SAN in the certificate.",
                              classes="help"))
        await ca.mount(Select([("no", "no"), ("yes", "yes")],
                              value=("yes" if ans.get("cert_proxy_enabled") else "no"),
                              allow_blank=False, id="w_certauth"))
        cs = Vertical(classes="cell"); await row2.mount(cs)
        # Honest label: unlike the cert-auth switch (which really does write
        # cert_proxy.enabled into access-profile.yml), this one ONLY tightens the
        # certificate check -- it is not persisted and configures no service.
        await cs.mount(Label("Plan for Mobile SSO?"))
        await cs.mount(Static("Checks the certificate for a <tenant>-amsso SAN "
                              "now. Does not configure SSO -- that is done in "
                              "Access afterwards.", classes="help"))
        await cs.mount(Select([("no", "no"), ("yes", "yes")],
                              value=("yes" if ans.get("sso_enabled") else "no"),
                              allow_blank=False, id="w_sso"))

    def _reset_go(self) -> None:
        """Back to step 1 of the two-step finish: validate first, then write."""
        self.state = "validate"
        go = self.query_one("#go", Button)
        go.label = "Validate"
        go.variant = "primary"

    # -- events -----------------------------------------------------------
    def on_input_changed(self, event: Input.Changed) -> None:
        # Any edit on the certificate page invalidates a previous validation.
        if self.page == len(PAGES) - 1 and self.state == "write":
            self._reset_go()
        # Requirements page: retype the SAN list live as the domain is typed.
        if event.input.id in ("w_req_tenant", "w_req_domain", "w_req_prefix") or \
                (event.input.id or "").startswith("w_req_host_"):
            self._refresh_coverage()
        # Renaming an access node changes what the certificate must cover.
        if (event.input.id or "").startswith("w_access_") and \
                (event.input.id or "").endswith("_host"):
            try:
                self.query_one("#acc_cert_note", Static).update(
                    self._access_cert_note())
            except Exception:
                pass

    def _refresh_coverage(self) -> None:
        from rich.text import Text
        try:
            self.query_one("#req_cov", Static).update(Text(self._coverage_text()))
        except Exception:
            pass          # not on the requirements page

    async def on_select_changed(self, event: Select.Changed) -> None:
        if self.page == len(PAGES) - 1 and self.state == "write":
            self._reset_go()
        if event.select.id in ("w_req_size", "w_req_naming"):
            if event.select.id == "w_req_size":
                # Remembered, so the real size field on a later page starts from
                # what the operator already told us here.
                self._app.answers["size"] = event.value
            else:
                self._app.answers["naming"] = event.value
            # Both change WHICH name fields belong here (count / prefix vs list).
            try:
                await self._render_naming(self.query_one("#naming_box", Vertical))
            except Exception:
                pass
            self._refresh_coverage()
            return
        if event.select.id == "w_size":
            if self._app.answers.get("size") != event.value:
                self._app.answers["size"] = event.value
                try:
                    box = self.query_one("#sec_access_nodes", Vertical)
                except Exception:
                    return
                await box.remove_children()
                await self._render_section("Access nodes", box)
        elif event.select.id == "w_td" and event.value not in (None, -1):
            t, d = self.props[event.value]
            self.query_one("#w_tenant", Input).value = t or ""
            self.query_one("#w_domain", Input).value = d

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "quit":
            self._app.exit(None)
        elif bid == "back":
            self._stash()
            self.page -= 1
            await self.render_page()
        elif bid == "recheck":
            await self.render_page()
        elif bid == "req_validate":
            self._check_cert_now()
        elif bid == "next":
            # Certificate-plan values are suggestions, not form fields, so they
            # are not covered by _collect -- carry them explicitly.
            self._stash_certplan()
            # Page 1 has no fields -- it gates on the requirements scan instead.
            # Without every required file the later pages cannot work (the cert
            # page opens found["cert"]), so block here and let Re-check re-scan.
            if self.page == 0:
                # Someone can click Next before the background probe returns.
                # Rather than guessing, finish the check right here -- the cache
                # makes it instant unless it genuinely has not run yet.
                if any(it.get("version_pending") for it in self._req_items):
                    self._versions_done(configure.prerequisites("."))
                missing = [it for it in self._req_items
                           if it["required"] and not it["satisfied"]]
                if missing:
                    self.query_one("#formerror", Static).update(
                        "Not ready: " + ", ".join(m["key"] for m in missing)
                        + " -- stage/fix, then press Re-check.")
                    return
            msg = self._collect(PAGES[self.page][2])
            if msg:
                self.query_one("#formerror", Static).update(msg)
                return
            self.page += 1
            await self.render_page()
        elif bid == "open":
            await self._open_cert()
        elif bid == "go":
            await self._go()

    def _stash(self) -> None:
        """Store current page values WITHOUT validation (for Back)."""
        self._stash_certplan()
        for name in PAGES[self.page][2]:
            for f in fields_for(name, self._app.answers):
                try:
                    self._app.answers[f.key] = str(
                        self.query_one(f"#w_{f.key}").value or "").strip()
                except Exception:
                    pass

    def _stash_certplan(self) -> None:
        """Carry the certificate-plan values forward as SUGGESTIONS.

        The prefix must travel (the node hostnames on page 4 are derived from
        it, and the SAN list the operator ordered was built with it). Tenant and
        domain travel too, so the last page starts pre-filled instead of asking
        for them a second time -- it still reads the authoritative pair from the
        certificate's SANs and can overwrite them there."""
        for wid, key in (("#w_req_tenant", "tenant_name"),
                         ("#w_req_domain", "domain")):
            try:
                if v := str(self.query_one(wid).value or "").strip():
                    self._app.answers[key] = v
            except Exception:
                pass          # not on the certificate-plan page
        try:
            self._app.answers["naming"] = self._naming_mode()
            prefix, override = self._naming_values()
            if prefix:
                self._app.answers["prefix"] = prefix
            if override:
                self._app.answers["access_override"] = " ".join(override)
        except Exception:
            pass

    def _collect(self, sections: list[str]) -> str | None:
        ans = self._app.answers
        for name in sections:
            for f in fields_for(name, ans):
                w = self.query_one(f"#w_{f.key}")
                val = str(w.value or "").strip()
                if not val and f.kind != "select":
                    val = f.default                 # empty accepts the suggestion
                if not val and not f.optional:
                    return f"{f.label} is required."
                if f.kind == "ip" and val:
                    if not validate.valid_ip(val):
                        return f"{f.label}: not a valid IP ({val})."
                    gw, nm = ans.get("gateway"), ans.get("netmask")
                    if f.key != "gateway" and f.subnet_check and gw and nm and \
                            not validate.ip_in_subnet(val, gw, nm):
                        return f"{f.label}: {val} not in subnet {gw}/{nm}."
                ans[f.key] = val
        return None

    async def _open_cert(self) -> None:
        pw = self.query_one("#w_pw", Input).value
        err = self.query_one("#formerror", Static)
        try:
            self.info = certs.read_cert(
                certs.pem_from_pfx(Path(self._app.found["cert"]), pw))
        except certs.CertError as e:
            err.update(str(e))
            return
        err.update("")
        self._app.answers["_pw"] = pw
        self.props = certs.propose_tenant_domain(self.info)
        await self._mount_cert_fields()

    async def _go(self) -> None:
        err = self.query_one("#formerror", Static)
        if self.info is None:
            err.update("Open the certificate first (enter the PFX password, press Open).")
            return
        err.update("")
        if self.state == "write":
            # Second press: the user has seen the validation result.
            self._write_and_exit()
            return
        ans = self._app.answers
        ans["tenant_name"] = self.query_one("#w_tenant", Input).value.strip()
        ans["domain"] = self.query_one("#w_domain", Input).value.strip()
        ans["lb_mode"] = self.query_one("#w_mode", Select).value
        ans["cert_proxy_enabled"] = self.query_one("#w_certauth", Select).value == "yes"
        ans["sso_enabled"] = self.query_one("#w_sso", Select).value == "yes"
        ans["is_self_signed"] = ans["lb_mode"] == "termination"
        if not ans["tenant_name"] or not ans["domain"]:
            err.update("Tenant name and domain are required.")
            return
        if not ans["is_self_signed"]:
            ans["custom_cert_file"] = str(Path("clusters") / self._app.cluster / "appliance.crt")
            ans["custom_cert_keyfile"] = str(Path("clusters") / self._app.cluster / "appliance.key")

        a = assemble(ans, self._app.found)
        cfg = build_config(a)
        self._app.cfg = cfg
        static_errs = validate.validate_config(cfg)
        cert = certs.validate_cluster(
            self.info, a["tenant_name"], a["domain"],
            [n["hostname"] for n in a["access"]],
            cert_auth=a["cert_proxy_enabled"], sso=a["sso_enabled"])
        vc_ok = netcheck.port_open(a["vc_host"], 443)
        fqdn = f"{a['tenant_name']}.{a['domain']}"
        addrs = netcheck.resolve_via(fqdn, a["dns"])
        dns_ok = a["lb_ip"] in addrs

        L = ["[b]Validation[/b]"]
        # The claim matches what validate_config actually checks: IP format,
        # node subnet, node counts per size, hostname DNS-label format, and
        # uniqueness of both IPs and hostnames across all nodes.
        L += ([f"  [red]FAIL[/red] {e}" for e in static_errs]
              or ["  [green]ok[/green] hostnames/IPs valid, in subnet, unique"])
        L.append(f"  certificate CN = {cert.cn or '(none)'}")
        for nm in cert.names:
            if not nm.required and not nm.covered:
                L.append(f"  [dim]--   {nm.fqdn} ({nm.role}) not required[/dim]")
            elif nm.covered:
                L.append(f"  [green]ok[/green]   {nm.fqdn} via {nm.via}")
            else:
                L.append(f"  [red]FAIL[/red] {nm.fqdn} ({nm.role})")
        if cert.expired:
            L.append("  [red]FAIL[/red] certificate expired")
        # The same notes as the review page. Showing them on only one of the two
        # is how a warning becomes invisible on whichever path the operator
        # happens to take -- and this is the page that writes the config.
        for note in cert.notes:
            L.append(f"  [yellow]![/yellow] {note}")
        L.append(f"  {'[green]ok[/green]' if vc_ok else '[red]FAIL[/red]'} "
                 f"vCenter {a['vc_host']}:443 reachable")
        L.append(f"  {'[green]ok[/green]' if dns_ok else '[red]FAIL[/red]'} "
                 f"DNS {fqdn} -> {a['lb_ip']} ({', '.join(sorted(addrs)) or 'no answer'})")
        all_ok = not static_errs and cert.ok and vc_ok and dns_ok
        L.append("")
        L.append("[green]All checks passed.[/green] Review above, then press "
                 "'Write configuration'." if all_ok else
                 "[yellow]Some checks are not green.[/yellow] Fix and re-validate, "
                 "or press 'Write anyway'.")
        self.query_one("#result", Static).update("\n".join(L))
        self.query_one("#form", VerticalScroll).scroll_end(animate=False)

        # First press only VALIDATES -- writing is always an explicit second press.
        self.state = "write"
        go = self.query_one("#go", Button)
        go.label = "Write configuration" if all_ok else "Write anyway"
        go.variant = "success" if all_ok else "warning"

    def _write_and_exit(self) -> None:
        ans = self._app.answers
        cluster = self._app.cluster
        if not ans["is_self_signed"]:
            cdir = Path("clusters") / cluster
            cdir.mkdir(parents=True, exist_ok=True)
            # 0700/0600, not the 0755/0644 the defaults give. This writes the
            # customer's TLS private key UNENCRYPTED (key_from_pfx uses -nodes)
            # and it has to stay -- phase 70 re-reads it on every deploy. So it
            # is not a deletion candidate, it is a permissions one: without
            # this, every local account can read it, indefinitely.
            # docs/04-findings.md already required 0600/0700; the code did not.
            cdir.chmod(0o700)
            pw, pfx = ans["_pw"], Path(self._app.found["cert"])
            Path(ans["custom_cert_file"]).write_bytes(certs.chain_pem_from_pfx(pfx, pw))
            keyfile = Path(ans["custom_cert_keyfile"])
            keyfile.write_bytes(certs.key_from_pfx(pfx, pw))
            keyfile.chmod(0o600)
        path = _write(cluster, self._app.cfg)
        self._app.exit(str(path))

    def action_quit_app(self) -> None:
        self._app.exit(None)


class ConfigureApp(App):
    CSS = CSS
    TITLE = "aXs . configure"

    def __init__(self, cluster: str, found: dict, answers: dict | None = None) -> None:
        super().__init__()
        self.cluster = cluster
        self.found = found
        self.answers: dict = answers or {}
        self.cfg: dict = {}

    def on_mount(self) -> None:
        from ._splash import SplashScreen
        self.register_theme(WS1_THEME)
        self.theme = "ws1purple"
        # Same splash as `axs deploy`: the two entry points are one tool, and
        # starting configure with a bare form made them look unrelated. It also
        # states up front whether this run edits an existing configuration --
        # otherwise pre-filled fields two pages in come as a surprise, and
        # without -c the cluster silently defaults to "default".
        cfg = Path("clusters") / self.cluster / "config.yml"
        if cfg.exists():
            tagline = (f"Found [b]{cfg}[/b] — Start opens the dialog with your "
                       "saved answers preloaded; nothing is changed until the "
                       "final Validate → Write.")
            label = "Edit config ▶"
        else:
            tagline = (f"No configuration yet for [b]{self.cluster}[/b] — Start "
                       f"opens the {len(PAGES)}-page dialog and writes {cfg} at "
                       "the end.")
            label = "Configure ▶"
        self.push_screen(SplashScreen(
            self, BANNER, self.cluster, tagline,
            on_start=lambda: self.push_screen(FormScreen(self)),
            start_label=label))


def run(cluster: str, found: dict) -> int:
    """Launch the TUI. Returns 0 if a config was written, 1 otherwise.

    An existing clusters/<cluster>/config.yml is loaded so the form continues
    from the saved values instead of starting blank."""
    import yaml
    answers: dict = {}
    existing = Path("clusters") / cluster / "config.yml"
    if existing.exists():
        try:
            answers = answers_from_config(yaml.safe_load(existing.read_text()) or {})
        except Exception:
            answers = {}
    written = ConfigureApp(cluster, found, answers).run()
    if written:
        print(f"Written: {written}")
        return 0
    print("Aborted -- nothing written.")
    return 1
