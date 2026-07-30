"""Minimal vCenter REST client -- stdlib only (urllib), no external deps.

Only what the phases need: authenticate, look up VMs by name and read their
power state (phase 00 preflight + phase 10 done-probe). vSphere 8 exposes these
under /api/ (the older /rest/com/vmware/cis paths 404). TLS verification is off
because the lab vCenter uses a self-signed cert, matching ovftool --noSSLVerify.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import quote

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class VCenterError(RuntimeError):
    pass


@dataclass
class VCenter:
    host: str
    user: str
    password: str

    def _call(self, method: str, path: str, headers: dict | None = None,
              body: object = None) -> tuple[object, dict]:
        """One request. Returns (parsed body, response headers).

        The headers matter for the VIM API, which hands back the session id in
        `vmware-api-session-id` rather than in the body."""
        url = f"https://{self.host}{path}"
        data = None
        h = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, method=method, headers=h, data=data)
        try:
            with urllib.request.urlopen(req, context=_CTX, timeout=20) as r:
                raw = r.read().decode()
                return (json.loads(raw) if raw else None), dict(r.headers)
        except urllib.error.HTTPError as e:
            raise VCenterError(f"{method} {path} -> HTTP {e.code}: {e.read().decode()[:200]}")
        except urllib.error.URLError as e:
            raise VCenterError(f"{self.host} not reachable: {e.reason}")

    def _req(self, method: str, path: str, headers: dict | None = None,
             body: object = None) -> object:
        return self._call(method, path, headers, body)[0]

    def session(self) -> str:
        token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        sid = self._req("POST", "/api/session", {"Authorization": f"Basic {token}"})
        if not isinstance(sid, str):
            raise VCenterError("vCenter login failed (no session id returned).")
        return sid

    def power_states(self, names: list[str],
                     datacenter: str | None = None,
                     folder: str | None = None) -> dict[str, str]:
        """name -> POWERED_ON / POWERED_OFF / SUSPENDED (missing names omitted).

        Pass `datacenter` to scope the lookup. Without it the match is
        vCenter-wide, and a same-named VM anywhere -- a second aXs cluster using
        the default `wsa` prefix, an old test instance -- makes phase 10 report
        "already deployed" for machines that were never created here.

        Pass `folder` to scope it further, to the folder the VMs are actually
        deployed INTO. The datacenter scope alone left the same hole one level
        down: with a folder configured, a same-named VM elsewhere in the SAME
        datacenter -- the very leftover the datacenter scoping was added to rule
        out, just in another folder -- still reported "already deployed", and the
        node was never built. Only meaningful with a datacenter (a folder MOID is
        resolved within one); ignored without.

        UNVERIFIED ASSUMPTION (docs/08 D): that vCenter honours `folders=<moid>`
        on GET /api/vcenter/vm as a filter. The parameter name is confirmed by
        Broadcom's API reference (plain `folders`, not `filter.folders`, matching
        what /api/vcenter/folder already requires), but the SERVER BEHAVIOUR --
        that the filter takes effect, and that an unknown one is rejected rather
        than ignored -- is not measured against a live vCenter 8. If it were
        silently ignored, this would fall back to the datacenter-wide list and
        the folder scope would do nothing while every test still passes. Measure
        with one query against the lab vCenter before relying on it.
        """
        sid = self.session()
        params: list[str] = []
        if datacenter:
            dc = self.datacenter_id(datacenter, sid)
            if not dc:
                # Falling back to a vCenter-wide search would silently restore
                # exactly what this parameter exists to prevent: an unrelated VM
                # of the same name in another datacenter reported as "already
                # deployed", so the node never gets built. A typo in
                # vcenter.datacenter, a rename, or missing read rights all land
                # here -- all worth saying out loud rather than searching wider.
                raise VCenterError(
                    f"datacenter {datacenter!r} not found in vCenter "
                    "(check vcenter.datacenter in the config, and that the "
                    "account may read it)")
            params.append(f"datacenters={dc}")
            if folder:
                moids = self._vm_folder_ids(datacenter, folder, sid)
                if len(moids) > 1:
                    # Two VM folders of the same name under different parents --
                    # vCenter allows it. `.get(name)` would have picked one
                    # arbitrarily, and the wrong one silently restores the very
                    # bug this scoping fixes (a leftover in the other folder
                    # reported as "already there") or reports every node missing.
                    # "We could not tell which" is not a verdict to guess.
                    raise VCenterError(
                        f"datacenter {datacenter!r} has {len(moids)} VM folders "
                        f"named {folder!r}; aXs cannot tell which one you mean. "
                        "Rename one, or use a uniquely named folder.")
                if not moids:
                    # The folder does not exist (phase 10's run() creates a leaf
                    # folder, or rejects a nested path with a clear message), so
                    # nothing is deployed there yet. The honest answer is "no
                    # matching VMs", not a wider search that would find the
                    # leftover this scoping exists to ignore.
                    return {}
                params.append(f"folders={moids[0]}")
        path = "/api/vcenter/vm"
        if params:
            path += "?" + "&".join(params)
        vms = self._req("GET", path, {"vmware-api-session-id": sid})
        if not isinstance(vms, list):
            return {}
        want = set(names)
        return {v["name"]: v.get("power_state", "?") for v in vms if v.get("name") in want}

    # -- VM folders ---------------------------------------------------------
    # ovftool's --vmFolder fails with "Invalid VM folder specified" if the
    # folder does not exist, and it says so only AFTER uploading. Checking is
    # cheap; creating saves a round trip through the vSphere UI.

    def datacenter_id(self, name: str, sid: str | None = None) -> str | None:
        sid = sid or self.session()
        dcs = self._req("GET", f"/api/vcenter/datacenter?names={quote(name)}",
                        {"vmware-api-session-id": sid})
        if isinstance(dcs, list) and dcs:
            return dcs[0].get("datacenter")
        return None

    def vm_folders(self, datacenter: str, sid: str | None = None) -> dict[str, str]:
        """name -> folder MOID, for the VM folders of one datacenter."""
        sid = sid or self.session()
        dc = self.datacenter_id(datacenter, sid)
        if not dc:
            raise VCenterError(f"datacenter {datacenter!r} not found")
        # Plain parameter names, NOT the `filter.`-prefixed ones: those belong
        # to the legacy /rest/ endpoints. /api/ rejects them with
        # "Unsupported property with name: filter.type" (seen on vCenter 8).
        out = self._req(
            "GET",
            f"/api/vcenter/folder?type=VIRTUAL_MACHINE&datacenters={dc}",
            {"vmware-api-session-id": sid})
        return {f["name"]: f["folder"] for f in out} if isinstance(out, list) else {}

    def _vm_folder_ids(self, datacenter: str, name: str,
                       sid: str | None = None) -> list[str]:
        """Every VM-folder MOID with exactly this name -- usually zero or one.

        Separate from `vm_folders`, which collapses to name -> MOID and so cannot
        see a duplicate name at all. The list length is the point: the caller has
        to distinguish "does not exist" (0) from "ambiguous" (>1), and a dict
        hides the second as silently as `.get` did.
        """
        sid = sid or self.session()
        dc = self.datacenter_id(datacenter, sid)
        if not dc:
            raise VCenterError(f"datacenter {datacenter!r} not found")
        out = self._req(
            "GET",
            f"/api/vcenter/folder?type=VIRTUAL_MACHINE&datacenters={dc}",
            {"vmware-api-session-id": sid})
        if not isinstance(out, list):
            return []
        return [f["folder"] for f in out if f.get("name") == name]

    # The Automation API (/api/...) can LIST folders but not create them; that
    # lives in the VIM JSON API under /sdk/vim25/, which needs its own login.
    _VIM = "/sdk/vim25/8.0.1.0"

    def _vim_session(self) -> str:
        content = self._req("GET", f"{self._VIM}/ServiceInstance/ServiceInstance/content")
        if not isinstance(content, dict):
            raise VCenterError("VIM API did not return ServiceContent "
                               "(vCenter older than 8.0?)")
        sm = (content.get("sessionManager") or {}).get("value")
        if not sm:
            raise VCenterError("VIM API returned no sessionManager")
        _, headers = self._call(
            "POST", f"{self._VIM}/SessionManager/{sm}/Login",
            body={"userName": self.user, "password": self.password})
        sid = headers.get("vmware-api-session-id")
        if not sid:
            raise VCenterError("VIM API login returned no session id")
        return sid

    def create_vm_folder(self, datacenter: str, name: str) -> str:
        """Create `name` directly under the datacenter's VM folder; return its MOID.

        Uses the VIM JSON API because the Automation API has no create call.
        Only ever creates one leaf folder -- an inventory path with slashes is
        the operator's own structure and is not invented here."""
        if "/" in name:
            raise VCenterError(
                f"{name!r} is an inventory path, not a folder name -- aXs only "
                "creates a single folder under the datacenter. Create nested "
                "folders in vCenter, or use a plain name.")
        sid = self.session()
        dc = self.datacenter_id(datacenter, sid)
        if not dc:
            raise VCenterError(f"datacenter {datacenter!r} not found")
        vim_sid = self._vim_session()
        h = {"vmware-api-session-id": vim_sid}
        root = self._req("GET", f"{self._VIM}/Datacenter/{dc}/vmFolder", h)
        moid = root.get("value") if isinstance(root, dict) else None
        if not moid:
            raise VCenterError(f"could not resolve the VM folder of {datacenter}")
        made = self._req("POST", f"{self._VIM}/Folder/{moid}/CreateFolder", h,
                         body={"name": name})
        return made.get("value") if isinstance(made, dict) else ""
