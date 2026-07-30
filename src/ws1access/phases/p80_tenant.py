"""Phase 80 -- Create the first Access tenant.

Documented procedure (from the bootstrap):

    wso access create-tenant     # non-interactive; waits for the saas restart
                                 # (~5-10 min) and prints a reset link the admin
                                 # uses to set the tenant admin password.

The tenant identity comes from access-profile.yml's first_tenant (phase 70).
No password is set here -- the admin sets it via the reset link.

Done-probe: `create-tenant.log` reports the tenant as created. The login page
https://<tenant>.<domain>/auth/login is asked too, but it is no longer the sole
evidence -- a load-balancer maintenance page answers 200 without there being a
tenant, and a bootstrap that cannot reach the LB VIP fails to get 200 when
there is one (docs/08 B5).
"""

from __future__ import annotations

import shlex

from ..context import Context, RemoteError, WSO_BUSY
from ..ssh import SshResult
from . import Probe

NAME = "80_tenant"
DEPS = ("70_services",)

_LOG = "create-tenant.log"
# '[w]so ...' avoids pgrep matching its own command line -- see p60 for the full
# explanation. Without it the phase never starts and waits forever.
_ALIVE = "pgrep -f '[w]so access create-tenant' >/dev/null"


def _login_url(ctx: Context) -> str:
    tenant = ctx.access["first_tenant"]["tenant_name"]
    domain = ctx.access["domain"]
    return f"https://{tenant}.{domain}/auth/login"


# The admin onboarding lines wso prints at the end of create-tenant. The reset
# link is the ONLY way the admin sets the first password -- it must be surfaced,
# not buried in the log.
_INFO_KEYS = ("Tenant Login URL", "TenantName", "Username", "Reset Password Link")


def onboarding_info(ctx: Context) -> str:
    """The admin onboarding block from create-tenant.log (login URL, username,
    reset-password link), or '' if not present. Read fresh so it also works on a
    resume where run() was skipped."""
    log = ctx.bootstrap_run(f"cat {_LOG} 2>/dev/null").output
    # The log is APPENDED to across runs (context.start_detached -- truncating
    # it would destroy the single-use reset link on any re-run). So read only
    # the LAST run's segment: an expired link from an earlier attempt shown as
    # the current one would be worse than showing none.
    lines = log.splitlines()
    marks = [i for i, ln in enumerate(lines) if ln.startswith("===== aXs start")]
    if marks:
        lines = lines[marks[-1] + 1:]
    picked = []
    for ln in lines:
        s = ln.strip()
        if any(s.startswith(k) for k in _INFO_KEYS):
            picked.append(s)
    return "\n".join(picked)


def _http_code(ctx: Context, url: str) -> str:
    # -L: the login endpoint 302-redirects to /SAAS/auth/login; follow it so a
    # healthy tenant returns the final 200, not the intermediate 302.
    r = ctx.bootstrap_run(
        f"curl -skL -o /dev/null -w '%{{http_code}}' --max-time 12 {shlex.quote(url)}",
        in_cluster_dir=False,
    )
    return r.output.strip().splitlines()[-1] if r.output.strip() else ""


# The string `wso access create-tenant` prints on success. As brittle as p60's
# `_NO_CHANGES` and for the same reason: it is wso's wording, not an interface,
# and B7 is the standing example of a second wording nobody knew about. If a
# future wso says it differently, this phase reports a healthy tenant as
# missing -- loudly, at least, rather than the other way round.
#
# What the log does NOT tell us is WHICH tenant. Whether the name appears on
# that line is unmeasured, so nothing here binds to it, and the warning texts
# below are careful to say "a tenant was created" rather than "the tenant
# exists" -- the log is evidence about the past, not about right now.
_CREATED = "created successfully"
_NOT_CREATED = "not created"


def _tenant_created(ctx: Context) -> bool:
    """Does the cluster's own log record a successful create-tenant?

    The WHOLE log, not the last run's segment: a tenant created three runs ago
    is still created. The segment rule applies to the reset link, which expires
    -- see onboarding_info -- not to this.

    `grep`, not `cat`: this runs on every probe of every deploy, the log grows
    with each run, and the answer is one bit. It also keeps the reset link on
    the bootstrap instead of pulling it through the probe. The second grep
    drops a line that merely CONTAINS the phrase inside a negation -- a
    substring match cannot tell "created successfully" from "not created
    successfully" on its own.
    """
    r = ctx.bootstrap_run(
        f"grep -i {shlex.quote(_CREATED)} {_LOG} 2>/dev/null "
        f"| grep -qiv {shlex.quote(_NOT_CREATED)} "
        f"&& echo AXS_CREATED || echo AXS_NOT")
    return "AXS_CREATED" in (r.output or "")


def is_done(ctx: Context) -> Probe:
    """Ask the CLUSTER first, the load balancer second.

    HTTP 200 alone was the whole probe, and it fails in both directions
    (docs/08 B5). A load-balancer maintenance page answers 200 -- no tenant, no
    admin, no reset link, and the phase skips itself; it would surface at the
    first login attempt. And the other way round: if the bootstrap cannot reach
    the LB VIP (hairpin), a perfectly good tenant stays red forever.

    So `create-tenant.log` decides -- the same string `run()` already gates on,
    which at least makes the two agree. HTTP stays, because it is genuinely
    useful and because it is the ONLY evidence on a cluster whose log is gone.
    What it no longer does is decide silently: a green verdict resting on HTTP
    alone says so.

    Deliberately NOT done: making HTTP 200 insufficient on its own. Reporting
    "not done" for a tenant that exists would re-run `wso access create-tenant`
    against it, and what that does is unmeasured. Warning is the honest half.
    """
    url = _login_url(ctx)
    created = _tenant_created(ctx)
    code = _http_code(ctx, url)
    http = f"{url} -> HTTP {code or '(no answer)'}"

    if created and code == "200":
        return Probe(True, detail=f"tenant created ✔ | {http}")
    if created:
        return Probe(
            True, detail=f"tenant created ✔ | {http}",
            warning=(f"NOTE — {_LOG} records a successful create-tenant, but "
                     f"{http}.\n"
                     "  Two different things look like this, and the log cannot "
                     "tell them apart — it says a tenant was created, not which "
                     "one, nor whether it is still there:\n"
                     "    1. the tenant is fine and the path to it is not — "
                     "load balancer, DNS for the tenant name, or the bootstrap "
                     "not reaching the LB VIP (hairpin). Nothing to re-run.\n"
                     "    2. the log refers to a DIFFERENT tenant — first_tenant "
                     "was renamed since, or the tenant was removed by hand. Then "
                     "this phase is skipping work that is genuinely outstanding: "
                     "`axs deploy -c <cluster> -p 80_tenant --force`."))
    if code == "200":
        return Probe(
            True, detail=http,
            warning=(f"NOTE — this phase counts as done on {http} ALONE: "
                     f"{_LOG} carries no '{_CREATED}'.\n"
                     "  A load balancer serving a maintenance page answers 200 "
                     "too, and that would mean no tenant, no admin and no "
                     "reset link.\n"
                     "  Confirm the tenant really exists before relying on it — "
                     "otherwise it surfaces at the first login."))
    return Probe(False, detail=f"no '{_CREATED}' in {_LOG} | {http}")


def run(ctx: Context) -> None:
    # Detached: create-tenant waits for a saas restart for several minutes.
    ctx.start_detached_once(_LOG, "wso access create-tenant", _ALIVE,
                            busy_cmd=WSO_BUSY)
    ctx.wait_while_running(_ALIVE,
                           label="wso access create-tenant (waits for a saas restart)",
                           logfile=_LOG)

    if not _tenant_created(ctx):
        log = ctx.bootstrap_run(f"cat {_LOG} 2>/dev/null").output
        raise RemoteError("wso access create-tenant", SshResult(1, log[-1500:]))

    # Surface that onboarding info is ready -- but NOT the reset token itself into
    # the progress sink (which is mirrored to clusters/<c>/deploy.log). The full
    # block is shown once in the final summary and stays in create-tenant.log on
    # the bootstrap; the token is single-use and expires.
    # This message is generic on purpose, but that alone was not enough: while
    # create-tenant still runs, wait_while_running tails this very log and
    # reports its last line, which can BE the reset link. Context.report()
    # therefore masks credential values (see context.redact) -- belt and braces.
    if onboarding_info(ctx):
        ctx.report("tenant created — admin login URL + reset-password link ready "
                   "(shown in the final summary)")


def explain_failure(ctx: Context, exc: Exception) -> str:
    if isinstance(exc, RemoteError):
        return (
            "wso access create-tenant did not report success.\n"
            f"  - Are all services READY? (phase 70 / `axs status -c "
            f"{ctx.local_name}`)\n"
            "  - Does <tenant>.<domain> resolve to the LB and is the LB serving?\n"
            f"  - Output:\n{exc.result.output}"
        )
    return str(exc)
