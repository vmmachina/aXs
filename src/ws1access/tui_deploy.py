"""aXs Textual TUI for `deploy` -- live phase progress.

Two screens:

  1. Credentials -- a proper form for the vCenter and configuser passwords, plus
     one per logging backend that was configured with a user (masked, with an
     explanation of what each is for). They are held only as in-process values
     and passed directly to config.context -- never put in the environment,
     never written to THIS machine's disk, gone when the process ends. The two
     places they provably do leave the process are named on that screen rather
     than glossed over.
  2. Progress    -- one row per phase with a live status icon, what the phase
     is doing right now, per-phase elapsed time and a total clock. Failures
     show the phase's own explanation and offer a retry.

The engine is the same logic as the plain cmd_deploy: probe every phase, then
run what is missing, re-probing after each run. It executes in a background
thread; the UI is updated via call_from_thread. A timestamped line log is
appended to clusters/<name>/deploy.log so there is a record without tee.
"""

from __future__ import annotations

import datetime as _dt
import threading
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import Screen
from textual.widgets import (Button, Checkbox, Footer, Header, Input, Label,
                             Static)

from rich.markup import escape

from ._splash import SplashScreen
from .tui import BANNER, WS1_THEME

# What each phase is actually doing -- shown while it runs, so a long silence
# never reads as a hang.
DOING = {
    "00_preflight":   "Checking OVA, ovftool version, vCenter login, tenant DNS.",
    "10_vms":         "Deploying node VMs via ovftool -- a few minutes per VM.",
    "20_nodes_ready": "Waiting for SSH on every node (fresh VMs can take up to ~20 min to boot).",
    "30_lb":          "Verifying tenant DNS resolves to the load balancer (via cluster DNS).",
    "40_bootstrap":   "Staging the asset bundle, installing the wso CLI, accepting the EULA, "
                      "then wso configure loads the container images (the slow part).",
    "50_cluster_init": "wso access init + inventory: SSH trust, cluster folder, cp-cluster.ini.",
    "60_platform":    "wso cp deploy -- the long one (guide: ~30-60 min) -- then healthcheck.",
    "70_services":    "Writing access-profile.yml, deploying access services, readiness check.",
    "80_tenant":      "Creating the first tenant, waiting for the login page.",
}

ICON = {"todo": "[dim]○[/dim]", "probing": "[yellow]…[/yellow]",
        "running": "[yellow]▶[/yellow]", "done": "[green]✔[/green]",
        "failed": "[red]✖[/red]"}

CSS = """
Screen { background: $surface; }
Header { background: $primary; color: $background; text-style: bold; }
#axe { color: $primary; height: auto; content-align: center top; }
#splash_ctx { color: $text-muted; height: auto; content-align: center top;
              padding: 1 0 0 0; }
#welcome_tag { color: $text-muted; text-style: italic; height: auto;
               content-align: center top; }
#body { padding: 1 3 1 3; }
#banner { color: $primary; text-style: bold; height: auto; }
.hint { color: $text-muted; text-style: italic; height: auto; margin: 1 0 0 0; }
.secbox { border: round $primary 40%; border-title-color: $primary;
          border-title-style: bold; padding: 1 2; margin: 1 0 0 0; height: auto; }
.secbox:focus-within { border: round $primary; }
.cell { width: 1fr; padding: 0 2 1 0; height: auto; }
.cell Label { color: $secondary; text-style: bold; }
.help { color: $text-muted; height: auto; }
.row { height: auto; }
Input { border: none; height: 1; background: $panel; padding: 0 1; }
Input:focus { background: $boost; }
#nav { height: 3; align: center middle; background: $panel; }
#nav Button { margin: 0 2; }
.phase { height: auto; margin: 0; }
.phasedetail { color: $text-muted; height: auto; padding: 0 0 0 4; }
#outcome { height: auto; margin: 1 0 0 0; }
#errbox { color: $error; height: auto; }

/* CURRENT box: right under the phase list, big and readable. */
#currentbox { border: round $accent; border-title-color: $accent;
              border-title-style: bold; border-subtitle-color: $secondary;
              margin: 1 0 0 0; padding: 0 2; height: auto; }
#cur_head { height: auto; }
#cur_msg { text-style: bold; height: auto; padding: 0 0 0 2; }

/* LIVE LOG box: the last ~10 raw lines of the long remote steps. */
#tailbox { border: round $secondary 60%; border-title-color: $secondary;
           border-title-style: bold; margin: 1 0 0 0; padding: 0 2; height: auto; }
#tail_msg { color: $text-muted; height: auto; }

/* ADMIN ONBOARDING box: shown at the end with the login URL + reset link. */
#onboardbox { border: round $success; border-title-color: $success;
              border-title-style: bold; margin: 1 0 0 0; padding: 1 2; height: auto; }
#onboard_msg { color: $text; height: auto; }
"""


def welcome_screen(app_ref: "DeployApp") -> SplashScreen:
    """The deploy splash -- the shared screen with deploy's wording.

    The tagline names both things the old one left out: that Start asks for
    credentials first, and that what follows runs for hours. Someone about to
    tie up an evening should know that before pressing it."""
    return SplashScreen(
        app_ref, BANNER, app_ref.cluster,
        f"Ready to deploy [b]{app_ref.cluster}[/b] — Start asks for the vCenter "
        "and configuser passwords, then the phases run unattended for roughly "
        "1-2 hours.",
        on_start=lambda: app_ref.push_screen(SecretsScreen(app_ref)),
        start_label="Deploy ▶")


class SecretsScreen(Screen):
    BINDINGS = [("escape", "quit_app", "Exit")]

    def __init__(self, app_ref: "DeployApp") -> None:
        super().__init__()
        self._app = app_ref

    def _cfg(self) -> dict:
        """The cluster's config.yml, secrets-free -- read only to show the user
        WHICH accounts these passwords belong to."""
        import yaml
        path = Path("clusters") / self._app.cluster / "config.yml"
        try:
            return yaml.safe_load(path.read_text()) or {}
        except Exception:
            return {}

    _POL_FALLBACK = {"min_length": 15, "require_digit": True,
                     "require_uppercase": True, "require_special": True,
                     "expires_days": 60}

    def _pol(self) -> dict:
        """configuser password policy from the OVA profile (the same constraints
        the appliance enforces)."""
        try:
            from . import ovftool
            return ovftool.load_profile()["constraints"]["configuser_password"]
        except Exception:
            return dict(self._POL_FALLBACK)

    def _policy(self) -> str:
        c = self._pol()
        bits = [f">= {c.get('min_length', 15)} chars"]
        if c.get("require_digit"):
            bits.append("1 digit")
        if c.get("require_uppercase"):
            bits.append("1 uppercase")
        if c.get("require_special"):
            bits.append("1 special char")
        tail = ""
        if c.get("expires_days"):
            tail = f"; expires {c['expires_days']} days after OVA deployment"
        return "Policy: " + ", ".join(bits) + tail + "."

    def _secret_caveats(self) -> str:
        """The two places a password provably leaves this process. Both are
        unavoidable and documented, so name them instead of implying otherwise:
        ovftool 5.x takes the vCenter password in its vi:// argument (no stdin
        support), and the guide's Ansible inventory carries the configuser
        password when cluster.auth is 'password'."""
        bits = ["· During phase 10 BOTH passwords sit in the local ovftool "
                "command line — the vCenter one in the vi:// target, and the "
                "configuser one as an OVF property that also becomes the "
                "appliances' root password. Readable via `ps` on this machine "
                "for the minutes each VM uploads; ovftool 5.x offers no stdin."]
        if self._cfg().get("cluster", {}).get("auth", "key") == "password":
            bits.append("· configuser: cluster.auth is 'password', so it is also "
                        "written into cp-cluster.ini on the bootstrap node — "
                        "the inventory the guide requires. Use auth 'key' to "
                        "avoid that part.")
        else:
            bits.append("· configuser: cluster.auth is 'key', so beyond phase 10 "
                        "it only ever travels over the SSH pty and is written "
                        "nowhere.")
        return "\n".join(bits)

    def _policy_missing(self, pw: str) -> list[str]:
        """Which policy rules the entered password violates (live check)."""
        c = self._pol()
        missing = []
        if len(pw) < c.get("min_length", 15):
            missing.append(f"{c.get('min_length', 15)} chars (has {len(pw)})")
        if c.get("require_digit") and not any(ch.isdigit() for ch in pw):
            missing.append("a digit")
        if c.get("require_uppercase") and not any(ch.isupper() for ch in pw):
            missing.append("an uppercase letter")
        if c.get("require_special") and not any(not ch.isalnum() for ch in pw):
            missing.append("a special character")
        return missing

    def compose(self) -> ComposeResult:
        cfg = self._cfg()
        vc = cfg.get("vcenter", {})
        nodes = cfg.get("nodes", {})
        boot = nodes.get("bootstrap", {})
        n_nodes = 1 + len(nodes.get("platform", []) or []) + len(nodes.get("access", []) or [])
        vc_ref = (f"user [b]{vc.get('user', '?')}[/b] @ [b]{vc.get('host', '?')}[/b]"
                  if vc else "see vcenter: in config.yml")
        cu_ref = (f"account [b]configuser[/b] on all {n_nodes} nodes "
                  f"(e.g. {boot.get('hostname', '?')} {boot.get('ip', '')})")
        yield Header(show_clock=False)
        with VerticalScroll(id="body"):
            yield Static(BANNER, id="banner")
            # Precise, not reassuring: aXs itself never persists either password
            # (not in config.yml, not in deploy.log, never in an env var), but
            # two things genuinely leave this process, and hiding that would be
            # the kind of claim this tool must not make.
            yield Static(f"Deploying cluster [b]{self._app.cluster}[/b] — two "
                         "credentials are needed for this run. aXs never writes "
                         "them to disk and forgets them when it ends.",
                         classes="hint")
            yield Static(self._secret_caveats(), classes="help")
            box = Vertical(classes="secbox", id="credbox")
            box.border_title = " CREDENTIALS "
            with box:
                # Labels+descriptions and the two inputs live in SEPARATE rows,
                # so the input fields align regardless of description height.
                with Horizontal(classes="row"):
                    with Vertical(classes="cell"):
                        yield Label("vCenter password")
                        yield Static(f"For {vc_ref} — deploys the node VMs "
                                     "(ovftool + vCenter API).", classes="help")
                    with Vertical(classes="cell"):
                        yield Label("configuser password")
                        # On a fresh deploy this same value is handed to the OVA
                        # for BOTH accounts (p10_vms: root and configuser share
                        # the appliance password) -- worth knowing before you
                        # pick one.
                        yield Static(f"For {cu_ref} — SSH access, set at OVA "
                                     "deployment. On a fresh deploy it is also "
                                     "set as the appliances' root password."
                                     f"\n{self._policy()}",
                                     classes="help")
                with Horizontal(classes="row"):
                    with Vertical(classes="cell"):
                        yield Input(password=True, id="w_vc_pw")
                    with Vertical(classes="cell"):
                        yield Input(password=True, id="w_cu_pw")
                        yield Static("", id="pwstatus", classes="help")
                yield Checkbox("Show passwords", id="w_show", value=False)
            # Logging backends configured with a user need their password too.
            # They are deliberately absent from config.yml, so this is the only
            # place they are entered -- once per run, in memory only.
            for name, user in self._logging_users():
                box = Vertical(classes="secbox")
                box.border_title = f" {name.upper()} "
                with box:
                    yield Label(f"Password for {user}")
                    yield Static("Written to profile.yml on the bootstrap; "
                                 "never stored on this machine.", classes="help")
                    yield Input(password=True, id=f"w_log_{name}")
            yield Static("", id="errbox")
        with Horizontal(id="nav"):
            yield Button("Exit", id="quit", variant="error")
            yield Button("Start deployment", id="start", variant="primary")
        yield Footer()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "w_show":
            for wid in ("#w_vc_pw", "#w_cu_pw"):
                self.query_one(wid, Input).password = not event.value

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "w_cu_pw":
            return
        pw = event.value
        status = self.query_one("#pwstatus", Static)
        if not pw:
            status.update("")
            return
        missing = self._policy_missing(pw)
        if missing:
            status.update("[red]still missing: " + ", ".join(missing) + "[/red]")
        else:
            status.update("[green]meets the policy ✔[/green]")

    def _logging_users(self) -> list[tuple[str, str]]:
        """(backend, username) for every logging backend that needs a password."""
        from . import profile_yml
        ops = self._cfg().get("deployment_settings", {}) or {}
        log = ops.get("logging") or {}
        return [(name, (log.get(name) or {}).get("username", "?"))
                for name in profile_yml.needs_passwords(ops)]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            self._app.exit(None)
        elif event.button.id == "start":
            vc = self.query_one("#w_vc_pw", Input).value
            cu = self.query_one("#w_cu_pw", Input).value
            if not vc or not cu:
                self.query_one("#errbox", Static).update(
                    "Both passwords are required.")
                return
            missing = self._policy_missing(cu)
            if missing:
                # On a fresh deploy this password SETS the appliance accounts --
                # a policy violation would fail the OVA deploy much later.
                self.query_one("#errbox", Static).update(
                    "configuser password does not meet the appliance policy "
                    "(missing: " + ", ".join(missing) + ").")
                return
            # Held only as in-process values on the app and passed directly to
            # config.context -- never in os.environ, never on disk.
            self._app.vc_password = vc
            self._app.cu_password = cu
            self._app.logging_passwords = {
                name: self.query_one(f"#w_log_{name}", Input).value
                for name, _ in self._logging_users()
            }
            self._app.push_screen(ProgressScreen(self._app))

    def action_quit_app(self) -> None:
        self._app.exit(None)


class ProgressScreen(Screen):
    BINDINGS = [
        ("escape", "quit_app", "Exit"),
        ("plus", "more_lines", "+ log lines"),
        ("equals_sign", "more_lines", ""),   # '+' without shift on most layouts
        ("minus", "fewer_lines", "− log lines"),
    ]

    def __init__(self, app_ref: "DeployApp") -> None:
        super().__init__()
        self._app = app_ref
        self.started = _dt.datetime.now()
        self.phase_started: _dt.datetime | None = None
        self.current: str | None = None
        self.finished = False
        # How many log lines the LIVE LOG box shows -- adjustable at runtime with
        # +/-. The engine sends a larger buffer; we slice the last `tail_n`.
        self.tail_n = 20
        self._tail_buf: list[str] = []

    @staticmethod
    def _row(name: str, title: str, status: str) -> str:
        # Fixed-width name column so icons, names and titles align.
        return f"{ICON[status]}  [b]{name:<16}[/b] {title}"

    def compose(self) -> ComposeResult:
        from .cli import PHASES
        yield Header(show_clock=False)
        with VerticalScroll(id="body"):
            yield Static(BANNER, id="banner")
            # "Idempotent" is true at PHASE level -- completed phases are skipped
            # via their probes. Inside a phase a re-run may redo work (phase 40
            # re-copies the multi-GB bundle), so do not promise "exactly where it
            # stopped".
            yield Static(f"[b]Deploying[/b] {self._app.cluster} — live progress. "
                         "Every phase is idempotent: a re-run skips the phases "
                         "already complete and resumes at the first that is not.",
                         classes="hint")
            box = Vertical(classes="secbox", id="phasebox")
            box.border_title = " PHASES "
            with box:
                for name, title, _deps in PHASES:
                    yield Static(self._row(name, title, "todo"),
                                 id=f"ph_{name}", classes="phase")
                    detail = Static("", id=f"phd_{name}", classes="phasedetail")
                    detail.display = False       # no blank line while empty
                    yield detail
            # CURRENT box sits directly under the phase list -- what is happening
            # RIGHT NOW, big and readable, not pinned to the far bottom.
            cur = Vertical(id="currentbox")
            cur.border_title = " CURRENT "
            with cur:
                yield Static("", id="cur_head")
                yield Static("waiting to start ...", id="cur_msg")
                yield Static("", id="cur_safe")
            # LIVE LOG box: the last ~10 raw lines of the long remote steps
            # (wso cp/services deploy, create-tenant). Hidden until there is one.
            tail = Vertical(id="tailbox")
            tail.border_title = f" LIVE LOG (last {self.tail_n} lines · +/- to change) "
            tail.display = False
            with tail:
                yield Static("", id="tail_msg")
            # ADMIN ONBOARDING box: filled at the very end with login URL +
            # reset link. Hidden until the deploy completes.
            ob = Vertical(id="onboardbox")
            ob.border_title = " ADMIN ONBOARDING "
            ob.display = False
            with ob:
                yield Static("", id="onboard_msg")
            yield Static("", id="outcome")
        with Horizontal(id="nav"):
            yield Button("Exit", id="quit", variant="error")
            yield Button("◀ Credentials", id="creds", variant="default")
            yield Button("Retry", id="retry", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#retry", Button).display = False
        self.query_one("#creds", Button).display = False
        self.set_interval(1.0, self._tick)
        self._start_engine()

    def _start_engine(self) -> None:
        self.finished = False
        self.query_one("#outcome", Static).update("")
        self.query_one("#retry", Button).display = False
        self.query_one("#creds", Button).display = False
        threading.Thread(target=self._engine_guarded, daemon=True).start()

    def _engine_guarded(self) -> None:
        """Run the engine and NEVER let it die in silence.

        _engine runs in a daemon thread, and a daemon thread's uncaught
        exception is swallowed: Python writes it to stderr, which the TUI has
        taken over, so it vanishes and the board freezes on whatever state it
        last painted -- the elapsed timer keeps ticking (the UI thread lives),
        which reads as a hang. This cost hours on 2026-07-30: a deploy that
        "hung" on the first probe had in fact thrown, and probe_of catches only
        `Exception`, so a bare BaseException walked straight out of the thread.

        Anything that escapes now lands in a file (stderr is hidden) and on the
        board as a failure. A deploy may fail; it must never freeze without a
        reason on the screen.
        """
        try:
            self._engine()
        except BaseException as exc:  # noqa: BLE001 -- catching all is the point
            import traceback
            from pathlib import Path
            # Everything up to the file write is inside the guard's own
            # try/except: the whole point is that this block cannot itself throw
            # and re-swallow the failure. The header is self-describing -- WHEN,
            # which cluster, and which phase was current, "(probe round)" if it
            # died before any phase ran, which is exactly what would have named
            # the 2026-07-30 hang at a glance. Overwrites, so the file is always
            # the latest failure, not a pile.
            try:
                where = getattr(self, "current", None) \
                    or "(probe round, before any phase ran)"
                header = (
                    "aXs deploy engine error -- the engine thread stopped here.\n"
                    f"time:    {_dt.datetime.now():%Y-%m-%d %H:%M:%S}\n"
                    f"cluster: {getattr(getattr(self, '_app', None), 'cluster', '?')}\n"
                    f"phase:   {where}\n" + "-" * 64 + "\n")
                Path("deploy-engine-error.log").write_text(
                    header + traceback.format_exc())
            except Exception:
                pass
            self._outcome(False, f"The deploy engine stopped on an unexpected "
                                 f"{type(exc).__name__}: {exc}. Nothing past this "
                                 f"ran. Full trace in deploy-engine-error.log.")

    # -- UI update helpers (called from the engine thread) -----------------
    def _set(self, name: str, status: str, detail: str = "") -> None:
        def apply() -> None:
            from .cli import PHASES
            title = next(t for n, t, _ in PHASES if n == name)
            self.query_one(f"#ph_{name}", Static).update(self._row(name, title, status))
            d = detail
            if status == "running":
                # The list stays calm (static description); the LIVE sub-step
                # goes to the pinned CURRENT box below.
                if self.current != name:
                    self.current = name
                    self.phase_started = _dt.datetime.now()
                d = DOING.get(name, "")
                self.query_one("#cur_msg", Static).update(
                    detail or DOING.get(name, ""))
                self._update_cur_head()
            elif self.current == name:
                self.current = None
                if status == "done":
                    self.query_one("#cur_msg", Static).update(
                        f"[green]{name} finished ✔[/green]")
                elif status == "failed":
                    # Escape: failure text is whatever the remote tool printed.
                    # A JSON error like {"args":["filter.type"]} is full of
                    # square brackets, which Rich reads as markup -- it ate part
                    # of the message and leaked a stray [/red] onto the screen.
                    self.query_one("#cur_msg", Static).update(
                        f"[red]{name} failed — {escape(detail[:160])}[/red]")
                self._update_cur_head()
            dw = self.query_one(f"#phd_{name}", Static)
            dw.update(escape(d[:300]) if status == "failed" else d[:300])
            dw.display = bool(d.strip())
        self._ui(apply)

    def _update_cur_head(self) -> None:
        from .cli import PHASES
        from .phases import REGISTRY
        if self.current and self.phase_started:
            title = next(t for n, t, _ in PHASES if n == self.current)
            el = str(_dt.datetime.now() - self.phase_started).split(".")[0]
            head = f"[yellow]▶[/yellow] [b]{self.current}[/b] — {title}   ({el})"
            mod = REGISTRY.get(self.current)
            if getattr(mod, "RESTART_SAFE", True):
                safe = ("[green]● safe to restart[/green] — a re-run skips finished "
                        "phases and re-attaches to running remote steps")
            else:
                note = getattr(mod, "RESTART_NOTE",
                               "this step should not be interrupted")
                safe = f"[red]● do NOT restart now[/red] — {note}"
        elif self.finished:
            head = "[dim]no phase running[/dim]"
            safe = ""
        else:
            head = "[dim]no phase running[/dim]"
            safe = "[green]● safe to restart[/green] — nothing is mid-flight"
        self.query_one("#cur_head", Static).update(head)
        try:
            self.query_one("#cur_safe", Static).update(safe)
        except Exception:
            pass

    class UiWork(Message):
        """A UI update handed over from the engine thread.

        Carries a callable rather than data because each site already builds its
        own closure -- the point of the message is only WHERE it runs, not what.
        """

        def __init__(self, fn) -> None:
            super().__init__()
            self.fn = fn

    def _ui(self, fn) -> None:
        """Run `fn` on the UI thread WITHOUT waiting for it.

        This used to be `call_from_thread`, which blocks the caller on a Future
        until the UI thread answers. On 2026-07-28 a deploy froze exactly there:
        the screen showed 30_lb done, the log did not have that line yet, and
        the engine thread sat in a condition wait while the event loop was idle.
        None of these updates needs a result, so nothing has to be waited for --
        and a posted message cannot deadlock. It also survives a closing app,
        where call_from_thread raises and would kill the engine mid-phase.
        """
        try:
            self.post_message(self.UiWork(fn))
        except Exception:
            pass          # app already gone -- a screen update is moot then

    def on_progress_screen_ui_work(self, message: "ProgressScreen.UiWork") -> None:
        """Apply one engine update. Runs on the UI thread, in order of posting."""
        try:
            message.fn()
        except Exception:
            pass          # a failed redraw must never take the deploy down

    def _set_tail(self, text: str) -> None:
        """Buffer the raw log lines of a long remote step (thread-safe), then
        render the last `tail_n` of them."""
        def apply() -> None:
            self._tail_buf = (text or "").splitlines()
            self._render_tail()
        self._ui(apply)

    def _render_tail(self) -> None:
        """Show the last `tail_n` buffered log lines. Runs on the UI thread --
        called both from _set_tail (new data) and the +/- actions (resize)."""
        box = self.query_one("#tailbox", Vertical)
        lines = self._tail_buf[-self.tail_n:] if self._tail_buf else []
        box.display = bool(lines)
        box.border_title = f" LIVE LOG (last {self.tail_n} lines · +/- to change) "
        if lines:
            self.query_one("#tail_msg", Static).update("\n".join(lines))

    def action_more_lines(self) -> None:
        self.tail_n = min(60, self.tail_n + 5)
        self._render_tail()

    def action_fewer_lines(self) -> None:
        self.tail_n = max(5, self.tail_n - 5)
        self._render_tail()

    def _show_onboarding(self, block: str) -> None:
        """Fill the ADMIN ONBOARDING box and hide the (now-frozen) LIVE LOG --
        makes clear the deploy is done and this is what to do next."""
        def apply() -> None:
            self.query_one("#onboardbox", Vertical).display = True
            self.query_one("#onboard_msg", Static).update(block)
            self.query_one("#tailbox", Vertical).display = False
        self._ui(apply)

    def _done_line(self, name, probe, *, ran: bool = False) -> None:
        """Mark a phase done AND show what its probe still had to say.

        A METHOD, not a function nested in _engine. It was nested, and every
        `self._done_line(...)` call therefore raised AttributeError -- caught by
        nothing (probe_of wraps only is_done), so it killed the engine thread on
        the FIRST done phase and froze the board on 'probing' with no error
        shown. That is the hang that cost 2026-07-30; the guard around _engine
        now surfaces such a thing, and this makes the three call sites resolve.

        Probe.warning exists because `detail` never reaches a done phase -- the
        board writes a fixed label over it. It was rendered in the first probe
        round only, which is the round a phase SKIPS whenever an earlier phase
        is still open. So on an ordinary resume, and again after a phase had
        just run, the warning was collected and thrown away. One helper, three
        call sites, so there is no fourth place to forget.
        """
        lines = [ln for ln in (getattr(probe, "warning", "") or "").splitlines()
                 if ln.strip()]
        label = "" if ran else "already done"
        self._log(f"{name}: done" if ran else f"{name}: already done")
        for line in lines:
            self._log(f"{name}: {line}")
        self._set(name, "done", lines[0][:200] if lines else label)

    def _outcome(self, ok: bool, text: str) -> None:
        def apply() -> None:
            self.finished = True
            colour = "green" if ok else "red"
            self.query_one("#outcome", Static).update(f"[{colour}]{text}[/{colour}]")
            self.query_one("#retry", Button).display = not ok
            # On failure also offer going back to the credentials screen -- the
            # fix for a wrong password (Retry alone reuses the same password).
            self.query_one("#creds", Button).display = not ok
        self._ui(apply)

    def _tick(self) -> None:
        if self.finished:
            return
        total = str(_dt.datetime.now() - self.started).split(".")[0]
        self.query_one("#currentbox", Vertical).border_subtitle = f" elapsed {total} "
        self._update_cur_head()

    def _log(self, line: str) -> None:
        """Append one line to clusters/<name>/deploy.log -- redacted.

        Redaction belongs HERE, at the single writer, not only in ctx.report:
        the failure path logs `explain_failure()`, which quotes raw remote
        output on purpose (p80 includes the tail of create-tenant.log). If
        create-tenant printed the reset link and then failed, the link used to
        land in this file permanently -- the exact thing context.redact exists
        to prevent.
        """
        from .context import redact
        path = Path("clusters") / self._app.cluster / "deploy.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with path.open("a") as f:
            f.write(f"{stamp} {redact(line)}\n")

    # -- the engine (background thread) ------------------------------------
    def _engine(self) -> None:
        from . import config
        from .cli import PHASES
        from .phases import REGISTRY, Probe

        try:
            ctx = config.context(self._app.cluster,
                                 password=self._app.cu_password,
                                 vc_password=self._app.vc_password,
                                 logging_passwords=self._app.logging_passwords)
        except Exception as exc:  # noqa: BLE001
            self._outcome(False, f"Could not load the configuration: {exc}")
            return

        # Fail fast on a wrong configuser password: otherwise every phase-20
        # node probe is refused and the phase spins for 20 minutes (and racks up
        # faillock lockouts). One quick check against the bootstrap up front.
        if ctx.password_refused():
            self._outcome(False,
                f"The configuser password was refused by {ctx.bootstrap_ip}. "
                "Press ◀ Credentials to re-enter it — nothing was changed. "
                "(A wrong password would make phase 20 wait 20 min for nodes it "
                "can't authenticate to.)")
            return

        # The LIVE LOG box follows whatever long remote step is running.
        ctx.log_sink = self._set_tail

        self._log(f"=== deploy {self._app.cluster} started ===")
        order = [n for n, _, _ in PHASES if n in REGISTRY]

        # Phases whose probe RAISED. Kept apart from "not done" on purpose: this
        # used to return a stand-in with done=False, which the run loop cannot
        # tell from a genuine "not finished" -- so a probe that crashed made the
        # TUI RUN the phase against a live cluster on the strength of a bug.
        broken: dict[str, str] = {}

        def probe_of(name: str):
            try:
                return REGISTRY[name].is_done(ctx)
            except Exception as exc:  # noqa: BLE001
                broken[name] = f"{type(exc).__name__}: {exc}"
                return Probe(False, detail=broken[name])

        # Probe round, dependency-aware: a phase whose dependency is still open
        # is NOT probed (its probe would just run into ssh timeouts against
        # machines that do not exist yet) -- it shows "waits for <dep>" and is
        # probed later, right before its turn.
        done: set[str] = set()
        unprobed: set[str] = set()
        for name in order:
            deps = [d for d in REGISTRY[name].DEPS if d in REGISTRY]
            open_deps = [d for d in deps if d not in done]
            if open_deps:
                unprobed.add(name)
                self._set(name, "todo", f"waits for {', '.join(open_deps)}")
                self._log(f"{name}: waiting on {', '.join(open_deps)}")
                continue
            self._set(name, "probing", "probing ...")
            probe = probe_of(name)
            if probe.done:
                done.add(name)
                self._done_line(name, probe)
            else:
                first = str(probe.detail or "").strip().splitlines()
                self._set(name, "todo", first[0][:200] if first else "")
                self._log(f"{name}: todo")

        for name in order:
            if name in done:
                continue
            phase = REGISTRY[name]
            missing = [d for d in phase.DEPS if d in REGISTRY and d not in done]
            if missing:
                self._set(name, "failed", f"waiting on {', '.join(missing)}")
                self._outcome(False, f"{name} cannot run -- {', '.join(missing)} "
                                     "did not complete.")
                return
            if name in unprobed:
                # Deps are complete now -- check whether the phase is in fact
                # already done (resume case) before running it.
                self._set(name, "probing", "probing ...")
                probe = probe_of(name)
                if probe.done:
                    done.add(name)
                    # Same rendering as the first probe round. It was missing
                    # here, and THIS is the path a phase takes whenever an
                    # earlier phase was still open -- so a done-with-warning
                    # phase (config drift, an unreachable tenant URL) went
                    # silent exactly on the ordinary resume.
                    self._done_line(name, probe)
                    continue
            if name in broken:
                self._set(name, "failed", broken[name][:300])
                self._log(f"{name}: probe raised: {broken[name]}")
                self._outcome(False, f"{name}: its probe raised "
                                     f"{broken[name]}. Nothing was changed — "
                                     "running the phase on a crashed probe "
                                     "would act on a cluster nobody could "
                                     "read. Fix the cause and press Retry.")
                return
            self._set_tail("")   # clear the previous phase's log tail
            self._set(name, "running")
            self._log(f"{name}: running")
            # Wire the live-progress sink: sub-steps (per-VM deploys, node
            # reachability counts) appear under the running phase.
            ctx.progress = lambda msg, _n=name: (self._set(_n, "running", msg),
                                                 self._log(f"{_n}: {msg}"))
            try:
                phase.run(ctx)
            except Exception as exc:  # noqa: BLE001
                msg = phase.explain_failure(ctx, exc)
                self._set(name, "failed", str(msg)[:300])
                self._log(f"{name}: FAILED: {msg}")
                self._outcome(False, f"{name} failed — see the line under the "
                                     "phase. Fix the cause and press Retry; "
                                     "completed phases are skipped.")
                return
            try:
                probe = phase.is_done(ctx)
            except Exception as exc:  # noqa: BLE001
                self._set(name, "failed", f"{type(exc).__name__}: {exc}"[:300])
                self._outcome(False, f"{name} ran, but the probe that confirms "
                                     f"it raised {type(exc).__name__}: {exc}. "
                                     "The work itself may have succeeded — "
                                     "press Retry to re-check.")
                return
            if not probe.done:
                self._set(name, "failed", "run finished but probe still reports not done")
                self._log(f"{name}: probe still not done after run")
                self._outcome(False, f"{name}: run finished but the probe still "
                                     "reports not done. Press Retry to re-check.")
                return
            done.add(name)
            # The run succeeded, and the probe can STILL have something to say
            # -- phase 80 measuring its own tenant URL as unreachable is the
            # case this was written for. Dropping it here meant the completion
            # banner advertised a login URL the probe had just found dead.
            self._done_line(name, probe, ran=True)

        a = ctx.access
        self._log("=== deploy complete ===")
        # Surface the admin onboarding block (login URL + reset-password link) --
        # it is what the operator needs next, and the reset link is the only way
        # to set the first admin password.
        onboard = ""
        try:
            p80 = REGISTRY.get("80_tenant")
            if p80 is not None and hasattr(p80, "onboarding_info"):
                onboard = p80.onboarding_info(ctx)
        except Exception:  # noqa: BLE001
            onboard = ""
        url = f"https://{a['first_tenant']['tenant_name']}.{a['domain']}"
        if onboard:
            self._show_onboarding(
                onboard +
                "\n\n[dim](the reset link is single-use and expires — use it now)[/dim]")
            self._outcome(True, f"Deployment complete. ✔   Login: {url}/auth/login")
        else:
            self._outcome(True, f"Deployment complete. ✔   Tenant: {url}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            self._app.exit(None)
        elif event.button.id == "retry":
            self._start_engine()
        elif event.button.id == "creds":
            # Back to the credentials screen to re-enter the password. The
            # SecretsScreen is still on the stack with its fields intact.
            self._app.pop_screen()

    def action_quit_app(self) -> None:
        self._app.exit(None)


class DeployApp(App):
    CSS = CSS
    TITLE = "aXs . deploy"
    # Deliberately NO suspend/background binding: suspending would pause the
    # local process mid-deploy (e.g. ovftool while a VM uploads). To put a long
    # deploy in the background, run it inside tmux and detach -- it keeps
    # running there.

    def __init__(self, cluster: str) -> None:
        super().__init__()
        self.cluster = cluster
        self.vc_password: str | None = None
        self.cu_password: str | None = None
        # Logging backend passwords, entered on the credentials screen.
        self.logging_passwords: dict = {}

    def on_mount(self) -> None:
        self.register_theme(WS1_THEME)
        self.theme = "ws1purple"
        # Startup splash (the axe), then the credentials form. Credentials are
        # ALWAYS entered interactively -- in-process only, gone when it ends.
        self.push_screen(welcome_screen(self))


def run(cluster: str) -> int:
    DeployApp(cluster).run()
    return 0
