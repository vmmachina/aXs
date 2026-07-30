"""The startup splash, shared by `axs configure` and `axs deploy`.

One screen, two callers. It used to live inside the deploy TUI, which meant
configure started with a bare form and the two entry points felt like different
tools. Only the wording and what Start leads to differ, so that is all the
caller passes in. It lives in its own module because tui_deploy already imports
from tui -- putting it in either would risk an import cycle.

Layout, top to bottom: the axe (given whatever height is left), the aXs logo,
one dim context line, one line saying what happens next, then Exit / Start.
The axe is sized from the measured height of everything else, so the splash
never scrolls -- a shorter terminal just gets a smaller axe, and below the point
where the blocks stop reading as an axe, none at all.
"""

from __future__ import annotations

from collections.abc import Callable

from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from . import __version__
from ._art import scaled_axe

# What the tool is pinned to. Worth stating up front: an operator holding a
# different release's OVA should see the mismatch before starting, not in
# phase 40.
TARGET_RELEASE = "Omnissa Access 26.07"

# Rows the splash needs for everything that is NOT the axe: logo, context line,
# tagline, button bar, header, footer and padding.
_CHROME = 10
# Below this the axe is dropped entirely rather than shrunk: under ~12 rows the
# blade and the handle merge and it reads as a smudge, and the words matter more
# than the art. (Verified by rendering scaled_axe at 10/12/14.)
_MIN_AXE = 12


class SplashScreen(Screen):
    """Startup splash. `tagline` says what happens next, `on_start` does it."""

    BINDINGS = [("escape", "quit_app", "Exit"), ("enter", "start", "Start")]

    def __init__(self, app_ref, banner: str, cluster: str, tagline: str,
                 on_start: Callable[[], None], start_label: str = "Start ▶") -> None:
        super().__init__()
        self._app = app_ref
        self._banner = banner
        self._cluster = cluster
        self._tagline = tagline
        self._on_start = on_start
        self._start_label = start_label

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="body"):
            yield Static("", id="axe")            # filled in _fit_axe()
            yield Static(self._banner, id="banner")
            yield Static(f"cluster [b]{self._cluster}[/b]  ·  target: "
                         f"{TARGET_RELEASE}  ·  aXs v{__version__}",
                         id="splash_ctx")
            yield Static(self._tagline, id="welcome_tag")
        with Horizontal(id="nav"):
            yield Button("Exit", id="quit", variant="error")
            yield Button(self._start_label, id="start", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        self._fit_axe()

    def on_resize(self, event) -> None:  # noqa: ANN001
        self._fit_axe()

    def _fit_axe(self) -> None:
        """Give the axe every row the text does not need -- and none if what is
        left is too little for it to read as an axe."""
        avail = self.size.height - (len(self._banner.splitlines()) + _CHROME)
        art = scaled_axe(avail) if avail >= _MIN_AXE else ""
        self.query_one("#axe", Static).update(art)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            self._app.exit(None)
        elif event.button.id == "start":
            self._on_start()

    def action_start(self) -> None:
        self._on_start()

    def action_quit_app(self) -> None:
        self._app.exit(None)
