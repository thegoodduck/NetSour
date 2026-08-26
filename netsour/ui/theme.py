"""Semantic colour management with graceful degradation.

Themes name *roles* ("accent", "danger", "proto_tcp"), never colours. A theme is
a small `ThemeSpec` of core colours; the full role table is generated from it,
so every palette stays internally consistent and a new theme is a dozen numbers
rather than fifty.

Resolution order: 256-colour, then the 8 ANSI colours, then attributes only.
"""

from __future__ import annotations

import curses
from dataclasses import dataclass, field
from typing import Dict, Tuple

DEFAULT = -1          # the terminal's own background


@dataclass(frozen=True)
class ThemeSpec:
    """Core colours a theme picks; every role is derived from these."""

    name: str
    dark: bool
    text: int           # primary foreground
    muted: int          # secondary text
    faint: int          # frame lines, disabled text
    panel: int          # popup / status-bar background
    accent: int         # primary highlight
    accent_alt: int     # secondary highlight
    ok: int
    warn: int
    danger: int
    info: int
    sel_fg: int
    sel_bg: int
    zebra: int          # alternating row background, or DEFAULT for none
    protos: Dict[str, int] = field(default_factory=dict)


# Protocol hues shared by the dark themes unless a theme overrides them.
DARK_PROTOS = {
    "tcp": 114, "udp": 117, "icmp": 176, "arp": 215,
    "dns": 222, "tls": 79, "http": 209, "other": 245,
}

THEME_SPECS = {
    "midnight": ThemeSpec(
        name="midnight", dark=True,
        text=253, muted=245, faint=238, panel=235,
        accent=45, accent_alt=81, ok=78, warn=214, danger=203, info=75,
        sel_fg=231, sel_bg=25, zebra=234, protos=DARK_PROTOS),

    "nord": ThemeSpec(
        name="nord", dark=True,
        text=252, muted=246, faint=239, panel=236,
        accent=110, accent_alt=116, ok=108, warn=222, danger=174, info=109,
        sel_fg=231, sel_bg=60, zebra=235,
        protos={"tcp": 108, "udp": 110, "icmp": 139, "arp": 222,
                "dns": 223, "tls": 115, "http": 173, "other": 245}),

    "matrix": ThemeSpec(
        name="matrix", dark=True,
        text=157, muted=71, faint=22, panel=233, accent=46, accent_alt=118, ok=46, warn=190, danger=196,
        info=85, sel_fg=16, sel_bg=40, zebra=234,
        protos={"tcp": 46, "udp": 85, "icmp": 121, "arp": 190,
                "dns": 148, "tls": 42, "http": 226, "other": 65}),

    "amber": ThemeSpec(
        name="amber", dark=True,
        text=223, muted=180, faint=94, panel=234,
        accent=214, accent_alt=220, ok=142, warn=208, danger=196, info=179,
        sel_fg=16, sel_bg=172, zebra=235,
        protos={"tcp": 214, "udp": 179, "icmp": 175, "arp": 220,
                "dns": 187, "tls": 143, "http": 208, "other": 137}),

    "paper": ThemeSpec(
        name="paper", dark=False,
        text=235, muted=241, faint=250, panel=254,
        accent=26, accent_alt=31, ok=28, warn=130, danger=124, info=25,
        sel_fg=231, sel_bg=25, zebra=255,
        protos={"tcp": 28, "udp": 24, "icmp": 90, "arp": 130,
                "dns": 94, "tls": 29, "http": 166, "other": 242}),
}

# Role -> (spec attribute for fg, spec attribute for bg, extra attributes).
# A bg of None means the terminal default.
ROLE_MAP = {
    "base":        ("text", None, 0),
    "dim":         ("muted", None, 0),
    "faint":       ("faint", None, curses.A_DIM),
    "frame":       ("faint", None, 0),
    "frame_hot":   ("accent", None, 0),
    "title":       ("accent_alt", None, curses.A_BOLD),
    "accent":      ("accent", None, 0),
    "header":      ("accent_alt", None, curses.A_BOLD),
    "ok":          ("ok", None, 0),
    "warn":        ("warn", None, 0),
    "danger":      ("danger", None, curses.A_BOLD),
    "info":        ("info", None, 0),
    "spark":       ("accent", None, 0),
    "bar":         ("accent_alt", None, 0),
    "hex_off":     ("faint", None, 0),
    "hex_ascii":   ("ok", None, 0),
    "zebra":       ("text", "zebra", 0),
    "zebra_dim":   ("muted", "zebra", 0),
    "select":      ("sel_fg", "sel_bg", curses.A_BOLD),
    "select_dim":  ("sel_fg", "sel_bg", 0),
    "status":      ("text", "panel", 0),
    "status_key":  ("accent", "panel", curses.A_BOLD),
    "status_dim":  ("muted", "panel", 0),
    "tab_on":      ("sel_fg", "accent", curses.A_BOLD),
    "tab_off":     ("muted", None, 0),
    "popup":       ("text", "panel", 0),
    "popup_dim":   ("muted", "panel", 0),
    "popup_edge":  ("accent", "panel", curses.A_BOLD),
    "popup_danger": ("danger", "panel", curses.A_BOLD),
    "prompt":      ("sel_fg", "accent", curses.A_BOLD),
    "danger_bg":   ("sel_fg", "danger", curses.A_BOLD),
}

# Fallback for 8-colour terminals, by role.
ANSI8 = {
    "base": (curses.COLOR_WHITE, DEFAULT, 0),
    "dim": (curses.COLOR_WHITE, DEFAULT, curses.A_DIM),
    "faint": (curses.COLOR_BLUE, DEFAULT, curses.A_DIM),
    "frame": (curses.COLOR_BLUE, DEFAULT, curses.A_DIM),
    "frame_hot": (curses.COLOR_CYAN, DEFAULT, 0),
    "title": (curses.COLOR_CYAN, DEFAULT, curses.A_BOLD),
    "accent": (curses.COLOR_CYAN, DEFAULT, 0),
    "header": (curses.COLOR_CYAN, DEFAULT, curses.A_BOLD),
    "ok": (curses.COLOR_GREEN, DEFAULT, 0),
    "warn": (curses.COLOR_YELLOW, DEFAULT, 0),
    "danger": (curses.COLOR_RED, DEFAULT, curses.A_BOLD),
    "info": (curses.COLOR_BLUE, DEFAULT, 0),
    "spark": (curses.COLOR_CYAN, DEFAULT, 0),
    "bar": (curses.COLOR_CYAN, DEFAULT, 0),
    "hex_off": (curses.COLOR_WHITE, DEFAULT, curses.A_DIM),
    "hex_ascii": (curses.COLOR_GREEN, DEFAULT, 0),
    "zebra": (curses.COLOR_WHITE, DEFAULT, 0),
    "zebra_dim": (curses.COLOR_WHITE, DEFAULT, curses.A_DIM),
    "select": (curses.COLOR_WHITE, curses.COLOR_BLUE, curses.A_BOLD),
    "select_dim": (curses.COLOR_WHITE, curses.COLOR_BLUE, 0),
    "status": (curses.COLOR_WHITE, curses.COLOR_BLUE, 0),
    "status_key": (curses.COLOR_CYAN, curses.COLOR_BLUE, curses.A_BOLD),
    "status_dim": (curses.COLOR_WHITE, curses.COLOR_BLUE, curses.A_DIM),
    "tab_on": (curses.COLOR_BLACK, curses.COLOR_CYAN, curses.A_BOLD),
    "tab_off": (curses.COLOR_WHITE, DEFAULT, curses.A_DIM),
    "popup": (curses.COLOR_WHITE, curses.COLOR_BLACK, 0),
    "popup_dim": (curses.COLOR_WHITE, curses.COLOR_BLACK, curses.A_DIM),
    "popup_edge": (curses.COLOR_CYAN, curses.COLOR_BLACK, curses.A_BOLD),
    "popup_danger": (curses.COLOR_RED, curses.COLOR_BLACK, curses.A_BOLD),
    "prompt": (curses.COLOR_BLACK, curses.COLOR_YELLOW, curses.A_BOLD),
    "danger_bg": (curses.COLOR_WHITE, curses.COLOR_RED, curses.A_BOLD),
}

PROTO_ANSI8 = {
    "tcp": curses.COLOR_GREEN, "udp": curses.COLOR_CYAN,
    "icmp": curses.COLOR_MAGENTA, "arp": curses.COLOR_YELLOW,
    "dns": curses.COLOR_YELLOW, "tls": curses.COLOR_GREEN,
    "http": curses.COLOR_YELLOW, "other": curses.COLOR_WHITE,
}

# Monochrome: roles collapse to attribute combinations.
MONO = {
    "title": curses.A_BOLD, "header": curses.A_BOLD, "accent": curses.A_BOLD,
    "frame_hot": curses.A_BOLD, "tab_on": curses.A_REVERSE | curses.A_BOLD,
    "tab_off": curses.A_DIM, "status": curses.A_REVERSE,
    "status_key": curses.A_REVERSE | curses.A_BOLD,
    "status_dim": curses.A_REVERSE,
    "select": curses.A_REVERSE, "select_dim": curses.A_REVERSE,
    "danger": curses.A_BOLD, "danger_bg": curses.A_REVERSE | curses.A_BOLD,
    "warn": curses.A_BOLD, "dim": curses.A_DIM, "faint": curses.A_DIM,
    "frame": curses.A_DIM, "hex_off": curses.A_DIM,
    "popup": curses.A_REVERSE, "popup_dim": curses.A_REVERSE,
    "popup_edge": curses.A_REVERSE | curses.A_BOLD,
    "popup_danger": curses.A_REVERSE | curses.A_BOLD,
    "prompt": curses.A_REVERSE | curses.A_BOLD,
}

THEMES = list(THEME_SPECS)

# Order protocol matching most-specific first: "TCP/TLS" must match TLS, not TCP.
PROTO_ORDER = ("tls", "http", "dns", "mdns", "arp", "icmp", "tcp", "udp")


def _resolve(spec: ThemeSpec, role: str) -> Tuple[int, int, int]:
    """(fg, bg, attrs) for a role in 256-colour mode."""
    fg_attr, bg_attr, attrs = ROLE_MAP[role]
    fg = getattr(spec, fg_attr)
    bg = DEFAULT if bg_attr is None else getattr(spec, bg_attr)
    return fg, bg, attrs


class Palette:
    """Resolves role names to curses attributes for the running terminal."""

    def __init__(self, name: str = "midnight"):
        self.name = name if name in THEME_SPECS else "midnight"
        self.has_color = False
        self.wide = False
        self._attrs: Dict[str, int] = {}
        self._proto: Dict[str, int] = {}
        self._next_pair = 1

    @property
    def spec(self) -> ThemeSpec:
        return THEME_SPECS[self.name]

    def init(self) -> None:
        try:
            curses.start_color()
            curses.use_default_colors()
            self.has_color = curses.has_colors()
            self.wide = self.has_color and curses.COLORS >= 256
        except Exception:
            self.has_color = False
        self._build()

    def _pair(self, fg: int, bg: int, attrs: int) -> int:
        limit = getattr(curses, "COLOR_PAIRS", 64)
        if self._next_pair >= limit - 1:
            return attrs
        try:
            curses.init_pair(self._next_pair, fg, bg)
            attr = curses.color_pair(self._next_pair) | attrs
            self._next_pair += 1
            return attr
        except Exception:
            return attrs

    def _build(self) -> None:
        self._attrs.clear()
        self._proto.clear()
        self._next_pair = 1
        if not self.has_color:
            self._attrs = {role: MONO.get(role, 0) for role in ROLE_MAP}
            self._proto = {name: MONO.get("dim", 0) if name == "other" else 0
                           for name in PROTO_ANSI8}
            return

        spec = self.spec
        for role in ROLE_MAP:
            if self.wide:
                fg, bg, attrs = _resolve(spec, role)
            else:
                fg, bg, attrs = ANSI8[role]
            self._attrs[role] = self._pair(fg, bg, attrs)

        for name in PROTO_ANSI8:
            if self.wide:
                fg = spec.protos.get(name, spec.text)
            else:
                fg = PROTO_ANSI8[name]
            self._proto[name] = self._pair(fg, DEFAULT, 0)

    def cycle(self, step: int = 1) -> str:
        self.name = THEMES[(THEMES.index(self.name) + step) % len(THEMES)]
        self._build()
        return self.name

    def use(self, name: str) -> bool:
        if name not in THEME_SPECS:
            return False
        self.name = name
        self._build()
        return True

    def __call__(self, role: str, *extra: int) -> int:
        attr = self._attrs.get(role, 0)
        for item in extra:
            attr |= item
        return attr

    def proto(self, proto: str) -> int:
        """Colour a protocol label by its most specific known component."""
        upper = proto.upper()
        for name in PROTO_ORDER:
            if name.upper() in upper:
                return self._proto.get("dns" if name == "mdns" else name,
                                       self._proto["other"])
        return self._proto["other"]

    def severity(self, level: str) -> int:
        return self({"high": "danger", "medium": "warn", "low": "info"}
                    .get(level, "dim"))

    def row(self, index: int, selected: bool, base: str = "base") -> int:
        """Row attribute with subtle zebra striping for long tables."""
        if selected:
            return self("select")
        if index % 2 and self.spec.zebra != DEFAULT:
            return self("zebra" if base == "base" else "zebra_dim")
        return self(base)
