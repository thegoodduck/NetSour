"""Addons: user code that rides along with a capture without touching it.

An addon is a single Python file in ``~/.config/netsour/addons``. It imports
:mod:`netsour.addon` and decorates plain functions to contribute three things:

* a packet hook, called on the capture thread for every dissected packet;
* a dashboard panel, rendered into a card on the Dashboard view;
* a key binding, called on the UI thread when its key is pressed.

Everything an addon contributes is wrapped. A hook that raises is counted, and
an addon that keeps raising is disabled with its traceback kept for the addons
menu — the same rule the built-in detectors follow, for the same reason: a bug
in optional code must not stop capture or kill the UI.

The built-in dashboard cards are registered through this exact registry, so the
addon API is the API NetSour itself draws with.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import traceback
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from .stats import StatsView, human_bytes, human_duration
from .ui.render import Glyphs
from .ui.render import bar as _bar
from .ui.render import sparkline as _sparkline

# An addon that raises this many times in a row is switched off. Packet hooks
# run thousands of times a second; a broken one would otherwise spend the whole
# capture throwing.
MAX_FAILURES = 5

# A panel cannot push the board around by returning ten thousand lines.
PANEL_LINE_LIMIT = 64

TEMPLATE = '''"""{name} — a NetSour addon.

Drop this file in {directory} and press A → Reload inside NetSour.
Everything below is optional: keep the parts you want.
"""

from netsour.addon import alert, key, on_packet, panel

# Addon state is just module state. Packet hooks run on the capture thread and
# panels render on the UI thread, but never at the same time — NetSour holds
# the session lock for both — so plain globals are safe here.
seen = 0
hosts = {{}}


@on_packet
def count(pkt):
    """Called for every packet. Keep it cheap: this is the hot path.

    `pkt` is a PacketRecord — plain strings and ints, already dissected:
    pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.proto, pkt.length, pkt.info,
    pkt.hostname, pkt.payload_text, pkt.tags, pkt.ts.
    """
    global seen
    seen += 1
    if pkt.hostname:
        hosts[pkt.hostname] = hosts.get(pkt.hostname, 0) + 1
    # Raise a finding into the Alerts view when something is worth flagging:
    # if pkt.dport == 23:
    #     alert("Telnet in use", f"{{pkt.src}} -> {{pkt.dst}}", "medium", pkt)


@panel("{name}")
def card(ctx):
    """Draw a Dashboard card. Return strings, or (text, role) pairs.

    Roles are theme colours: base, dim, accent, ok, warn, danger, header.
    `ctx` gives you ctx.width, ctx.stats, ctx.bar(), ctx.spark(),
    ctx.bytes(), ctx.recent() and ctx.session.
    """
    lines = [(f"{{seen:,}} packets seen", "accent")]
    top = sorted(hosts.items(), key=lambda kv: -kv[1])[:5]
    peak = max([count for _, count in top], default=1)
    for host, count in top:
        lines.append(f"{{host[:ctx.width - 14]:<{{max(4, ctx.width - 14)}}}} "
                     f"{{ctx.bar(count, peak, 8)}}")
    if not top:
        lines.append(("waiting for named traffic…", "dim"))
    return lines


@key("z", "say hello")
def hello(ui):
    """Called when the user presses this key. `ui` is the running App."""
    ui.notify(f"{name}: {{seen:,}} packets so far", "accent")
'''


# --------------------------------------------------------------------------
# contributions
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Line:
    """One rendered line of a panel: text plus a theme role."""

    text: str
    role: str = "base"


@dataclass
class PanelSpec:
    """A dashboard card someone can draw."""

    key: str
    title: str
    render: Callable
    source: str = "built-in"
    order: int = 100


@dataclass
class PanelData:
    """A panel's output for one frame — plain strings, safe to render."""

    key: str
    title: str
    source: str
    lines: List[Line] = field(default_factory=list)
    error: str = ""


@dataclass
class KeySpec:
    """A key an addon claims, shown in the help and the addons menu."""

    char: str
    help: str
    handler: Callable
    source: str = ""


@dataclass
class Addon:
    """One loaded addon file and everything it contributed."""

    name: str
    path: str = ""
    doc: str = ""
    error: str = ""
    failures: int = 0
    enabled: bool = True
    panels: List[PanelSpec] = field(default_factory=list)
    keys: List[KeySpec] = field(default_factory=list)
    packet_hooks: List[Callable] = field(default_factory=list)
    start_hooks: List[Callable] = field(default_factory=list)
    clear_hooks: List[Callable] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.error and not self.enabled:
            return "failed"
        if not self.enabled:
            return "off"
        return "ok"

    def summary(self) -> str:
        parts = []
        if self.panels:
            parts.append(f"{len(self.panels)} panel"
                         f"{'s' if len(self.panels) > 1 else ''}")
        if self.packet_hooks:
            parts.append("packet hook")
        if self.keys:
            parts.append("key " + " ".join(k.char for k in self.keys))
        return " · ".join(parts) or "nothing registered"


# --------------------------------------------------------------------------
# panel context
# --------------------------------------------------------------------------

class PanelContext:
    """What a panel is handed. Built once per frame, under the session lock.

    Reading `session` here is safe precisely because of that lock: panels run
    inside :meth:`Session.derive`, which is the one place allowed to walk the
    live capture structures. Anything a panel returns is a plain string, so
    nothing live escapes into the render path.
    """

    def __init__(self, session=None, stats: Optional[StatsView] = None,
                 width: int = 60, unicode_ok: bool = True):
        self.session = session
        self.stats = stats or StatsView()
        self.width = max(8, width)
        self.unicode = unicode_ok
        self._glyphs = Glyphs(unicode_ok)

    # ---- formatting helpers ----------------------------------------------

    def bar(self, value: float, peak: float, width: Optional[int] = None) -> str:
        return _bar(value, peak, self.width - 12 if width is None else width,
                    self.unicode)

    def spark(self, values: Sequence[float], width: Optional[int] = None) -> str:
        return _sparkline(values, self.width - 2 if width is None else width,
                          self._glyphs)

    @staticmethod
    def bytes(count: float) -> str:
        return human_bytes(count)

    @staticmethod
    def duration(seconds: float) -> str:
        return human_duration(seconds)

    def pair(self, label: str, value: str, role: str = "base") -> Line:
        """`label ....... value`, right-aligned to the card width."""
        room = max(0, self.width - len(label) - 1)
        return Line(f"{label} {value[:room]:>{room}}", role)

    # ---- capture state ----------------------------------------------------

    def recent(self, count: int = 200) -> List:
        """The newest `count` packet records, oldest first."""
        if self.session is None:
            return []
        records = self.session.records
        return list(records)[-count:]

    def recent_alerts(self, count: int = 5) -> List:
        if self.session is None:
            return []
        return list(self.session.alerts.alerts)[-count:][::-1]

    @property
    def flows(self) -> List:
        if self.session is None:
            return []
        return list(self.session.flows.flows.values())


# --------------------------------------------------------------------------
# registration side — what netsour.addon writes into
# --------------------------------------------------------------------------

class _Draft:
    """Contributions collected while one addon file is being executed."""

    def __init__(self, name: str):
        self.name = name
        self.addon = Addon(name=name)


_DRAFT: Optional[_Draft] = None
_REGISTRY: Optional["AddonRegistry"] = None


def _begin(name: str) -> _Draft:
    global _DRAFT
    _DRAFT = _Draft(name)
    return _DRAFT


def _finish() -> Optional[Addon]:
    global _DRAFT
    draft, _DRAFT = _DRAFT, None
    return draft.addon if draft else None


def current_draft() -> Optional[_Draft]:
    """The addon being loaded, or None when nothing is loading."""
    return _DRAFT


def current_registry() -> Optional["AddonRegistry"]:
    """The registry attached to the running session, for `addon.alert`."""
    return _REGISTRY


# --------------------------------------------------------------------------
# the registry
# --------------------------------------------------------------------------

def config_dir() -> str:
    """`~/.config/netsour`, or wherever XDG says configuration lives."""
    override = os.environ.get("NETSOUR_CONFIG_HOME")
    if override:
        return override
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, "netsour")


def addon_dir() -> str:
    return os.path.join(config_dir(), "addons")


class AddonRegistry:
    """Loads addon files and owns every contribution, built-in ones included."""

    def __init__(self, directories: Optional[Sequence[str]] = None,
                 enabled: bool = True, load_builtins: bool = True):
        self.directories = [os.path.expanduser(d)
                            for d in (directories if directories is not None
                                      else [addon_dir()])]
        self.enabled = enabled
        self.load_builtins = load_builtins
        self.addons: List[Addon] = []
        self.builtins: List[PanelSpec] = []
        self.session = None
        self.hidden: set = set()
        self.card_width = 46
        self.unicode = True
        self._config_path = os.path.join(config_dir(), "dashboard.json")
        self._load_layout()

    @property
    def directory(self) -> str:
        """Where addons come from — the default one when none was configured."""
        return self.directories[0] if self.directories else addon_dir()

    # ---- lifecycle --------------------------------------------------------

    def attach(self, session) -> None:
        """Bind the registry to a session so `addon.alert` knows where to fire."""
        global _REGISTRY
        self.session = session
        _REGISTRY = self
        for addon in self.addons:
            for hook in addon.start_hooks:
                self._call(addon, hook, session)

    def load(self) -> None:
        """(Re)load every addon file. Safe to call at any time."""
        if self.load_builtins:
            from .dashboard import builtin_panels

            self.builtins = list(builtin_panels())
        self.addons = []
        if not self.enabled:
            return
        for directory in self.directories:
            if not os.path.isdir(directory):
                continue
            for name in sorted(os.listdir(directory)):
                if not name.endswith(".py") or name.startswith("_"):
                    continue
                self.addons.append(self.load_file(os.path.join(directory, name)))
        if self.session is not None:
            for addon in self.addons:
                for hook in addon.start_hooks:
                    self._call(addon, hook, self.session)

    def load_file(self, path: str) -> Addon:
        """Execute one addon file, capturing whatever it registers or raises."""
        name = os.path.splitext(os.path.basename(path))[0]
        draft = _begin(name)
        module_name = f"netsour_addon_{name}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                raise ImportError(f"cannot import {path}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            addon = _finish() or draft.addon
            addon.doc = (module.__doc__ or "").strip().split("\n")[0]
            addon.name = getattr(module, "NAME", name)
        except Exception:
            addon = _finish() or draft.addon
            addon.error = traceback.format_exc(limit=6)
            addon.enabled = False
        addon.path = path
        for spec_ in addon.panels:
            spec_.source = addon.name
        for key_spec in addon.keys:
            key_spec.source = addon.name
        return addon

    def reload(self) -> str:
        """Reload from disk and report what happened, for the message line."""
        if not self.enabled:
            return "Addons are disabled for this session"
        self.load()
        if self.session is not None:
            self.attach(self.session)
        broken = [a.name for a in self.addons if a.status == "failed"]
        if broken:
            return (f"Loaded {len(self.addons) - len(broken)} addon(s); "
                    f"{', '.join(broken)} failed to load")
        if not self.addons:
            return f"No addons found in {self.directory}"
        return f"Loaded {len(self.addons)} addon(s)"

    def configure(self, card_width: int, unicode_ok: bool) -> None:
        """Tell panels how wide their card will be, before they render."""
        self.card_width = max(12, card_width)
        self.unicode = unicode_ok

    # ---- dispatch ---------------------------------------------------------

    def dispatch_packet(self, rec) -> None:
        """Feed one packet to every addon hook. Called under the session lock."""
        for addon in self.addons:
            if not addon.enabled:
                continue
            for hook in addon.packet_hooks:
                self._call(addon, hook, rec)

    def dispatch_clear(self) -> None:
        for addon in self.addons:
            if not addon.enabled:
                continue
            for hook in addon.clear_hooks:
                self._call(addon, hook)

    def handle_key(self, char: str, ui) -> bool:
        """Run an addon key binding. Returns True when one claimed the key."""
        for addon in self.addons:
            if not addon.enabled:
                continue
            for key_spec in addon.keys:
                if key_spec.char == char:
                    self._call(addon, key_spec.handler, ui)
                    return True
        return False

    def key_specs(self) -> List[KeySpec]:
        return [k for addon in self.addons if addon.enabled for k in addon.keys]

    def _call(self, addon: Addon, func: Callable, *args):
        """Run addon code. It may not raise into NetSour, ever."""
        try:
            result = func(*args)
        except Exception:
            addon.failures += 1
            addon.error = traceback.format_exc(limit=6)
            if addon.failures >= MAX_FAILURES:
                addon.enabled = False
            return None
        addon.failures = 0
        return result

    # ---- panels -----------------------------------------------------------

    def panel_specs(self, include_hidden: bool = False) -> List[PanelSpec]:
        """Every card that could be drawn, built-ins first, in board order."""
        specs = list(self.builtins)
        for addon in self.addons:
            if addon.enabled:
                specs.extend(addon.panels)
        specs.sort(key=lambda spec: (spec.order, spec.title.lower()))
        if include_hidden:
            return specs
        return [spec for spec in specs if spec.key not in self.hidden]

    def render_panels(self, session=None, stats: Optional[StatsView] = None
                      ) -> List[PanelData]:
        """Render every visible card to plain text. Call under the lock."""
        ctx = PanelContext(session if session is not None else self.session,
                           stats, self.card_width, self.unicode)
        out: List[PanelData] = []
        for spec in self.panel_specs():
            data = PanelData(key=spec.key, title=spec.title, source=spec.source)
            addon = self._owner(spec)
            try:
                result = spec.render(ctx)
            except Exception:
                data.error = _one_line_error()
                if addon is not None:
                    addon.failures += 1
                    addon.error = traceback.format_exc(limit=6)
                    if addon.failures >= MAX_FAILURES:
                        addon.enabled = False
            else:
                if addon is not None:
                    addon.failures = 0
                data.lines = normalize_lines(result)
            out.append(data)
        return out

    def _owner(self, spec: PanelSpec) -> Optional[Addon]:
        for addon in self.addons:
            if spec in addon.panels:
                return addon
        return None

    # ---- alerts -----------------------------------------------------------

    def alert(self, title: str, detail: str = "", severity: str = "medium",
              rec=None, key: str = "") -> None:
        """Raise an addon finding into the Alerts view."""
        if self.session is None:
            return
        self.session.alerts.emit(title, detail=detail, severity=severity,
                                 rec=rec, key=key)

    # ---- board layout -----------------------------------------------------

    def toggle_panel(self, key: str) -> bool:
        """Show or hide one card; returns True when it is now visible."""
        if key in self.hidden:
            self.hidden.discard(key)
            visible = True
        else:
            self.hidden.add(key)
            visible = False
        self._save_layout()
        return visible

    def _load_layout(self) -> None:
        try:
            with open(self._config_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            self.hidden = set(data.get("hidden", []))
        except Exception:
            self.hidden = set()          # no config yet, or an unreadable one

    def _save_layout(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._config_path), exist_ok=True)
            with open(self._config_path, "w", encoding="utf-8") as handle:
                json.dump({"hidden": sorted(self.hidden)}, handle, indent=2)
        except Exception:
            pass                          # a read-only home is not a crash

    # ---- scaffolding ------------------------------------------------------

    def scaffold(self, name: str) -> str:
        """Write a working addon template and return its path."""
        stem = "".join(c if c.isalnum() or c in "-_" else "_"
                       for c in name).strip("_") or "addon"
        directory = self.directory
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{stem}.py")
        if os.path.exists(path):
            raise FileExistsError(path)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(TEMPLATE.format(name=stem, directory=directory))
        return path


def normalize_lines(result) -> List[Line]:
    """Turn whatever a panel returned into a bounded list of Lines."""
    if result is None:
        return []
    if isinstance(result, (str, Line)):
        result = [result]
    try:
        items = list(result)
    except TypeError:
        items = [str(result)]
    lines: List[Line] = []
    for item in items[:PANEL_LINE_LIMIT]:
        if isinstance(item, Line):
            lines.append(item)
        elif isinstance(item, str):
            lines.append(Line(item))
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            lines.append(Line(str(item[0]), str(item[1])))
        else:
            lines.append(Line(str(item)))
    return lines


def _one_line_error() -> str:
    exc_type, exc, _ = sys.exc_info()
    return f"{exc_type.__name__}: {exc}" if exc_type else "failed"
