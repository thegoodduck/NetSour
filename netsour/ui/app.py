"""The NetSour terminal application: layout, chrome, and input handling.

Single-threaded by design. Capture runs on its own thread and only appends to
the session under a lock; everything the user sees is drawn from one snapshot
per frame, so there is no way for a redraw to race a packet arrival.
"""

from __future__ import annotations

import curses
import os
import time
from typing import Dict, List, Optional

from ..capture import interface_address
from ..enrich import is_private
from ..osint import SOURCES, SOURCES_BY_KEY, target_kind
from ..session import HOST_SORTS, Session
from ..stats import human_bytes, human_duration
from . import views
from .menu import Menu, MenuItem, menu_hit
from .render import (Glyphs, addstr, box, clamp, detect_unicode, ellipsize,
                     fill)
from .theme import THEME_SPECS, THEMES, Palette

VIEWS = ["Packets", "Devices", "Flows", "Stats", "Alerts", "Hosts", "Recon",
         "OSINT", "Dash"]
# Named so that inserting a view never means renumbering conditionals by hand.
(PACKETS_VIEW, DEVICES_VIEW, FLOWS_VIEW, STATS_VIEW, ALERTS_VIEW, HOSTS_VIEW,
 RECON_VIEW, OSINT_VIEW, DASH_VIEW) = range(len(VIEWS))
DETAIL_MODES = ["tree", "hex", "stream", "geo", "nmap"]
FLOW_SORTS = ["bytes", "packets", "last", "duration", "rate"]

HELP_SECTIONS = [
    ("Views", [
        (f"1 – {len(VIEWS)}", "jump straight to a view"),
        ("← / →", "previous / next view"),
        ("Tab", "move focus between the packet list and the detail pane"),
        ("?", "show or hide this help"),
        ("q", "quit"),
    ]),
    ("Navigation", [
        ("↑ ↓ / k j", "move the selection"),
        ("PgUp PgDn", "page through the list"),
        ("Home End / g G", "jump to the first or last row"),
        ("f", "follow mode - stick to the newest packet"),
        ("Enter", "focus the detail pane on the selected row"),
    ]),
    ("Capture", [
        ("Space", "pause or resume capture (the interface keeps running)"),
        ("c", "clear the buffer, statistics, flows and alerts"),
        ("w", "write the buffer to a pcap file"),
        ("W", "write only the packets matching the current filter"),
        ("b", "set a BPF capture filter and restart capture"),
    ]),
    ("Display filter", [
        ("/", "filter by text - matches address, port, protocol and info"),
        ("Esc", "clear the text filter"),
        ("t u i a o", "toggle TCP / UDP / ICMP / ARP / other (o means offline "
                      "on the devices view)"),
        ("!", "show only packets NetSour flagged"),
        ("F", "reset every filter"),
    ]),
    ("Devices view", [
        ("Enter", "filter the packet list to the selected device"),
        ("o", "show or hide devices last seen minutes ago"),
        ("v", "switch layout: address list and identity pane, or card grid"),
        ("S", "ARP-sweep the subnet to find quiet devices"),
    ]),
    ("Inspection", [
        ("d", "cycle the detail pane: tree, hex, stream, geo, nmap"),
        ("s", "cycle the sort key (flows, alerts and hosts views)"),
        ("y", "copy the selected row's summary to the message line"),
    ]),
    ("Active probing — asks before it touches the network", [
        ("n", "Nmap the selected packet's destination host"),
        ("N", "choose an Nmap profile, then scan"),
        ("G", "geolocate the selected addresses (external HTTP lookup)"),
        ("S", "ARP-sweep the local /24 to enumerate hosts"),
    ]),
    ("Dashboard and addons", [
        ("9", "the dashboard - built-in cards plus anything addons drew"),
        ("Enter", "choose which cards the board shows"),
        ("A", "addons: reload from disk, or scaffold a new one"),
    ]),
    ("Appearance", [
        ("T", "cycle the colour theme"),
        ("Ctrl-L", "force a full redraw"),
    ]),
]


class App:
    """Owns UI state; the session owns capture state."""

    def __init__(self, stdscr, session: Session, theme: str = "midnight",
                 refresh_hz: int = 12):
        self.stdscr = stdscr
        self.session = session
        self.pal = Palette(theme)
        self.glyphs = Glyphs(detect_unicode())
        self.frame_delay = max(0.02, 1.0 / max(1, refresh_hz))

        self.view = PACKETS_VIEW
        self.detail_mode = "tree"
        self.detail_length = 0
        self.osint_length = 0
        self.dash_length = 0                   # virtual height of the card board
        self.focus = "list"                    # "list" | "detail"
        self.follow = True
        self.running = True
        self.show_help = False
        self.help_scroll = 0

        self.cursor: Dict[str, int] = {name.lower(): 0 for name in VIEWS}
        self.cursor["detail"] = 0
        self.cursor["osint"] = 0
        self.cursor["devices"] = 0
        self.device_columns = 1
        self._device_hits = (0, 1)
        # A device that has not been heard from in minutes is a memory, not a
        # host on the segment. Hidden by default; 'o' brings them back.
        self.show_offline = False
        # "panes" is the address list beside an identity pane; "grid" is the
        # card wall. 'v' switches; both draw the same devices.
        self.device_layout = "panes"
        self.scroll: Dict[str, int] = dict(self.cursor)

        self.flow_sort = "bytes"
        self.host_sort = "traffic"
        self.alert_sort = "time"
        self.nmap_profile = "fast"
        self.osint_target = ""
        self.nmap_last_target = ""
        self.menu: Optional[Menu] = None
        self._menu_rect = (0, 0, 0)
        self._menu_width = 0
        self._row_hits: Dict[str, tuple] = {}   # view -> (first row y, height)

        self.message = ""
        self.message_role = "base"
        self.message_until = 0.0
        self.prompt: Optional[dict] = None
        # Where the text caret belongs this frame, or None to hide it. Applied
        # once at the end of draw(): anything drawn after a move() would leave
        # the physical cursor at its own end position instead.
        self._caret: Optional[tuple] = None
        self._caret_visible = False

        # One immutable bundle per refresh; every view reads from this and
        # never from the live session structures.
        self.derived = session.derive()
        self._derived_at = 0.0

    # ---- helpers ----------------------------------------------------------

    def notify(self, text: str, role: str = "base", seconds: float = 4.0) -> None:
        self.message, self.message_role = text, role
        self.message_until = time.time() + seconds

    def clamp_scroll(self, key: str, total: int, visible: int) -> int:
        """Keep `key`'s cursor on-screen and return the resulting scroll offset."""
        cursor = clamp(self.cursor.get(key, 0), 0, max(0, total - 1))
        self.cursor[key] = cursor
        offset = self.scroll.get(key, 0)
        offset = min(offset, max(0, total - visible))
        offset = clamp(offset, 0, max(0, total - 1))
        if cursor < offset:
            offset = cursor
        elif cursor >= offset + visible:
            offset = cursor - visible + 1
        offset = max(0, min(offset, max(0, total - visible)))
        self.scroll[key] = offset
        return offset

    def selected_record(self):
        if not self.visible:
            return None
        index = clamp(self.cursor["packets"], 0, len(self.visible) - 1)
        return self.visible[index]

    @property
    def list_key(self) -> str:
        """The scroll key for whichever list the active view shows."""
        return VIEWS[self.view].lower()

    # ---- derived tables ---------------------------------------------------

    def refresh_derived(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._derived_at < 0.25:
            return
        self._derived_at = now
        if self.view == DASH_VIEW:
            # Panels render inside derive(), so they have to be told how wide
            # their card will be before the frame is built.
            width = self.stdscr.getmaxyx()[1]
            self.session.addons.configure(views.dashboard_card_width(width - 2),
                                          self.glyphs.unicode)
        self.derived = self.session.derive(
            flow_sort=self.flow_sort,
            alert_sort=self.alert_sort,
            host_sort=self.host_sort,
            want_devices=self.view == DEVICES_VIEW,
            want_flows=self.view == FLOWS_VIEW,
            want_alerts=self.view == ALERTS_VIEW,
            want_hosts=self.view == HOSTS_VIEW,
            want_stats=self.view == STATS_VIEW,
            want_panels=self.view == DASH_VIEW,
        )

    # Views read these; they are plain lists copied under the session lock.
    @property
    def visible(self) -> List:
        return self.derived.packets

    @property
    def flow_rows(self) -> List:
        return self.derived.flows

    @property
    def alert_rows(self) -> List:
        return self.derived.alerts

    @property
    def host_rows(self) -> List:
        return self.derived.hosts

    @property
    def device_rows(self) -> List:
        """The devices worth showing — online ones unless 'o' says otherwise."""
        devices = self.derived.devices
        if self.show_offline:
            return devices
        return [device for device in devices if device.status != "offline"]

    @property
    def hidden_devices(self) -> int:
        """How many devices the offline filter is holding back."""
        if self.show_offline:
            return 0
        return sum(1 for device in self.derived.devices
                   if device.status == "offline")

    # ---- main loop --------------------------------------------------------

    def run(self) -> None:
        self._init_curses()
        while self.running:
            self.refresh_derived()
            if self.follow and self.view == PACKETS_VIEW and self.visible:
                self.cursor["packets"] = len(self.visible) - 1
            self._check_capture_error()
            try:
                self.draw()
            except curses.error:
                pass                            # a resize mid-frame; next frame wins
            self._pump_input()

    def _init_curses(self) -> None:
        curses.curs_set(0)
        self.pal.init()
        self.stdscr.nodelay(True)
        self.stdscr.timeout(int(self.frame_delay * 1000))
        self.stdscr.keypad(True)
        try:
            curses.mousemask(curses.BUTTON1_CLICKED | curses.BUTTON4_PRESSED
                             | getattr(curses, "BUTTON5_PRESSED", 0))
        except Exception:
            pass

    def _check_capture_error(self) -> None:
        error = self.session.capture.error
        if error and error != getattr(self, "_last_error", None):
            self._last_error = error
            self.notify(error, "danger", seconds=30)

    def _pump_input(self) -> None:
        key = self.stdscr.getch()
        if key == -1:
            return
        if self.menu is not None:
            self._menu_key(key)
            return
        if self.prompt is not None:
            self._prompt_key(key)
            return
        if self.show_help:
            self._help_key(key)
            return
        self.handle_key(key)

    def _menu_key(self, key: int) -> None:
        if key == curses.KEY_MOUSE:
            self._menu_mouse()
            return
        if key == curses.KEY_RESIZE:
            return
        if not self.menu.key(key):
            self.menu = None

    def _menu_mouse(self) -> None:
        try:
            _id, mx, my, _z, state = curses.getmouse()
        except curses.error:
            return
        if state & curses.BUTTON4_PRESSED:
            self.menu.move(-1)
            return
        if state & getattr(curses, "BUTTON5_PRESSED", 0):
            self.menu.move(1)
            return
        row = menu_hit(self._menu_rect, self._menu_width, my, mx)
        if row is None:
            self.menu = None
        elif not self.menu.click(row):
            self.menu = None

    def open_menu(self, title: str, items: List[MenuItem], callback,
                  footer: str = "", danger: bool = False) -> None:
        """Show a modal chooser. Selecting an item calls `callback(value)`."""
        selectable = [item for item in items if item.selectable]
        if not selectable:
            self.notify(f"{title}: nothing to choose from", "warn")
            return
        if len(selectable) == 1 and not danger:
            callback(selectable[0].value)
            return
        self.menu = Menu(title=title, items=items, callback=callback,
                         footer=footer, danger=danger)

    # ---- input ------------------------------------------------------------

    def handle_key(self, key: int) -> None:
        if key == curses.KEY_RESIZE:
            self.stdscr.erase()
            return
        if key == curses.KEY_MOUSE:
            self._mouse()
            return

        # NUL rather than "" - an empty string is a substring of everything,
        # which would make every `char in "…"` test below fire on arrow keys.
        char = chr(key) if 0 <= key < 256 else "\0"

        if char.isdigit() and char != "0" and int(char) <= len(VIEWS):
            self.view = int(char) - 1
            self.refresh_derived(force=True)
            return

        if char == "q":
            self.running = False
            return
        if char == "?":
            self.show_help = True
            self.help_scroll = 0
            return
        if char == "\t":
            self.focus = "detail" if self.focus == "list" else "list"
            return
        if key == 12:                               # Ctrl-L
            self.stdscr.clearok(True)
            return

        # View-specific meanings win, and must be tried before the global
        # arrow bindings: the device list needs left/right to move between
        # addresses, not to change view.
        if self._view_key(key, char):
            return
        if key == curses.KEY_RIGHT and self.focus == "list":
            self.view = (self.view + 1) % len(VIEWS)
            self.refresh_derived(force=True)
            return
        if key == curses.KEY_LEFT and self.focus == "list":
            self.view = (self.view - 1) % len(VIEWS)
            self.refresh_derived(force=True)
            return
        if key in (curses.KEY_ENTER, 10, 13):
            self.focus = "detail"
            return
        if self._navigation_key(key, char):
            return
        if self._capture_key(char):
            return
        if self._filter_key(key, char):
            return
        if self._probe_key(char):
            return

        if char == "d":
            index = (DETAIL_MODES.index(self.detail_mode) + 1) % len(DETAIL_MODES)
            self.detail_mode = DETAIL_MODES[index]
            self.scroll["detail"] = self.cursor["detail"] = 0
            return
        if char == "T":
            self._choose_theme()
            return
        if char == "A":
            self._addons_menu()
            return
        if char == "s":
            self._cycle_sort()
            return
        if char == "y":
            self._yank()
            return

        # Addon bindings come last, so an addon can never shadow a NetSour key.
        self.session.addons.handle_key(char, self)

    def _view_key(self, key: int, char: str) -> bool:
        """Keys that mean something different depending on the active view."""
        if self.view == DEVICES_VIEW:
            if key in (curses.KEY_ENTER, 10, 13):
                self._focus_device()
                return True
            if key in (curses.KEY_LEFT,) or char == "h":
                self._move("devices", -1)
                return True
            if key in (curses.KEY_RIGHT,) or char == "l":
                self._move("devices", 1)
                return True
            if key == curses.KEY_UP or char == "k":
                self._move("devices", -max(1, self.device_columns))
                return True
            if key == curses.KEY_DOWN or char == "j":
                self._move("devices", max(1, self.device_columns))
                return True
            if char == "v":
                self.device_layout = ("grid" if self.device_layout == "panes"
                                      else "panes")
                self.scroll["devices"] = self.scroll["devices_row"] = 0
                self.notify(f"Devices view: {self.device_layout}", "accent")
                return True
            if char == "o":
                self.show_offline = not self.show_offline
                self.cursor["devices"] = self.scroll["devices"] = 0
                self.scroll["devices_row"] = 0
                self.notify("Showing offline devices" if self.show_offline
                            else "Hiding devices last seen minutes ago",
                            "accent")
                return True
        if self.view == DASH_VIEW and key in (curses.KEY_ENTER, 10, 13):
            self._dashboard_menu()
            return True
        if self.view == ALERTS_VIEW and key in (curses.KEY_ENTER, 10, 13):
            self._alert_actions()
            return True
        if self.view == OSINT_VIEW:
            if key in (curses.KEY_ENTER, 10, 13):
                self._osint_source_menu()
                return True
            if char == "r":
                self.notify(self.session.osint.run_all(self.osint_target),
                            "accent")
                return True
            if char == "R":
                self._confirm(f"Run every OSINT source against "
                              f"{self.osint_target or '(no target)'}, including "
                              "ones that connect to it? (y/N) ",
                              self._osint_run_active)
                return True
            if char == "x":
                self._ask("OSINT target - address or hostname: ",
                          self.osint_target, self._start_osint)
                return True
            if char == "X":
                self.session.osint.clear(self.osint_target)
                self.notify(f"Cleared the report for {self.osint_target}", "dim")
                return True
        return False

    def _osint_run_active(self) -> None:
        self.notify(self.session.osint.run_all(self.osint_target,
                                               include_active=True), "warn")

    def _osint_source_menu(self) -> None:
        target = self.osint_target
        if not target:
            self._choose_target("OSINT target", self._start_osint)
            return
        report = self.session.osint.report(target)
        items = [MenuItem("Passive — queries registries, never the target")]
        for source in SOURCES:
            if source.active:
                continue
            items.append(self._source_item(source, report, target))
        items.append(MenuItem(""))
        items.append(MenuItem("Active — connects to the target, it can log this"))
        for source in SOURCES:
            if source.active:
                items.append(self._source_item(source, report, target))
        self.open_menu(f"OSINT · {target}", items, self._run_osint_source,
                       footer="r runs all passive · R runs everything")

    def _source_item(self, source, report, target) -> MenuItem:
        section = report.sections.get(source.key)
        status = section.status if section else "idle"
        supported = source.supports(target)
        hint = source.note if supported else f"not applicable to {target}"
        if status != "idle":
            hint = f"[{status}] {hint}"
        return MenuItem(source.title, hint, source.key,
                        role="warn" if source.active else "base",
                        enabled=supported)

    def _run_osint_source(self, key: str) -> None:
        source = SOURCES_BY_KEY[key]
        target = self.osint_target

        def go() -> None:
            self.notify(self.session.osint.run(target, key, force=True),
                        "accent")

        if source.active:
            self._confirm(f"{source.title} connects to {target} — "
                          f"{source.note}. Continue? (y/N) ", go)
        else:
            go()

    def _alert_actions(self) -> None:
        """Pivot from an alert to the traffic, the host, or a lookup."""
        if not self.alert_rows:
            return
        alert = self.alert_rows[clamp(self.cursor["alerts"], 0,
                                      len(self.alert_rows) - 1)]
        endpoints = [ip for ip in (alert.src, alert.dst) if ip]
        items = [
            MenuItem("Show the conversation", "open this flow in Flows",
                     ("flow", alert), enabled=alert.flow_key is not None),
            MenuItem("Jump to the packet",
                     f"packet #{alert.packet_index} in Packets",
                     ("packet", alert), enabled=alert.packet_index is not None),
            MenuItem("Filter packets to these hosts",
                     " ↔ ".join(endpoints) or "no addresses",
                     ("filter", alert), enabled=bool(endpoints)),
            MenuItem(""),
        ]
        for ip in endpoints:
            items.append(MenuItem(f"OSINT on {ip}", "open the OSINT view",
                                  ("osint", ip)))
        for ip in endpoints:
            items.append(MenuItem(f"Nmap {ip}",
                                  f"{self.nmap_profile} · actively probes it",
                                  ("nmap", ip), role="warn"))
        self.open_menu(f"{alert.severity.upper()} · {alert.title}", items,
                       self._alert_action, footer=alert.detail[:70])

    def _alert_action(self, action) -> None:
        kind, payload = action
        if kind == "osint":
            self._start_osint(payload)
        elif kind == "nmap":
            self._confirm_scan(payload)
        elif kind == "flow":
            self._goto_flow(payload)
        elif kind == "packet":
            self._goto_packet(payload)
        elif kind == "filter":
            self._filter_to_alert(payload)

    def selected_device(self):
        devices = self.device_rows
        if not devices:
            return None
        return devices[clamp(self.cursor["devices"], 0, len(devices) - 1)]

    def _focus_device(self) -> None:
        """Show only this device's traffic in the packet list."""
        device = self.selected_device()
        if device is None:
            return
        self.session.set_text_filter(device.ip)
        self.view = PACKETS_VIEW
        self.follow = False
        self.cursor["packets"] = 0
        self.scroll["packets"] = 0
        self.refresh_derived(force=True)
        name = device.hostname or device.label
        self.notify(f"Showing traffic for {device.ip} ({name}) — "
                    "Esc or F clears the filter", "accent", seconds=8)

    def _goto_flow(self, alert) -> None:
        self.view = FLOWS_VIEW
        self.refresh_derived(force=True)
        for index, flow in enumerate(self.flow_rows):
            same = ((flow.a_ip, flow.b_ip) == (alert.src, alert.dst)
                    or (flow.b_ip, flow.a_ip) == (alert.src, alert.dst))
            if same:
                self.cursor["flows"] = index
                self.notify(f"{flow.proto} {flow.endpoint_a()} ↔ "
                            f"{flow.endpoint_b()}", "accent")
                return
        self.notify("That conversation is no longer in the buffer", "warn")

    def _goto_packet(self, alert) -> None:
        self.view = PACKETS_VIEW
        self.follow = False
        self.refresh_derived(force=True)
        for index, rec in enumerate(self.visible):
            if rec.index == alert.packet_index:
                self.cursor["packets"] = index
                self.notify(f"Packet #{rec.index}: {rec.info[:60]}", "accent")
                return
        self.notify(f"Packet #{alert.packet_index} is filtered out or has "
                    "rotated out of the buffer", "warn")

    def _filter_to_alert(self, alert) -> None:
        self.view = PACKETS_VIEW
        self.follow = False
        self.session.set_text_filter(alert.src or alert.dst)
        self.cursor["packets"] = 0
        self.refresh_derived(force=True)
        self.notify(f"Filtered to {alert.src or alert.dst}", "accent")

    def _navigation_key(self, key: int, char: str) -> bool:
        target = "detail" if (self.focus == "detail" and self.view == PACKETS_VIEW) \
            else self.list_key
        step_keys = {curses.KEY_UP: -1, curses.KEY_DOWN: 1}
        if char == "k":
            key = curses.KEY_UP
        elif char == "j":
            key = curses.KEY_DOWN

        if key in step_keys:
            self._move(target, step_keys[key])
            return True
        if key == curses.KEY_NPAGE:
            self._move(target, max(1, self._page_size(target)))
            return True
        if key == curses.KEY_PPAGE:
            self._move(target, -max(1, self._page_size(target)))
            return True
        if key == curses.KEY_HOME or char == "g":
            self.follow = False
            self.cursor[target] = 0
            self.scroll[target] = 0
            return True
        if key == curses.KEY_END or char == "G":
            self.cursor[target] = max(0, self._row_count(target) - 1)
            return True
        if char == "f" and self.view == PACKETS_VIEW:
            self.follow = not self.follow
            self.notify(f"Follow mode {'on' if self.follow else 'off'}", "accent")
            return True
        return False

    def _capture_key(self, char: str) -> bool:
        if char == " ":
            paused = self.session.capture.toggle_pause()
            self.notify("Capture paused - the interface is still up"
                        if paused else "Capture resumed", "warn" if paused else "ok")
            return True
        if char == "c":
            self._confirm("Clear the buffer, stats, flows and alerts? (y/N) ",
                          self._do_clear)
            return True
        if char in ("w", "W"):
            visible_only = char == "W"
            self._ask(f"Write {'filtered' if visible_only else 'all'} packets to ",
                      "",
                      lambda path: self.notify(
                          self.session.save_pcap(path.strip(), visible_only), "ok",
                          seconds=6),
                      default=time.strftime("netsour-%Y%m%d-%H%M%S.pcap"))
            return True
        if char == "b":
            self._ask("BPF capture filter (empty for none): ", self.session.bpf,
                      self._apply_bpf)
            return True
        return False

    def _filter_key(self, key: int, char: str) -> bool:
        toggles = {"t": "TCP", "u": "UDP", "i": "ICMP", "a": "ARP", "o": "OTHER"}
        if char in toggles:
            proto = toggles[char]
            state = self.session.toggle_protocol(proto)
            self.notify(f"{proto} {'shown' if state else 'hidden'}",
                        "ok" if state else "dim")
            self._reset_list_scroll()
            return True
        if char == "/":
            self._ask("filter: ", self.session.filter.text, self._apply_text_filter,
                      live=True)
            return True
        if key == 27:                                # Esc
            if self.session.filter.text:
                self.session.set_text_filter("")
                self.notify("Text filter cleared", "dim")
            self._reset_list_scroll()
            return True
        if char == "!":
            state = self.session.toggle_only_alerts()
            self.notify("Showing flagged packets only" if state
                        else "Showing all packets", "warn" if state else "dim")
            self._reset_list_scroll()
            return True
        if char == "F":
            self.session.reset_filter()
            self.notify("All filters reset", "ok")
            self._reset_list_scroll()
            return True
        return False

    def _probe_key(self, char: str) -> bool:
        if char == "n":
            self._choose_scan_target()
            return True
        if char == "N":
            self._choose_scan_profile()
            return True
        if char == "G":
            self._choose_target("Geolocate", self._start_geo,
                                public_only=True)
            return True
        if char == "O":
            self._choose_target("OSINT target", self._start_osint)
            return True
        if char == "S":
            self._confirm("ARP-sweep the local /24? This sends probes. (y/N) ",
                          self._do_recon)
            return True
        return False

    # ---- target selection -------------------------------------------------

    def candidate_targets(self) -> List[tuple]:
        """(address, where it came from) for the current selection.

        This is what makes every address on screen scannable: whichever view
        you are in, the row under the cursor contributes its endpoints, so you
        are never limited to a packet's destination.
        """
        seen: Dict[str, str] = {}

        def offer(address: str, label: str) -> None:
            if address and address not in seen:
                seen[address] = label

        if self.view == DEVICES_VIEW and self.device_rows:
            device = self.selected_device()
            if device is not None:
                offer(device.ip, "selected device")
                offer(device.hostname, "device hostname")
        elif self.view == FLOWS_VIEW and self.flow_rows:
            flow = self.flow_rows[clamp(self.cursor["flows"], 0,
                                        len(self.flow_rows) - 1)]
            offer(flow.a_ip, "endpoint A")
            offer(flow.b_ip, "endpoint B")
            offer(flow.hostname, "hostname")
        elif self.view == ALERTS_VIEW and self.alert_rows:
            alert = self.alert_rows[clamp(self.cursor["alerts"], 0,
                                          len(self.alert_rows) - 1)]
            offer(alert.src, "alert source")
            offer(alert.dst, "alert destination")
        elif self.view == HOSTS_VIEW and self.host_rows:
            host = self.host_rows[clamp(self.cursor["hosts"], 0,
                                        len(self.host_rows) - 1)]
            offer(host["ip"], "selected host")
            offer(host["name"], "hostname")
        elif self.view == RECON_VIEW and self.derived.recon_hosts:
            index = clamp(self.cursor["recon"], 0,
                          max(0, len(self.derived.recon_hosts) - 2))
            for address, _mac in self.derived.recon_hosts[1:][index:index + 1]:
                offer(address, "swept host")
            offer(self.derived.recon_hosts[0][0], "gateway")
        elif self.view == OSINT_VIEW and self.osint_target:
            offer(self.osint_target, "current target")

        rec = self.selected_record()
        if rec is not None:
            offer(rec.dst, "packet destination")
            offer(rec.src, "packet source")
            offer(rec.hostname, "hostname seen")
        if self.osint_target:
            offer(self.osint_target, "OSINT target")

        # Account names recovered from the traffic itself, so you can pivot
        # straight from "this device used Reddit" to "look that name up".
        for hint in self.session.social.hints_for()[:8]:
            if hint.kind == "username":
                offer(hint.value, f"{hint.platform} account · {hint.confidence}")
        return list(seen.items())

    def _choose_target(self, title: str, callback, public_only: bool = False,
                       footer: str = "") -> None:
        """Pick one address out of everything the current row references."""
        targets = self.candidate_targets()
        if public_only:
            targets = [(address, label) for address, label in targets
                       if target_kind(address) != "username"
                       and not is_private(address)]
        items = []
        for address, label in targets:
            hint = label
            kind = target_kind(address)
            if kind == "ip" and is_private(address):
                hint += "  · private"
            elif kind == "username":
                hint += "  · account name"
            items.append(MenuItem(address, hint, address))
        items.append(MenuItem("Type an address…", "enter any host or IP",
                              "\0prompt", role="accent"))

        def chosen(value):
            if value == "\0prompt":
                self._ask(f"{title} - address or hostname: ", "",
                          lambda text: text.strip() and callback(text.strip()))
            else:
                callback(value)

        self.open_menu(title, items, chosen,
                       footer or "↑↓ select · Enter confirm · Esc cancel")

    def _choose_scan_target(self) -> None:
        if not self.session.nmap.available:
            self.notify("Nmap unavailable: install nmap and python-nmap",
                        "danger")
            return
        profile = self.nmap_profile
        self._choose_target(
            f"Nmap target  ({profile}: {self.session.nmap.describe(profile)})",
            self._confirm_scan,
            footer="N changes the profile · scanning sends packets to the host")

    def _confirm_scan(self, target: str) -> None:
        profile = self.nmap_profile
        self._confirm(f"Nmap {profile} against {target}? "
                      "This actively probes it. (y/N) ",
                      lambda: self._start_scan(target, profile))

    def _choose_scan_profile(self) -> None:
        profiles = self.session.nmap.PROFILES
        rooted = os.geteuid() == 0 if hasattr(os, "geteuid") else False
        items = []
        for key, (args, description, needs_root, duration) in profiles.items():
            usable = rooted or not needs_root
            hint = f"{args:<22} {duration}"
            if not usable:
                hint += "  · needs root"
            items.append(MenuItem(f"{key}  {description}", hint, key,
                                  role="accent" if key == self.nmap_profile
                                  else "base", enabled=usable))
        self.open_menu("Nmap profile", items, self._set_profile,
                       footer=f"current: {self.nmap_profile}")

    def _set_profile(self, profile: str) -> None:
        self.nmap_profile = profile
        self.notify(f"Nmap profile: {profile} — "
                    f"{self.session.nmap.describe(profile)}", "accent")

    def _start_scan(self, target: str, profile: str) -> None:
        result = self.session.nmap.request(target, profile)
        self.detail_mode = "nmap"
        self.nmap_last_target = target
        self.notify(f"Nmap {profile} on {target}: {result}",
                    "warn" if "need" in result or "not installed" in result
                    else "accent")

    def _start_geo(self, target: str) -> None:
        result = self.session.geo.request(target)
        self.detail_mode = "geo"
        self.notify(f"Geolocating {target}: {result}", "accent")

    def _start_osint(self, target: str) -> None:
        self.osint_target = target
        self.view = OSINT_VIEW
        self.cursor["osint"] = self.scroll["osint"] = 0
        if target_kind(target) == "username":
            # The only source for a bare account name contacts other sites, so
            # it never runs without being asked for.
            self.notify(f"'{target}' looks like an account name — press R to "
                        "check it against public profile pages", "accent",
                        seconds=8)
        else:
            self.notify(self.session.osint.run_all(target,
                                                   include_active=False),
                        "accent")
        self.refresh_derived(force=True)

    def _mouse(self) -> None:
        try:
            _id, mx, my, _z, state = curses.getmouse()
        except curses.error:
            return
        target = "detail" if (self.focus == "detail" and self.view == PACKETS_VIEW) \
            else self.list_key
        if state & curses.BUTTON4_PRESSED:
            self._move(target, -3)
            return
        if state & getattr(curses, "BUTTON5_PRESSED", 0):
            self._move(target, 3)
            return
        if state & curses.BUTTON1_CLICKED:
            self._click(my, mx)

    def _click(self, my: int, mx: int) -> None:
        """Select the clicked row; a second click on it opens its actions."""
        if my == 1:
            self._click_tab(mx)
            return
        if self.view == DEVICES_VIEW:
            self._click_device(my, mx)
            return
        for key, (top, height) in self._row_hits.items():
            if not top <= my < top + height:
                continue
            index = self.scroll.get(key, 0) + (my - top)
            if index >= self._row_count(key):
                return
            if key == "packets":
                self.follow = False
                self.focus = "list"
            already = self.cursor.get(key) == index
            self.cursor[key] = index
            if already:
                self._row_actions(key)
            return
        if self.view == PACKETS_VIEW and my > 2:
            self.focus = "detail"

    def _click_device(self, my: int, mx: int) -> None:
        """Work out which device was clicked; a second click opens its traffic."""
        index = (self._grid_hit(my, mx) if self.device_layout == "grid"
                 else self._list_hit(my, mx))
        if index is None or index >= len(self.device_rows):
            return
        if self.cursor["devices"] == index:
            self._focus_device()
        else:
            self.cursor["devices"] = index

    def _grid_hit(self, my: int, mx: int):
        """Which card covers this cell, if any."""
        from .views import CARD_HEIGHT, CARD_WIDTH

        top, columns = self._device_hits
        if my < top or not self.device_rows:
            return None
        column = (mx - 1) // CARD_WIDTH
        if column < 0 or column >= max(1, columns):
            return None
        row = (my - top) // CARD_HEIGHT
        return (self.scroll.get("devices_row", 0) + row) * max(1, columns) \
            + column

    def _list_hit(self, my: int, mx: int):
        """Which address row covers this cell, if any."""
        from .views import device_pane_width

        top, rows = self._device_hits
        if my < top or my >= top + rows or not self.device_rows:
            return None
        width = self.stdscr.getmaxyx()[1] - 2
        if mx - 1 >= device_pane_width(width):
            return None                  # the identity pane is not a list
        return self.scroll.get("devices", 0) + (my - top)

    def _click_tab(self, mx: int) -> None:
        column = 1
        for index, name in enumerate(VIEWS):
            width = len(f" {index + 1} {name} ")
            if column <= mx < column + width:
                self.view = index
                self.refresh_derived(force=True)
                return
            column += width + 1

    def _row_actions(self, key: str) -> None:
        """Clicking an already-selected row offers what you can do with it."""
        if key == "alerts":
            self._alert_actions()
            return
        targets = self.candidate_targets()
        if not targets:
            return
        items = [MenuItem(f"Nmap {address}",
                          f"{self.nmap_profile} · {origin} · probes the host",
                          ("nmap", address), role="warn")
                 for address, origin in targets]
        items += [MenuItem(f"OSINT {address}", f"{origin} · lookups",
                           ("osint", address))
                  for address, origin in targets]
        self.open_menu("Actions for this row", items, self._alert_action,
                       footer="Esc cancels")

    # ---- dashboard and addons ---------------------------------------------

    def _dash_hint(self) -> str:
        """The pane subtitle: how much of the board came from where."""
        panels = self.derived.panels
        contributed = sum(1 for panel in panels if panel.source != "built-in")
        parts = [f"{len(panels)} cards"]
        if contributed:
            parts.append(f"{contributed} from addons")
        broken = [a.name for a in self.session.addons.addons
                  if a.status == "failed"]
        if broken:
            parts.append(f"{len(broken)} addon(s) failing")
        return " · ".join(parts)

    def _dashboard_menu(self) -> None:
        """Pick which cards the board shows. The choice is remembered on disk."""
        registry = self.session.addons
        items = [MenuItem("Cards — Enter shows or hides one")]
        for spec in registry.panel_specs(include_hidden=True):
            shown = spec.key not in registry.hidden
            mark = self.glyphs["check"] if shown else " "
            items.append(MenuItem(f"{mark} {spec.title}", spec.source, spec.key,
                                  role="base" if shown else "dim"))
        items.append(MenuItem(""))
        items.append(MenuItem("Addons…", "reload, scaffold, inspect",
                              "\0addons"))
        self.open_menu("Dashboard", items, self._toggle_card,
                       footer="Esc closes · the layout is saved")

    def _toggle_card(self, key: str) -> None:
        if key == "\0addons":
            self._addons_menu()
            return
        visible = self.session.addons.toggle_panel(key)
        self.refresh_derived(force=True)
        self.notify(f"Card {'shown' if visible else 'hidden'}",
                    "ok" if visible else "dim", seconds=2)
        self._dashboard_menu()              # stay open: toggling one is rare

    def _addons_menu(self) -> None:
        registry = self.session.addons
        directory = registry.directory
        items = [
            MenuItem("Reload addons", f"re-read {directory}", ("reload", None)),
            MenuItem("New addon…", "write a starter file, ready to edit",
                     ("new", None)),
            MenuItem("Choose dashboard cards", "show or hide cards",
                     ("cards", None)),
            MenuItem(""),
            MenuItem("Loaded"),
        ]
        if not registry.addons:
            items.append(MenuItem("none",
                                  directory if registry.enabled
                                  else "addons are disabled here", None))
        for addon in registry.addons:
            role = {"failed": "danger", "off": "dim"}.get(addon.status, "base")
            keys = " ".join(k.char for k in addon.keys)
            hint = addon.doc or addon.summary()
            items.append(MenuItem(f"{addon.name}"
                                  + (f"  [{keys}]" if keys else ""),
                                  f"{addon.status} · {hint}", ("show", addon),
                                  role=role))
        self.open_menu("Addons", items, self._addon_action, footer=directory)

    def _addon_action(self, action) -> None:
        kind, payload = action
        if kind == "reload":
            self.notify(self.session.addons.reload(), "accent", seconds=6)
            self.refresh_derived(force=True)
        elif kind == "new":
            self._ask("Name for the new addon: ", "", self._scaffold_addon)
        elif kind == "cards":
            self._dashboard_menu()
        elif kind == "show":
            self._show_addon(payload)

    def _show_addon(self, addon) -> None:
        """An addon's error is the thing worth reading; otherwise its path."""
        if addon.error:
            first = [line for line in addon.error.strip().split("\n") if line]
            self.notify(f"{addon.name}: {first[-1]}", "danger", seconds=20)
            return
        self.notify(f"{addon.name} — {addon.summary()} · {addon.path}",
                    "accent", seconds=10)

    def _scaffold_addon(self, name: str) -> None:
        try:
            path = self.session.addons.scaffold(name.strip())
        except FileExistsError as exc:
            self.notify(f"{exc} already exists", "warn", seconds=8)
            return
        except Exception as exc:
            self.notify(f"Could not write the addon: {exc}", "danger", seconds=8)
            return
        self.session.addons.reload()
        self.refresh_derived(force=True)
        self.notify(f"Wrote {path} — edit it, then A → Reload", "ok", seconds=12)

    # ---- actions ----------------------------------------------------------

    def _move(self, target: str, delta: int) -> None:
        if target == "packets" and delta != 0:
            self.follow = False
        total = self._row_count(target)
        self.cursor[target] = clamp(self.cursor.get(target, 0) + delta, 0,
                                    max(0, total - 1))

    def _row_count(self, target: str) -> int:
        return {
            "packets": len(self.visible),
            "flows": len(self.flow_rows),
            "alerts": len(self.alert_rows),
            "hosts": len(self.host_rows),
            "detail": self.detail_length,
            "recon": max(0, len(self.derived.recon_hosts) - 1),
            "stats": 1,
            "osint": self.osint_length,
            "devices": len(self.device_rows),
            "dash": self.dash_length,
        }.get(target, 1)

    def _page_size(self, target: str) -> int:
        height = self.stdscr.getmaxyx()[0]
        if target == "detail":
            return max(1, self._detail_height(height) - 1)
        return max(1, height - 8)

    def _reset_list_scroll(self) -> None:
        self.cursor["packets"] = 0 if not self.follow else self.cursor["packets"]
        self.scroll["packets"] = 0

    def _choose_theme(self) -> None:
        items = [MenuItem(name,
                          "light" if not THEME_SPECS[name].dark else "dark",
                          name,
                          role="accent" if name == self.pal.name else "base")
                 for name in THEMES]
        self.open_menu("Colour theme", items, self._set_theme,
                       footer=f"current: {self.pal.name}")

    def _set_theme(self, name: str) -> None:
        self.pal.use(name)
        self.notify(f"Theme: {name}", "accent")

    def _cycle_sort(self) -> None:
        if self.view == FLOWS_VIEW:
            self.flow_sort = FLOW_SORTS[(FLOW_SORTS.index(self.flow_sort) + 1)
                                        % len(FLOW_SORTS)]
            self.notify(f"Flows sorted by {self.flow_sort}", "accent")
        elif self.view == ALERTS_VIEW:
            self.alert_sort = "severity" if self.alert_sort == "time" else "time"
            self.notify(f"Alerts sorted by {self.alert_sort}", "accent")
        elif self.view == HOSTS_VIEW:
            self.host_sort = HOST_SORTS[(HOST_SORTS.index(self.host_sort) + 1)
                                        % len(HOST_SORTS)]
            self.notify(f"Hosts sorted by {self.host_sort}", "accent")
        else:
            self.notify("Nothing to sort in this view", "dim")
        self.refresh_derived(force=True)

    def _yank(self) -> None:
        rec = self.selected_record()
        if rec is None:
            return
        summary = (f"#{rec.index} {rec.src}:{rec.sport or '-'} → "
                   f"{rec.dst}:{rec.dport or '-'} {rec.proto} {rec.info}")
        self.notify(summary, "accent", seconds=12)

    def _apply_bpf(self, expression: str) -> None:
        expression = expression.strip()
        self.session.capture.stop()
        time.sleep(0.15)
        self.session.bpf = expression
        self.session.capture.bpf = expression
        self.session.capture.error = None
        self.session.capture.start()
        self.notify(f"Capture filter: {expression or 'none'}", "ok")

    def _apply_text_filter(self, text: str) -> None:
        self.session.set_text_filter(text)
        self.cursor["packets"] = max(0, len(self.session.view) - 1) \
            if self.follow else 0
        self.refresh_derived(force=True)

    def _do_clear(self) -> None:
        self.session.clear()
        self.refresh_derived(force=True)
        for key in self.cursor:
            self.cursor[key] = self.scroll[key] = 0
        self.notify("Buffer cleared", "ok")

    def _do_recon(self) -> None:
        self.view = RECON_VIEW
        self.session.start_recon()
        self.notify("ARP sweep started", "accent")

    # ---- prompts ----------------------------------------------------------

    def _ask(self, label: str, initial: str, callback, live: bool = False,
             default: str = "") -> None:
        """Open the prompt line.

        `initial` prefills the editable buffer (for values you tweak, like a BPF
        expression). `default` instead stays out of the buffer and is used only
        if you press Enter on an empty line, so typing replaces it rather than
        appending to it.
        """
        if default:
            label = f"{label}[{default}] "
        self.prompt = {"label": label, "buffer": initial or "", "callback": callback,
                       "live": live, "confirm": False, "default": default}

    def _confirm(self, label: str, callback) -> None:
        self.prompt = {"label": label, "buffer": "", "callback": callback,
                       "live": False, "confirm": True, "default": ""}

    def _prompt_key(self, key: int) -> None:
        prompt = self.prompt
        if prompt["confirm"]:
            if key in (ord("y"), ord("Y")):
                self.prompt = None
                prompt["callback"]()
            elif key != -1:
                self.prompt = None
                self.notify("Cancelled", "dim", seconds=2)
            return

        if key in (27,):                                     # Esc
            self.prompt = None
            if prompt["live"]:
                self._apply_text_filter("")
            return
        if key in (curses.KEY_ENTER, 10, 13):
            self.prompt = None
            prompt["callback"](prompt["buffer"] or prompt["default"])
            return
        if key in (curses.KEY_BACKSPACE, 127, 8):
            prompt["buffer"] = prompt["buffer"][:-1]
        elif key == 21:                                       # Ctrl-U
            prompt["buffer"] = ""
        elif 32 <= key < 127:
            prompt["buffer"] += chr(key)
        else:
            return
        if prompt["live"]:
            prompt["callback"](prompt["buffer"])

    def _help_key(self, key: int) -> None:
        if key in (curses.KEY_DOWN, ord("j")):
            self.help_scroll += 1
        elif key in (curses.KEY_UP, ord("k")):
            self.help_scroll = max(0, self.help_scroll - 1)
        elif key == curses.KEY_NPAGE:
            self.help_scroll += 10
        elif key == curses.KEY_PPAGE:
            self.help_scroll = max(0, self.help_scroll - 10)
        elif key != -1:
            self.show_help = False

    # ---- drawing ----------------------------------------------------------

    def draw(self) -> None:
        stdscr = self.stdscr
        stdscr.erase()
        self._caret = None
        height, width = stdscr.getmaxyx()
        if height < 12 or width < 60:
            addstr(stdscr, 0, 0, "Terminal too small - need at least 60x12.",
                   self.pal("danger"))
            stdscr.refresh()
            return

        self._draw_title(width)
        self._draw_tabs(width)
        content_top, content_height = 3, height - 5
        self._draw_view(content_top, content_height, width)
        self._draw_message(height, width)
        self._draw_hints(height, width)
        if self.show_help:
            self._draw_help(height, width)
        if self.menu is not None:
            self._menu_rect = self.menu.draw(stdscr, self.pal, self.glyphs,
                                             height, width)
            self._menu_width = min(width - 4, max(34, self._menu_longest()))
        self._place_caret()
        stdscr.refresh()

    def _place_caret(self) -> None:
        """Put the caret where the user is typing - the last thing each frame.

        Without this the cursor ends up wherever the final addstr finished (the
        hints row), so typing into a prompt looks like it is going nowhere.
        """
        hidden = (self._caret is None or self.menu is not None
                  or self.show_help)
        self._caret_visible = not hidden
        try:
            curses.curs_set(0 if hidden else 1)
        except curses.error:
            pass
        if hidden:
            return
        try:
            self.stdscr.move(*self._caret)
        except curses.error:
            pass

    def _menu_longest(self) -> int:
        items = self.menu.items
        label = max((len(item.label) for item in items), default=10)
        hint = max((len(item.hint) for item in items), default=0)
        return max(len(self.menu.title) + 6, label + hint + 12,
                   len(self.menu.footer) + 4)

    def _draw_title(self, width: int) -> None:
        pal, g = self.pal, self.glyphs
        stats = self.derived.stats
        capture = self.session.capture
        fill(self.stdscr, 0, 0, width, pal("status"))

        col = 1
        col += addstr(self.stdscr, 0, col, "NetSour", pal("title", curses.A_BOLD))
        col += addstr(self.stdscr, 0, col, f"  {g['sep']}  ", pal("frame"))

        source = self.session.pcap_path or self.session.iface or "any"
        col += addstr(self.stdscr, 0, col, os.path.basename(source), pal("accent"))
        address = interface_address(self.session.iface) if self.session.iface else ""
        if address:
            col += addstr(self.stdscr, 0, col, f" {address}", pal("dim"))
        col += addstr(self.stdscr, 0, col, f"  {g['sep']}  ", pal("frame"))

        if capture.error:
            state, role = "ERROR", "danger"
        elif capture.paused:
            state, role = f"{g['pause']} PAUSED", "warn"
        elif capture.finished:
            state, role = "FILE EOF", "dim"
        elif capture.running:
            state, role = f"{g['live']} LIVE", "ok"
        else:
            state, role = "STOPPED", "warn"
        col += addstr(self.stdscr, 0, col, state, pal(role))

        right = (f"{stats.total_packets:,} pkts {g['dot']} "
                 f"{human_bytes(stats.total_bytes)} {g['dot']} "
                 f"{stats.pps:.0f} p/s {g['dot']} {human_bytes(stats.bps)}/s "
                 f"{g['dot']} "
                 f"{human_duration(stats.elapsed)}")
        addstr(self.stdscr, 0, max(col + 2, width - len(right) - 2), right,
               pal("status"))

    def _draw_tabs(self, width: int) -> None:
        pal = self.pal
        counts = self.derived.alert_counts
        badges = {ALERTS_VIEW: counts.get("high", 0) + counts.get("medium", 0)}
        col = 1
        for index, name in enumerate(VIEWS):
            label = f" {index + 1} {name} "
            if badges.get(index):
                label += f"{badges[index]} "
            active = index == self.view
            attr = pal("tab_on") if active else pal("tab_off")
            addstr(self.stdscr, 1, col, label, attr)
            if badges.get(index) and not active:
                addstr(self.stdscr, 1, col + len(label) - 1 - len(str(badges[index])),
                       str(badges[index]), pal("danger"))
            col += len(label) + 1

        session_filter = self.session.filter
        if session_filter.active():
            text = f"filter: {session_filter.describe()}"
            addstr(self.stdscr, 1, max(col + 2, width - len(text) - 2),
                   ellipsize(text, width - col - 3), pal("warn"))
        elif self.follow and self.view == PACKETS_VIEW:
            addstr(self.stdscr, 1, width - 12, "follow on", pal("dim"))

    def _detail_height(self, height: int) -> int:
        """Rows given to the detail pane, leaving the list at least half."""
        available = height - 5
        return clamp(available // 2, 6, max(6, available - 6))

    def _draw_view(self, top: int, height: int, width: int) -> None:
        if self.view == PACKETS_VIEW:
            detail_h = self._detail_height(self.stdscr.getmaxyx()[0])
            list_h = height - detail_h - 1
            self._pane(top - 1, 0, list_h + 2, width, "Packets",
                       self.focus == "list",
                       f"{len(self.visible):,} shown of "
                       f"{self.derived.buffered:,}")
            views.draw_packet_list(self.stdscr, (top, 1, list_h, width - 2), self)
            self._row_hits = {"packets": (top + 1, max(0, list_h - 1))}

            detail_top = top + list_h + 1
            title = f"Detail · {self.detail_mode}"
            hint = " ".join(m if m != self.detail_mode else f"[{m}]"
                            for m in DETAIL_MODES)
            self._pane(detail_top, 0, detail_h, width, title,
                       self.focus == "detail", hint)
            views.draw_detail(self.stdscr,
                              (detail_top + 1, 1, detail_h - 2, width - 2), self)
            return

        titles = {
            DEVICES_VIEW: ("Devices on this network",
                           f"{len(self.device_rows)} found"),
            FLOWS_VIEW: ("Conversations", f"sorted by {self.flow_sort}"),
            STATS_VIEW: ("Statistics", "live"),
            ALERTS_VIEW: ("Security alerts", f"sorted by {self.alert_sort}"),
            HOSTS_VIEW: ("Hosts", f"sorted by {self.host_sort}"),
            RECON_VIEW: ("Network recon", "ARP sweep"),
            OSINT_VIEW: ("OSINT", self.osint_target or "no target"),
            DASH_VIEW: ("Dashboard", self._dash_hint())}
        title, hint = titles.get(self.view, (VIEWS[self.view], ""))
        self._pane(top - 1, 0, height + 2, width, title, True, hint)
        rect = (top, 1, height, width - 2)
        renderer = {DEVICES_VIEW: views.draw_devices,
                    FLOWS_VIEW: views.draw_flows,
                    STATS_VIEW: views.draw_stats,
                    ALERTS_VIEW: views.draw_alerts,
                    HOSTS_VIEW: views.draw_hosts,
                    RECON_VIEW: views.draw_recon,
                    OSINT_VIEW: views.draw_osint,
                    DASH_VIEW: views.draw_dashboard}[self.view]

        if self.view == DEVICES_VIEW and self.device_layout == "grid":
            # Give the grid the room on a short terminal; the detail pane
            # shrinks to the fields that matter rather than vanishing.
            detail_h = 9 if height >= 34 else (6 if height >= 20 else 0)
            views.draw_device_grid(self.stdscr,
                                   (top, 1, height - detail_h, width - 2), self)
            if self.device_rows and detail_h:
                views.draw_device_detail(
                    self.stdscr,
                    (top + height - detail_h, 1, detail_h, width - 2), self)
            self._device_hits = (top + 2, self.device_columns)
            self._row_hits = {}
            return

        renderer(self.stdscr, rect, self)
        if self.view == DASH_VIEW:
            # The board scrolls as a whole; there are no rows to click.
            self._row_hits = {}
        elif self.view == DEVICES_VIEW:
            # The address list starts two rows into the pane, and the identity
            # pane beside it is not clickable.
            self._device_hits = (top + 2, max(0, height - 2))
            self._row_hits = {}
        else:
            header_rows = {FLOWS_VIEW: 1, ALERTS_VIEW: 2, HOSTS_VIEW: 1,
                           RECON_VIEW: 5, OSINT_VIEW: 2}.get(self.view, 0)
            self._row_hits = {VIEWS[self.view].lower():
                              (top + header_rows, max(0, height - header_rows))}

        if self.view == ALERTS_VIEW and self.alert_rows:
            self._draw_alert_detail(top, height, width)

    def _draw_alert_detail(self, top: int, height: int, width: int) -> None:
        """A one-line expansion of the selected alert, pinned to the pane foot."""
        index = clamp(self.cursor["alerts"], 0, len(self.alert_rows) - 1)
        alert = self.alert_rows[index]
        row = top + height - 1
        text = f"{alert.title}: {alert.detail}"
        if alert.packet_index:
            text += f"   (packet #{alert.packet_index})"
        fill(self.stdscr, row, 1, width - 2, self.pal("status"))
        addstr(self.stdscr, row, 2, ellipsize(text, width - 4), self.pal("status"))

    def _pane(self, y: int, x: int, height: int, width: int, title: str,
              focused: bool, hint: str = "") -> None:
        pal = self.pal
        attr = pal("frame_hot") if focused else pal("frame")
        box(self.stdscr, y, x, height, width, self.glyphs, attr, title,
            pal("title") if focused else pal("header"))
        if hint and width > len(hint) + 8:
            addstr(self.stdscr, y, x + width - len(hint) - 3, f" {hint} ",
                   pal("dim"))

    def _draw_message(self, height: int, width: int) -> None:
        row = height - 2
        pal = self.pal

        if self.prompt is not None:
            label = self.prompt["label"]
            fill(self.stdscr, row, 0, width - 1, pal("prompt"))
            addstr(self.stdscr, row, 1, label, pal("prompt"))
            typed = ellipsize(self.prompt["buffer"], width - len(label) - 4)
            addstr(self.stdscr, row, 1 + len(label), typed, pal("prompt"))
            if not self.prompt["confirm"]:
                self._caret = (row, min(width - 2, 1 + len(label) + len(typed)))
            return
        if self.message and time.time() < self.message_until:
            addstr(self.stdscr, row, 1, ellipsize(self.message, width - 2),
                   pal(self.message_role))
        else:
            self.message = ""

    def _draw_hints(self, height: int, width: int) -> None:
        pal = self.pal
        row = height - 1
        fill(self.stdscr, row, 0, width - 1, pal("status"))
        pairs = self._hint_pairs()
        col = 1
        for key, label in pairs:
            if col + len(key) + len(label) + 3 >= width:
                break
            col += addstr(self.stdscr, row, col, key, pal("status_key"))
            col += addstr(self.stdscr, row, col, f" {label}   ", pal("status"))

    def _hint_pairs(self):
        common = [("?", "help"), ("q", "quit"), (f"1-{len(VIEWS)}", "views")]
        if self.view == PACKETS_VIEW:
            return common + [("/", "filter"), ("d", "detail"), ("f", "follow"),
                             ("t/u/i/a", "protos"), ("n", "nmap"), ("w", "save")]
        if self.view == FLOWS_VIEW:
            return common + [("s", "sort"), ("↑↓", "select")]
        if self.view == ALERTS_VIEW:
            return common + [("Enter", "pivot"), ("s", "sort"),
                             ("O", "osint"), ("n", "nmap")]
        if self.view == HOSTS_VIEW:
            return common + [("s", "sort"), ("n", "nmap host")]
        if self.view == DEVICES_VIEW:
            return common + [("Enter", "show its traffic"), ("v", "layout"),
                             ("S", "ARP sweep"), ("o", "offline"),
                             ("n", "nmap"), ("O", "osint")]
        if self.view == RECON_VIEW:
            return common + [("S", "ARP sweep"), ("n", "nmap host")]
        if self.view == OSINT_VIEW:
            return common + [("r", "passive"), ("R", "all"), ("x", "target"),
                             ("Enter", "source"), ("n", "nmap")]
        if self.view == DASH_VIEW:
            return common + [("Enter", "cards"), ("A", "addons"),
                             ("↑↓", "scroll")]
        return common + [("T", "theme")]

    def _draw_help(self, height: int, width: int) -> None:
        pal, g = self.pal, self.glyphs
        lines: List[tuple] = [
            ("NetSour — keyboard reference", "title"),
            ("", "base"),
        ]
        for section, entries in HELP_SECTIONS:
            lines.append((section.upper(), "header"))
            for key, description in entries:
                lines.append((f"  {key:<16} {description}", "base"))
            lines.append(("", "base"))
        lines.append(("Only capture and scan networks you are authorised to "
                      "test.", "warn"))
        lines.append(("", "base"))
        lines.append(("press any other key to close · ↑↓ to scroll", "dim"))

        popup_w = min(width - 4, 78)
        popup_h = min(height - 4, len(lines) + 2)
        top = (height - popup_h) // 2
        left = (width - popup_w) // 2
        for row in range(popup_h):
            fill(self.stdscr, top + row, left, popup_w, pal("popup"))
        box(self.stdscr, top, left, popup_h, popup_w, g, pal("popup_edge"),
            "Help", pal("popup_edge"))

        body = popup_h - 2
        self.help_scroll = clamp(self.help_scroll, 0, max(0, len(lines) - body))
        for row in range(body):
            index = self.help_scroll + row
            if index >= len(lines):
                break
            text, role = lines[index]
            attr = pal("popup") if role == "base" else pal(role)
            addstr(self.stdscr, top + 1 + row, left + 2,
                   ellipsize(text, popup_w - 4), attr)


def _ip_key(ip: str):
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, ip)
