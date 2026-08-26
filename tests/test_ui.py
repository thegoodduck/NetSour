"""UI layer: drawing primitives, layout maths, and a headless render pass.

The render tests drive the real `App` against a real curses screen created on a
pseudo-terminal, so a layout bug that would raise `curses.error` on a user's
machine fails here instead.
"""

import curses
import os
import select
import threading
import time
import unittest
import unittest.mock

from netsour.detail import follow_stream, packet_bytes, packet_tree
from netsour.dissect import dissect
from netsour.session import Session
from netsour.ui.render import (Glyphs, bar, columns, ellipsize, hexdump_lines,
                               pad, sanitize, sparkline, wrap)

from . import factory

GLYPHS = Glyphs(True)


class TestRenderPrimitives(unittest.TestCase):

    def test_sanitize_strips_control_characters(self):
        self.assertEqual(sanitize("a\x00b\x1bc"), "a.b.c")
        self.assertEqual(sanitize("plain"), "plain")

    def test_ellipsize_marks_truncation(self):
        self.assertEqual(ellipsize("abcdef", 4), "abc…")
        self.assertEqual(ellipsize("abc", 10), "abc")
        self.assertEqual(ellipsize("abc", 0), "")

    def test_pad_produces_exact_width(self):
        self.assertEqual(len(pad("abc", 8)), 8)
        self.assertEqual(len(pad("abcdefghij", 5)), 5)

    def test_sparkline_length_matches_the_requested_width(self):
        self.assertEqual(len(sparkline([1, 2, 3], 10, GLYPHS)), 10)
        self.assertEqual(len(sparkline([], 10, GLYPHS)), 0)
        self.assertEqual(sparkline([0, 0], 4, GLYPHS), " " * 4)

    def test_bar_scales_with_the_ratio(self):
        self.assertEqual(len(bar(1.0, 1.0, 10)), 10)
        self.assertEqual(bar(0, 1, 10), "")
        self.assertLess(len(bar(0.5, 1.0, 10)), 10)

    def test_hexdump_rows_align(self):
        rows = hexdump_lines(bytes(range(20)))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "00000000")
        self.assertEqual(rows[1][0], "00000010")
        self.assertEqual(rows[0][2], "................")

    def test_wrap_respects_width_and_newlines(self):
        lines = wrap("one two three four", 9)
        self.assertTrue(all(len(line) <= 9 for line in lines))
        self.assertEqual(wrap("a\nb", 10), ["a", "b"])

    def test_wrap_breaks_words_longer_than_the_width(self):
        self.assertTrue(all(len(line) <= 5 for line in wrap("a" * 17, 5)))


class TestColumnLayout(unittest.TestCase):

    SPECS = [(7, 0, 3), (13, 0, 2), (20, 2, 0), (20, 2, 0), (10, 0, 0),
             (6, 0, 1), (24, 5, 0)]

    def test_spare_space_goes_to_weighted_columns(self):
        widths = columns(self.SPECS, 200)
        self.assertLessEqual(sum(widths), 200)
        self.assertGreater(widths[6], 24)          # info column grew
        self.assertEqual(widths[0], 7)             # fixed column did not

    def test_narrow_layouts_drop_columns_by_priority(self):
        widths = columns(self.SPECS, 78)
        self.assertEqual(widths[0], 0)             # "#" dropped first
        self.assertGreater(widths[6], 0)           # info survives
        self.assertLessEqual(sum(widths), 78)

    def test_undroppable_columns_shrink_rather_than_overflow(self):
        widths = columns(self.SPECS, 50)
        self.assertLessEqual(sum(widths), 50)
        self.assertTrue(all(w >= 0 for w in widths))


class TestDetailBuilders(unittest.TestCase):

    def test_tree_covers_every_layer(self):
        record = dissect(factory.tcp(dport=443), 1, 1000.0)
        headers = [text for indent, text, _ in packet_tree(record) if indent == 0]
        self.assertEqual(headers[:4], ["Frame", "Ethernet", "IP", "TCP"])

    def test_tree_shows_flags_and_service_names(self):
        record = dissect(factory.tcp(dport=443, flags="SA"), 1, 1000.0)
        body = "\n".join(text for _, text, _ in packet_tree(record))
        self.assertIn("[SA]", body)
        self.assertIn("443(https)", body)

    def test_tree_survives_a_record_without_a_packet(self):
        record = dissect(factory.tcp(), 1, 1000.0)
        record.packet = None
        self.assertEqual(len(packet_tree(record)), 1)

    def test_packet_bytes_match_the_wire(self):
        packet = factory.tcp(payload=b"hello")
        self.assertEqual(packet_bytes(dissect(packet, 1, 0.0)), bytes(packet))

    def test_follow_stream_labels_both_directions(self):
        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session._on_packet(factory.tcp(src="10.0.0.1", dst="10.0.0.2",
                                       sport=5000, dport=80, flags="PA",
                                       payload=b"request"))
        session._on_packet(factory.tcp(src="10.0.0.2", dst="10.0.0.1",
                                       sport=80, dport=5000, flags="PA",
                                       payload=b"response"))
        chunks = follow_stream(session.records, session.records[0])
        self.assertEqual([d for d, _ in chunks], ["→", "←"])
        self.assertEqual(chunks[1][1], b"response")


class _HeadlessTerminal:
    """One curses screen on a pseudo-terminal, shared by every render test.

    curses is process-global state, so this is created once and resized between
    tests rather than torn down and rebuilt - repeatedly re-entering initscr
    leaves drain threads blocked on closed file descriptors.
    """

    def __init__(self):
        self.stdscr = None
        self._draining = False

    def start(self):
        self._primary, self._secondary = os.openpty()
        os.environ.setdefault("TERM", "xterm-256color")
        self._draining = True
        self._drain = threading.Thread(target=self._drain_loop, daemon=True)
        self._drain.start()

        self._saved_in, self._saved_out = os.dup(0), os.dup(1)
        os.dup2(self._secondary, 0)
        os.dup2(self._secondary, 1)
        curses.setupterm(term=os.environ["TERM"], fd=self._secondary)
        self.stdscr = curses.initscr()
        return self

    def _drain_loop(self):
        while self._draining:
            ready, _, _ = select.select([self._primary], [], [], 0.2)
            if not ready:
                continue
            try:
                if not os.read(self._primary, 1 << 16):
                    return
            except OSError:
                return

    def resize(self, width, height):
        curses.resizeterm(height, width)
        self.stdscr.erase()
        return self.stdscr

    def stop(self):
        if self.stdscr is None:
            return
        try:
            curses.endwin()
        except curses.error:
            pass
        os.dup2(self._saved_in, 0)
        os.dup2(self._saved_out, 1)
        self._draining = False
        self._drain.join(timeout=2.0)
        for fd in (self._saved_in, self._saved_out, self._secondary,
                   self._primary):
            try:
                os.close(fd)
            except OSError:
                pass
        self.stdscr = None


_TERMINAL = _HeadlessTerminal()


def setUpModule():
    _TERMINAL.start()


def tearDownModule():
    _TERMINAL.stop()


def screen(width=120, height=40):
    """A curses window of the requested size, ready to draw on."""
    return _TERMINAL.resize(width, height)


class TestHeadlessRender(unittest.TestCase):
    """Every view, at several terminal sizes, must draw without raising."""

    SIZES = [(200, 60), (120, 40), (80, 24), (62, 14)]

    def _session(self):
        session = Session(iface="lo", enable_rdns=False, enable_geo=False)
        session.osint.report("93.184.216.34").section("rdns").findings = []
        for packet in (factory.tcp(dport=80, flags="PA",
                                   payload=b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"),
                       factory.tls_client_hello(), factory.dns_query(),
                       factory.dns_response(), factory.udp(dport=123),
                       factory.icmp(), factory.arp(),
                       factory.tcp(dport=31337, flags="S")):
            session._on_packet(packet)
        session.recon_hosts = [("192.168.1.1", "aa:bb:cc:dd:ee:ff"),
                               ("192.168.1.10", "aa:bb:cc:dd:ee:01")]
        return session

    def test_every_view_draws_at_every_size(self):
        from netsour.ui.app import DETAIL_MODES, VIEWS, App

        session = self._session()
        for width, height in self.SIZES:
            app = App(screen(width, height), session)
            app.pal.init()
            for view in range(len(VIEWS)):
                app.view = view
                app.refresh_derived(force=True)
                for mode in DETAIL_MODES:
                    app.detail_mode = mode
                    app.draw()
            app.show_help = True
            app.draw()

    def test_drawing_an_empty_session_is_safe(self):
        from netsour.ui.app import VIEWS, App

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        app = App(screen(100, 30), session)
        app.pal.init()
        for view in range(len(VIEWS)):
            app.view = view
            app.refresh_derived(force=True)
            app.draw()

    def test_a_tiny_terminal_shows_a_message_instead_of_crashing(self):
        from netsour.ui.app import App

        app = App(screen(40, 8), self._session())
        app.pal.init()
        app.draw()


class TestAppInput(unittest.TestCase):
    """Key handling, driven without drawing."""

    def _app(self):
        from netsour.ui.app import App

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        for i in range(20):
            session._on_packet(factory.tcp(sport=1000 + i))
        app = App(screen(120, 40), session)
        app.pal.init()
        app.refresh_derived(force=True)
        return app

    def test_digits_select_views_and_arrows_do_not(self):
        app = self._app()
        app.handle_key(ord("3"))
        self.assertEqual(app.view, 2)
        app.handle_key(curses.KEY_UP)          # must not be read as a view digit
        self.assertEqual(app.view, 2)

    def test_movement_disables_follow_mode(self):
        app = self._app()
        self.assertTrue(app.follow)
        app.handle_key(curses.KEY_UP)
        self.assertFalse(app.follow)

    def test_cursor_stays_inside_the_list(self):
        app = self._app()
        for _ in range(100):
            app.handle_key(curses.KEY_DOWN)
        self.assertEqual(app.cursor["packets"], len(app.visible) - 1)
        for _ in range(100):
            app.handle_key(curses.KEY_UP)
        self.assertEqual(app.cursor["packets"], 0)

    def test_detail_mode_cycles(self):
        from netsour.ui.app import DETAIL_MODES

        app = self._app()
        for expected in DETAIL_MODES[1:] + DETAIL_MODES[:1]:
            app.handle_key(ord("d"))
            self.assertEqual(app.detail_mode, expected)

    def test_protocol_toggle_reaches_the_session(self):
        app = self._app()
        app.handle_key(ord("t"))
        self.assertFalse(app.session.filter.protocols["TCP"])
        app.handle_key(ord("t"))
        self.assertTrue(app.session.filter.protocols["TCP"])

    def test_quit_stops_the_loop(self):
        app = self._app()
        app.handle_key(ord("q"))
        self.assertFalse(app.running)

    def test_destructive_actions_require_confirmation(self):
        app = self._app()
        app.handle_key(ord("c"))
        self.assertIsNotNone(app.prompt)
        self.assertEqual(len(app.session.records), 20)
        app._prompt_key(ord("n"))
        self.assertEqual(len(app.session.records), 20)
        app.handle_key(ord("c"))
        app._prompt_key(ord("y"))
        self.assertEqual(len(app.session.records), 0)

    def test_text_prompt_edits_and_applies(self):
        app = self._app()
        app.handle_key(ord("/"))
        for char in "tcp":
            app._prompt_key(ord(char))
        self.assertEqual(app.prompt["buffer"], "tcp")
        app._prompt_key(curses.KEY_BACKSPACE)
        self.assertEqual(app.prompt["buffer"], "tc")
        app._prompt_key(10)                      # Enter
        self.assertIsNone(app.prompt)
        self.assertEqual(app.session.filter.text, "tc")

    def test_a_default_is_used_only_when_nothing_is_typed(self):
        app = self._app()
        app.handle_key(ord("w"))
        self.assertIn("[netsour-", app.prompt["label"])
        self.assertEqual(app.prompt["buffer"], "")
        saved = []
        app.prompt["callback"] = saved.append
        app._prompt_key(10)
        self.assertTrue(saved[0].startswith("netsour-"))

        app.handle_key(ord("w"))
        app.prompt["callback"] = saved.append
        for char in "mine.pcap":
            app._prompt_key(ord(char))
        app._prompt_key(10)
        self.assertEqual(saved[1], "mine.pcap")

    def test_escape_cancels_a_prompt(self):
        app = self._app()
        app.handle_key(ord("b"))
        app._prompt_key(27)
        self.assertIsNone(app.prompt)

    def test_unknown_keys_are_ignored(self):
        app = self._app()
        for key in (curses.KEY_F10, 999, ord("Z"), ord("~")):
            app.handle_key(key)
        self.assertTrue(app.running)


if __name__ == "__main__":
    unittest.main()


class TestConcurrentRendering(unittest.TestCase):
    """The UI must never read a live capture structure mid-mutation.

    Regression test for `RuntimeError: deque mutated during iteration`, raised
    when the host view iterated the record buffer while the capture thread was
    appending to it. The same hazard applies to sorting the flow dict, walking
    the alert list, and `Counter.most_common` in the statistics view, so this
    exercises every view against a live writer.
    """

    DURATION = 2.5

    def test_every_view_renders_while_packets_arrive(self):
        from netsour.ui.app import DETAIL_MODES, VIEWS, App

        session = Session(iface="", buffer_size=400, enable_rdns=False,
                          enable_geo=False)
        failures = []
        stop = threading.Event()

        packets = [factory.tcp(src=f"10.0.0.{n}", dst=f"10.0.1.{n % 30}",
                              sport=1024 + n, dport=(80, 443, 53)[n % 3],
                              flags="S") for n in range(40)]
        packets += [factory.dns_query(f"host{n}.example.com") for n in range(10)]
        packets += [factory.arp(psrc=f"10.0.0.{n}") for n in range(10)]
        packets += [factory.udp(dport=123), factory.icmp(),
                    factory.tls_client_hello(),
                    factory.tcp(dport=80, flags="PA",
                                payload=b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")]

        def capture():
            """Hammer the session the way the sniffer thread does."""
            i = 0
            while not stop.is_set():
                try:
                    session._on_packet(packets[i % len(packets)])
                except Exception as exc:                  # pragma: no cover
                    failures.append(("capture", exc))
                    return
                i += 1

        writer = threading.Thread(target=capture, daemon=True)
        writer.start()
        try:
            app = App(screen(140, 44), session)
            app.pal.init()
            deadline = time.time() + self.DURATION
            frames = 0
            while time.time() < deadline:
                for view in range(len(VIEWS)):
                    app.view = view
                    app.refresh_derived(force=True)
                    for mode in DETAIL_MODES:
                        app.detail_mode = mode
                        try:
                            app.draw()
                        except Exception as exc:
                            failures.append((f"view {view}/{mode}", exc))
                            raise
                        frames += 1
        finally:
            stop.set()
            writer.join(timeout=2.0)

        self.assertEqual(failures, [])
        self.assertGreater(frames, 100)
        self.assertGreater(session.stats.total_packets, 1000)

    def test_host_rows_survive_a_rotating_buffer(self):
        """The original crash, reduced: derive while the deque rotates."""
        session = Session(iface="", buffer_size=50, enable_rdns=False,
                          enable_geo=False)
        stop = threading.Event()
        errors = []

        def capture():
            i = 0
            while not stop.is_set():
                session._on_packet(factory.tcp(src=f"10.0.0.{i % 250}",
                                               sport=1024 + i % 900))
                i += 1

        writer = threading.Thread(target=capture, daemon=True)
        writer.start()
        try:
            deadline = time.time() + 1.5
            while time.time() < deadline:
                try:
                    session.derive(want_hosts=True, want_flows=True,
                                   want_alerts=True, want_stats=True)
                except Exception as exc:
                    errors.append(exc)
                    break
        finally:
            stop.set()
            writer.join(timeout=2.0)
        self.assertEqual(errors, [])


class TestThemes(unittest.TestCase):
    """Every theme must resolve every role on this terminal."""

    def test_all_themes_build_all_roles(self):
        from netsour.ui.theme import ROLE_MAP, THEMES, Palette

        screen(100, 30)
        for name in THEMES:
            pal = Palette(name)
            pal.init()
            for role in ROLE_MAP:
                self.assertIsInstance(pal(role), int, f"{name}/{role}")
            for proto in ("TCP", "UDP", "TCP/TLS", "UDP/DNS", "ARP", "ICMP",
                          "TCP/HTTP", "weird"):
                self.assertIsInstance(pal.proto(proto), int, f"{name}/{proto}")

    def test_protocol_colours_prefer_the_application_label(self):
        from netsour.ui.theme import Palette

        screen(100, 30)
        pal = Palette("midnight")
        pal.init()
        self.assertEqual(pal.proto("TCP/TLS"), pal.proto("TLS"))
        self.assertNotEqual(pal.proto("TCP/TLS"), pal.proto("TCP"))
        self.assertEqual(pal.proto("UDP/MDNS"), pal.proto("UDP/DNS"))

    def test_unknown_theme_falls_back(self):
        from netsour.ui.theme import Palette

        self.assertEqual(Palette("chartreuse").name, "midnight")

    def test_use_and_cycle(self):
        from netsour.ui.theme import THEMES, Palette

        screen(100, 30)
        pal = Palette("midnight")
        pal.init()
        self.assertTrue(pal.use("matrix"))
        self.assertEqual(pal.name, "matrix")
        self.assertFalse(pal.use("nope"))
        seen = {pal.cycle() for _ in range(len(THEMES))}
        self.assertEqual(seen, set(THEMES))

    def test_severity_and_row_helpers(self):
        from netsour.ui.theme import Palette

        screen(100, 30)
        pal = Palette("midnight")
        pal.init()
        self.assertEqual(pal.severity("high"), pal("danger"))
        self.assertEqual(pal.severity("unknown"), pal("dim"))
        self.assertEqual(pal.row(0, True), pal("select"))


class TestTargetSelection(unittest.TestCase):
    """Scanning must reach any address on the current row, not just dst."""

    def _app(self, view=None):
        from netsour.ui.app import PACKETS_VIEW, App

        view = PACKETS_VIEW if view is None else view
        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session._on_packet(factory.tcp(src="10.0.0.5", dst="93.184.216.34",
                                       sport=4000, dport=443, flags="S"))
        session._on_packet(factory.tcp(src="10.0.0.9", dst="10.0.0.5",
                                       dport=31337, flags="S"))
        app = App(screen(140, 44), session)
        app.pal.init()
        app.view = view
        app.refresh_derived(force=True)
        return app

    def test_packet_view_offers_both_endpoints(self):
        from netsour.ui.app import PACKETS_VIEW

        app = self._app(PACKETS_VIEW)
        app.cursor["packets"] = 0
        addresses = [address for address, _ in app.candidate_targets()]
        self.assertIn("93.184.216.34", addresses)
        self.assertIn("10.0.0.5", addresses)

    def test_source_is_reachable_not_only_destination(self):
        from netsour.ui.app import PACKETS_VIEW

        app = self._app(PACKETS_VIEW)
        app.cursor["packets"] = 0
        origins = dict(app.candidate_targets())
        self.assertEqual(origins["10.0.0.5"], "packet source")

    def test_host_view_offers_the_selected_host(self):
        from netsour.ui.app import HOSTS_VIEW

        app = self._app(HOSTS_VIEW)
        self.assertTrue(app.host_rows)
        app.cursor["hosts"] = 0
        origins = dict(app.candidate_targets())
        self.assertIn(app.host_rows[0]["ip"], origins)

    def test_flow_view_offers_both_flow_endpoints(self):
        from netsour.ui.app import FLOWS_VIEW

        app = self._app(FLOWS_VIEW)
        self.assertTrue(app.flow_rows)
        app.cursor["flows"] = 0
        addresses = [address for address, _ in app.candidate_targets()]
        flow = app.flow_rows[0]
        self.assertIn(flow.a_ip, addresses)
        self.assertIn(flow.b_ip, addresses)

    def test_alert_view_offers_the_alert_endpoints(self):
        from netsour.ui.app import ALERTS_VIEW

        app = self._app(ALERTS_VIEW)
        self.assertTrue(app.alert_rows)
        app.cursor["alerts"] = 0
        origins = dict(app.candidate_targets())
        alert = app.alert_rows[0]
        self.assertEqual(origins.get(alert.src), "alert source")

    def test_candidates_are_deduplicated(self):
        app = self._app()
        addresses = [address for address, _ in app.candidate_targets()]
        self.assertEqual(len(addresses), len(set(addresses)))

    def test_the_picker_opens_a_menu_with_a_manual_entry(self):
        app = self._app()
        app.session.nmap.available = True
        app.handle_key(ord("n"))
        self.assertIsNotNone(app.menu)
        labels = [item.label for item in app.menu.items]
        self.assertIn("Type an address…", labels)

    def test_geo_picker_offers_only_public_addresses(self):
        app = self._app()
        app.cursor["packets"] = 0
        app.handle_key(ord("G"))
        if app.menu is not None:
            values = [item.value for item in app.menu.items
                      if item.selectable and item.value != "\0prompt"]
            self.assertNotIn("10.0.0.5", values)

    def test_profile_menu_disables_root_only_profiles_for_a_user(self):
        app = self._app()
        with unittest.mock.patch("os.geteuid", return_value=1000):
            app._choose_scan_profile()
        blocked = {item.value for item in app.menu.items if not item.enabled}
        self.assertIn("stealth", blocked)
        self.assertNotIn("fast", blocked)


class TestAlertPivots(unittest.TestCase):
    """Alerts must lead somewhere: the flow, the packet, a filter, a lookup."""

    def _app(self):
        from netsour.ui.app import ALERTS_VIEW, App

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        for _ in range(3):
            session._on_packet(factory.tcp(src="10.0.0.9", dst="10.0.0.5",
                                           dport=31337, flags="S"))
        app = App(screen(140, 44), session)
        app.pal.init()
        app.view = ALERTS_VIEW
        app.refresh_derived(force=True)
        return app

    def test_enter_opens_the_pivot_menu(self):
        app = self._app()
        app.handle_key(10)
        self.assertIsNotNone(app.menu)
        labels = [item.label for item in app.menu.items]
        self.assertIn("Show the conversation", labels)
        self.assertIn("Jump to the packet", labels)

    def test_jumping_to_the_flow_switches_view_and_selects_it(self):
        app = self._app()
        alert = app.alert_rows[0]
        from netsour.ui.app import FLOWS_VIEW

        app._alert_action(("flow", alert))
        self.assertEqual(app.view, FLOWS_VIEW)
        flow = app.flow_rows[app.cursor["flows"]]
        self.assertIn(alert.src, (flow.a_ip, flow.b_ip))

    def test_jumping_to_the_packet_selects_it_and_stops_following(self):
        app = self._app()
        alert = app.alert_rows[0]
        from netsour.ui.app import PACKETS_VIEW

        app._alert_action(("packet", alert))
        self.assertEqual(app.view, PACKETS_VIEW)
        self.assertFalse(app.follow)
        self.assertEqual(app.visible[app.cursor["packets"]].index,
                         alert.packet_index)

    def test_filtering_to_an_alert_narrows_the_packet_list(self):
        app = self._app()
        alert = app.alert_rows[0]
        from netsour.ui.app import PACKETS_VIEW

        app._alert_action(("filter", alert))
        self.assertEqual(app.view, PACKETS_VIEW)
        self.assertEqual(app.session.filter.text, alert.src)
        self.assertTrue(all(alert.src in (r.src, r.dst) for r in app.visible))

    def test_a_missing_packet_reports_rather_than_crashing(self):
        app = self._app()
        alert = app.alert_rows[0]
        alert.packet_index = 999999
        app._alert_action(("packet", alert))
        self.assertIn("rotated out", app.message)

    def test_alerts_carry_their_flow_key(self):
        app = self._app()
        self.assertIsNotNone(app.alert_rows[0].flow_key)


class TestOsintView(unittest.TestCase):

    def _app(self):
        from netsour.ui.app import App

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session._on_packet(factory.tcp(dst="93.184.216.34", dport=443))
        app = App(screen(140, 44), session)
        app.pal.init()
        app.refresh_derived(force=True)
        return app

    def test_opening_a_target_switches_view_and_queues_passive_work(self):
        app = self._app()
        with unittest.mock.patch.object(app.session.osint, "run_all",
                                        return_value="queued") as run_all:
            app._start_osint("93.184.216.34")
        from netsour.ui.app import OSINT_VIEW

        run_all.assert_called_once()
        self.assertFalse(run_all.call_args.kwargs.get("include_active", False))
        self.assertEqual(app.view, OSINT_VIEW)
        self.assertEqual(app.osint_target, "93.184.216.34")

    def test_active_sources_need_confirmation(self):
        from netsour.ui.app import OSINT_VIEW

        app = self._app()
        app.view = OSINT_VIEW
        app.osint_target = "93.184.216.34"
        app.handle_key(ord("R"))
        self.assertIsNotNone(app.prompt)
        self.assertTrue(app.prompt["confirm"])

    def test_choosing_an_active_source_confirms_first(self):
        app = self._app()
        app.osint_target = "93.184.216.34"
        with unittest.mock.patch.object(app.session.osint, "run") as run:
            app._run_osint_source("tls")
            run.assert_not_called()
        self.assertIsNotNone(app.prompt)

    def test_choosing_a_passive_source_runs_immediately(self):
        app = self._app()
        app.osint_target = "93.184.216.34"
        with unittest.mock.patch.object(app.session.osint, "run",
                                        return_value="started") as run:
            app._run_osint_source("rdap")
            run.assert_called_once()

    def test_the_view_draws_with_and_without_a_target(self):
        from netsour.ui.app import OSINT_VIEW

        app = self._app()
        app.view = OSINT_VIEW
        app.draw()
        app.osint_target = "93.184.216.34"
        app.session.osint.report("93.184.216.34").section("rdns").status = "done"
        app.refresh_derived(force=True)
        app.draw()


class TestCaretPlacement(unittest.TestCase):
    """The caret must sit where the user is typing.

    Regression test for prompts that echoed nothing visible: `draw()` set the
    cursor in `_draw_message`, then the hints row and any overlay drew after it
    and left the physical cursor at their own end position, so typing had no
    visible caret at all.
    """

    def _app(self, width=140, height=44):
        from netsour.ui.app import App

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session._on_packet(factory.tcp())
        app = App(screen(width, height), session)
        app.pal.init()
        app.refresh_derived(force=True)
        return app

    def test_no_caret_without_a_prompt(self):
        app = self._app()
        app.draw()
        self.assertIsNone(app._caret)

    def test_caret_lands_after_the_typed_text(self):
        app = self._app(width=140, height=44)
        app._ask("target: ", "", lambda value: None)
        for char in "example.com":
            app._prompt_key(ord(char))
        app.draw()
        self.assertIsNotNone(app._caret)
        row, col = app._caret
        self.assertEqual(row, 44 - 2)                     # the prompt row
        self.assertEqual(col, 1 + len("target: ") + len("example.com"))

    def test_caret_follows_edits(self):
        app = self._app()
        app._ask("q: ", "", lambda value: None)
        for char in "abcd":
            app._prompt_key(ord(char))
        app.draw()
        after_typing = app._caret[1]
        app._prompt_key(curses.KEY_BACKSPACE)
        app.draw()
        self.assertEqual(app._caret[1], after_typing - 1)
        app._prompt_key(21)                               # Ctrl-U clears
        app.draw()
        self.assertEqual(app._caret[1], 1 + len("q: "))

    def test_the_caret_survives_everything_drawn_after_the_prompt(self):
        """The hints row is drawn last; it must not steal the cursor."""
        app = self._app()
        app._ask("target: ", "", lambda value: None)
        app._prompt_key(ord("x"))
        app.draw()
        expected = app._caret
        height, width = app.stdscr.getmaxyx()
        self.assertEqual(app.stdscr.getyx(), expected)
        self.assertNotEqual(app.stdscr.getyx()[0], height - 1)

    def test_confirmations_show_no_caret(self):
        app = self._app()
        app._confirm("Really? (y/N) ", lambda: None)
        app.draw()
        self.assertIsNone(app._caret)

    def test_an_open_menu_hides_the_caret(self):
        from netsour.ui.menu import MenuItem

        app = self._app()
        app._ask("target: ", "", lambda value: None)
        app.draw()
        self.assertTrue(app._caret_visible)
        app.open_menu("Pick", [MenuItem("a", "", 1), MenuItem("b", "", 2)],
                      lambda value: None)
        app.draw()
        self.assertIsNotNone(app.menu)
        self.assertFalse(app._caret_visible)

    def test_the_help_overlay_hides_the_caret(self):
        app = self._app()
        app._ask("target: ", "", lambda value: None)
        app.show_help = True
        app.draw()
        self.assertFalse(app._caret_visible)

    def test_the_caret_is_visible_while_a_prompt_is_open(self):
        app = self._app()
        app.draw()
        self.assertFalse(app._caret_visible)
        app._ask("target: ", "", lambda value: None)
        app.draw()
        self.assertTrue(app._caret_visible)
        app._prompt_key(27)
        app.draw()
        self.assertFalse(app._caret_visible)

    def test_caret_stays_inside_a_narrow_terminal(self):
        app = self._app(width=62, height=14)
        app._ask("a very long prompt label for a narrow screen: ", "",
                 lambda value: None)
        for char in "abcdefghijklmnopqrstuvwxyz":
            app._prompt_key(ord(char))
        app.draw()
        self.assertLess(app._caret[1], 62)


class TestDevicesView(unittest.TestCase):
    """The grid, its 2D navigation, and the click-to-filter pivot."""

    def _app(self, width=165, height=44):
        from netsour.devices import DeviceRegistry
        from netsour.ui.app import DEVICES_VIEW, App

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session.devices = DeviceRegistry(local_prefix="192.168.1.",
                                         gateway="192.168.1.1")
        for last in range(2, 12):
            session._on_packet(factory.tcp(src="192.168.1.10",
                                           dst=f"192.168.1.{last}",
                                           dport=443, flags="PA", payload=b"x"))
        session.recon_hosts = [(f"192.168.1.{n}", f"aa:bb:cc:00:00:{n:02x}")
                               for n in range(1, 12)]
        session.recon_time = max(r.ts for r in session.records)
        app = App(screen(width, height), session)
        app.pal.init()
        app.view = DEVICES_VIEW
        app.refresh_derived(force=True)
        app.draw()
        return app

    def test_the_grid_lists_local_devices(self):
        app = self._app()
        self.assertGreater(len(app.device_rows), 5)
        self.assertTrue(all(d.ip.startswith("192.168.1.")
                            for d in app.device_rows))

    def test_left_and_right_move_within_the_grid_not_between_views(self):
        from netsour.ui.app import DEVICES_VIEW

        app = self._app()
        app.handle_key(curses.KEY_RIGHT)
        self.assertEqual(app.view, DEVICES_VIEW)
        self.assertEqual(app.cursor["devices"], 1)
        app.handle_key(curses.KEY_LEFT)
        self.assertEqual(app.cursor["devices"], 0)
        self.assertEqual(app.view, DEVICES_VIEW)

    def test_up_and_down_move_one_address_at_a_time(self):
        app = self._app()
        app.handle_key(curses.KEY_DOWN)
        self.assertEqual(app.cursor["devices"], 1)
        app.handle_key(curses.KEY_UP)
        self.assertEqual(app.cursor["devices"], 0)

    def test_the_cursor_cannot_leave_the_grid(self):
        app = self._app()
        for _ in range(200):
            app.handle_key(curses.KEY_RIGHT)
        self.assertEqual(app.cursor["devices"], len(app.device_rows) - 1)
        for _ in range(200):
            app.handle_key(curses.KEY_LEFT)
        self.assertEqual(app.cursor["devices"], 0)

    def test_enter_filters_the_packet_list_to_that_device(self):
        from netsour.ui.app import PACKETS_VIEW

        app = self._app()
        app.cursor["devices"] = 3
        device = app.device_rows[3]
        app.handle_key(10)
        # The grid is only built for its own view, so re-read after the pivot.
        self.assertEqual(app.view, PACKETS_VIEW)
        self.assertEqual(app.session.filter.text, device.ip)
        self.assertFalse(app.follow)
        self.assertTrue(all(device.ip in (r.src, r.dst) for r in app.visible))

    def test_the_filter_can_be_cleared_again(self):
        app = self._app()
        app.handle_key(10)
        self.assertTrue(app.session.filter.active())
        app.handle_key(ord("F"))
        self.assertFalse(app.session.filter.active())

    def test_offline_devices_are_hidden_until_asked_for(self):
        from netsour.devices import IDLE_SECONDS

        app = self._app()
        # Age everything already captured, then let one host speak now: the
        # capture clock moves to it and the rest fall out of the window.
        for record in list(app.session.records):
            record.ts -= IDLE_SECONDS + 60
        app.session.recon_time -= IDLE_SECONDS + 60
        app.session._on_packet(factory.tcp(src="192.168.1.99",
                                           dst="192.168.1.98"))
        app.refresh_derived(force=True)

        self.assertEqual([d.ip for d in app.device_rows], ["192.168.1.99"])
        self.assertGreater(app.hidden_devices, 0)
        app.draw()                                  # the empty pane explains it

        app.handle_key(ord("o"))
        app.refresh_derived(force=True)
        self.assertGreater(len(app.device_rows), 1)
        self.assertEqual(app.hidden_devices, 0)
        app.draw()

    def test_v_switches_between_the_two_layouts(self):
        from netsour.ui.views import CARD_HEIGHT, CARD_WIDTH

        app = self._app()
        self.assertEqual(app.device_layout, "panes")
        app.handle_key(ord("v"))
        self.assertEqual(app.device_layout, "grid")
        app.draw()
        self.assertGreater(app.device_columns, 1)      # the card wall is back

        # And the cards are clickable where they are drawn.
        top, columns = app._device_hits
        app._click_device(top + CARD_HEIGHT + 1, 2)
        self.assertEqual(app.cursor["devices"], columns)
        app._click_device(top + 1, 1 + CARD_WIDTH + CARD_WIDTH // 2)
        self.assertEqual(app.cursor["devices"], 1)

        app.handle_key(ord("v"))
        self.assertEqual(app.device_layout, "panes")
        app.draw()
        self.assertEqual(app.device_columns, 1)

    def test_both_layouts_draw_at_every_size(self):
        for width, height in ((60, 14), (100, 30), (165, 44)):
            for layout in ("panes", "grid"):
                app = self._app(width=width, height=height)
                app.device_layout = layout
                app.draw()

    def test_the_selected_device_is_offered_as_a_scan_target(self):
        app = self._app()
        device = app.device_rows[0]
        origins = dict(app.candidate_targets())
        self.assertEqual(origins.get(device.ip), "selected device")

    def test_a_click_selects_an_address_and_a_second_click_opens_it(self):
        from netsour.ui.app import DEVICES_VIEW, PACKETS_VIEW

        app = self._app()
        top, _rows = app._device_hits
        expected = app.device_rows[1].ip
        app._click_device(top + 1, 4)
        self.assertEqual(app.cursor["devices"], 1)
        self.assertEqual(app.view, DEVICES_VIEW)      # first click only selects
        app._click_device(top + 1, 4)
        self.assertEqual(app.view, PACKETS_VIEW)      # second click opens it
        self.assertEqual(app.session.filter.text, expected)

    def test_a_click_on_the_identity_pane_selects_nothing(self):
        from netsour.ui.views import device_pane_width

        app = self._app()
        top, _rows = app._device_hits
        app.cursor["devices"] = 2
        app._click_device(top + 1, device_pane_width(163) + 4)
        self.assertEqual(app.cursor["devices"], 2)

    def test_a_click_past_the_last_address_is_ignored(self):
        app = self._app()
        top, _rows = app._device_hits
        app._click_device(top + 1, 5)
        before = app.cursor["devices"]
        app._click_device(top + 200, 5)
        self.assertEqual(app.cursor["devices"], before)

    def test_the_identity_pane_is_dropped_on_a_narrow_terminal(self):
        from netsour.ui.views import device_pane_width

        self.assertEqual(device_pane_width(46), 46)
        self.assertLess(device_pane_width(200), 200)

    def test_an_empty_grid_draws_guidance_instead_of_crashing(self):
        from netsour.ui.app import DEVICES_VIEW, App

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        app = App(screen(120, 30), session)
        app.pal.init()
        app.view = DEVICES_VIEW
        app.refresh_derived(force=True)
        app.draw()
        self.assertEqual(app.device_rows, [])
        app.handle_key(10)                      # Enter with nothing selected

    def test_the_alert_badge_sits_on_the_alerts_tab(self):
        """Regression: the badge index was hardcoded and drifted onto Stats."""
        from netsour.ui.app import ALERTS_VIEW, VIEWS, App

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        for _ in range(3):
            session._on_packet(factory.tcp(dport=31337, flags="S"))
        app = App(screen(150, 40), session)
        app.pal.init()
        app.refresh_derived(force=True)
        app.draw()
        counts = app.derived.alert_counts
        self.assertGreater(counts.get("medium", 0) + counts.get("high", 0), 0)
        row = app.stdscr.instr(1, 0).decode("utf-8", "replace")
        alerts_tab = f"{ALERTS_VIEW + 1} {VIEWS[ALERTS_VIEW]}"
        position = row.index(alerts_tab)
        tail = row[position:position + len(alerts_tab) + 4]
        self.assertRegex(tail, r"\d+\s*$|\d")
