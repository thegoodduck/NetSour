"""Addons: loading, isolation, the dashboard board and its layout.

The point of every test here is the same one: an addon is user code running on
the capture thread and in the render path, so a broken one must degrade to a
message on a card and nothing worse.
"""

import os
import tempfile
import unittest

from netsour.addons import (MAX_FAILURES, AddonRegistry, Line, PanelContext,
                            normalize_lines)
from netsour.session import Session
from netsour.ui.views import (dashboard_card_width, dashboard_columns,
                              dashboard_layout)

from . import factory

COUNTER = '''
"""Counts packets."""
from netsour.addon import alert, key, on_packet, panel

seen = []


@on_packet
def watch(pkt):
    seen.append(pkt.proto_base)
    if pkt.dport == 23:
        alert("Telnet", f"{pkt.src} -> {pkt.dst}", "high", pkt)


@panel("Counter", key="counter")
def card(ctx):
    return [f"{len(seen)} packets", ("wide" if ctx.width > 20 else "narrow",
                                     "dim")]


@key("z", "count")
def press(ui):
    ui.notify(f"{len(seen)} packets")
'''

BROKEN_IMPORT = '''
raise ValueError("this addon is broken")
'''

BROKEN_HOOK = '''
from netsour.addon import on_packet, panel


@on_packet
def boom(pkt):
    raise RuntimeError("hook is broken")


@panel("Boom", key="boom")
def card(ctx):
    raise RuntimeError("panel is broken")
'''


class AddonCase(unittest.TestCase):
    """A registry pointed at a throwaway directory, with a config to match."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addons_dir = os.path.join(self.tmp.name, "addons")
        os.makedirs(self.addons_dir)
        self._config = os.environ.get("NETSOUR_CONFIG_HOME")
        os.environ["NETSOUR_CONFIG_HOME"] = self.tmp.name
        self.addCleanup(self._restore)

    def _restore(self):
        if self._config is None:
            os.environ.pop("NETSOUR_CONFIG_HOME", None)
        else:
            os.environ["NETSOUR_CONFIG_HOME"] = self._config
        self.tmp.cleanup()

    def write(self, name, source):
        path = os.path.join(self.addons_dir, f"{name}.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)
        return path

    def registry(self):
        registry = AddonRegistry(directories=[self.addons_dir])
        registry.load()
        return registry

    def session(self, registry):
        return Session(iface="", enable_rdns=False, enable_geo=False,
                       addons=registry)


class TestLoading(AddonCase):

    def test_an_addon_contributes_a_hook_a_panel_and_a_key(self):
        self.write("counter", COUNTER)
        registry = self.registry()
        self.assertEqual([a.name for a in registry.addons], ["counter"])
        addon = registry.addons[0]
        self.assertEqual(addon.status, "ok")
        self.assertEqual(addon.doc, "Counts packets.")
        self.assertEqual(len(addon.panels), 1)
        self.assertEqual(len(addon.packet_hooks), 1)
        self.assertEqual([k.char for k in addon.keys], ["z"])

    def test_a_file_that_raises_on_import_is_reported_not_raised(self):
        self.write("bad", BROKEN_IMPORT)
        registry = self.registry()
        addon = registry.addons[0]
        self.assertEqual(addon.status, "failed")
        self.assertIn("ValueError", addon.error)

    def test_a_broken_addon_does_not_stop_a_good_one(self):
        self.write("bad", BROKEN_IMPORT)
        self.write("counter", COUNTER)
        registry = self.registry()
        self.assertEqual({a.name: a.status for a in registry.addons},
                         {"bad": "failed", "counter": "ok"})

    def test_files_starting_with_underscore_are_ignored(self):
        self.write("_helper", "raise ValueError('never loaded')")
        self.assertEqual(self.registry().addons, [])

    def test_the_scaffold_writes_an_addon_that_loads(self):
        registry = AddonRegistry(directories=[self.addons_dir])
        path = registry.scaffold("my thing")
        self.assertTrue(os.path.exists(path))
        registry.load()
        addon = registry.addons[0]
        self.assertEqual(addon.status, "ok", addon.error)
        self.assertTrue(addon.panels and addon.packet_hooks and addon.keys)

    def test_the_scaffold_refuses_to_overwrite(self):
        registry = AddonRegistry(directories=[self.addons_dir])
        registry.scaffold("dup")
        with self.assertRaises(FileExistsError):
            registry.scaffold("dup")

    def test_reload_picks_up_a_new_file(self):
        registry = self.registry()
        self.assertEqual(registry.addons, [])
        self.write("counter", COUNTER)
        registry.reload()
        self.assertEqual([a.name for a in registry.addons], ["counter"])

    def test_disabling_addons_loads_the_builtin_cards_only(self):
        self.write("counter", COUNTER)
        registry = AddonRegistry(directories=[self.addons_dir], enabled=False)
        registry.load()
        self.assertEqual(registry.addons, [])
        self.assertTrue(registry.builtins)


class TestDispatch(AddonCase):

    def test_packet_hooks_see_captured_packets(self):
        self.write("counter", COUNTER)
        registry = self.registry()
        session = self.session(registry)
        for packet in (factory.tcp(), factory.udp(), factory.arp()):
            session._on_packet(packet)
        module = registry.addons[0]
        panels = session.derive(want_panels=True).panels
        card = [p for p in panels if p.key == "counter"][0]
        self.assertEqual(card.lines[0].text, "3 packets")
        self.assertEqual(module.status, "ok")

    def test_an_addon_can_raise_an_alert(self):
        self.write("counter", COUNTER)
        session = self.session(self.registry())
        session._on_packet(factory.tcp(dport=23, flags="PA", payload=b"hi"))
        titles = [alert.title for alert in session.alerts.alerts]
        self.assertIn("Telnet", titles)

    def test_a_hook_that_keeps_raising_is_disabled_and_capture_continues(self):
        self.write("boom", BROKEN_HOOK)
        registry = self.registry()
        session = self.session(registry)
        for _ in range(MAX_FAILURES + 2):
            session._on_packet(factory.tcp())
        self.assertEqual(len(session.records), MAX_FAILURES + 2)
        addon = registry.addons[0]
        self.assertFalse(addon.enabled)
        self.assertIn("RuntimeError", addon.error)

    def test_a_panel_that_raises_becomes_an_error_on_its_card(self):
        self.write("boom", BROKEN_HOOK)
        registry = self.registry()
        session = self.session(registry)
        card = [p for p in session.derive(want_panels=True).panels
                if p.key == "boom"][0]
        self.assertIn("RuntimeError", card.error)
        self.assertEqual(card.lines, [])

    def test_key_bindings_dispatch_to_the_addon(self):
        self.write("counter", COUNTER)
        registry = self.registry()
        session = self.session(registry)
        session._on_packet(factory.tcp())

        class FakeUI:
            message = ""

            def notify(self, text, role="base", seconds=4.0):
                self.message = text

        ui = FakeUI()
        self.assertTrue(registry.handle_key("z", ui))
        self.assertEqual(ui.message, "1 packets")
        self.assertFalse(registry.handle_key("Q", ui))

    def test_clearing_the_session_notifies_addons(self):
        self.write("clearer", '''
from netsour.addon import on_clear
cleared = []


@on_clear
def reset():
    cleared.append(1)
''')
        registry = self.registry()
        session = self.session(registry)
        session.clear()
        self.assertEqual(registry.addons[0].status, "ok")


class TestPanels(AddonCase):

    def test_the_builtin_cards_render_without_a_capture(self):
        session = self.session(self.registry())
        panels = session.derive(want_panels=True).panels
        self.assertTrue(panels)
        self.assertTrue(all(panel.error == "" for panel in panels))
        self.assertTrue(all(isinstance(line, Line)
                            for panel in panels for line in panel.lines))

    def test_the_builtin_cards_render_with_traffic(self):
        session = self.session(self.registry())
        for packet in (factory.tcp(dport=80, flags="PA", payload=b"GET /"),
                       factory.dns_query(), factory.arp(), factory.icmp()):
            session._on_packet(packet)
        panels = {p.key: p for p in session.derive(want_panels=True).panels}
        self.assertTrue(panels["protocols"].lines)
        self.assertTrue(panels["talkers"].lines)
        self.assertEqual(panels["capture"].error, "")

    def test_hiding_a_card_removes_it_and_survives_a_reload(self):
        registry = self.registry()
        self.assertFalse(registry.toggle_panel("talkers"))
        keys = [spec.key for spec in registry.panel_specs()]
        self.assertNotIn("talkers", keys)
        self.assertIn("talkers",
                      [s.key for s in registry.panel_specs(include_hidden=True)])
        again = AddonRegistry(directories=[self.addons_dir])
        again.load()
        self.assertNotIn("talkers", [s.key for s in again.panel_specs()])

    def test_panels_are_only_rendered_when_the_board_is_on_screen(self):
        session = self.session(self.registry())
        self.assertEqual(session.derive().panels, [])

    def test_panel_context_helpers_are_bounded_by_the_card_width(self):
        ctx = PanelContext(width=30)
        self.assertEqual(len(ctx.spark([1, 2, 3])), 28)
        self.assertLessEqual(len(ctx.bar(1, 2, 10)), 10)
        self.assertEqual(len(ctx.pair("label", "value").text), 30)
        self.assertEqual(ctx.bytes(2048), "2.0K")


class TestNormalize(unittest.TestCase):

    def test_strings_tuples_and_lines_all_become_lines(self):
        lines = normalize_lines(["a", ("b", "warn"), Line("c", "ok"), 4])
        self.assertEqual([line.text for line in lines], ["a", "b", "c", "4"])
        self.assertEqual([line.role for line in lines],
                         ["base", "warn", "ok", "base"])

    def test_a_bare_string_is_one_line(self):
        self.assertEqual(len(normalize_lines("only")), 1)

    def test_nothing_returned_is_no_lines(self):
        self.assertEqual(normalize_lines(None), [])

    def test_a_flood_of_lines_is_capped(self):
        self.assertLessEqual(len(normalize_lines(["x"] * 10000)), 64)


class TestBoardLayout(unittest.TestCase):

    def test_columns_grow_with_the_terminal_and_never_exceed_three(self):
        self.assertEqual(dashboard_columns(40), 1)
        self.assertEqual(dashboard_columns(80), 2)
        self.assertEqual(dashboard_columns(200), 3)

    def test_card_width_leaves_room_for_the_border(self):
        for width in (40, 80, 120, 200):
            count = dashboard_columns(width)
            outer = dashboard_card_width(width) + 4
            self.assertLessEqual(outer * count + (count - 1), width)

    def test_cards_are_placed_into_the_shortest_column(self):
        panels = [_panel(lines) for lines in (10, 2, 2, 2)]
        placements, total = dashboard_layout(panels, 120)
        columns = [column for column, _row, _panel in placements]
        self.assertEqual(columns, [0, 1, 2, 1])
        self.assertEqual(total, 13)          # the tall card sets the height

    def test_a_narrow_terminal_stacks_every_card(self):
        placements, total = dashboard_layout([_panel(3), _panel(3)], 40)
        self.assertEqual([column for column, _r, _p in placements], [0, 0])
        self.assertEqual(total, 12)


def _panel(line_count):
    from netsour.addons import PanelData

    return PanelData(key="k", title="t", source="built-in",
                     lines=[Line("x")] * line_count)


if __name__ == "__main__":
    unittest.main()
