"""The modal chooser: navigation, headings, disabled rows, selection."""

import curses
import unittest

from netsour.ui.menu import Menu, MenuItem, menu_hit


def build(items, **kwargs):
    chosen = []
    menu = Menu(title="T", items=items, callback=chosen.append, **kwargs)
    return menu, chosen


class TestMenuItems(unittest.TestCase):

    def test_a_valueless_item_is_a_heading(self):
        item = MenuItem("Section")
        self.assertTrue(item.is_heading)
        self.assertFalse(item.selectable)

    def test_a_disabled_item_is_not_a_heading(self):
        item = MenuItem("stealth", "needs root", "stealth", enabled=False)
        self.assertFalse(item.is_heading)
        self.assertFalse(item.selectable)

    def test_a_normal_item_is_selectable(self):
        self.assertTrue(MenuItem("fast", "", "fast").selectable)


class TestMenuNavigation(unittest.TestCase):

    def items(self):
        return [MenuItem("Heading"),
                MenuItem("one", "", 1),
                MenuItem("blocked", "needs root", 2, enabled=False),
                MenuItem("three", "", 3),
                MenuItem("Another heading"),
                MenuItem("five", "", 5)]

    def test_cursor_starts_on_the_first_selectable_row(self):
        menu, _ = build(self.items())
        self.assertEqual(menu.cursor, 1)

    def test_movement_skips_headings_and_disabled_rows(self):
        menu, _ = build(self.items())
        menu.move(1)
        self.assertEqual(menu.cursor, 3)
        menu.move(1)
        self.assertEqual(menu.cursor, 5)
        menu.move(-1)
        self.assertEqual(menu.cursor, 3)

    def test_movement_stops_at_the_ends(self):
        menu, _ = build(self.items())
        for _ in range(10):
            menu.move(1)
        self.assertEqual(menu.cursor, 5)
        for _ in range(10):
            menu.move(-1)
        self.assertEqual(menu.cursor, 1)

    def test_home_and_end(self):
        menu, _ = build(self.items())
        menu.key(curses.KEY_END)
        self.assertEqual(menu.cursor, 5)
        menu.key(curses.KEY_HOME)
        self.assertEqual(menu.cursor, 1)

    def test_vim_keys_move_too(self):
        menu, _ = build(self.items())
        menu.key(ord("j"))
        self.assertEqual(menu.cursor, 3)
        menu.key(ord("k"))
        self.assertEqual(menu.cursor, 1)


class TestMenuSelection(unittest.TestCase):

    def items(self):
        return [MenuItem("Heading"),
                MenuItem("one", "", 1),
                MenuItem("blocked", "", 2, enabled=False),
                MenuItem("three", "", 3)]

    def test_enter_selects_and_closes(self):
        menu, chosen = build(self.items())
        self.assertFalse(menu.key(10))
        self.assertEqual(chosen, [1])

    def test_escape_closes_without_selecting(self):
        menu, chosen = build(self.items())
        self.assertFalse(menu.key(27))
        self.assertEqual(chosen, [])

    def test_digits_pick_by_visible_number(self):
        menu, chosen = build(self.items())
        self.assertFalse(menu.key(ord("2")))
        self.assertEqual(chosen, [3])          # the disabled row is not numbered

    def test_out_of_range_digits_are_ignored(self):
        menu, chosen = build(self.items())
        self.assertTrue(menu.key(ord("9")))
        self.assertEqual(chosen, [])

    def test_a_disabled_row_cannot_be_chosen(self):
        menu, chosen = build(self.items())
        menu.cursor = 2
        self.assertTrue(menu.key(10))
        self.assertEqual(chosen, [])

    def test_first_click_selects_and_second_confirms(self):
        menu, chosen = build(self.items())
        self.assertTrue(menu.click(3))         # row index 3 -> "three"
        self.assertEqual(menu.cursor, 3)
        self.assertEqual(chosen, [])
        self.assertFalse(menu.click(3))
        self.assertEqual(chosen, [3])

    def test_clicking_a_heading_does_nothing(self):
        menu, chosen = build(self.items())
        self.assertTrue(menu.click(0))
        self.assertEqual(chosen, [])


class TestMenuHitTesting(unittest.TestCase):

    def test_positions_inside_and_outside_the_popup(self):
        rect = (5, 10, 6)          # top, left, body_top
        self.assertEqual(menu_hit(rect, 40, 8, 20), 2)
        self.assertIsNone(menu_hit(rect, 40, 8, 5))     # left of the popup
        self.assertIsNone(menu_hit(rect, 40, 8, 55))    # right of it
        self.assertIsNone(menu_hit(rect, 40, 4, 20))    # above the body


if __name__ == "__main__":
    unittest.main()
