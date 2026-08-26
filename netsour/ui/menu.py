"""A modal chooser overlay.

Used wherever the answer is "pick one of these" rather than "type something":
which address to scan, which Nmap profile, which OSINT source to run. Keeping
it one widget means every picker navigates identically.
"""

from __future__ import annotations

import curses
from dataclasses import dataclass
from typing import Any, Callable, List, Optional

from .render import addstr, box, clamp, ellipsize, fill, scrollbar


@dataclass
class MenuItem:
    """One row. `value` of None makes the row a non-selectable heading."""

    label: str
    hint: str = ""
    value: Any = None
    role: str = "base"
    enabled: bool = True

    @property
    def selectable(self) -> bool:
        return self.enabled and self.value is not None

    @property
    def is_heading(self) -> bool:
        """A row with no value at all is a section heading, not a dead option."""
        return self.value is None


@dataclass
class Menu:
    """Modal list selection. `callback` receives the chosen item's value."""

    title: str
    items: List[MenuItem]
    callback: Callable
    footer: str = ""
    cursor: int = 0
    scroll: int = 0
    danger: bool = False          # tints the frame for actions that emit packets

    def __post_init__(self):
        self.cursor = self._next_selectable(-1, 1)

    # ---- navigation -------------------------------------------------------

    def _next_selectable(self, start: int, step: int) -> int:
        """First selectable row from `start` moving by `step`, else `start`."""
        index = start + step
        while 0 <= index < len(self.items):
            if self.items[index].selectable:
                return index
            index += step
        return max(0, start)

    def move(self, step: int) -> None:
        self.cursor = self._next_selectable(self.cursor, step)

    def key(self, key: int) -> bool:
        """Handle a keypress. Returns False when the menu should close."""
        char = chr(key) if 0 <= key < 256 else "\0"
        if key in (27, ord("q")):
            return False
        if key in (curses.KEY_UP,) or char == "k":
            self.move(-1)
        elif key in (curses.KEY_DOWN,) or char == "j":
            self.move(1)
        elif key == curses.KEY_HOME or char == "g":
            self.cursor = self._next_selectable(-1, 1)
        elif key == curses.KEY_END or char == "G":
            self.cursor = self._next_selectable(len(self.items), -1)
        elif key == curses.KEY_PPAGE:
            for _ in range(5):
                self.move(-1)
        elif key == curses.KEY_NPAGE:
            for _ in range(5):
                self.move(1)
        elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
            return self._choose(self.cursor)
        elif char.isdigit() and char != "0":
            wanted = int(char)
            selectable = [i for i, item in enumerate(self.items)
                          if item.selectable]
            if wanted <= len(selectable):
                return self._choose(selectable[wanted - 1])
        return True

    def _choose(self, index: int) -> bool:
        if 0 <= index < len(self.items) and self.items[index].selectable:
            self.callback(self.items[index].value)
            return False
        return True

    def click(self, row: int) -> bool:
        """Select the row at a rendered offset; returns False when closing."""
        index = self.scroll + row
        if 0 <= index < len(self.items) and self.items[index].selectable:
            if index == self.cursor:
                return self._choose(index)
            self.cursor = index
        return True

    # ---- drawing ----------------------------------------------------------

    def draw(self, win, pal, glyphs, height: int, width: int) -> tuple:
        """Render centred. Returns (top, left, body_top) for hit-testing."""
        label_width = max((len(item.label) for item in self.items), default=10)
        hint_width = max((len(item.hint) for item in self.items), default=0)
        inner = max(len(self.title) + 6, label_width + hint_width + 12,
                    len(self.footer) + 4)
        popup_w = min(width - 4, max(34, inner))
        body = min(len(self.items), max(3, height - 8))
        popup_h = min(height - 2, body + 4 if self.footer else body + 3)
        body = popup_h - (4 if self.footer else 3)
        top = max(0, (height - popup_h) // 2)
        left = max(0, (width - popup_w) // 2)

        for row in range(popup_h):
            fill(win, top + row, left, popup_w, pal("popup"))
        edge = pal("popup_danger") if self.danger else pal("popup_edge")
        box(win, top, left, popup_h, popup_w, glyphs, edge, self.title, edge)

        self.scroll = clamp(self.scroll, max(0, self.cursor - body + 1),
                            max(0, self.cursor))
        self.scroll = min(self.scroll, max(0, len(self.items) - body))

        number = 0
        for offset in range(body):
            index = self.scroll + offset
            if index >= len(self.items):
                break
            item = self.items[index]
            row_y = top + 1 + offset
            selected = index == self.cursor and item.selectable
            if item.selectable:
                number += 1
            if selected:
                fill(win, row_y, left + 1, popup_w - 2, pal("select"))
            if item.is_heading:
                addstr(win, row_y, left + 2,
                       ellipsize(item.label, popup_w - 4), pal("header"))
                continue
            if not item.enabled:
                # Unavailable, but still worth showing with its reason.
                addstr(win, row_y, left + 6,
                       ellipsize(item.label, label_width + 1), pal("faint"))
                if item.hint:
                    hint_x = left + 8 + label_width
                    addstr(win, row_y, hint_x,
                           ellipsize(item.hint,
                                     max(0, left + popup_w - 2 - hint_x)),
                           pal("faint"))
                continue
            attr = pal("select") if selected else pal(item.role)
            marker = f"{number}." if number < 10 else " •"
            addstr(win, row_y, left + 2, marker,
                   pal("select") if selected else pal("dim"))
            addstr(win, row_y, left + 6,
                   ellipsize(item.label, label_width + 1), attr)
            if item.hint:
                hint_x = left + 8 + label_width
                addstr(win, row_y, hint_x,
                       ellipsize(item.hint, max(0, left + popup_w - 2 - hint_x)),
                       pal("select") if selected else pal("dim"))

        if len(self.items) > body:
            scrollbar(win, top + 1, left + popup_w - 2, body, len(self.items),
                      self.scroll, body, glyphs, pal("frame"), pal("accent"))
        if self.footer:
            addstr(win, top + popup_h - 2, left + 2,
                   ellipsize(self.footer, popup_w - 4), pal("dim"))
        return top, left, top + 1


def menu_hit(rect: tuple, popup_w: int, my: int, mx: int) -> Optional[int]:
    """Row offset for a mouse position inside a drawn menu, else None."""
    top, left, body_top = rect
    if mx < left or mx >= left + popup_w:
        return None
    row = my - body_top
    return row if row >= 0 else None
