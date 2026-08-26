"""Low-level drawing helpers: clipped text, boxes, bars, sparklines.

Every routine here is defensive. Curses raises on any write that touches the
last cell of the screen or falls outside a window, and a packet sniffer must not
die because the user made the terminal one column narrower.
"""

from __future__ import annotations

import curses
import locale
import sys
from typing import List, Sequence

UNICODE_GLYPHS = {
    "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│",
    "lt": "├", "rt": "┤", "tt": "┬", "bt": "┴", "cross": "┼",
    "arrow": "→", "dot": "·", "bullet": "•", "tri": "▸", "tri_down": "▾",
    "block": "█", "sep": "│", "check": "✓", "cross_mark": "✗",
    "scroll": "▐", "up": "▲", "down": "▼", "live": "●", "pause": "❙❙",
    "trough": "┆",
}

ASCII_GLYPHS = {
    "tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|",
    "lt": "+", "rt": "+", "tt": "+", "bt": "+", "cross": "+",
    "arrow": "->", "dot": ".", "bullet": "*", "tri": ">", "tri_down": "v",
    "block": "#", "sep": "|", "check": "y", "cross_mark": "x",
    "scroll": "|", "up": "^", "down": "v", "live": "*", "pause": "||",
    "trough": ":",
}

SPARK_UNICODE = " ▁▂▃▄▅▆▇█"
SPARK_ASCII = " .:-=+*#%"
BAR_UNICODE = "▏▎▍▌▋▊▉█"


def detect_unicode() -> bool:
    """True when the terminal encoding can carry box-drawing characters."""
    try:
        encoding = (locale.getpreferredencoding(False) or "").lower()
    except Exception:
        encoding = ""
    if "utf" in encoding:
        return True
    stdout_enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in stdout_enc


class Glyphs:
    """Box-drawing character set, chosen once at startup."""

    def __init__(self, unicode_ok: bool = True):
        self.unicode = unicode_ok
        self.g = UNICODE_GLYPHS if unicode_ok else ASCII_GLYPHS
        self.spark = SPARK_UNICODE if unicode_ok else SPARK_ASCII

    def __getitem__(self, key: str) -> str:
        return self.g[key]


# Control characters would move the cursor or corrupt the frame, and packet
# payloads are full of them. Everything drawn passes through this table.
_CONTROL = {c: 0xFFFD for c in range(0x20)}
_CONTROL.update({0x7F: 0xFFFD})
_CONTROL.update({c: 0xFFFD for c in range(0x80, 0xA0)})


def sanitize(text: str) -> str:
    """Replace control characters so untrusted packet data cannot break the UI."""
    if text.isprintable():
        return text
    return text.translate(_CONTROL).replace("\ufffd", ".")


def addstr(win, y: int, x: int, text: str, attr: int = 0,
           max_width: int | None = None) -> int:
    """Write `text` at (y, x), clipped to the window. Returns columns written."""
    if not text:
        return 0
    text = sanitize(text)
    try:
        height, width = win.getmaxyx()
    except Exception:
        return 0
    if y < 0 or y >= height or x >= width:
        return 0
    if x < 0:
        text = text[-x:]
        x = 0
    room = width - x
    if max_width is not None:
        room = min(room, max_width)
    if room <= 0:
        return 0
    # The bottom-right cell cannot be written without scrolling the window.
    if y == height - 1:
        room -= 1
    if room <= 0:
        return 0
    chunk = text[:room]
    try:
        win.addstr(y, x, chunk, attr)
    except curses.error:
        try:
            win.addstr(y, x, chunk[:-1], attr)
        except curses.error:
            return 0
    return len(chunk)


def fill(win, y: int, x: int, width: int, attr: int = 0, char: str = " ") -> None:
    """Paint a run of `width` cells - used for status bars and popup bodies."""
    addstr(win, y, x, char * max(0, width), attr)


def hline(win, y: int, x: int, width: int, glyphs: Glyphs, attr: int = 0) -> None:
    addstr(win, y, x, glyphs["h"] * max(0, width), attr)


def vline(win, y: int, x: int, height: int, glyphs: Glyphs, attr: int = 0) -> None:
    for row in range(height):
        addstr(win, y + row, x, glyphs["v"], attr)


def box(win, y: int, x: int, height: int, width: int, glyphs: Glyphs,
        attr: int = 0, title: str = "", title_attr: int | None = None) -> None:
    """Draw a rounded box with an optional inline title on the top edge."""
    if height < 2 or width < 2:
        return
    g = glyphs
    addstr(win, y, x, g["tl"] + g["h"] * (width - 2) + g["tr"], attr)
    for row in range(1, height - 1):
        addstr(win, y + row, x, g["v"], attr)
        addstr(win, y + row, x + width - 1, g["v"], attr)
    addstr(win, y + height - 1, x, g["bl"] + g["h"] * (width - 2) + g["br"], attr)
    if title and width > 8:
        label = f" {title} "[:width - 4]
        addstr(win, y, x + 2, label, attr if title_attr is None else title_attr)


def scrollbar(win, y: int, x: int, height: int, total: int, offset: int,
              visible: int, glyphs: Glyphs, attr: int = 0,
              thumb_attr: int = 0) -> None:
    """A one-column proportional scrollbar beside a scrolling region."""
    if height <= 0:
        return
    if total <= visible or total <= 0:
        return                      # nothing to scroll: leave the column blank
    thumb = max(1, int(height * visible / total))
    span = max(1, total - visible)
    top = int((height - thumb) * min(1.0, offset / span))
    for row in range(height):
        inside = top <= row < top + thumb
        addstr(win, y + row, x, glyphs["scroll"] if inside else glyphs["trough"],
               thumb_attr if inside else attr)


def sparkline(values: Sequence[float], width: int, glyphs: Glyphs) -> str:
    """Render a series as a single row of block characters."""
    if width <= 0:
        return ""
    series = list(values)[-width:]
    if not series:
        return ""
    series = [0.0] * (width - len(series)) + series
    peak = max(series)
    if peak <= 0:
        return glyphs.spark[0] * width
    levels = len(glyphs.spark) - 1
    return "".join(glyphs.spark[max(1, int(v / peak * levels))] if v > 0
                   else glyphs.spark[0] for v in series)


def bar(value: float, peak: float, width: int, unicode_ok: bool = True) -> str:
    """A horizontal bar with sub-cell precision when Unicode is available."""
    if width <= 0 or peak <= 0:
        return ""
    ratio = max(0.0, min(1.0, value / peak))
    if not unicode_ok:
        return "#" * int(round(ratio * width))
    exact = ratio * width
    full = int(exact)
    out = BAR_UNICODE[-1] * full
    remainder = exact - full
    if full < width and remainder > 0.05:
        out += BAR_UNICODE[min(len(BAR_UNICODE) - 1,
                               int(remainder * len(BAR_UNICODE)))]
    return out


def ellipsize(text: str, width: int) -> str:
    """Trim to `width`, marking truncation with an ellipsis."""
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    return text[:width - 1] + "…" if width > 1 else text[:width]


def pad(text: str, width: int) -> str:
    """Trim or space-pad to exactly `width` columns."""
    return ellipsize(text, width).ljust(width)


def columns(specs: Sequence[tuple], total: int) -> List[int]:
    """Lay out table columns as (min_width, weight[, drop_order]).

    Fixed minimums come first; leftover space is shared by weight, so the info
    column grows on a wide terminal and the address columns do not. When the
    terminal is too narrow to hold every minimum, whole columns are dropped -
    highest `drop_order` first - and returned as width 0, which renderers skip.
    A column with drop_order 0 (the default) is never dropped; if only
    undroppable columns remain they shrink proportionally.
    """
    widths = [max(0, spec[0]) for spec in specs]
    weights = [spec[1] for spec in specs]
    drops = [spec[2] if len(spec) > 2 else 0 for spec in specs]
    alive = [True] * len(specs)

    def used() -> int:
        return sum(w for w, ok in zip(widths, alive) if ok)

    while used() > total:
        droppable = [i for i, ok in enumerate(alive) if ok and drops[i] > 0]
        if not droppable:
            break
        alive[max(droppable, key=lambda i: drops[i])] = False

    spare = total - used()
    live = [i for i, ok in enumerate(alive) if ok]
    if spare > 0 and sum(weights[i] for i in live) > 0:
        pool = sum(weights[i] for i in live)
        for i in live:
            if weights[i]:
                widths[i] += spare * weights[i] // pool
    elif spare < 0:
        # Every remaining column is undroppable: shave the widest ones down.
        deficit = -spare
        for i in sorted(live, key=lambda i: -widths[i]):
            if deficit <= 0:
                break
            take = min(deficit, max(0, widths[i] - 4))
            widths[i] -= take
            deficit -= take
    return [w if ok else 0 for w, ok in zip(widths, alive)]


def hexdump_lines(data: bytes, width: int = 16, glyphs: Glyphs | None = None
                  ) -> List[tuple]:
    """Classic offset / hex / ASCII rows as (offset, hex, ascii) tuples."""
    out = []
    for start in range(0, len(data), width):
        chunk = data[start:start + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        if len(chunk) > 8:
            hex_part = hex_part[:23] + " " + hex_part[23:]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append((f"{start:08x}", hex_part.ljust(width * 3 + 1), text))
    return out


def wrap(text: str, width: int) -> List[str]:
    """Word-wrap, preserving explicit newlines."""
    if width <= 0:
        return []
    lines: List[str] = []
    for paragraph in text.split("\n"):
        if not paragraph:
            lines.append("")
            continue
        current = ""
        for word in paragraph.split(" "):
            candidate = f"{current} {word}".strip()
            if len(candidate) <= width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                while len(word) > width:
                    lines.append(word[:width])
                    word = word[width:]
                current = word
        if current:
            lines.append(current)
    return lines


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))
