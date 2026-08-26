"""Per-view renderers.

Each function draws one region and is handed the app so it can reach session
state, the palette and the shared scroll positions. Drawing is pure: no view
mutates capture state, only its own scroll clamping.
"""

from __future__ import annotations

import time
from typing import List

from ..detail import packet_bytes, packet_tree
from ..devices import describe, icon_for
from ..enrich import is_private
from ..osint import SOURCES, target_kind
from ..services import service_name
from ..stats import human_bytes, human_duration
from .render import (addstr, bar, box, clamp, columns, ellipsize, fill,
                     hexdump_lines, pad, scrollbar, sparkline, vline, wrap)

# (label, minimum width, growth weight, drop order) - see render.columns.
PACKET_COLUMNS = [
    ("#", 7, 0, 3), ("Time", 13, 0, 2), ("Source", 20, 2, 0),
    ("Destination", 20, 2, 0), ("Proto", 10, 0, 0), ("Len", 6, 0, 1),
    ("Info", 24, 5, 0),
]


def _endpoint(ip: str, port, width: int) -> str:
    """`1.2.3.4:443`, dropping the port when the column is too narrow."""
    if not port:
        return ip
    combined = f"{ip}:{port}"
    return combined if len(combined) <= width else ip


def draw_packet_list(win, rect, app) -> None:
    """The scrolling packet table with header row and selection."""
    y, x, height, width = rect
    pal, g = app.pal, app.glyphs
    records = app.visible
    body_height = height - 1
    if body_height <= 0:
        return

    widths = columns([c[1:] for c in PACKET_COLUMNS], width - 2)

    # Header row
    fill(win, y, x, width, pal("header"))
    col = x + 1
    for (label, *_), col_width in zip(PACKET_COLUMNS, widths):
        addstr(win, y, col, pad(label, col_width - 1), pal("header"))
        col += col_width
    if not records:
        message = ("Waiting for packets…" if app.session.capture.running
                   else "No packets captured.")
        if app.session.filter.active():
            message = f"No packets match the filter ({app.session.filter.describe()})."
        addstr(win, y + 2, x + 2, message, pal("dim"))
        return

    offset = app.clamp_scroll("packets", len(records), body_height)
    cursor = app.cursor["packets"]

    for row in range(body_height):
        index = offset + row
        if index >= len(records):
            break
        rec = records[index]
        selected = index == cursor
        row_y = y + 1 + row
        base_attr = pal("select") if selected else 0
        if selected:
            fill(win, row_y, x, width - 1, base_attr)

        marker = ""
        marker_role = "dim"
        if "cleartext" in rec.tags:
            marker, marker_role = g["bullet"], "warn"
        if "reset" in rec.tags:
            marker, marker_role = g["cross_mark"], "danger"
        if marker:
            addstr(win, row_y, x, marker,
                   base_attr if selected else pal(marker_role))

        cells = [
            (str(rec.index), "dim"),
            (time.strftime("%H:%M:%S", time.localtime(rec.ts))
             + f".{int(rec.ts % 1 * 1000):03d}", "dim"),
            (_endpoint(rec.src, rec.sport, widths[2] - 1), "base"),
            (_endpoint(rec.dst, rec.dport, widths[3] - 1), "base"),
            (rec.proto, "proto"),
            (str(rec.length), "dim"),
            (rec.info, "base"),
        ]
        col = x + 1
        for (text, role), col_width in zip(cells, widths):
            if selected:
                attr = base_attr
            elif role == "proto":
                attr = pal.proto(rec.proto)
            else:
                attr = pal(role)
            addstr(win, row_y, col, pad(text, col_width - 1), attr,
                   max_width=col_width - 1)
            col += col_width

    scrollbar(win, y + 1, x + width - 1, body_height, len(records), offset,
              body_height, g, pal("frame"), pal("accent"))


def draw_detail(win, rect, app) -> None:
    """The lower pane: dissection tree, hex, stream, geo or Nmap output."""
    y, x, height, width = rect
    pal = app.pal
    rec = app.selected_record()
    mode = app.detail_mode

    if rec is None:
        addstr(win, y, x + 1, "Select a packet to inspect it.", pal("dim"))
        return

    if mode == "hex":
        lines = _hex_lines(rec, width - 2, app)
    elif mode == "stream":
        lines = _stream_lines(rec, app, width - 2)
    elif mode == "geo":
        lines = _geo_lines(rec, app)
    elif mode == "nmap":
        lines = _nmap_lines(rec, app)
    else:
        lines = [(indent, text, role)
                 for indent, text, role in packet_tree(rec, app.session.vendors,
                                                       app.session.rdns)]

    app.detail_length = len(lines)
    offset = app.clamp_scroll("detail", len(lines), height)
    for row in range(height):
        index = offset + row
        if index >= len(lines):
            break
        indent, text, role = lines[index]
        addstr(win, y + row, x + 1 + indent * 2,
               ellipsize(text, max(0, width - 3 - indent * 2)), pal(role))
    if len(lines) > height:
        scrollbar(win, y, x + width - 1, height, len(lines), offset, height,
                  app.glyphs, pal("frame"), pal("accent"))


def _hex_lines(rec, width: int, app) -> List[tuple]:
    data = packet_bytes(rec)
    if not data:
        return [(0, "No raw bytes available.", "dim")]
    per_row = 16 if width >= 74 else 8
    out = []
    for offset, hex_part, text in hexdump_lines(data, per_row):
        out.append((0, f"{offset}  {hex_part} {text}", "base"))
    return out


def _stream_lines(rec, app, width: int) -> List[tuple]:
    chunks = app.session.stream_for(rec)
    if not chunks:
        return [(0, "No payload bytes in this conversation yet.", "dim")]
    out = [(0, f"Following {rec.proto_base} "
               f"{rec.src}:{rec.sport} ↔ {rec.dst}:{rec.dport}", "header"),
           (0, "", "base")]
    for direction, data in chunks:
        role = "proto_tcp" if direction == "→" else "proto_udp"
        text = data.decode("latin-1", "replace").replace("\r\n", "\n")
        printable = "".join(c if 32 <= ord(c) < 127 or c == "\n" else "."
                            for c in text)
        for line in printable.split("\n"):
            for piece in wrap(line, max(10, width - 4)) or [""]:
                out.append((0, f"{direction} {piece}", role))
    return out


def _geo_lines(rec, app) -> List[tuple]:
    session = app.session
    out: List[tuple] = []
    for label, ip in (("Source", rec.src), ("Destination", rec.dst)):
        if not ip:
            continue
        out.append((0, f"{label}  {ip}", "header"))
        host = session.rdns.get(ip)
        if host:
            out.append((1, f"{'rdns':<10} {host}", "dim"))
        if is_private(ip):
            out.append((1, f"{'scope':<10} private / non-routable", "dim"))
            out.append((1, "", "base"))
            continue
        status = session.geo.status(ip)
        if status == "disabled":
            out.append((1, "geo lookups are disabled (--no-geo)", "dim"))
        elif status == "ready":
            data = session.geo.get(ip) or {}
            if "error" in data:
                out.append((1, f"{'error':<10} {data['error']}", "danger"))
            else:
                for key, field in (("city", "city"), ("regionName", "region"),
                                   ("country", "country"), ("isp", "isp"),
                                   ("org", "org"), ("as", "asn")):
                    value = data.get(key)
                    if value:
                        out.append((1, f"{field:<10} {value}", "base"))
                if data.get("lat") is not None:
                    out.append((1, f"{'coords':<10} {data['lat']}, {data['lon']}",
                                "dim"))
        elif status == "pending":
            out.append((1, "looking up…", "warn"))
        else:
            out.append((1, "press 'G' to look this address up", "accent"))
        out.append((1, "", "base"))
    return out


def _nmap_lines(rec, app) -> List[tuple]:
    scanner = app.session.nmap
    out: List[tuple] = []
    if not scanner.available:
        return [(0, "Nmap integration unavailable.", "warn"),
                (1, "Install the nmap binary and `pip install python-nmap`.", "dim")]
    for label, ip in (("Source", rec.src), ("Destination", rec.dst)):
        if not ip:
            continue
        out.append((0, f"{label}  {ip}", "header"))
        lines = scanner.summary_lines(ip)
        if not lines:
            out.append((1, "not scanned - press 'n' to scan this host", "accent"))
        for line in lines:
            role = "ok" if "/tcp" in line or "/udp" in line else "base"
            out.append((1, line, role))
        out.append((1, "", "base"))
    out.append((0, "Scans are active probes. Only scan hosts you are "
                   "authorised to test.", "dim"))
    return out


def draw_flows(win, rect, app) -> None:
    """Conversation table, sorted by the current sort key."""
    y, x, height, width = rect
    pal, g = app.pal, app.glyphs
    flows = app.flow_rows
    specs = [("Proto", 9, 0, 0), ("Endpoint A", 22, 2, 0),
             ("Endpoint B", 22, 2, 0), ("Host", 14, 2, 6), ("Pkts", 8, 0, 0),
             ("Bytes", 9, 0, 0), ("A→B", 9, 0, 4), ("B→A", 9, 0, 5),
             ("Rate/s", 9, 0, 3), ("Dur", 8, 0, 2), ("State", 10, 0, 1)]
    widths = columns([spec[1:] for spec in specs], width - 2)

    fill(win, y, x, width, pal("header"))
    col = x + 1
    for (label, *_), col_width in zip(specs, widths):
        addstr(win, y, col, pad(label, col_width - 1), pal("header"))
        col += col_width

    if not flows:
        addstr(win, y + 2, x + 2, "No conversations recorded yet.", pal("dim"))
        return

    body = height - 1
    offset = app.clamp_scroll("flows", len(flows), body)
    cursor = app.cursor["flows"]
    for row in range(body):
        index = offset + row
        if index >= len(flows):
            break
        flow = flows[index]
        selected = index == cursor
        row_y = y + 1 + row
        attr = pal("select") if selected else 0
        if selected:
            fill(win, row_y, x, width - 1, attr)
        cells = [
            (flow.proto, pal.proto(flow.proto)),
            (flow.endpoint_a(), pal("base")),
            (flow.endpoint_b(), pal("base")),
            (flow.hostname or service_name(flow.b_port) or "", pal("accent")),
            (f"{flow.packets:,}", pal("dim")),
            (human_bytes(flow.bytes), pal("base")),
            (human_bytes(flow.bytes_ab), pal("dim")),
            (human_bytes(flow.bytes_ba), pal("dim")),
            (human_bytes(flow.rate) if flow.rate else "-", pal("info")),
            (human_duration(flow.duration), pal("dim")),
            (flow.state(), pal("ok") if flow.state() == "open"
             else pal("warn") if flow.state() in ("reset", "unanswered")
             else pal("dim")),
        ]
        col = x + 1
        for (text, cell_attr), col_width in zip(cells, widths):
            addstr(win, row_y, col, pad(text, col_width - 1),
                   attr if selected else cell_attr, max_width=col_width - 1)
            col += col_width
    scrollbar(win, y + 1, x + width - 1, body, len(flows), offset, body, g,
              pal("frame"), pal("accent"))


def draw_stats(win, rect, app) -> None:
    """Dashboard: throughput sparklines, protocol mix, top talkers and ports."""
    y, x, height, width = rect
    pal, g = app.pal, app.glyphs
    stats = app.derived.stats
    unicode_ok = g.unicode

    left_width = max(34, width // 2 - 1)
    right_x = x + left_width + 2
    right_width = width - left_width - 3
    row = y

    summary = [
        ("captured", f"{stats.total_packets:,} packets  ·  "
                     f"{human_bytes(stats.total_bytes)}"),
        ("uptime", f"{human_duration(stats.elapsed)}  ·  "
                   f"avg {stats.total_packets / stats.elapsed:.1f} pkt/s"),
        ("current", f"{stats.pps:.0f} pkt/s  ·  {human_bytes(stats.bps)}/s  "
                    f"(peak {stats.peak_pps} pkt/s)"),
        ("buffer", f"{stats.buffer_len:,} held  ·  "
                   f"{stats.dropped:,} rotated out"),
        ("flows", f"{stats.flow_count:,} conversations"),
    ]
    addstr(win, row, x + 1, "OVERVIEW", pal("header"))
    row += 1
    for label, value in summary:
        addstr(win, row, x + 2, f"{label:<9}", pal("dim"))
        addstr(win, row, x + 12, ellipsize(value, left_width - 12), pal("base"))
        row += 1

    row += 1
    addstr(win, row, x + 1, "THROUGHPUT", pal("header"))
    row += 1
    spark_width = max(10, left_width - 12)
    history = stats.history[-spark_width:]
    addstr(win, row, x + 2, f"{'pkt/s':<9}", pal("dim"))
    addstr(win, row, x + 12, sparkline([h[1] for h in history], spark_width, g),
           pal("spark"))
    row += 1
    addstr(win, row, x + 2, f"{'bytes/s':<9}", pal("dim"))
    addstr(win, row, x + 12, sparkline([h[2] for h in history], spark_width, g),
           pal("bar"))
    row += 2

    addstr(win, row, x + 1, "PROTOCOL MIX", pal("header"))
    row += 1
    total = max(1, sum(count for _, count in stats.proto_packets))
    peak = max((count for _, count in stats.proto_packets), default=1)
    for proto, count in stats.proto_packets[:6]:
        if row >= y + height:
            break
        share = count / total * 100
        addstr(win, row, x + 2, pad(proto, 9), pal.proto(proto))
        addstr(win, row, x + 12, f"{share:5.1f}%", pal("dim"))
        addstr(win, row, x + 19,
               bar(count, peak, max(4, left_width - 30), unicode_ok), pal("bar"))
        addstr(win, row, x + left_width - 10, f"{count:>9,}", pal("dim"))
        row += 1

    row += 1
    if row < y + height - 2:
        addstr(win, row, x + 1, "PACKET SIZES", pal("header"))
        row += 1
        size_peak = max(stats.sizes.values(), default=1)
        for label in ("≤64", "65-128", "129-256", "257-512", "513-1K",
                      "1K-1514", ">1514"):
            if row >= y + height:
                break
            count = stats.sizes.get(label, 0)
            addstr(win, row, x + 2, pad(label, 9), pal("dim"))
            addstr(win, row, x + 12,
                   bar(count, size_peak, max(4, left_width - 24), unicode_ok),
                   pal("spark"))
            addstr(win, row, x + left_width - 10, f"{count:>9,}", pal("dim"))
            row += 1

    if right_width < 24:
        return

    # ---- right column ----
    row = y
    for column_title, counter, formatter in (
        ("TOP TALKERS (sent)", stats.talkers_sent, human_bytes),
        ("TOP DESTINATIONS", stats.talkers_recv, human_bytes),
    ):
        addstr(win, row, right_x, column_title, pal("header"))
        row += 1
        peak = max((value for _, value in counter), default=1)
        for host, value in counter[:6]:
            if row >= y + height:
                return
            name = app.session.rdns.get(host)
            label = f"{host}" + (f"  ({ellipsize(name, 18)})" if name else "")
            addstr(win, row, right_x + 1, pad(label, right_width - 22), pal("base"))
            addstr(win, row, right_x + right_width - 20,
                   bar(value, peak, 10, unicode_ok), pal("bar"))
            addstr(win, row, right_x + right_width - 9,
                   f"{formatter(value):>8}", pal("dim"))
            row += 1
        row += 1

    addstr(win, row, right_x, "TOP SERVICES", pal("header"))
    row += 1
    peak = max((count for _, count in stats.ports), default=1)
    for port, count in stats.ports[:6]:
        if row >= y + height:
            return
        name = service_name(port)
        label = f"{port}" + (f" {name}" if name else "")
        addstr(win, row, right_x + 1, pad(label, right_width - 22), pal("accent"))
        addstr(win, row, right_x + right_width - 20, bar(count, peak, 10, unicode_ok),
               pal("bar"))
        addstr(win, row, right_x + right_width - 9, f"{count:>8,}", pal("dim"))
        row += 1
    row += 1

    if stats.hostnames and row < y + height - 1:
        addstr(win, row, right_x, "RESOLVED NAMES", pal("header"))
        row += 1
        for host, count in stats.hostnames[:8]:
            if row >= y + height:
                return
            addstr(win, row, right_x + 1, pad(host, right_width - 8), pal("base"))
            addstr(win, row, right_x + right_width - 7, f"{count:>6,}", pal("dim"))
            row += 1


def draw_alerts(win, rect, app) -> None:
    """Security findings, newest or most severe first."""
    y, x, height, width = rect
    pal, g = app.pal, app.glyphs
    alerts = app.alert_rows

    counts = app.derived.alert_counts
    addstr(win, y, x + 1, "SEVERITY", pal("header"))
    col = x + 11
    for severity in ("high", "medium", "low", "info"):
        role = {"high": "danger", "medium": "warn", "low": "info",
                "info": "dim"}[severity]
        addstr(win, y, col, f"{g['bullet']} {severity} {counts.get(severity, 0)}",
               pal(role))
        col += len(severity) + 8
    addstr(win, y, x + width - 26, f"sort: {app.alert_sort}", pal("dim"))

    if not alerts:
        addstr(win, y + 2, x + 2,
               "No suspicious activity detected yet.", pal("ok"))
        addstr(win, y + 3, x + 2,
               "Detectors: port scan, host sweep, SYN/ICMP flood, ARP spoofing, "
               "DNS tunnelling,", pal("dim"))
        addstr(win, y + 4, x + 2,
               "NXDOMAIN storms, cleartext credentials, suspicious ports.",
               pal("dim"))
        return

    body = height - 2
    offset = app.clamp_scroll("alerts", len(alerts), body)
    cursor = app.cursor["alerts"]
    for row in range(body):
        index = offset + row
        if index >= len(alerts):
            break
        alert = alerts[index]
        row_y = y + 2 + row
        selected = index == cursor
        role = {"high": "danger", "medium": "warn", "low": "info",
                "info": "dim"}[alert.severity]
        if selected:
            fill(win, row_y, x, width - 1, pal("select"))
        attr = pal("select") if selected else pal(role)
        badge = {"high": "HIGH", "medium": "MED", "low": "LOW",
                 "info": "INFO"}[alert.severity]
        addstr(win, row_y, x + 1, f"{alert.when} ", attr if selected else pal("dim"))
        addstr(win, row_y, x + 10, pad(badge, 5), attr)
        addstr(win, row_y, x + 15, pad(alert.category, 13),
               attr if selected else pal("accent"))
        headline = alert.title + (f"  (×{alert.count})" if alert.count > 1 else "")
        addstr(win, row_y, x + 28, ellipsize(headline, width - 30),
               attr if selected else pal("base"))
        col_detail = x + 28 + len(headline) + 2
        if not selected and alert.detail and col_detail < x + width - 6:
            addstr(win, row_y, col_detail,
                   ellipsize(alert.detail, x + width - 2 - col_detail), pal("dim"))
    scrollbar(win, y + 2, x + width - 1, body, len(alerts), offset, body, g,
              pal("frame"), pal("accent"))


def draw_hosts(win, rect, app) -> None:
    """Every endpoint observed, with traffic totals and identification."""
    y, x, height, width = rect
    pal, g = app.pal, app.glyphs
    rows = app.host_rows
    specs = [("Address", 18, 2, 0), ("Hostname", 24, 3, 0), ("MAC", 19, 0, 3),
             ("Vendor", 20, 2, 4), ("Sent", 9, 0, 0), ("Recv", 9, 0, 0),
             ("Pkts", 8, 0, 1), ("Scope", 8, 0, 2)]
    widths = columns([spec[1:] for spec in specs], width - 2)

    fill(win, y, x, width, pal("header"))
    col = x + 1
    for (label, *_), col_width in zip(specs, widths):
        addstr(win, y, col, pad(label, col_width - 1), pal("header"))
        col += col_width

    if not rows:
        addstr(win, y + 2, x + 2, "No hosts observed yet.", pal("dim"))
        return

    body = height - 1
    offset = app.clamp_scroll("hosts", len(rows), body)
    cursor = app.cursor["hosts"]
    for row in range(body):
        index = offset + row
        if index >= len(rows):
            break
        host = rows[index]
        row_y = y + 1 + row
        selected = index == cursor
        attr = pal("select") if selected else 0
        if selected:
            fill(win, row_y, x, width - 1, attr)
        private = is_private(host["ip"])
        cells = [
            (host["ip"], pal("base")),
            (host["name"] or "", pal("accent")),
            (host["mac"] or "", pal("dim")),
            (host["vendor"] or "", pal("dim")),
            (human_bytes(host["sent"]), pal("base")),
            (human_bytes(host["recv"]), pal("base")),
            (f"{host['packets']:,}", pal("dim")),
            ("private" if private else "public",
             pal("ok") if private else pal("warn")),
        ]
        col = x + 1
        for (text, cell_attr), col_width in zip(cells, widths):
            addstr(win, row_y, col, pad(text, col_width - 1),
                   attr if selected else cell_attr, max_width=col_width - 1)
            col += col_width
    scrollbar(win, y + 1, x + width - 1, body, len(rows), offset, body, g,
              pal("frame"), pal("accent"))


def draw_recon(win, rect, app) -> None:
    """ARP sweep results drawn as a topology tree."""
    y, x, height, width = rect
    pal, g = app.pal, app.glyphs
    session = app.session
    recon = app.derived
    row = y

    addstr(win, row, x + 1, "LOCAL SEGMENT", pal("header"))
    row += 1
    from ..capture import interface_address

    address = interface_address(session.iface)
    addstr(win, row, x + 2,
           f"interface {session.iface or '-'}   address {address or 'none'}",
           pal("base"))
    row += 2

    if recon.recon_running:
        addstr(win, row, x + 2, "ARP sweep in progress…", pal("warn"))
        return
    if recon.recon_error:
        addstr(win, row, x + 2, recon.recon_error, pal("danger"))
        row += 2
    if not recon.recon_hosts:
        addstr(win, row, x + 2, "Press 'S' to ARP-sweep the local /24.",
               pal("accent"))
        row += 1
        addstr(win, row, x + 2,
               "This sends ARP requests to every address on your subnet. "
               "Only sweep networks you administer.", pal("dim"))
        return

    scanned = time.strftime("%H:%M:%S", time.localtime(recon.recon_time))
    addstr(win, row, x + 2,
           f"{len(recon.recon_hosts)} hosts responded  ·  swept at {scanned}",
           pal("ok"))
    row += 2

    gateway = recon.recon_hosts[0][0] if recon.recon_hosts else ""
    addstr(win, row, x + 2, f"{g['live']} {gateway}", pal("accent"))
    addstr(win, row, x + 2 + len(gateway) + 3, "(lowest address - likely gateway)",
           pal("dim"))
    row += 1

    body = height - (row - y)
    rows = recon.recon_hosts[1:]
    offset = app.clamp_scroll("recon", len(rows), max(1, body))
    for i in range(max(0, body)):
        index = offset + i
        if index >= len(rows):
            break
        ip, mac = rows[index]
        vendor = session.vendors.get(mac)
        name = session.rdns.get(ip)
        branch = g["bl"] if index == len(rows) - 1 else g["lt"]
        addstr(win, row, x + 3, f"{branch}{g['h']}{g['h']} ", pal("frame"))
        addstr(win, row, x + 8, pad(ip, 17), pal("base"))
        addstr(win, row, x + 26, pad(mac, 19), pal("dim"))
        addstr(win, row, x + 46, ellipsize(vendor or "", 26), pal("accent"))
        if name:
            addstr(win, row, x + 74, ellipsize(name, max(0, width - 76)),
                   pal("info"))
        row += 1


def draw_osint(win, rect, app) -> None:
    """Assembled intelligence on one target: registry, DNS, TLS, path, ports."""
    y, x, height, width = rect
    pal, g = app.pal, app.glyphs
    target = app.osint_target
    row = y

    if not target:
        addstr(win, row + 1, x + 2, "No OSINT target selected.", pal("header"))
        addstr(win, row + 3, x + 2,
               "Press 'O' anywhere to pick an address from the current row, "
               "or 'x' here to type one.", pal("accent"))
        addstr(win, row + 4, x + 2,
               "A target can be an IP, a hostname, or a bare account name.",
               pal("dim"))
        addstr(win, row + 6, x + 2, "Sources:", pal("header"))
        for offset, source in enumerate(SOURCES):
            line = row + 7 + offset
            addstr(win, line, x + 4, pad(source.title, 22), pal("base"))
            addstr(win, line, x + 26,
                   pad("active" if source.active else "passive", 9),
                   pal("warn") if source.active else pal("ok"))
            addstr(win, line, x + 36, pad(source.applies, 9), pal("accent"))
            addstr(win, line, x + 46,
                   ellipsize(source.note, max(0, width - 48)), pal("dim"))
        addstr(win, row + 8 + len(SOURCES), x + 2,
               "Passive sources query public registries and resolvers. "
               "Active sources connect to the target itself.", pal("dim"))
        app.osint_length = 0
        return

    report = app.session.osint.report(target)
    lines = _osint_lines(app, target, report, width - 4)
    app.osint_length = len(lines)

    kind = target_kind(target)
    header = f"{target}"
    if kind == "username":
        scope = "account name"
    elif kind == "host":
        # is_private() answers True for anything it cannot parse, which is the
        # right default for gating a lookup and the wrong label for a name.
        scope = "hostname"
    elif is_private(target):
        scope = "private / RFC1918"
    else:
        scope = "public"
    addstr(win, row, x + 2, header, pal("title"))
    addstr(win, row, x + 3 + len(header), f"· {scope}", pal("dim"))
    running = [s.title for s in report.sections.values() if s.status == "running"]
    status = f"gathering: {', '.join(running)}" if running else "idle"
    addstr(win, row, max(x + 30, x + width - len(status) - 3),
           ellipsize(status, 40), pal("warn") if running else pal("dim"))
    row += 2

    body = height - (row - y)
    offset = app.clamp_scroll("osint", len(lines), max(1, body))
    for i in range(max(0, body)):
        index = offset + i
        if index >= len(lines):
            break
        indent, text, role = lines[index]
        addstr(win, row + i, x + 2 + indent * 2,
               ellipsize(text, max(0, width - 5 - indent * 2)), pal(role))
    if len(lines) > body:
        scrollbar(win, row, x + width - 1, body, len(lines), offset, body, g,
                  pal("frame"), pal("accent"))


def _osint_lines(app, target, report, width) -> List[tuple]:
    """Flatten a report into (indent, text, role) rows."""
    out: List[tuple] = []
    for source in SOURCES:
        if not source.supports(target):
            continue
        section = report.sections.get(source.key)
        status = section.status if section else "idle"
        marker = {"done": "✓", "running": "…", "error": "✗"}.get(status, "·")
        badge = "ACTIVE" if source.active else "passive"
        role = {"done": "header", "running": "warn", "error": "danger"}.get(
            status, "dim")
        took = f"  {section.took:.1f}s" if section and section.took else ""
        out.append((0, f"{marker} {source.title}   [{badge}]{took}", role))

        if status == "idle":
            out.append((1, "not gathered - press Enter to choose a source",
                        "dim"))
        elif status == "running":
            out.append((1, "working…", "warn"))
        elif status == "error":
            out.append((1, section.error, "danger"))
        else:
            for finding in section.findings:
                out.append((1, f"{finding.label:<14} {finding.value}",
                            finding.role))
        out.append((0, "", "base"))

    if target_kind(target) == "username":
        return out          # nothing to port-scan about an account name

    scan = app.session.nmap
    lines = scan.summary_lines(target)
    if lines:
        out.append((0, "✓ Open ports   [ACTIVE]", "header"))
        for line in lines:
            out.append((1, line, "ok" if "/tcp" in line or "/udp" in line
                        else "base"))
    else:
        out.append((0, "· Open ports   [ACTIVE]", "dim"))
        out.append((1, "not scanned - press 'n' to run Nmap against this host",
                    "dim"))
    return out


ADDRESS_PANE_MIN = 24
ADDRESS_PANE_MAX = 40
IDENTITY_PANE_MIN = 26


def device_pane_width(width: int) -> int:
    """Width of the address pane. The identity pane takes what is left.

    Below the combined minimum there is no room for two panes, so the address
    list takes the whole width and the identity pane is dropped rather than
    squeezed into four columns.
    """
    if width < ADDRESS_PANE_MIN + IDENTITY_PANE_MIN:
        return width
    return clamp(width // 3, ADDRESS_PANE_MIN, ADDRESS_PANE_MAX)


CARD_WIDTH = 38
CARD_HEIGHT = 6


def device_grid_columns(width: int) -> int:
    """How many cards fit across the pane."""
    return max(1, (width - 2) // CARD_WIDTH)


def draw_device_grid(win, rect, app) -> None:
    """The devices on this network, as a selectable grid of cards."""
    y, x, height, width = rect
    pal, g = app.pal, app.glyphs
    devices = app.device_rows

    _draw_device_header(win, y, x, width, app)

    if not devices:
        _draw_empty_devices(win, y, x, width, app)
        app.device_columns = 1
        return

    columns = device_grid_columns(width)
    app.device_columns = columns
    rows = (len(devices) + columns - 1) // columns
    visible_rows = max(1, (height - 2) // CARD_HEIGHT)

    cursor_row = app.cursor["devices"] // columns
    top_row = app.scroll.get("devices_row", 0)
    top_row = min(top_row, max(0, rows - visible_rows))
    if cursor_row < top_row:
        top_row = cursor_row
    elif cursor_row >= top_row + visible_rows:
        top_row = cursor_row - visible_rows + 1
    app.scroll["devices_row"] = top_row

    for slot in range(visible_rows * columns):
        index = (top_row * columns) + slot
        if index >= len(devices):
            break
        card_x = x + 1 + (slot % columns) * CARD_WIDTH
        card_y = y + 2 + (slot // columns) * CARD_HEIGHT
        if card_y + CARD_HEIGHT > y + height:
            break
        _draw_device_card(win, card_y, card_x, devices[index],
                          index == app.cursor["devices"], app)

    if rows > visible_rows:
        scrollbar(win, y + 2, x + width - 1, visible_rows * CARD_HEIGHT,
                  rows, top_row, visible_rows, g, pal("frame"), pal("accent"))


def _draw_device_card(win, y: int, x: int, device, selected: bool, app) -> None:
    pal, g = app.pal, app.glyphs
    inner = CARD_WIDTH - 3

    edge = pal("frame_hot") if selected else pal("frame")
    box(win, y, x, CARD_HEIGHT - 1, CARD_WIDTH - 1, g, edge)
    if selected:
        fill(win, y + 1, x + 1, CARD_WIDTH - 3, pal("select_dim"))

    icon = icon_for(device.kind, g.unicode)
    icon_attr = pal("danger") if device.is_gateway else pal.proto(device.kind)
    for offset, line in enumerate(icon):
        addstr(win, y + 1 + offset, x + 2, line,
               pal("select") if selected and offset == 0 else icon_attr)

    text_x = x + 2 + len(icon[0]) + 2
    text_width = max(4, x + CARD_WIDTH - 2 - text_x)

    name = device.hostname or device.ip
    addstr(win, y + 1, text_x, ellipsize(name, text_width),
           pal("select") if selected else pal("title"))
    second = device.ip if device.hostname else describe(device)
    addstr(win, y + 2, text_x, ellipsize(second, text_width), pal("base"))
    third = describe(device) if device.hostname else (device.os_hint or
                                                     device.presence)
    addstr(win, y + 3, text_x, ellipsize(third, text_width), pal("dim"))

    stats = (f"{g['up']}{human_bytes(device.bytes_sent)} "
             f"{g['down']}{human_bytes(device.bytes_recv)} "
             f"{device.packets}p")
    addstr(win, y + 4, x + 2, ellipsize(stats, inner - 10), pal("dim"))
    badge = ("GATEWAY" if device.is_gateway
             else "offline" if device.status == "offline"
             else device.confidence)
    addstr(win, y + 4, x + CARD_WIDTH - 2 - len(badge), badge,
           pal("danger") if device.is_gateway
           else pal("warn") if badge in ("offline", "likely")
           else pal("ok") if badge == "confirmed" else pal("dim"))


def draw_device_detail(win, rect, app) -> None:
    """The selected device's full record, under the grid."""
    y, x, height, width = rect
    pal = app.pal
    devices = app.device_rows
    if not devices:
        return
    device = devices[clamp(app.cursor["devices"], 0, len(devices) - 1)]

    lines = [
        ("address", device.ip, "base"),
        ("hardware", f"{device.mac or 'unknown MAC'}"
                     f"{'  ·  ' + device.vendor if device.vendor else ''}",
         "base"),
        ("hostname", device.hostname or "not resolved", "base"),
        ("kind", f"{device.label}  ({device.confidence})", "accent"),
        ("evidence", "; ".join(device.evidence) or "no identifying signals seen",
         "dim"),
        ("os guess", device.os_hint or "no TTL observed", "dim"),
        ("services", ", ".join(str(port) for port in sorted(device.services))
         or "none observed", "base"),
        ("presence", device.presence,
         "ok" if device.online else "warn" if device.status == "offline"
         else "dim"),
        ("traffic", f"{human_bytes(device.bytes_sent)} sent · "
                    f"{human_bytes(device.bytes_recv)} received · "
                    f"{device.packets} packets", "base"),
    ]
    for offset, (label, value, role) in enumerate(lines):
        if offset >= height:
            break
        addstr(win, y + offset, x + 2, f"{label:<10}", pal("dim"))
        addstr(win, y + offset, x + 13,
               ellipsize(value, max(0, width - 16)), pal(role))


def draw_devices(win, rect, app) -> None:
    """Two panes: every address on the left, who it is on the right."""
    y, x, height, width = rect
    pal, g = app.pal, app.glyphs
    devices = app.device_rows
    app.device_columns = 1

    _draw_device_header(win, y, x, width, app)

    if not devices:
        _draw_empty_devices(win, y, x, width, app)
        return

    pane = device_pane_width(width)
    list_top = y + 2
    visible = max(1, height - 2)
    offset = app.clamp_scroll("devices", len(devices), visible)
    cursor = app.cursor["devices"]

    for row in range(visible):
        index = offset + row
        if index >= len(devices):
            break
        _draw_device_row(win, list_top + row, x + 1, pane - 2,
                         devices[index], index == cursor, app)
    if len(devices) > visible:
        scrollbar(win, list_top, x + pane - 1, visible, len(devices), offset,
                  visible, g, pal("frame"), pal("accent"))

    if pane >= width:
        return
    vline(win, list_top, x + pane, visible, g, pal("frame"))
    draw_device_identity(win, (list_top, x + pane + 2, visible,
                               width - pane - 3), app)


def _draw_device_header(win, y: int, x: int, width: int, app) -> None:
    pal = app.pal
    devices = app.device_rows
    online = sum(1 for device in devices if device.online)
    header = f"{len(devices)} device{'s' if len(devices) != 1 else ''}"
    col = x + 1
    col += addstr(win, y, col, header.upper(), pal("header"))
    col += addstr(win, y, col, f"   {online} online", pal("ok"))
    if app.hidden_devices:
        col += addstr(win, y, col,
                      f"   {app.hidden_devices} offline hidden ('o')",
                      pal("dim"))
    swept = app.derived.recon_hosts
    note = (f"   ARP sweep found {len(swept)}" if swept
            else "   press 'S' to ARP-sweep the subnet")
    if x + width - col > len(note) + 2:
        col += addstr(win, y, col, note, pal("ok") if swept else pal("accent"))
    hint = "Enter or click an address to see only its traffic"
    if x + width - col > len(hint) + 4:
        addstr(win, y, x + width - len(hint) - 2, hint, pal("dim"))


def _draw_empty_devices(win, y: int, x: int, width: int, app) -> None:
    pal = app.pal
    if app.hidden_devices:
        addstr(win, y + 2, x + 2,
               f"Every device seen is offline — press 'o' to show "
               f"{app.hidden_devices} of them.", pal("header"))
        return
    addstr(win, y + 2, x + 2, "No local devices identified yet.", pal("header"))
    explanation = (
        "On a switched network passive capture only shows broadcast "
        "traffic, so most devices stay invisible until they speak.",
        "Press 'S' to ARP-sweep the subnet — that asks every address "
        "directly and fills this list in.")
    for offset, line in enumerate(explanation):
        for row, wrapped in enumerate(wrap(line, max(20, width - 6))):
            addstr(win, y + 4 + offset * 2 + row, x + 2, wrapped, pal("dim"))


def _status_mark(device, glyphs) -> str:
    if device.status == "online":
        return glyphs["live"]
    return "○" if glyphs.unicode else "-"


def _draw_device_row(win, y: int, x: int, width: int, device, selected: bool,
                     app) -> None:
    """One address: presence, IP, and whatever names it."""
    pal, g = app.pal, app.glyphs
    if width <= 0:
        return
    if selected:
        fill(win, y, x, width, pal("select_dim"))

    mark_attr = (pal("danger") if device.is_gateway
                 else pal("ok") if device.online else pal("dim"))
    addstr(win, y, x, _status_mark(device, g), mark_attr)

    name_x = 18
    ip_attr = (pal("select") if selected
               else pal("title") if device.online else pal("dim"))
    addstr(win, y, x + 2, pad(device.ip, min(15, max(0, width - 2))), ip_attr)
    if width > name_x:
        label = device.hostname or device.label
        addstr(win, y, x + name_x, ellipsize(label, width - name_x),
               pal("base") if device.online else pal("dim"))


def draw_device_identity(win, rect, app) -> None:
    """The selected device: what it is, how we know, and what it has sent."""
    y, x, height, width = rect
    pal, g = app.pal, app.glyphs
    devices = app.device_rows
    if not devices or height <= 0:
        return
    device = devices[clamp(app.cursor["devices"], 0, len(devices) - 1)]

    icon = icon_for(device.kind, g.unicode)
    icon_attr = pal("danger") if device.is_gateway else pal.proto(device.kind)
    for offset, line in enumerate(icon):
        if offset < height:
            addstr(win, y + offset, x, line, icon_attr)

    text_x = x + len(icon[0]) + 2
    text_width = max(4, x + width - text_x)
    addstr(win, y, text_x, ellipsize(device.hostname or device.ip, text_width),
           pal("title"))
    addstr(win, y + 1, text_x, ellipsize(f"{device.label}  ({device.confidence})",
                                         text_width), pal("accent"))
    badge = "GATEWAY" if device.is_gateway else device.status.upper()
    badge_attr = (pal("danger") if device.is_gateway
                  else pal("ok") if device.online
                  else pal("warn") if device.status == "offline" else pal("dim"))
    addstr(win, y + 2, text_x, ellipsize(badge, text_width), badge_attr)

    lines = [
        ("address", device.ip, "base"),
        ("hardware", f"{device.mac or 'unknown MAC'}"
                     f"{'  ·  ' + device.vendor if device.vendor else ''}",
         "base"),
        ("hostname", device.hostname or "not resolved", "base"),
        ("evidence", "; ".join(device.evidence) or "no identifying signals seen",
         "dim"),
        ("os guess", device.os_hint or "no TTL observed", "dim"),
        ("services", ", ".join(str(port) for port in sorted(device.services))
         or "none observed", "base"),
        ("presence", device.presence,
         "ok" if device.online else "warn" if device.status == "offline"
         else "dim"),
        ("traffic", f"{human_bytes(device.bytes_sent)} sent · "
                    f"{human_bytes(device.bytes_recv)} received · "
                    f"{device.packets} packets", "base"),
    ]
    top = y + len(icon) + 1
    for offset, (label, value, role) in enumerate(lines):
        row = top + offset
        if row >= y + height:
            break
        addstr(win, row, x, f"{label:<10}", pal("dim"))
        addstr(win, row, x + 11, ellipsize(value, max(0, width - 11)), pal(role))


# ---- dashboard -----------------------------------------------------------

# A card narrower than this cannot hold a label, a bar and a value, so the
# board drops to fewer columns rather than shredding every row.
CARD_MIN_WIDTH = 34
CARD_GAP = 1
CARD_CHROME = 4                      # "│ " + text + " │"


def dashboard_columns(width: int) -> int:
    """How many card columns fit, between one and three."""
    return max(1, min(3, (width + CARD_GAP) // (CARD_MIN_WIDTH + CARD_GAP)))


def dashboard_card_width(width: int) -> int:
    """The text width inside one card - what panels are told to render to."""
    count = dashboard_columns(width)
    outer = (width - (count - 1) * CARD_GAP) // count
    return max(10, outer - CARD_CHROME)


def dashboard_layout(panels, width: int):
    """Place cards into columns, shortest column first, order preserved.

    Returns (placements, total_height) where a placement is
    (column, row offset, panel) - the board is then drawn with one vertical
    scroll offset applied to every column.
    """
    count = dashboard_columns(width)
    heights = [0] * count
    placements = []
    for panel in panels:
        column = heights.index(min(heights))
        placements.append((column, heights[column], panel))
        heights[column] += max(3, len(panel.lines) + 2) + 1
    return placements, max(heights, default=0)


def draw_dashboard(win, rect, app) -> None:
    """The card board: built-in cards and whatever addons contributed."""
    y, x, height, width = rect
    pal = app.pal
    panels = app.derived.panels
    if not panels:
        hidden = len(app.session.addons.panel_specs(include_hidden=True))
        message = ("Every card is hidden - press Enter to choose cards."
                   if hidden else "No dashboard cards are registered.")
        addstr(win, y + 1, x + 2, message, pal("dim"))
        addstr(win, y + 3, x + 2, "A opens the addons menu.", pal("faint"))
        app.dash_length = 0
        return

    placements, total = dashboard_layout(panels, width)
    app.dash_length = total
    offset = app.clamp_scroll("dash", total, height)
    count = dashboard_columns(width)
    outer = (width - (count - 1) * CARD_GAP) // count

    for column, row, panel in placements:
        top = y + row - offset
        card_height = max(3, len(panel.lines) + 2)
        if top >= y + height or top + card_height <= y:
            continue                       # entirely scrolled out of the pane
        _draw_card(win, top, x + column * (outer + CARD_GAP), outer, panel,
                   app, y, y + height)


def _draw_card(win, top: int, x: int, outer: int, panel, app, limit_top: int,
               limit_bottom: int) -> None:
    """One card, clipped to the pane rather than the window.

    `addstr` already clips to the screen, but the board scrolls inside a pane
    with a border and a hint line below it, so rows outside the pane have to be
    dropped here or a scrolled card would paint over the chrome.
    """
    pal, g = app.pal, app.glyphs
    inner = outer - CARD_CHROME
    edge = pal("frame_hot") if panel.source != "built-in" else pal("frame")
    rows = [top]

    def place(row_y: int, draw) -> None:
        if limit_top <= row_y < limit_bottom:
            draw(row_y)

    title = ellipsize(f" {panel.title} ", outer - 4)
    tail = max(0, outer - 2 - len(title) - 1)

    def header(row_y: int) -> None:
        addstr(win, row_y, x, g["tl"] + g["h"], edge)
        addstr(win, row_y, x + 2, title,
               pal("accent") if panel.source == "built-in" else pal("header"))
        addstr(win, row_y, x + 2 + len(title), g["h"] * tail + g["tr"], edge)

    place(top, header)

    for index, line in enumerate(panel.lines or [_placeholder_line(panel)]):
        row_y = top + 1 + index
        rows.append(row_y)

        def body(row_y: int, line=line) -> None:
            addstr(win, row_y, x, g["v"], edge)
            addstr(win, row_y, x + 2, ellipsize(line.text, inner),
                   pal(line.role if line.role else "base"))
            addstr(win, row_y, x + outer - 1, g["v"], edge)

        place(row_y, body)

    footer_y = top + max(2, len(panel.lines) + 1)

    def footer(row_y: int) -> None:
        addstr(win, row_y, x, g["bl"] + g["h"] * (outer - 2) + g["br"], edge)
        if panel.error:
            addstr(win, row_y, x + 2, ellipsize(f" {panel.error} ", outer - 4),
                   pal("danger"))

    place(footer_y, footer)


def _placeholder_line(panel):
    """What a card shows when its panel returned nothing at all."""
    from ..addons import Line

    return Line(panel.error or "no data", "danger" if panel.error else "dim")
