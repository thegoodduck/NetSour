"""The built-in Dashboard cards.

These are ordinary addon panels — same signature, same registry, same failure
handling — so the API an addon writes against is the one NetSour itself uses.
Each function takes a :class:`~netsour.addons.PanelContext` and returns lines;
the board decides where the card lands and how wide it is.
"""

from __future__ import annotations

import os
from typing import List

from .addons import Line, PanelSpec
from .services import service_name

BAR_WIDTH = 8


def _bars(ctx, rows, formatter, label_role: str = "base") -> List[Line]:
    """`label   ▇▇▇▇   value` for a top-N counter, scaled to the card."""
    out: List[Line] = []
    peak = max((value for _, value in rows), default=1)
    value_width = max(len(formatter(value)) for _, value in rows) if rows else 0
    label_width = max(6, ctx.width - BAR_WIDTH - value_width - 3)
    for label, value in rows:
        out.append(Line(f"{str(label)[:label_width]:<{label_width}} "
                        f"{ctx.bar(value, peak, BAR_WIDTH):<{BAR_WIDTH}} "
                        f"{formatter(value):>{value_width}}", label_role))
    return out


def capture_card(ctx) -> List[Line]:
    """Where the packets are coming from and how the buffer is holding up."""
    session, stats = ctx.session, ctx.stats
    if session is None:
        return [Line("no session", "dim")]
    capture = session.capture
    if capture.error:
        state, role = "error", "danger"
    elif capture.paused:
        state, role = "paused", "warn"
    elif capture.finished:
        state, role = "file replayed", "dim"
    elif capture.running:
        state, role = "live", "ok"
    else:
        state, role = "stopped", "warn"
    # The basename, like the title bar: a pcap path is longer than any card.
    source = os.path.basename(session.pcap_path) or session.iface or "any"
    lines = [ctx.pair("source", source, "accent"),
             ctx.pair("state", state, role),
             ctx.pair("uptime", ctx.duration(stats.elapsed), "dim"),
             ctx.pair("packets", f"{stats.total_packets:,}"),
             ctx.pair("volume", ctx.bytes(stats.total_bytes))]
    if session.bpf:
        lines.append(ctx.pair("bpf", session.bpf, "dim"))
    if stats.dropped:
        lines.append(ctx.pair("rotated out", f"{stats.dropped:,}", "warn"))
    return lines


def throughput_card(ctx) -> List[Line]:
    """Packets and bytes per second, as two sparklines over the last minutes."""
    stats = ctx.stats
    history = stats.history[-(ctx.width - 2):]
    return [
        Line(ctx.spark([point[1] for point in history]), "spark"),
        Line(f"{stats.pps:>7.0f} pkt/s   peak {stats.peak_pps:,}", "dim"),
        Line(""),
        Line(ctx.spark([point[2] for point in history]), "bar"),
        Line(f"{ctx.bytes(stats.bps):>7}/s", "dim"),
    ]


def protocol_card(ctx) -> List[Line]:
    """The protocol mix by packet count."""
    rows = ctx.stats.proto_packets[:6]
    if not rows:
        return [Line("nothing captured yet", "dim")]
    total = max(1, sum(count for _, count in rows))
    peak = max(count for _, count in rows)
    label_width = max(6, ctx.width - BAR_WIDTH - 9)
    return [Line(f"{proto[:label_width]:<{label_width}} "
                 f"{ctx.bar(count, peak, BAR_WIDTH):<{BAR_WIDTH}} "
                 f"{count / total * 100:4.0f}%")
            for proto, count in rows]


def talkers_card(ctx) -> List[Line]:
    """Who is sending the most, by volume."""
    rows = ctx.stats.talkers_sent[:6]
    if not rows:
        return [Line("no traffic yet", "dim")]
    return _bars(ctx, rows, ctx.bytes)


def services_card(ctx) -> List[Line]:
    """The busiest destination ports, named where NetSour knows them."""
    rows = ctx.stats.ports[:6]
    if not rows:
        return [Line("no ports seen yet", "dim")]
    named = [(f"{port} {service_name(port)}".strip(), count)
             for port, count in rows]
    return _bars(ctx, named, lambda count: f"{count:,}", "accent")


def alerts_card(ctx) -> List[Line]:
    """Severity counts, then the newest findings."""
    session = ctx.session
    if session is None:
        return [Line("no session", "dim")]
    counts = session.alerts.counts()
    header = "  ".join(f"{level[:4]} {counts.get(level, 0)}"
                       for level in ("high", "medium", "low", "info"))
    role = "danger" if counts.get("high") else (
        "warn" if counts.get("medium") else "dim")
    lines = [Line(header, role)]
    recent = ctx.recent_alerts(4)
    if not recent:
        lines.append(Line("nothing flagged", "dim"))
    for alert in recent:
        lines.append(Line(f"{alert.when} {alert.title}"[:ctx.width],
                          {"high": "danger", "medium": "warn"}
                          .get(alert.severity, "dim")))
    return lines


def flows_card(ctx) -> List[Line]:
    """The busiest conversations right now."""
    flows = sorted(ctx.flows, key=lambda flow: -flow.bytes)[:5]
    if not flows:
        return [Line("no conversations yet", "dim")]
    rows = [(f"{flow.endpoint_a()} {flow.endpoint_b()}", flow.bytes)
            for flow in flows]
    return _bars(ctx, rows, ctx.bytes)


def names_card(ctx) -> List[Line]:
    """Hostnames the traffic asked about — SNI, DNS questions, HTTP Host."""
    rows = ctx.stats.hostnames[:6]
    if not rows:
        return [Line("no names observed", "dim")]
    return _bars(ctx, rows, lambda count: f"{count:,}", "accent")


BUILTINS = [
    ("capture", "Capture", capture_card, 10),
    ("throughput", "Throughput", throughput_card, 20),
    ("protocols", "Protocol mix", protocol_card, 30),
    ("alerts", "Alerts", alerts_card, 40),
    ("talkers", "Top talkers", talkers_card, 50),
    ("services", "Services", services_card, 60),
    ("flows", "Busiest flows", flows_card, 70),
    ("names", "Names asked for", names_card, 80),
]


def builtin_panels() -> List[PanelSpec]:
    """Fresh PanelSpecs for the built-in cards, in board order."""
    return [PanelSpec(key=key, title=title, render=render, source="built-in",
                      order=order) for key, title, render, order in BUILTINS]
