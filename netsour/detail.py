"""Build the expandable protocol tree shown in the detail pane.

Returns plain (indent, text, role) tuples so the renderer stays dumb and the
tree can be unit-tested without a terminal.
"""

from __future__ import annotations

from typing import List, Tuple

from .dissect import PacketRecord, tcp_flag_str
from .services import port_label

Line = Tuple[int, str, str]          # (indent level, text, palette role)

# Fields worth surfacing per layer, in the order an analyst reads them.
LAYER_FIELDS = {
    "Ethernet": ["src", "dst", "type"],
    "ARP": ["op", "hwsrc", "psrc", "hwdst", "pdst"],
    "IP": ["version", "ihl", "tos", "len", "id", "flags", "frag", "ttl",
           "proto", "chksum", "src", "dst"],
    "IPv6": ["version", "tc", "fl", "plen", "nh", "hlim", "src", "dst"],
    "TCP": ["sport", "dport", "seq", "ack", "dataofs", "flags", "window",
            "chksum", "urgptr"],
    "UDP": ["sport", "dport", "len", "chksum"],
    "ICMP": ["type", "code", "chksum", "id", "seq"],
    "DNS": ["id", "qr", "opcode", "rcode", "qdcount", "ancount", "nscount",
            "arcount"],
}


def _layer_name(layer) -> str:
    name = layer.__class__.__name__
    return {"Ether": "Ethernet", "IPv6": "IPv6"}.get(name, name)


def _format_value(layer, field: str):
    try:
        value = getattr(layer, field)
    except Exception:
        return None
    try:
        pretty = layer.get_field(field).i2repr(layer, value)
    except Exception:
        pretty = repr(value)
    return pretty.strip("'")


def packet_tree(rec: PacketRecord, vendors=None, rdns=None) -> List[Line]:
    """A Wireshark-style dissection of one packet."""
    lines: List[Line] = []
    packet = rec.packet
    if packet is None:
        return [(0, "No packet data retained for this record.", "dim")]

    lines.append((0, "Frame", "header"))
    lines.append((1, f"captured   {rec.length} bytes", "base"))
    lines.append((1, f"number     #{rec.index}", "base"))
    lines.append((1, f"epoch      {rec.ts:.6f}", "dim"))
    if rec.tags:
        lines.append((1, f"flagged    {', '.join(rec.tags)}", "warn"))

    layer = packet
    while layer is not None:
        name = _layer_name(layer)
        if name in ("Raw", "Padding", "NoPayload"):
            break
        lines.append((0, name, "header"))
        fields = LAYER_FIELDS.get(name)
        if fields is None:
            fields = [f.name for f in getattr(layer, "fields_desc", [])][:14]
        for field in fields:
            value = _format_value(layer, field)
            if value is None:
                continue
            role = "base"
            if name == "TCP" and field == "flags":
                value = f"{value}  [{tcp_flag_str(int(layer.flags))}]"
                role = "accent"
            elif field in ("sport", "dport"):
                proto = "udp" if name == "UDP" else "tcp"
                value = port_label(int(value) if str(value).isdigit()
                                   else getattr(layer, field), proto)
            lines.append((1, f"{field:<10} {value}", role))

        extra = _layer_extras(name, layer, vendors, rdns, rec)
        lines.extend(extra)
        layer = layer.payload if layer.payload else None

    payload = _raw_payload(packet)
    if payload:
        lines.append((0, f"Payload  ({len(payload)} bytes)", "header"))
        preview = payload[:400].decode("latin-1", "replace")
        printable = "".join(c if 32 <= ord(c) < 127 or c in "\r\n\t" else "."
                            for c in preview)
        for row in printable.replace("\r\n", "\n").split("\n")[:12]:
            lines.append((1, row[:200], "hex_ascii"))
    return lines


def _layer_extras(name: str, layer, vendors, rdns, rec: PacketRecord) -> List[Line]:
    """Enrichment lines appended under a layer: vendor, rDNS, resolved names."""
    out: List[Line] = []
    if name in ("Ethernet", "ARP") and vendors is not None:
        for field, label in (("src", "src vendor"), ("dst", "dst vendor"),
                             ("hwsrc", "src vendor"), ("hwdst", "dst vendor")):
            mac = getattr(layer, field, None)
            if isinstance(mac, str) and ":" in mac:
                vendor = vendors.get(mac)
                if vendor:
                    out.append((1, f"{label:<10} {vendor}", "dim"))
    if name in ("IP", "IPv6") and rdns is not None:
        for field, label in (("src", "src name"), ("dst", "dst name")):
            host = rdns.get(getattr(layer, field, ""))
            if host:
                out.append((1, f"{label:<10} {host}", "dim"))
    if name == "DNS" and rec.hostname:
        out.append((1, f"{'name':<10} {rec.hostname}", "accent"))
    return out


def _raw_payload(packet) -> bytes:
    try:
        from scapy.packet import Raw

        if Raw in packet:
            return bytes(packet[Raw].load)
    except Exception:
        pass
    return b""


def packet_bytes(rec: PacketRecord) -> bytes:
    """Full on-the-wire bytes of a record, for the hex pane."""
    if rec.packet is None:
        return b""
    try:
        return bytes(rec.packet)
    except Exception:
        return b""


def follow_stream(records, target: PacketRecord, limit: int = 200
                  ) -> List[Tuple[str, bytes]]:
    """Reassemble the payload of every packet in `target`'s conversation.

    Returns (direction, data) pairs where direction is "→" for A-to-B traffic
    and "←" for the reply path. Ordering is capture order, not sequence order -
    good enough to read a protocol exchange, not a substitute for full TCP
    reassembly.
    """
    key = target.key
    out: List[Tuple[str, bytes]] = []
    origin = (target.src, target.sport)
    for rec in records:
        if rec.key != key:
            continue
        data = _raw_payload(rec.packet)
        if not data:
            continue
        direction = "→" if (rec.src, rec.sport) == origin else "←"
        out.append((direction, data))
        if len(out) >= limit:
            break
    return out
