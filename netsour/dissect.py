"""Turn a raw scapy packet into a flat, render-ready record.

Dissection happens once, on the capture side, so the UI thread never touches a
scapy object to draw a row. Everything the packet list needs lives on
:class:`PacketRecord` as plain strings and ints.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Optional

from scapy.layers.dns import DNSQR

from .services import CLEARTEXT_PORTS, port_label, service_name

TCP_FLAG_ORDER = [
    (0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
    (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C"),
]

ICMP_TYPES = {
    0: "echo-reply", 3: "dest-unreachable", 4: "source-quench",
    5: "redirect", 8: "echo-request", 9: "router-advert",
    10: "router-solicit", 11: "ttl-exceeded", 12: "param-problem",
    13: "timestamp", 14: "timestamp-reply",
}

DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}


def _dns_qtypes() -> dict:
    """Pull the qtype enum out of scapy's field definition, once."""
    for fld in DNSQR.fields_desc:
        if fld.name == "qtype":
            return dict(getattr(fld, "i2s", {}) or {})
    return {}


DNS_QTYPES = _dns_qtypes()


_NAME_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "0123456789-._*")


def decode_name(raw) -> str:
    """Decode a DNS/TLS wire name to text without the trailing root dot.

    Returns "" for anything that is not plausibly a hostname: random UDP
    payloads regularly parse as DNS, and treating their bytes as a name feeds
    garbage to the display and to the tunnelling detector.
    """
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("ascii")
        except UnicodeDecodeError:
            return ""
    name = str(raw).rstrip(".")
    if not name or len(name) > 253 or any(c not in _NAME_OK for c in name):
        return ""
    return name

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS",
                b"PATCH", b"TRACE", b"CONNECT")

# How much of each payload stays searchable. Bounded so a full buffer of
# jumbo frames cannot balloon memory.
PAYLOAD_SEARCH_BYTES = 256


@dataclass
class PacketRecord:
    """One captured packet, pre-dissected for display."""

    index: int
    ts: float
    length: int
    proto: str = "?"
    src: str = ""
    dst: str = ""
    sport: Optional[int] = None
    dport: Optional[int] = None
    info: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    flags: str = ""
    ttl: int = 0                # IP TTL / IPv6 hop limit, for OS fingerprinting
    hostname: str = ""          # the host this packet is ABOUT: SNI, DNS
                                # question, HTTP Host. A target, never the sender.
    device_name: str = ""       # a name the SENDER claims for ITSELF: DHCP
                                # option 12, or an mDNS A record pointing at its
                                # own address. Safe to label a device with.
    services: tuple = ()        # DNS-SD service types the sender advertised
    payload_len: int = 0
    payload_text: str = ""      # payload prefix, original case, for search
                                # and for quoting what a detector matched
    packet: Any = None          # original scapy packet, kept for detail views
    tags: list = field(default_factory=list)   # e.g. ["cleartext", "syn"]

    @property
    def key(self) -> tuple:
        """Bidirectional conversation key (endpoints sorted so A->B == B->A)."""
        a = (self.src, self.sport or 0)
        b = (self.dst, self.dport or 0)
        lo, hi = (a, b) if a <= b else (b, a)
        return (self.proto_base, lo, hi)

    @property
    def proto_base(self) -> str:
        """Transport-level protocol, ignoring the application label."""
        for base in ("TCP", "UDP", "ICMP", "ARP"):
            if self.proto == base or self.proto.startswith(base + "/"):
                return base
        return self.proto

    def matches(self, needle: str) -> bool:
        """Case-insensitive substring match across the fields a user searches."""
        needle = needle.lower()
        return (
            needle in self.src.lower()
            or needle in self.dst.lower()
            or needle in self.proto.lower()
            or needle in self.info.lower()
            or needle in self.hostname.lower()
            or needle in self.payload_text.lower()
            or needle == str(self.sport)
            or needle == str(self.dport)
        )


def tcp_flag_str(flags: int) -> str:
    """Render TCP flags as the conventional letter set, e.g. `SA` or `PA`."""
    return "".join(letter for bit, letter in TCP_FLAG_ORDER if flags & bit) or "-"


def layer_map(packet) -> dict:
    """Walk the layer chain once, returning {layer name: layer}.

    Scapy's `Layer in packet` and `packet[Layer]` each re-walk the chain, and a
    full dissection asks a dozen such questions. One traversal answers them all,
    which roughly halves the per-packet cost on a busy link.
    """
    found: dict = {}
    layer = packet
    while layer is not None:
        name = layer.__class__.__name__
        if name == "NoPayload":
            break
        if name not in found:
            found[name] = layer
        layer = layer.payload
    return found


def wire_length(packet) -> int:
    """Length of the frame as captured, without rebuilding it.

    `len(packet)` re-serialises every layer; sniffed packets already carry their
    original bytes, so prefer those.
    """
    original = getattr(packet, "original", None)
    if original:
        return len(original)
    wirelen = getattr(packet, "wirelen", None)
    if wirelen:
        return int(wirelen)
    try:
        return len(packet)
    except Exception:
        return 0


def _payload_bytes(layers: dict) -> bytes:
    raw = layers.get("Raw")
    if raw is None:
        return b""
    try:
        return bytes(raw.load)
    except Exception:
        return b""


def parse_tls_sni(data: bytes) -> str:
    """Extract the SNI hostname from a TLS ClientHello, or "" if absent.

    Hand-rolled rather than pulled from scapy's TLS layer, which is optional and
    heavy; a ClientHello is a fixed walk of length-prefixed blocks.
    """
    try:
        if len(data) < 45 or data[0] != 0x16:       # not a TLS handshake record
            return ""
        if data[5] != 0x01:                          # not a ClientHello
            return ""
        pos = 43                                     # skip record+hs hdr, ver, random
        sid_len = data[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2 + cs_len
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > len(data):
            return ""
        ext_total = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2
        end = min(len(data), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", data[pos:pos + 4])
            pos += 4
            if ext_type == 0x0000:                   # server_name
                # list_len(2) entry_type(1) name_len(2) name
                if pos + 5 > len(data):
                    return ""
                name_len = struct.unpack("!H", data[pos + 3:pos + 5])[0]
                return decode_name(data[pos + 5:pos + 5 + name_len])
            pos += ext_len
    except Exception:
        return ""
    return ""


def parse_http(data: bytes) -> tuple[str, str]:
    """Return (summary, host) for an HTTP request/response, or ("", "")."""
    try:
        if not (data.startswith(HTTP_METHODS) or data.startswith(b"HTTP/")):
            return "", ""
        head = data[:2048].split(b"\r\n\r\n", 1)[0]
        lines = head.split(b"\r\n")
        first = lines[0].decode("latin-1", "replace")[:120]
        host = ""
        for line in lines[1:]:
            if line[:5].lower() == b"host:":
                host = line[5:].strip().decode("latin-1", "replace")
                break
        return first, host
    except Exception:
        return "", ""


def dhcp_hostname(dhcp) -> str:
    """Option 12 from a DHCP message - a device naming itself to the server."""
    try:
        for option in dhcp.options:
            if isinstance(option, tuple) and option[0] == "hostname":
                value = option[1]
                if isinstance(value, bytes):
                    value = value.decode("utf-8", "replace")
                return decode_name(value)
    except Exception:
        pass
    return ""


def self_announcement(dns, src: str) -> str:
    """The sender's own hostname, if this DNS/mDNS answer points at itself.

    A device announcing over mDNS publishes an A record whose name is its own
    hostname and whose value is its own address. That equality is what makes
    the name trustworthy as an identity - unlike a resolver's answer, which
    names whatever someone else asked about.
    """
    try:
        if int(dns.qr) != 1 or not src:
            return ""
        for index in range(int(dns.ancount or 0)):
            record = dns.an[index]
            rdata = record.rdata
            if isinstance(rdata, bytes):
                rdata = rdata.decode("latin-1", "replace")
            if str(rdata) != src:
                continue
            name = decode_name(record.rrname)
            if not name or name.startswith("_") or "._tcp" in name \
                    or "._udp" in name:
                continue
            return name[:-6] if name.endswith(".local") else name
    except Exception:
        pass
    return ""


def advertised_services(dns) -> tuple:
    """DNS-SD service types named in this packet, e.g. `_googlecast._tcp`.

    These describe what the sender *offers*, which is strong evidence of what
    kind of device it is - but they are service identifiers, not hostnames.
    """
    found = []
    try:
        for section in (dns.qd, dns.an):
            if section is None:
                continue
            entries = section if isinstance(section, list) else [section]
            for entry in entries:
                for attribute in ("qname", "rrname"):
                    raw = getattr(entry, attribute, None)
                    if raw is None:
                        continue
                    name = decode_name(raw)
                    if "._tcp" in name or "._udp" in name:
                        service = name.split(".")[0] if name.startswith("_") \
                            else next((part for part in name.split(".")
                                       if part.startswith("_")), "")
                        if service and service not in found:
                            found.append(service)
    except Exception:
        pass
    return tuple(found[:6])


def _dns_info(dns) -> tuple[str, str]:
    """Summarise a DNS layer as (info, primary_name)."""
    name = ""
    try:
        if dns.qd is not None:
            qd = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
            name = decode_name(qd.qname)
            qtype = DNS_QTYPES.get(int(qd.qtype), str(qd.qtype))
        else:
            qtype = "?"
    except Exception:
        qtype = "?"
    if dns.qr == 0:
        return f"Query {qtype} {name}", name
    rcode = DNS_RCODES.get(int(dns.rcode), str(dns.rcode))
    answers = []
    try:
        for i in range(int(dns.ancount)):
            rr = dns.an[i]
            answers.append(decode_name(rr.rdata))
    except Exception:
        pass
    tail = " " + ",".join(answers[:3]) if answers else ""
    return f"Response {rcode} {name}{tail}", name


def dissect(packet, index: int, ts: float) -> PacketRecord:
    """Build a :class:`PacketRecord` from a scapy packet. Never raises."""
    rec = PacketRecord(index=index, ts=ts, length=wire_length(packet),
                       packet=packet)
    try:
        _dissect_into(packet, rec, layer_map(packet))
    except Exception as exc:                     # a malformed packet must not kill capture
        rec.proto = rec.proto or "?"
        rec.info = rec.info or f"<dissect error: {exc.__class__.__name__}>"
    rec.tags = list(dict.fromkeys(rec.tags))
    return rec


def _dissect_into(packet, rec: PacketRecord, layers: dict) -> None:
    ether = layers.get("Ether")
    if ether is not None:
        rec.src_mac = ether.src
        rec.dst_mac = ether.dst

    arp = layers.get("ARP")
    if arp is not None:
        rec.proto = "ARP"
        rec.src, rec.dst = arp.psrc, arp.pdst
        if arp.op == 1:
            rec.info = f"Who has {arp.pdst}?  Tell {arp.psrc}"
        elif arp.op == 2:
            rec.info = f"{arp.psrc} is at {arp.hwsrc}"
        else:
            rec.info = f"op={arp.op}"
        return

    ip = layers.get("IP")
    ip6 = layers.get("IPv6")
    if ip is not None:
        rec.src, rec.dst = ip.src, ip.dst
        rec.ttl = int(ip.ttl)
        rec.flags = f"ttl={ip.ttl}"
    elif ip6 is not None:
        rec.src, rec.dst = ip6.src, ip6.dst
        rec.ttl = int(ip6.hlim)
        rec.flags = f"hlim={ip6.hlim}"
    else:
        rec.proto = "Ether" if ether is not None else packet.__class__.__name__
        rec.src = rec.src or rec.src_mac
        rec.dst = rec.dst or rec.dst_mac
        rec.info = packet.summary()[:160]
        return

    payload = _payload_bytes(layers)
    rec.payload_len = len(payload)
    if payload:
        # A searchable prefix, so `/password` finds the packet that carries it.
        rec.payload_text = payload[:PAYLOAD_SEARCH_BYTES].decode(
            "latin-1", "replace")

    tcp = layers.get("TCP")
    if tcp is not None:
        rec.proto = "TCP"
        rec.sport, rec.dport = int(tcp.sport), int(tcp.dport)
        flags = tcp_flag_str(int(tcp.flags))
        rec.flags = flags
        _app_layer(layers, rec, payload, "tcp")
        if not rec.info:
            rec.info = (f"{port_label(rec.sport)} → {port_label(rec.dport)} "
                        f"[{flags}] seq={tcp.seq} win={tcp.window} len={len(payload)}")
        if flags == "S":
            rec.tags.append("syn")
        elif flags in ("R", "RA"):
            rec.tags.append("reset")
        if rec.dport in CLEARTEXT_PORTS and payload:
            rec.tags.append("cleartext")
        return

    udp = layers.get("UDP")
    if udp is not None:
        rec.proto = "UDP"
        rec.sport, rec.dport = int(udp.sport), int(udp.dport)
        dhcp = layers.get("DHCP")
        if dhcp is not None:
            rec.device_name = dhcp_hostname(dhcp)
        _app_layer(layers, rec, payload, "udp")
        if not rec.info:
            rec.info = (f"{port_label(rec.sport, 'udp')} → "
                        f"{port_label(rec.dport, 'udp')}  len={len(payload)}")
        return

    icmp = layers.get("ICMP")
    if icmp is not None:
        rec.proto = "ICMP"
        tname = ICMP_TYPES.get(int(icmp.type), f"type={icmp.type}")
        rec.info = f"{tname} id={icmp.id} seq={icmp.seq}"
        return

    rec.proto = f"IP/{ip.proto}" if ip is not None else "IPv6"
    rec.info = packet.summary()[:160]


def _app_layer(layers: dict, rec: PacketRecord, payload: bytes, l4: str) -> None:
    """Label the application protocol on top of TCP/UDP, if we recognise one."""
    sport, dport = rec.sport or 0, rec.dport or 0

    dns = layers.get("DNS")
    if dns is not None:
        info, name = _dns_info(dns)
        label = "MDNS" if 5353 in (sport, dport) else "DNS"
        rec.proto = f"{l4.upper()}/{label}"
        rec.info, rec.hostname = info, name
        rec.device_name = self_announcement(dns, rec.src)
        rec.services = advertised_services(dns)
        return

    if not payload:
        return

    if 443 in (sport, dport) or 8443 in (sport, dport):
        sni = parse_tls_sni(payload)
        rec.proto = f"{l4.upper()}/TLS"
        if sni:
            rec.hostname = sni
            rec.info = f"ClientHello SNI={sni}"
        elif payload[0] == 0x16:
            rec.info = "TLS handshake"
        else:
            rec.info = f"Application Data len={len(payload)}"
        return

    summary, host = parse_http(payload)
    if summary:
        rec.proto = f"{l4.upper()}/HTTP"
        rec.hostname = host
        rec.info = f"{summary}{'  Host: ' + host if host else ''}"
        rec.tags.append("cleartext")
        return

    name = service_name(dport, l4) or service_name(sport, l4)
    if name:
        rec.proto = f"{l4.upper()}/{name.upper()[:8]}"
