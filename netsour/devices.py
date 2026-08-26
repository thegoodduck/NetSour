"""Identify the physical devices on the local network.

A device is assembled from every signal the capture already carries - ARP
replies, MAC vendor, reverse DNS, mDNS names, the ports it speaks, its IP TTL -
and classified into a kind so it can be named as something recognisable rather
than a row of numbers.

Every classification is a heuristic and says so: `Device.confidence` reports how
much evidence stands behind the guess, and `Device.evidence` lists what that
evidence actually was.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Set

from .enrich import is_private
from .stats import human_duration

# ---- device kinds ---------------------------------------------------------

ROUTER, PHONE, COMPUTER, PRINTER, TV, IOT = (
    "router", "phone", "computer", "printer", "tv", "iot")
NAS, CAMERA, CONSOLE, VM, SPEAKER, UNKNOWN = (
    "nas", "camera", "console", "vm", "speaker", "unknown")

KIND_LABELS = {
    ROUTER: "Router / Gateway", PHONE: "Phone / Tablet",
    COMPUTER: "Computer", PRINTER: "Printer", TV: "TV / Streaming",
    IOT: "Smart device", NAS: "NAS / Server", CAMERA: "Camera",
    CONSOLE: "Game console", VM: "Virtual machine", SPEAKER: "Speaker",
    UNKNOWN: "Unidentified",
}

# Three-line icons, drawn beside the identity pane.
ICONS_UNICODE = {
    ROUTER:   ("╭──────╮", "│ ((•))│", "╰─┬┬┬┬─╯"),
    PHONE:    (" ╭────╮ ", " │▒▒▒▒│ ", " ╰─▭──╯ "),
    COMPUTER: ("╭──────╮", "│▒▒▒▒▒▒│", "╰──▬▬──╯"),
    PRINTER:  ("╭──────╮", "│▤▤▤▤▤▤│", "╰─┤▬▬├─╯"),
    TV:       ("╭──────╮", "│▒▒▒▒▒▒│", "╰──┬┬──╯"),
    IOT:      ("  ╭──╮  ", " ╭┤••├╮ ", " ╰────╯ "),
    NAS:      ("╭──────╮", "│▪▪▪▪▪▪│", "│▪▪▪▪▪▪│"),
    CAMERA:   (" ╭────╮ ", "╭┤ (◉) ├", " ╰──┬─╯ "),
    CONSOLE:  ("╭──────╮", "│ ⊕  ⊙ │", "╰──────╯"),
    VM:       ("╭┄┄┄┄┄┄╮", "┊▒▒▒▒▒▒┊", "╰┄┄▬▬┄┄╯"),
    SPEAKER:  (" ╭────╮ ", " │ (◎) │", " ╰────╯ "),
    UNKNOWN:  ("╭──────╮", "│  ??  │", "╰──────╯"),
}

ICONS_ASCII = {
    ROUTER:   ("+------+", "| ((*))|", "+-||||-+"),
    PHONE:    (" +----+ ", " |####| ", " +--__-+ "),
    COMPUTER: ("+------+", "|######|", "+--====+"),
    PRINTER:  ("+------+", "|======|", "+-[==]-+"),
    TV:       ("+------+", "|######|", "+--||--+"),
    IOT:      ("  +--+  ", " +|..|+ ", " +----+ "),
    NAS:      ("+------+", "|::::::|", "|::::::|"),
    CAMERA:   (" +----+ ", "+| (O) |", " +--|-+ "),
    CONSOLE:  ("+------+", "| (+) o|", "+------+"),
    VM:       ("+......+", ":######:", "+..====+"),
    SPEAKER:  (" +----+ ", " | (O) |", " +----+ "),
    UNKNOWN:  ("+------+", "|  ??  |", "+------+"),
}

ICON_WIDTH = 8

# How long a device may stay quiet before it is treated as gone. A host that
# answered an ARP sweep or sent a packet within this window is on the segment
# now; anything older is a memory of one, and the view used to present the two
# identically.
IDLE_SECONDS = 300.0

# ---- classification evidence ---------------------------------------------

# MAC vendor substring -> kind. Checked case-insensitively, first match wins.
VENDOR_KINDS = [
    (("tp-link", "netgear", "ubiquiti", "mikrotik", "d-link", "zyxel",
      "asustek comp", "cisco", "juniper", "aruba", "ruckus", "fritz",
      "avm gmbh", "technicolor", "sagemcom", "arris", "actiontec"), ROUTER),
    (("apple", "samsung electro", "xiaomi", "oneplus", "huawei", "oppo",
      "vivo mobile", "motorola mobility", "google, inc", "nothing tech"), PHONE),
    (("hewlett", "canon", "brother", "epson", "lexmark", "kyocera", "ricoh",
      "xerox", "zebra tech"), PRINTER),
    (("roku", "amazon tech", "vizio", "tcl ", "hisense", "sony corp",
      "lg electronics", "panasonic"), TV),
    (("sonos", "bose", "harman", "denon", "yamaha"), SPEAKER),
    (("synology", "qnap", "western digital", "netapp", "buffalo.inc"), NAS),
    (("hikvision", "dahua", "axis comm", "reolink", "amcrest", "ubnt camera",
      "wyze"), CAMERA),
    (("nintendo", "sony interactive", "microsoft corp"), CONSOLE),
    (("espressif", "tuya", "shelly", "sonoff", "itead", "tasmota",
      "philips lighting", "signify", "ikea of sweden", "nest labs",
      "ecobee", "wiz connected"), IOT),
    (("raspberry pi", "intel corp", "dell inc", "micro-star", "gigabyte",
      "asrock", "lenovo", "acer inc", "toshiba", "framework comp"), COMPUTER),
    (("qemu", "vmware", "virtualbox", "oracle virt", "xensource", "parallels",
      "microsoft hyper"), VM),
]

# Open/served port -> kind. Only ports a device *serves* count as evidence.
PORT_KINDS = {
    9100: PRINTER, 631: PRINTER, 515: PRINTER,
    554: CAMERA, 8554: CAMERA,
    8009: TV, 8008: TV, 7000: TV, 32400: NAS,
    445: COMPUTER, 139: COMPUTER, 3389: COMPUTER,
    22: NAS, 548: NAS, 2049: NAS, 5000: NAS,
    1400: SPEAKER, 8060: TV,
}

# DNS-SD service type -> kind. A device advertising `_googlecast._tcp` is a
# streaming target; one advertising `_ipp._tcp` is a printer. These are strong,
# self-declared signals - far better than guessing from a vendor OUI.
SERVICE_KINDS = {
    "_googlecast": TV, "_airplay": TV, "_raop": SPEAKER, "_roku": TV,
    "_androidtvremote": TV, "_amzn-wplay": TV, "_spotify-connect": SPEAKER,
    "_sonos": SPEAKER, "_ipp": PRINTER, "_ipps": PRINTER, "_pdl-datastream":
    PRINTER, "_printer": PRINTER, "_scanner": PRINTER, "_uscan": PRINTER,
    "_smb": NAS, "_afpovertcp": NAS, "_nfs": NAS, "_adisk": NAS,
    "_daap": NAS, "_plexmediasvr": NAS, "_rtsp": CAMERA, "_axis-video": CAMERA,
    "_homekit": IOT, "_hap": IOT, "_hue": IOT, "_matter": IOT, "_esphomelib": IOT,
    "_workstation": COMPUTER, "_ssh": COMPUTER, "_sftp-ssh": COMPUTER,
    "_companion-link": PHONE, "_apple-mobdev2": PHONE,
    "_nvstream": CONSOLE, "_xbox": CONSOLE,
}

# Substrings in a hostname or mDNS name -> kind.
NAME_KINDS = [
    (("iphone", "ipad", "android", "galaxy", "pixel", "phone", "oneplus"), PHONE),
    (("router", "gateway", "gw", "openwrt", "unifi", "fritz", "livebox"), ROUTER),
    (("printer", "envy", "officejet", "laserjet", "brother", "epson"), PRINTER),
    (("tv", "roku", "chromecast", "firetv", "shield", "appletv", "bravia"), TV),
    (("camera", "cam", "doorbell", "ipcam"), CAMERA),
    (("nas", "synology", "diskstation", "truenas", "unraid", "server"), NAS),
    (("echo", "alexa", "sonos", "homepod", "speaker"), SPEAKER),
    (("macbook", "imac", "desktop", "laptop", "-pc", "thinkpad", "workstation"),
     COMPUTER),
    (("switch", "playstation", "ps5", "ps4", "xbox"), CONSOLE),
    (("esp", "shelly", "tasmota", "sonoff", "bulb", "plug", "sensor",
      "thermostat"), IOT),
]

# Initial TTL -> likely OS family. Devices decrement it in transit, so only the
# nearest round number above the observed value is meaningful.
TTL_HINTS = ((64, "Linux / Android / macOS"), (128, "Windows"),
             (255, "network appliance / BSD"))


def ttl_os_hint(ttl: int) -> str:
    """Best-guess OS family from an observed TTL, or "" when implausible."""
    if not ttl:
        return ""
    for initial, name in TTL_HINTS:
        if 0 < ttl <= initial and initial - ttl <= 24:
            return name
    return ""


@dataclass
class Device:
    """One host on the local network, with everything known about it."""

    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    kind: str = UNKNOWN
    os_hint: str = ""
    services: Set[int] = field(default_factory=set)
    advertised: Set[str] = field(default_factory=set)   # DNS-SD service types
    evidence: List[str] = field(default_factory=list)
    packets: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    is_gateway: bool = False
    responded_to_arp: bool = False
    arp_ts: float = 0.0          # when the ARP sweep that found it ran
    observed_at: float = 0.0     # the capture clock when this list was built

    @property
    def label(self) -> str:
        return KIND_LABELS.get(self.kind, KIND_LABELS[UNKNOWN])

    @property
    def bytes_total(self) -> int:
        return self.bytes_sent + self.bytes_recv

    @property
    def confidence(self) -> str:
        """How much independent evidence backs the kind."""
        if self.kind == UNKNOWN:
            return "unknown"
        if len(self.evidence) >= 2:
            return "confirmed"
        return "likely"

    @property
    def last_seen(self) -> float:
        """Newest evidence that this device exists, on the capture clock."""
        return max(self.last_ts, self.arp_ts)

    @property
    def idle(self) -> float:
        """Seconds since that evidence, or 0.0 when there is none to date."""
        if not self.last_seen or not self.observed_at:
            return 0.0
        return max(0.0, self.observed_at - self.last_seen)

    @property
    def status(self) -> str:
        """"online", "offline", or "unknown" when nothing is timestamped.

        Measured against the capture clock - the newest packet in the capture,
        not the wall clock - so a pcap replay reports what was true during the
        capture rather than marking every host offline.
        """
        if not self.last_seen:
            return "unknown"
        return "offline" if self.idle > IDLE_SECONDS else "online"

    @property
    def online(self) -> bool:
        return self.status == "online"

    @property
    def presence(self) -> str:
        """Whether the device is known to be on the segment right now."""
        if self.status == "offline":
            return f"offline · last seen {human_duration(self.idle)} ago"
        if self.responded_to_arp:
            return "ARP reply"
        if self.mac:
            return "seen on the wire"
        return "address only"

    def sort_key(self) -> tuple:
        try:
            octets = tuple(int(part) for part in self.ip.split("."))
        except ValueError:
            octets = (999,)
        return (0 if self.is_gateway else 1,
                1 if self.status == "offline" else 0, octets)


class DeviceRegistry:
    """Builds the device list from a capture session's accumulated state."""

    def __init__(self, local_prefix: str = "", gateway: str = ""):
        self.local_prefix = local_prefix
        self.gateway = gateway

    # ---- construction -----------------------------------------------------

    def build(self, records, stats, flows, recon_hosts, vendors, rdns,
              nmap=None, recon_time: float = 0.0) -> List[Device]:
        """Assemble every local device. Call under the session lock."""
        devices: Dict[str, Device] = {}

        for ip, mac in recon_hosts or ():
            if not self._is_local(ip):
                continue
            device = self._device(devices, ip)
            device.mac = mac or device.mac
            device.responded_to_arp = True
            device.arp_ts = recon_time

        # A source MAC is a frame the host actually put on the wire.
        for ip, mac in (stats.macs or {}).items():
            if self._is_local(ip):
                self._device(devices, ip).mac = mac or ""

        for ip in stats.talkers_sent:
            if self._is_local(ip):
                self._device(devices, ip)

        # Receiving is not evidence of existing. An ARP sweep addresses all 254
        # hosts of the /24 whether or not anything is there, so counting every
        # destination invented a device per empty address. Bytes received are
        # filled in only for hosts that proved themselves some other way.
        for device in devices.values():
            device.bytes_sent = stats.talkers_sent.get(device.ip, 0)
            device.bytes_recv = stats.talkers_recv.get(device.ip, 0)

        for record in records:
            for address in (record.src, record.dst):
                if address in devices:
                    device = devices[address]
                    device.packets += 1
                    device.last_ts = max(device.last_ts, record.ts)
                    if not device.first_ts:
                        device.first_ts = record.ts
            sender = devices.get(record.src)
            if sender is None:
                continue
            if record.ttl:
                sender.os_hint = ttl_os_hint(record.ttl) or sender.os_hint
            # Only a name the sender claims for *itself* may name the device.
            # `record.hostname` is whatever the packet was about - a DNS answer
            # from your router would otherwise label the router with the site
            # someone looked up.
            if record.device_name:
                sender.hostname = sender.hostname or record.device_name
            if record.services:
                sender.advertised.update(record.services)

        self._add_services(devices, flows)

        # The capture clock: the newest thing this session has observed. Idle
        # times are measured from here rather than time.time() so an offline
        # replay judges presence by the capture's own timeline.
        observed_at = max([recon_time]
                          + [device.last_ts for device in devices.values()])

        for device in devices.values():
            device.observed_at = observed_at
            device.vendor = vendors.get(device.mac) if device.mac else ""
            device.hostname = device.hostname or (rdns.get(device.ip) or "")
            device.is_gateway = (device.ip == self.gateway)
            if nmap is not None:
                self._add_nmap_services(device, nmap)
            classify(device)

        return sorted(devices.values(), key=Device.sort_key)

    def _device(self, devices: Dict[str, Device], ip: str) -> Device:
        if ip not in devices:
            devices[ip] = Device(ip=ip)
        return devices[ip]

    def _is_local(self, ip: str) -> bool:
        """A device is a real host on *this* segment.

        Private-address membership is not enough: multicast groups, the subnet
        broadcast and the network address all look private but are not things
        you can point at in a room.
        """
        if not ip or not is_private(ip):
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if address.version != 4:
            return False
        if (address.is_multicast or address.is_loopback
                or address.is_unspecified or address.is_link_local):
            return False
        last = int(ip.rsplit(".", 1)[1])
        if last in (0, 255):                 # network and broadcast of a /24
            return False
        if self.local_prefix:
            return ip.startswith(self.local_prefix)
        return True

    @staticmethod
    def _add_services(devices: Dict[str, Device], flows) -> None:
        """A port counts as a service only on the side that was connected to."""
        for flow in (flows.flows.values() if flows else ()):
            for ip, port, peer_packets in ((flow.b_ip, flow.b_port,
                                            flow.packets_ab),
                                           (flow.a_ip, flow.a_port,
                                            flow.packets_ba)):
                if ip in devices and port and port < 49152 and peer_packets:
                    devices[ip].services.add(port)

    @staticmethod
    def _add_nmap_services(device: Device, nmap) -> None:
        entry = nmap.results.get(device.ip)
        if not entry:
            return
        for proto in ("tcp", "udp"):
            for port, info in (entry.get("data", {}).get(proto) or {}).items():
                if info.get("state") == "open":
                    device.services.add(int(port))


# How much each kind of signal is worth. A MAC OUI is the weakest: a
# manufacturer makes phones, TVs and appliances alike, so anything the device
# says about itself outranks a guess from who built it.
WEIGHT_GATEWAY = 6
WEIGHT_SERVICE = 4       # DNS-SD advertisement - self-declared and specific
WEIGHT_HOSTNAME = 3      # a name the device claims for itself
WEIGHT_PORT = 3          # a port it actually serves
WEIGHT_VENDOR = 1        # the OUI of whoever made the network chip


def classify(device: Device) -> None:
    """Decide a device's kind by weighing every signal, recording the evidence.

    Signals vote with a weight rather than a plain count, so one self-declared
    service beats one vendor guess. `Device.evidence` lists everything that
    contributed, heaviest first, so the reasoning is always inspectable.
    """
    device.evidence = []
    scores: Dict[str, int] = {}
    reasons: List[tuple] = []

    def vote(kind: str, weight: int, reason: str) -> None:
        scores[kind] = scores.get(kind, 0) + weight
        reasons.append((weight, reason))

    if device.is_gateway:
        vote(ROUTER, WEIGHT_GATEWAY, "default gateway for this network")

    for service in sorted(device.advertised):
        kind = SERVICE_KINDS.get(service)
        if kind:
            vote(kind, WEIGHT_SERVICE, f"advertises {service}")
            break

    name = (device.hostname or "").lower()
    if name:
        for needles, kind in NAME_KINDS:
            if any(needle in name for needle in needles):
                vote(kind, WEIGHT_HOSTNAME, f"hostname {device.hostname}")
                break

    for port in sorted(device.services):
        kind = PORT_KINDS.get(port)
        if kind:
            vote(kind, WEIGHT_PORT, f"serves port {port}")
            break

    vendor = (device.vendor or "").lower()
    if vendor:
        for needles, kind in VENDOR_KINDS:
            if any(needle.strip() in vendor for needle in needles):
                vote(kind, WEIGHT_VENDOR, f"MAC vendor {device.vendor}")
                break

    device.evidence = [reason for _, reason
                       in sorted(reasons, key=lambda item: -item[0])]

    if scores:
        device.kind = max(scores, key=lambda kind: scores[kind])
    elif device.services or device.advertised:
        device.kind = COMPUTER
        device.evidence.append("serves network ports")
    else:
        device.kind = UNKNOWN


def icon_for(kind: str, unicode_ok: bool = True) -> tuple:
    icons = ICONS_UNICODE if unicode_ok else ICONS_ASCII
    return icons.get(kind, icons[UNKNOWN])


def describe(device: Device) -> str:
    """One-line description of what a device is."""
    parts = [device.label]
    if device.vendor:
        parts.append(device.vendor.split(",")[0].split(" Inc")[0].strip())
    elif device.os_hint:
        parts.append(device.os_hint)
    return " · ".join(parts)
