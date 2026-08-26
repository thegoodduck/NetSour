"""The capture session: the single source of truth the UI renders from.

Packets arrive on the capture thread, are dissected and folded into the flow
table, statistics and alert engine under one lock, then appended to a bounded
ring buffer. The display filter is applied incrementally as packets arrive and
rebuilt in full only when the filter itself changes, so the render loop never
does O(captured) work.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, List, Optional

from .capture import (CaptureEngine, default_gateway, local_prefix,
                      write_pcap)
from .devices import DeviceRegistry
from .dissect import PacketRecord, dissect
from .enrich import GeoIP, MacVendor, NmapScanner, ReverseDNS
from .flows import FlowTable
from .osint import OsintEngine
from .security import AlertEngine, Thresholds
from .social import SocialTracker
from .stats import Stats, StatsView

PROTOCOLS = ("TCP", "UDP", "ICMP", "ARP", "OTHER")

HOST_SORTS = ("traffic", "packets", "address")


@dataclass
class Derived:
    """One consistent view of the session, copied out under the lock.

    Everything the UI draws in a frame comes from here. Reading the live
    structures during a render is a race: the capture thread appends to the
    record deque, the flow dict and the alert list continuously, and iterating
    any of them mid-mutation raises RuntimeError.
    """

    packets: List[PacketRecord] = field(default_factory=list)
    flows: List = field(default_factory=list)
    alerts: List = field(default_factory=list)
    alert_counts: dict = field(default_factory=dict)
    hosts: List[dict] = field(default_factory=list)
    devices: List = field(default_factory=list)
    stats: StatsView = field(default_factory=StatsView)
    recon_hosts: List[tuple] = field(default_factory=list)
    recon_running: bool = False
    recon_error: str = ""
    recon_time: float = 0.0
    buffered: int = 0


@dataclass
class DisplayFilter:
    """What the packet list is allowed to show."""

    protocols: dict = field(
        default_factory=lambda: {name: True for name in PROTOCOLS})
    text: str = ""
    only_alerts: bool = False

    def active(self) -> bool:
        return (bool(self.text) or self.only_alerts
                or not all(self.protocols.values()))

    def describe(self) -> str:
        parts = []
        off = [name for name, on in self.protocols.items() if not on]
        if off:
            parts.append("no " + "/".join(off))
        if self.text:
            parts.append(f'"{self.text}"')
        if self.only_alerts:
            parts.append("flagged only")
        return " · ".join(parts) if parts else "none"

    def allows(self, rec: PacketRecord) -> bool:
        base = rec.proto_base if rec.proto_base in self.protocols else "OTHER"
        if not self.protocols.get(base, True):
            return False
        if self.only_alerts and not rec.tags:
            return False
        if self.text and not rec.matches(self.text):
            return False
        return True


class Session:
    """Owns capture state and every derived view of it."""

    def __init__(self, iface: str = "", bpf: str = "", pcap_path: str = "",
                 buffer_size: int = 20000, promisc: bool = True,
                 enable_rdns: bool = True, enable_geo: bool = True,
                 thresholds: Optional[Thresholds] = None):
        self.iface = iface
        self.bpf = bpf
        self.pcap_path = pcap_path
        self.buffer_size = buffer_size
        self.lock = threading.RLock()

        self.records: Deque[PacketRecord] = deque(maxlen=buffer_size)
        self.view: List[PacketRecord] = []
        self.filter = DisplayFilter()

        self.flows = FlowTable()
        self.stats = Stats()
        self.social = SocialTracker()
        self.alerts = AlertEngine(thresholds or Thresholds(),
                                  local_prefix=local_prefix(iface) if iface else "")
        self.rdns = ReverseDNS(enabled=enable_rdns)
        self.geo = GeoIP(enabled=enable_geo)
        self.vendors = MacVendor()
        self.nmap = NmapScanner()
        # OSINT stays available even with --no-geo: most of it is local
        # analysis or registry lookups. Only the geo source needs geo.
        self.osint = OsintEngine(geo=self.geo, rdns=self.rdns,
                                 social=self.social)

        self.recon_hosts: List[tuple] = []
        self.recon_error = ""
        self.recon_running = False
        self.recon_time = 0.0

        self._counter = 0
        self.devices = DeviceRegistry(local_prefix=local_prefix(iface) if iface
                                      else "", gateway=default_gateway(iface))
        self.capture = CaptureEngine(iface=iface, on_packet=self._on_packet,
                                     bpf=bpf, promisc=promisc, pcap_path=pcap_path)

    # ---- capture ----------------------------------------------------------

    def start(self) -> None:
        self.capture.start()

    def stop(self) -> None:
        self.capture.stop()

    def _on_packet(self, packet) -> None:
        ts = float(getattr(packet, "time", 0) or time.time())
        with self.lock:
            self._counter += 1
            rec = dissect(packet, self._counter, ts)
            if len(self.records) == self.records.maxlen:
                self.stats.dropped += 1
                dropped = self.records[0]
                if self.view and self.view[0] is dropped:
                    self.view.pop(0)
            self.records.append(rec)
            self.stats.add(rec)
            self.flows.add(rec)
            self.alerts.inspect(rec)
            self.social.inspect(rec)
            if self.filter.allows(rec):
                self.view.append(rec)

    # ---- display filter ---------------------------------------------------

    def rebuild_view(self) -> None:
        """Re-apply the display filter across the whole buffer."""
        with self.lock:
            self.view = [r for r in self.records if self.filter.allows(r)]

    def set_text_filter(self, text: str) -> None:
        self.filter.text = text.strip()
        self.rebuild_view()

    def toggle_protocol(self, proto: str) -> bool:
        state = not self.filter.protocols.get(proto, True)
        self.filter.protocols[proto] = state
        self.rebuild_view()
        return state

    def toggle_only_alerts(self) -> bool:
        self.filter.only_alerts = not self.filter.only_alerts
        self.rebuild_view()
        return self.filter.only_alerts

    def reset_filter(self) -> None:
        self.filter = DisplayFilter()
        self.rebuild_view()

    # ---- data access ------------------------------------------------------

    def snapshot(self) -> List[PacketRecord]:
        """A stable list of the currently visible packets for one render pass."""
        with self.lock:
            return list(self.view)

    def derive(self, flow_sort: str = "bytes", alert_sort: str = "time",
               host_sort: str = "traffic", want_flows: bool = False,
               want_alerts: bool = False, want_hosts: bool = False,
               want_stats: bool = False, want_devices: bool = False) -> Derived:
        """Build everything the UI needs for one frame, under a single lock.

        The `want_*` flags skip work for views that are not on screen; the
        packet list and the header counters are always cheap enough to include.
        """
        with self.lock:
            bundle = Derived(
                packets=list(self.view),
                buffered=len(self.records),
                alert_counts=self.alerts.counts(),
                recon_hosts=list(self.recon_hosts),
                recon_running=self.recon_running,
                recon_error=self.recon_error,
                recon_time=self.recon_time,
                stats=self.stats.header(),
            )
            if want_flows:
                bundle.flows = self.flows.sorted_flows(flow_sort)
            if want_alerts:
                bundle.alerts = self.alerts.sorted_alerts(alert_sort)
            if want_hosts:
                bundle.hosts = self._host_rows(host_sort)
            if want_devices:
                bundle.devices = self.devices.build(
                    self.records, self.stats, self.flows, self.recon_hosts,
                    self.vendors, self.rdns, self.nmap, self.recon_time)
            if want_stats:
                bundle.stats = self.stats.snapshot()
                bundle.stats.dropped = self.stats.dropped
                bundle.stats.buffer_len = len(self.records)
                bundle.stats.flow_count = len(self.flows.flows)
            return bundle

    def _host_rows(self, sort: str = "traffic") -> List[dict]:
        """Every endpoint seen, with traffic totals. Call under the lock."""
        stats = self.stats
        packets_by_host: dict = {}
        for rec in self.records:
            for endpoint in (rec.src, rec.dst):
                if endpoint:
                    packets_by_host[endpoint] = packets_by_host.get(endpoint, 0) + 1
        rows = []
        for ip in set(stats.talkers_sent) | set(stats.talkers_recv):
            mac = stats.macs.get(ip, "")
            rows.append({
                "ip": ip,
                "mac": mac,
                "vendor": self.vendors.get(mac) if mac else "",
                "name": self.rdns.get(ip),
                "sent": stats.talkers_sent.get(ip, 0),
                "recv": stats.talkers_recv.get(ip, 0),
                "packets": packets_by_host.get(ip, 0),
            })
        if sort == "packets":
            rows.sort(key=lambda h: -h["packets"])
        elif sort == "address":
            rows.sort(key=lambda h: _address_key(h["ip"]))
        else:
            rows.sort(key=lambda h: -(h["sent"] + h["recv"]))
        return rows

    def stream_for(self, rec: PacketRecord, limit: int = 200) -> List[tuple]:
        """Payloads of `rec`'s conversation, read from a locked copy."""
        from .detail import follow_stream

        with self.lock:
            records = list(self.records)
        return follow_stream(records, rec, limit)

    def clear(self) -> None:
        with self.lock:
            self.records.clear()
            self.view.clear()
            self.flows.clear()
            self.alerts.clear()
            self.social.clear()
            self.stats.reset()
            self._counter = 0

    def save_pcap(self, path: str, visible_only: bool = False) -> str:
        """Write the buffer to `path`; returns a status message."""
        with self.lock:
            source = list(self.view if visible_only else self.records)
        try:
            count = write_pcap(path, (r.packet for r in source))
        except Exception as exc:
            return f"Save failed: {exc}"
        scope = "filtered" if visible_only else "captured"
        return f"Wrote {count} {scope} packets to {path}"

    # ---- recon ------------------------------------------------------------

    def start_recon(self) -> None:
        """Kick off an ARP sweep of the local /24 (explicitly user-initiated)."""
        if self.recon_running:
            return
        self.recon_running = True
        self.recon_error = ""

        def worker() -> None:
            from .enrich import arp_sweep

            hosts, error = arp_sweep(self.iface)
            with self.lock:
                self.recon_hosts = hosts
                self.recon_error = error
                self.recon_time = time.time()
                self.recon_running = False

        threading.Thread(target=worker, name="netsour-recon", daemon=True).start()


def _address_key(ip: str):
    """Sort IPv4 numerically; anything else sorts after, alphabetically."""
    parts = ip.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return (0, tuple(int(part) for part in parts), "")
    return (1, (), ip)
