"""Heuristic threat detection over the live packet stream.

Every detector is intentionally cheap and stateless-ish: sliding deques keyed by
source, evaluated per packet. They flag *suspicion*, not proof - the UI presents
them as leads to investigate.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional

from .dissect import PacketRecord
from .services import CLEARTEXT_PORTS

INFO, LOW, MEDIUM, HIGH = "info", "low", "medium", "high"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}

# Ports that are unusual enough as a destination to be worth a note.
SUSPICIOUS_PORTS = {
    31337: "Back Orifice", 12345: "NetBus", 4444: "Metasploit default",
    5555: "ADB / backdoor", 6666: "IRC bot", 1337: "leet backdoor",
    9001: "Tor ORPort", 9050: "Tor SOCKS", 4899: "Radmin", 65535: "shell",
}

CRED_PATTERNS = [
    (re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.I), "HTTP Basic auth"),
    (re.compile(rb"(?:^|\r\n)PASS\s+(\S+)", re.I), "FTP password"),
    (re.compile(rb"(?:^|\r\n)USER\s+(\S+)", re.I), "FTP username"),
    (re.compile(rb"(?:^|\r\n)LOGIN\s+(\S+)", re.I), "IMAP login"),
    (re.compile(rb"(?:^|\r\n)AUTH\s+PLAIN", re.I), "SMTP plain auth"),
    (re.compile(rb"[?&](?:password|passwd|pwd|token|api_?key)=([^&\s]+)", re.I),
     "credential in URL"),
    (re.compile(rb'"(?:password|passwd|api_?key|secret)"\s*:\s*"([^"]+)"', re.I),
     "credential in JSON body"),
]


@dataclass
class Alert:
    """One finding, ready to render."""

    ts: float
    severity: str
    category: str
    title: str
    detail: str = ""
    src: str = ""
    dst: str = ""
    packet_index: Optional[int] = None
    flow_key: Optional[tuple] = None    # links the alert back to its conversation
    proto: str = ""
    count: int = 1

    @property
    def when(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.ts))


@dataclass
class Thresholds:
    """Tunable detector limits, all windows in seconds."""

    scan_window: float = 10.0
    scan_ports: int = 20            # distinct ports on one host -> port scan
    sweep_hosts: int = 25           # distinct hosts probed -> host sweep
    flood_window: float = 5.0
    flood_packets: int = 500        # packets/window from one source -> flood
    syn_flood: int = 200            # unanswered SYNs/window -> SYN flood
    icmp_flood: int = 150
    dns_nxdomain: int = 30
    dns_label_len: int = 45         # long labels suggest DNS tunnelling
    cooldown: float = 30.0          # per-key alert suppression
    max_alerts: int = 2000


class AlertEngine:
    """Runs all detectors over each packet and accumulates deduplicated alerts."""

    def __init__(self, thresholds: Optional[Thresholds] = None,
                 local_prefix: str = ""):
        self.t = thresholds or Thresholds()
        self.local_prefix = local_prefix
        self.alerts: List[Alert] = []
        self._last_fired: Dict[str, float] = {}
        self._by_key: Dict[str, Alert] = {}

        self._syn_targets: Dict[str, deque] = defaultdict(deque)   # src -> (ts, dst, port)
        self._syn_to: Dict[tuple, deque] = defaultdict(deque)      # (dst,port) -> ts
        self._synack_from: Dict[tuple, float] = {}
        self._rate: Dict[str, deque] = defaultdict(deque)          # src -> ts
        self._icmp: Dict[str, deque] = defaultdict(deque)
        self._nxdomain: Dict[str, deque] = defaultdict(deque)
        self._arp_macs: Dict[str, str] = {}
        self._known_hosts: set = set()
        self._first_seen_grace = time.time() + 3.0   # don't alert on the initial burst

    # ---- public API -------------------------------------------------------

    def inspect(self, rec: PacketRecord) -> None:
        """Feed one packet through every detector. Never raises."""
        try:
            self._scan_and_flood(rec)
            self._arp_watch(rec)
            self._dns_watch(rec)
            self._cleartext_watch(rec)
            self._port_watch(rec)
            self._new_host(rec)
        except Exception:
            pass   # a detector bug must never interrupt capture

    def counts(self) -> Dict[str, int]:
        out = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
        for alert in self.alerts:
            out[alert.severity] = out.get(alert.severity, 0) + 1
        return out

    def sorted_alerts(self, by: str = "time") -> List[Alert]:
        if by == "severity":
            return sorted(self.alerts,
                          key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), -a.ts))
        return sorted(self.alerts, key=lambda a: a.ts, reverse=True)

    def emit(self, title: str, detail: str = "", severity: str = MEDIUM,
             rec: Optional[PacketRecord] = None, key: str = "",
             category: str = "Addon") -> None:
        """Raise a finding from outside the built-in detectors — an addon.

        Deduplicated on the same cooldown as everything else, so an addon that
        calls this per packet gets one alert with a count, not a wall of them.
        """
        if severity not in SEVERITY_ORDER:
            severity = MEDIUM
        self._fire(key or f"addon:{category}:{title}", severity, category,
                   title, detail, rec)

    def clear(self) -> None:
        self.alerts.clear()
        self._last_fired.clear()
        self._by_key.clear()

    # ---- emission ---------------------------------------------------------

    def _fire(self, key: str, severity: str, category: str, title: str,
              detail: str = "", rec: Optional[PacketRecord] = None) -> None:
        now = time.time()
        last = self._last_fired.get(key)
        if last is not None and now - last < self.t.cooldown:
            existing = self._by_key.get(key)
            if existing is not None:
                existing.count += 1
            return
        self._last_fired[key] = now
        alert = Alert(ts=now, severity=severity, category=category, title=title,
                      detail=detail,
                      src=rec.src if rec else "", dst=rec.dst if rec else "",
                      packet_index=rec.index if rec else None,
                      flow_key=rec.key if rec else None,
                      proto=rec.proto if rec else "")
        self._by_key[key] = alert
        self.alerts.append(alert)
        if len(self.alerts) > self.t.max_alerts:
            del self.alerts[:len(self.alerts) - self.t.max_alerts]

    @staticmethod
    def _prune(dq: deque, cutoff: float, index: int = 0) -> None:
        while dq and (dq[0][index] if isinstance(dq[0], tuple) else dq[0]) < cutoff:
            dq.popleft()

    # ---- detectors --------------------------------------------------------

    def _scan_and_flood(self, rec: PacketRecord) -> None:
        now = rec.ts
        if not rec.src:
            return

        rate = self._rate[rec.src]
        rate.append(now)
        self._prune(rate, now - self.t.flood_window)
        if len(rate) > self.t.flood_packets:
            pps = len(rate) / self.t.flood_window
            self._fire(f"flood:{rec.src}", HIGH, "DoS",
                       f"Traffic flood from {rec.src}",
                       f"{pps:.0f} packets/s sustained over {self.t.flood_window:.0f}s "
                       f"(threshold {self.t.flood_packets / self.t.flood_window:.0f}/s)",
                       rec)

        if rec.proto_base == "ICMP":
            icmp = self._icmp[rec.src]
            icmp.append(now)
            self._prune(icmp, now - self.t.flood_window)
            if len(icmp) > self.t.icmp_flood:
                self._fire(f"icmpflood:{rec.src}", MEDIUM, "DoS",
                           f"ICMP flood from {rec.src}",
                           f"{len(icmp)} ICMP packets in {self.t.flood_window:.0f}s", rec)
            if rec.payload_len > 1000:
                self._fire(f"icmptunnel:{rec.src}", MEDIUM, "Exfiltration",
                           f"Oversized ICMP payload from {rec.src}",
                           f"{rec.payload_len} bytes of ICMP data - possible tunnel", rec)
            return

        if rec.proto_base != "TCP":
            return

        if rec.flags == "SA":
            self._synack_from[(rec.src, rec.sport or 0)] = now
            return
        if "S" not in (rec.flags or "") or "A" in (rec.flags or ""):
            return

        # --- SYN-only from here on: scan / sweep / SYN-flood territory ---
        targets = self._syn_targets[rec.src]
        targets.append((now, rec.dst, rec.dport or 0))
        self._prune(targets, now - self.t.scan_window)

        ports_per_host = defaultdict(set)
        hosts = set()
        for _, dst, port in targets:
            ports_per_host[dst].add(port)
            hosts.add(dst)

        for dst, ports in ports_per_host.items():
            if len(ports) >= self.t.scan_ports:
                low = sorted(ports)[:6]
                self._fire(f"portscan:{rec.src}:{dst}", HIGH, "Recon",
                           f"Port scan {rec.src} → {dst}",
                           f"{len(ports)} distinct ports in {self.t.scan_window:.0f}s "
                           f"(e.g. {', '.join(map(str, low))}…)", rec)
        if len(hosts) >= self.t.sweep_hosts:
            self._fire(f"sweep:{rec.src}", HIGH, "Recon",
                       f"Host sweep from {rec.src}",
                       f"SYNs to {len(hosts)} distinct hosts in "
                       f"{self.t.scan_window:.0f}s", rec)

        target_key = (rec.dst, rec.dport or 0)
        syns = self._syn_to[target_key]
        syns.append(now)
        self._prune(syns, now - self.t.flood_window)
        answered = self._synack_from.get(target_key, 0) > now - self.t.flood_window
        if len(syns) > self.t.syn_flood and not answered:
            self._fire(f"synflood:{rec.dst}:{rec.dport}", HIGH, "DoS",
                       f"SYN flood against {rec.dst}:{rec.dport}",
                       f"{len(syns)} unanswered SYNs in {self.t.flood_window:.0f}s", rec)

    def _arp_watch(self, rec: PacketRecord) -> None:
        if rec.proto_base != "ARP" or not rec.src_mac or not rec.src:
            return
        previous = self._arp_macs.get(rec.src)
        if previous and previous != rec.src_mac:
            self._fire(f"arpspoof:{rec.src}", HIGH, "MITM",
                       f"ARP conflict for {rec.src}",
                       f"MAC changed {previous} → {rec.src_mac} - possible ARP spoofing",
                       rec)
        self._arp_macs[rec.src] = rec.src_mac

    def _dns_watch(self, rec: PacketRecord) -> None:
        if "DNS" not in rec.proto:
            return
        if rec.hostname:
            longest = max((len(part) for part in rec.hostname.split(".")), default=0)
            if longest >= self.t.dns_label_len:
                self._fire(f"dnstunnel:{rec.src}", MEDIUM, "Exfiltration",
                           f"Suspicious DNS label from {rec.src}",
                           f"{longest}-character label in {rec.hostname[:60]} - "
                           "possible DNS tunnelling", rec)
        if "NXDOMAIN" in rec.info:
            nx = self._nxdomain[rec.dst or rec.src]
            nx.append(rec.ts)
            self._prune(nx, rec.ts - 60.0)
            if len(nx) > self.t.dns_nxdomain:
                self._fire(f"nxdomain:{rec.dst}", MEDIUM, "Malware",
                           f"NXDOMAIN storm toward {rec.dst}",
                           f"{len(nx)} failed lookups in 60s - possible DGA activity",
                           rec)

    def _cleartext_watch(self, rec: PacketRecord) -> None:
        if "cleartext" not in rec.tags or rec.packet is None:
            return
        service = CLEARTEXT_PORTS.get(rec.dport or 0, "")
        data = rec.payload_text.encode("latin-1", "replace")
        for pattern, label in CRED_PATTERNS:
            match = pattern.search(data[:4096])
            if match:
                captured = match.group(match.lastindex or 0)[:40].decode("latin-1", "replace")
                self._fire(f"creds:{rec.src}:{rec.dst}:{label}", HIGH, "Credentials",
                           f"{label} in the clear",
                           f"{rec.src} → {rec.dst}:{rec.dport} · {captured}", rec)
                return
        if service and rec.payload_len > 0:
            self._fire(f"plaintext:{rec.src}:{rec.dst}:{rec.dport}", LOW, "Hygiene",
                       f"Unencrypted {service} traffic",
                       f"{rec.src} → {rec.dst}:{rec.dport} carries readable payload", rec)

    def _port_watch(self, rec: PacketRecord) -> None:
        name = SUSPICIOUS_PORTS.get(rec.dport or 0)
        if name and rec.proto_base == "TCP":
            self._fire(f"badport:{rec.dst}:{rec.dport}", MEDIUM, "Suspicious",
                       f"Connection to port {rec.dport} ({name})",
                       f"{rec.src} → {rec.dst}:{rec.dport}", rec)

    def _new_host(self, rec: PacketRecord) -> None:
        if not self.local_prefix or not rec.src.startswith(self.local_prefix):
            return
        if rec.src in self._known_hosts:
            return
        self._known_hosts.add(rec.src)
        if time.time() < self._first_seen_grace:
            return
        self._fire(f"newhost:{rec.src}", INFO, "Inventory",
                   f"New local host {rec.src}",
                   f"MAC {rec.src_mac or 'unknown'} first seen on this segment", rec)
