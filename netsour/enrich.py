"""Optional, always-asynchronous enrichment: rDNS, geo-IP, MAC vendor, Nmap.

Nothing here ever runs on the render path. Every lookup is queued to a small
worker pool and its result is cached; the UI reads whatever is ready and shows a
placeholder otherwise. Active probing (Nmap, ARP sweep) is strictly user-driven -
NetSour never scans a host you did not ask it to scan.
"""

from __future__ import annotations

import ipaddress
import os
import queue
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

OUI_PATHS = ("/usr/share/hwdata/oui.txt", "/usr/share/misc/oui.txt",
             "/var/lib/ieee-data/oui.txt", "/usr/share/nmap/nmap-mac-prefixes")


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return True


class _Worker:
    """A tiny bounded worker pool shared by the async resolvers."""

    def __init__(self, name: str, workers: int = 3):
        self.queue: queue.Queue = queue.Queue(maxsize=512)
        for i in range(workers):
            threading.Thread(target=self._loop, name=f"{name}-{i}",
                             daemon=True).start()

    def submit(self, fn, *args) -> bool:
        try:
            self.queue.put_nowait((fn, args))
            return True
        except queue.Full:
            return False

    def _loop(self) -> None:
        while True:
            fn, args = self.queue.get()
            try:
                fn(*args)
            except Exception:
                pass
            finally:
                self.queue.task_done()


class ReverseDNS:
    """Background PTR lookups with a negative cache."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.cache: Dict[str, str] = {}
        self._pending: set = set()
        self._lock = threading.Lock()
        self._pool = _Worker("rdns", workers=4)

    def get(self, ip: str) -> str:
        """Return the cached hostname, kicking off a lookup on first miss."""
        if not self.enabled or not ip:
            return ""
        cached = self.cache.get(ip)
        if cached is not None:
            return cached
        with self._lock:
            if ip in self._pending:
                return ""
            self._pending.add(ip)
        self._pool.submit(self._resolve, ip)
        return ""

    def _resolve(self, ip: str) -> None:
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ""
        self.cache[ip] = name
        with self._lock:
            self._pending.discard(ip)


class GeoIP:
    """On-demand geolocation for public addresses (ip-api.com, no key needed)."""

    ENDPOINT = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,lat,lon,reverse"

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.cache: Dict[str, dict] = {}
        self._pending: set = set()
        self._lock = threading.Lock()
        self._pool = _Worker("geo", workers=2)
        self.last_error = ""

    def status(self, ip: str) -> str:
        if not self.enabled:
            return "disabled"
        if is_private(ip):
            return "private"
        if ip in self.cache:
            return "ready"
        return "pending" if ip in self._pending else "unqueried"

    def get(self, ip: str) -> Optional[dict]:
        return self.cache.get(ip)

    def request(self, ip: str) -> str:
        """Queue a lookup. Returns the resulting status string."""
        if not self.enabled:
            return "disabled"
        if not ip or is_private(ip):
            return "private"
        if ip in self.cache:
            return "ready"
        with self._lock:
            if ip in self._pending:
                return "pending"
            self._pending.add(ip)
        self._pool.submit(self._lookup, ip)
        return "pending"

    def _lookup(self, ip: str) -> None:
        data: dict
        try:
            import json
            import urllib.request

            with urllib.request.urlopen(self.ENDPOINT.format(ip=ip), timeout=6) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            if data.get("status") != "success":
                data = {"error": data.get("message", "lookup failed")}
        except Exception as exc:
            data = {"error": f"{exc.__class__.__name__}: {exc}"}
            self.last_error = data["error"]
        self.cache[ip] = data
        with self._lock:
            self._pending.discard(ip)


class MacVendor:
    """MAC OUI -> vendor, read lazily from whichever system database exists."""

    def __init__(self):
        self._table: Optional[Dict[str, str]] = None
        self._lock = threading.Lock()

    def _load(self) -> Dict[str, str]:
        table: Dict[str, str] = {}
        for path in OUI_PATHS:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        if "(hex)" in line:
                            prefix, _, vendor = line.partition("(hex)")
                            table[prefix.strip().replace("-", ":").upper()] = vendor.strip()
                        elif line[:6].isalnum() and "\t" in line:
                            prefix, _, vendor = line.partition("\t")
                            prefix = prefix.strip().upper()
                            if len(prefix) == 6:
                                table[":".join(prefix[i:i + 2] for i in (0, 2, 4))] = vendor.strip()
            except Exception:
                continue
            if table:
                break
        return table

    def get(self, mac: str) -> str:
        if not mac or len(mac) < 8:
            return ""
        with self._lock:
            if self._table is None:
                self._table = self._load()
        return self._table.get(mac[:8].upper(), "")


class NmapScanner:
    """User-triggered Nmap scans, one host at a time, results cached by IP."""

    # key -> (nmap arguments, description, needs_root, rough duration)
    PROFILES = {
        "fast": ("-F -T4", "Top 100 ports", False, "seconds"),
        "top1000": ("-T4", "Top 1000 ports", False, "under a minute"),
        "service": ("-sV -F -T4", "Top 100 ports + service versions", False,
                    "under a minute"),
        "stealth": ("-sS -F -T4", "SYN scan, no full handshake", True,
                    "seconds"),
        "udp": ("-sU --top-ports 50 -T4", "Top 50 UDP ports", True, "minutes"),
        "os": ("-O -F -T4", "Top 100 ports + OS fingerprint", True, "seconds"),
        "aggressive": ("-A -T4", "OS, versions, scripts, traceroute", True,
                       "minutes"),
        "vuln": ("--script vuln -T4", "NSE vulnerability scripts", False,
                 "many minutes"),
        "full": ("-p- -T4", "All 65535 ports", False, "many minutes"),
        "ping": ("-sn", "Host discovery only, no port scan", False, "seconds"),
    }

    def __init__(self):
        self.results: Dict[str, dict] = {}
        self.status: Dict[str, str] = {}       # ip -> "running" | "done" | error text
        self.available = self._probe()
        self._lock = threading.Lock()
        self._pool = _Worker("nmap", workers=1)   # serialise: scans are noisy

    @staticmethod
    def _probe() -> bool:
        import importlib.util

        if importlib.util.find_spec("nmap") is None:
            return False
        from shutil import which

        return which("nmap") is not None

    def request(self, ip: str, profile: str = "fast") -> str:
        if not self.available:
            return "python-nmap or the nmap binary is not installed"
        if not ip:
            return "no target"
        if self.profile_needs_root(profile) and os.geteuid() != 0:
            return f"the {profile} profile needs root"
        with self._lock:
            if self.status.get(ip) == "running":
                return "already running"
            self.status[ip] = "running"
        if not self._pool.submit(self._scan, ip, profile):
            self.status[ip] = "queue full"
        return "queued"

    def profile_needs_root(self, profile: str) -> bool:
        entry = self.PROFILES.get(profile)
        return bool(entry and entry[2])

    def describe(self, profile: str) -> str:
        entry = self.PROFILES.get(profile)
        return entry[1] if entry else profile

    def _scan(self, ip: str, profile: str) -> None:
        args = self.PROFILES.get(profile, self.PROFILES["fast"])[0]
        started = time.time()
        try:
            import nmap

            scanner = nmap.PortScanner()
            scanner.scan(ip, arguments=args)
            data = scanner[ip] if ip in scanner.all_hosts() else {}
            self.results[ip] = {"data": data, "profile": profile,
                                "elapsed": time.time() - started,
                                "args": args}
            self.status[ip] = "done"
        except Exception as exc:
            self.status[ip] = f"failed: {exc}"

    def summary_lines(self, ip: str) -> List[str]:
        """Human-readable scan output for the detail pane."""
        state = self.status.get(ip)
        if state is None:
            return []
        if state == "running":
            return [f"Scanning {ip} …"]
        if state != "done":
            return [f"Scan of {ip} {state}"]

        entry = self.results.get(ip, {})
        data = entry.get("data", {}) or {}
        lines = [f"nmap {entry.get('args', '')} {ip}   "
                 f"({entry.get('elapsed', 0):.1f}s)", ""]
        hostnames = [h.get("name") for h in data.get("hostnames", []) if h.get("name")]
        if hostnames:
            lines.append(f"hostname   {', '.join(hostnames)}")
        if data.get("status"):
            lines.append(f"state      {data['status'].get('state', '?')}")
        for osmatch in (data.get("osmatch") or [])[:2]:
            lines.append(f"os guess   {osmatch.get('name')} ({osmatch.get('accuracy')}%)")
        lines.append("")

        found = False
        for proto in ("tcp", "udp"):
            ports = data.get(proto) or {}
            open_ports = {p: v for p, v in ports.items() if v.get("state") == "open"}
            if not open_ports:
                continue
            found = True
            lines.append(f"{proto.upper()}  {len(open_ports)} open")
            for port in sorted(open_ports):
                info = open_ports[port]
                version = " ".join(filter(None, (info.get("product", ""),
                                                 info.get("version", "")))).strip()
                lines.append(f"  {port:>6}/{proto}  {info.get('name', '?'):<14}"
                             f"{version}")
            lines.append("")
        if not found:
            lines.append("No open ports found in the scanned range.")
        return lines


def arp_sweep(iface: str, timeout: float = 2.0) -> Tuple[List[Tuple[str, str]], str]:
    """ARP-scan the interface's /24. Returns (hosts, error)."""
    try:
        from scapy.layers.l2 import arping

        from .capture import interface_address

        addr = interface_address(iface)
        if not addr:
            return [], f"{iface} has no IPv4 address to derive a subnet from"
        answered, _ = arping(addr.rsplit(".", 1)[0] + ".0/24", timeout=timeout,
                             verbose=0)
        hosts = sorted({(rcv.psrc, rcv.hwsrc) for _snd, rcv in answered},
                       key=lambda h: tuple(int(o) for o in h[0].split(".")))
        return hosts, ""
    except PermissionError:
        return [], "ARP sweep needs root privileges"
    except Exception as exc:
        return [], f"{exc.__class__.__name__}: {exc}"
