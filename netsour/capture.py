"""Packet acquisition: live sniffing, offline pcap replay, and pcap export."""

from __future__ import annotations

import os
import threading
import time
from typing import Callable, List, Optional

from scapy.config import conf
from scapy.sendrecv import sniff
from scapy.utils import PcapWriter, rdpcap


def list_interfaces() -> List[str]:
    """Interface names available for capture, loopback last."""
    names: List[str] = []
    sys_net = "/sys/class/net"
    if os.path.isdir(sys_net):
        names = sorted(os.listdir(sys_net))
    else:
        try:
            from scapy.arch import get_if_list

            names = sorted(get_if_list())
        except Exception:
            names = []
    return [n for n in names if n != "lo"] + [n for n in names if n == "lo"]


def interface_address(iface: str) -> str:
    """IPv4 address bound to `iface`, or "" when it has none."""
    try:
        from scapy.arch import get_if_addr

        addr = get_if_addr(iface)
        return "" if addr in ("0.0.0.0", None) else addr
    except Exception:
        return ""


def local_prefix(iface: str) -> str:
    """First three octets of the interface address, for "is this local?" tests."""
    addr = interface_address(iface)
    return addr.rsplit(".", 1)[0] + "." if addr.count(".") == 3 else ""


def default_gateway(iface: str = "") -> str:
    """The default route's next hop, read from /proc - "" when there is none."""
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as handle:
            for line in handle.readlines()[1:]:
                fields = line.split()
                if len(fields) < 3 or fields[1] != "00000000":
                    continue
                if iface and fields[0] != iface:
                    continue
                packed = int(fields[2], 16)
                return ".".join(str((packed >> shift) & 0xFF)
                                for shift in (0, 8, 16, 24))
    except Exception:
        pass
    return ""


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:                    # non-POSIX
        return False


class CaptureEngine:
    """Owns the sniffer thread and feeds packets to a callback.

    The callback runs on the capture thread, so it must be cheap and
    thread-safe; :class:`~netsour.session.Session` handles the locking.
    """

    def __init__(self, iface: str, on_packet: Callable, bpf: str = "",
                 promisc: bool = True, pcap_path: str = ""):
        self.iface = iface
        self.bpf = bpf
        self.promisc = promisc
        self.pcap_path = pcap_path
        self.on_packet = on_packet

        self.running = False
        self.paused = False
        self.error: Optional[str] = None
        self.finished = False                 # offline replay reached EOF
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ---- lifecycle --------------------------------------------------------

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.running = True
        self.error = None
        target = self._run_offline if self.pcap_path else self._run_live
        self._thread = threading.Thread(target=target, name="netsour-capture",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.running = False

    def toggle_pause(self) -> bool:
        self.paused = not self.paused
        return self.paused

    # ---- workers ----------------------------------------------------------

    def _deliver(self, packet) -> None:
        if self.paused:
            return
        self.on_packet(packet)

    def _run_live(self) -> None:
        try:
            conf.sniff_promisc = bool(self.promisc)
            sniff(iface=self.iface or None,
                  filter=self.bpf or None,
                  prn=self._deliver,
                  store=False,
                  promisc=self.promisc,
                  stop_filter=lambda _p: self._stop.is_set())
        except PermissionError:
            self.error = ("Permission denied opening the capture device. "
                          "Run with sudo, or grant CAP_NET_RAW.")
        except OSError as exc:
            self.error = f"Capture failed on {self.iface}: {exc}"
        except Exception as exc:
            self.error = f"{exc.__class__.__name__}: {exc}"
        finally:
            self.running = False

    def _run_offline(self) -> None:
        """Replay a pcap as fast as the UI can absorb it."""
        try:
            packets = rdpcap(self.pcap_path)
            for packet in packets:
                if self._stop.is_set():
                    break
                while self.paused and not self._stop.is_set():
                    time.sleep(0.05)
                self._deliver(packet)
                if len(packets) > 5000:
                    time.sleep(0)             # yield to the UI thread
        except FileNotFoundError:
            self.error = f"No such capture file: {self.pcap_path}"
        except Exception as exc:
            self.error = f"Could not read {self.pcap_path}: {exc}"
        finally:
            self.finished = True
            self.running = False


def write_pcap(path: str, packets) -> int:
    """Write packets to `path`. Returns the number written."""
    written = 0
    writer = PcapWriter(path, append=False, sync=True)
    try:
        for packet in packets:
            if packet is not None:
                writer.write(packet)
                written += 1
    finally:
        writer.close()
    return written
