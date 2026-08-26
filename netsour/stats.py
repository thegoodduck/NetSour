"""Rolling counters and time-series used by the statistics view."""

from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List

from .dissect import PacketRecord


@dataclass
class StatsView:
    """An immutable copy of the counters, taken under the session lock.

    The stats view renders from one of these rather than from the live
    counters: `Counter.most_common()` walks the underlying dict, and the
    capture thread mutating it mid-walk raises RuntimeError.
    """

    total_packets: int = 0
    total_bytes: int = 0
    dropped: int = 0
    elapsed: float = 0.001
    pps: float = 0.0
    bps: float = 0.0
    peak_pps: int = 0
    history: List[tuple] = field(default_factory=list)
    proto_packets: List[tuple] = field(default_factory=list)
    sizes: Dict[str, int] = field(default_factory=dict)
    talkers_sent: List[tuple] = field(default_factory=list)
    talkers_recv: List[tuple] = field(default_factory=list)
    ports: List[tuple] = field(default_factory=list)
    hostnames: List[tuple] = field(default_factory=list)
    buffer_len: int = 0
    flow_count: int = 0


class Stats:
    """Aggregate counters plus a one-second-resolution traffic history."""

    def __init__(self, history: int = 240):
        self.started = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.dropped = 0                     # packets discarded by the ring buffer
        self.proto_packets: Counter = Counter()
        self.proto_bytes: Counter = Counter()
        self.talkers_sent: Counter = Counter()
        self.talkers_recv: Counter = Counter()
        self.ports: Counter = Counter()
        self.hostnames: Counter = Counter()
        self.macs: Dict[str, str] = {}       # ip -> mac, last seen
        self.sizes: Counter = Counter()      # bucketed packet sizes

        self._history: Deque[tuple] = deque(maxlen=history)   # (second, pkts, bytes)
        self._bucket = int(time.time())
        self._bucket_packets = 0
        self._bucket_bytes = 0

    # ---- ingest -----------------------------------------------------------

    def add(self, rec: PacketRecord) -> None:
        self.total_packets += 1
        self.total_bytes += rec.length
        self.proto_packets[rec.proto_base] += 1
        self.proto_bytes[rec.proto_base] += rec.length
        if rec.src:
            self.talkers_sent[rec.src] += rec.length
        if rec.dst:
            self.talkers_recv[rec.dst] += rec.length
        if rec.dport:
            self.ports[rec.dport] += 1
        if rec.hostname:
            self.hostnames[rec.hostname] += 1
        if rec.src_mac and rec.src:
            self.macs[rec.src] = rec.src_mac
        self.sizes[self._size_bucket(rec.length)] += 1
        self._roll(rec.ts, rec.length)

    @staticmethod
    def _size_bucket(n: int) -> str:
        for limit, label in ((64, "≤64"), (128, "65-128"), (256, "129-256"),
                             (512, "257-512"), (1024, "513-1K"), (1514, "1K-1514")):
            if n <= limit:
                return label
        return ">1514"

    def _roll(self, ts: float, length: int) -> None:
        second = int(ts)
        if second != self._bucket:
            self._history.append((self._bucket, self._bucket_packets, self._bucket_bytes))
            # Fill any silent seconds so the sparkline stays time-accurate.
            for gap in range(self._bucket + 1, min(second, self._bucket + 120)):
                self._history.append((gap, 0, 0))
            self._bucket, self._bucket_packets, self._bucket_bytes = second, 0, 0
        self._bucket_packets += 1
        self._bucket_bytes += length

    # ---- queries ----------------------------------------------------------

    def history(self, seconds: int) -> list:
        """Most recent `seconds` buckets as (second, packets, bytes), oldest first."""
        live = list(self._history)
        live.append((self._bucket, self._bucket_packets, self._bucket_bytes))
        return live[-seconds:]

    def current_rate(self, window: int = 5) -> tuple:
        """(packets/sec, bytes/sec) averaged over the last `window` seconds."""
        buckets = self.history(window)
        if not buckets:
            return 0.0, 0.0
        span = max(1, len(buckets))
        return (sum(b[1] for b in buckets) / span,
                sum(b[2] for b in buckets) / span)

    @property
    def elapsed(self) -> float:
        return max(0.001, time.time() - self.started)

    def header(self) -> StatsView:
        """Just the scalars the title bar needs - no counter walks."""
        pps, bps = self.current_rate()
        return StatsView(total_packets=self.total_packets,
                         total_bytes=self.total_bytes, dropped=self.dropped,
                         elapsed=self.elapsed, pps=pps, bps=bps)

    def snapshot(self, history_seconds: int = 240, top: int = 10) -> StatsView:
        """Copy everything the statistics view needs. Call under the lock."""
        history = self.history(history_seconds)
        pps, bps = self.current_rate()
        return StatsView(
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            dropped=self.dropped,
            elapsed=self.elapsed,
            pps=pps,
            bps=bps,
            peak_pps=max((bucket[1] for bucket in history), default=0),
            history=history,
            proto_packets=self.proto_packets.most_common(top),
            sizes=dict(self.sizes),
            talkers_sent=self.talkers_sent.most_common(top),
            talkers_recv=self.talkers_recv.most_common(top),
            ports=self.ports.most_common(top),
            hostnames=self.hostnames.most_common(top),
        )

    def reset(self) -> None:
        self.__init__(history=self._history.maxlen)


def human_bytes(n: float) -> str:
    """Compact byte formatting: 1.2K, 3.4M, 5.6G."""
    for unit, limit in (("B", 1024), ("K", 1024 ** 2), ("M", 1024 ** 3), ("G", 1024 ** 4)):
        if abs(n) < limit:
            div = limit // 1024
            return f"{n / div:.0f}{unit}" if div == 1 else f"{n / div:.1f}{unit}"
    return f"{n / 1024 ** 4:.1f}T"


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
