"""Conversation (flow) tracking, aggregated bidirectionally."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from .dissect import PacketRecord


@dataclass
class Flow:
    """A bidirectional conversation between two endpoints."""

    proto: str
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    first_ts: float
    last_ts: float
    packets_ab: int = 0
    packets_ba: int = 0
    bytes_ab: int = 0
    bytes_ba: int = 0
    hostname: str = ""
    flags_seen: set = field(default_factory=set)

    @property
    def packets(self) -> int:
        return self.packets_ab + self.packets_ba

    @property
    def bytes(self) -> int:
        return self.bytes_ab + self.bytes_ba

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def rate(self) -> float:
        """Average bytes/second over the flow's lifetime."""
        return self.bytes / self.duration if self.duration > 0.05 else 0.0

    def endpoint_a(self) -> str:
        return f"{self.a_ip}:{self.a_port}" if self.a_port else self.a_ip

    def endpoint_b(self) -> str:
        return f"{self.b_ip}:{self.b_port}" if self.b_port else self.b_ip

    def state(self) -> str:
        """Coarse TCP-ish state derived from the flags observed."""
        if self.proto != "TCP":
            return "-"
        if "R" in self.flags_seen:
            return "reset"
        if "F" in self.flags_seen:
            return "closed"
        if self.packets_ba == 0:
            return "unanswered"
        return "open"


class FlowTable:
    """Maintains the set of live conversations, capped at `max_flows`."""

    def __init__(self, max_flows: int = 4096):
        self.max_flows = max_flows
        self.flows: Dict[tuple, Flow] = {}
        self.evicted = 0

    def add(self, rec: PacketRecord) -> Flow:
        key = rec.key
        flow = self.flows.get(key)
        if flow is None:
            (_, (a_ip, a_port), (b_ip, b_port)) = key
            flow = Flow(proto=rec.proto_base, a_ip=a_ip, a_port=a_port,
                        b_ip=b_ip, b_port=b_port,
                        first_ts=rec.ts, last_ts=rec.ts)
            self.flows[key] = flow
            self._evict_if_needed()
        flow.last_ts = rec.ts
        if rec.hostname and not flow.hostname:
            flow.hostname = rec.hostname
        if rec.flags and rec.proto_base == "TCP":
            flow.flags_seen.update(rec.flags)
        if (rec.src, rec.sport or 0) == (flow.a_ip, flow.a_port):
            flow.packets_ab += 1
            flow.bytes_ab += rec.length
        else:
            flow.packets_ba += 1
            flow.bytes_ba += rec.length
        return flow

    def _evict_if_needed(self) -> None:
        """Drop the least recently active flows once over the cap."""
        overflow = len(self.flows) - self.max_flows
        if overflow <= 0:
            return
        stale = sorted(self.flows.items(), key=lambda kv: kv[1].last_ts)
        for key, _ in stale[:overflow + self.max_flows // 10]:
            del self.flows[key]
            self.evicted += 1

    def sorted_flows(self, key: str = "bytes") -> list:
        getters = {
            "bytes": lambda f: f.bytes,
            "packets": lambda f: f.packets,
            "last": lambda f: f.last_ts,
            "duration": lambda f: f.duration,
            "rate": lambda f: f.rate,
        }
        return sorted(self.flows.values(), key=getters.get(key, getters["bytes"]),
                      reverse=True)

    def clear(self) -> None:
        self.flows.clear()
        self.evicted = 0
