"""Open-source intelligence lookups for an address or hostname.

Each source is a small, self-contained probe that fills one section of a
report. Everything runs on a background pool and is cached per (target,
source); nothing here is ever called from a render path.

Sources are split into **passive** (they query public registries and resolvers,
never the target itself) and **active** (they open a connection to the target,
which it can see and log). The UI confirms before running an active source, and
`run_all` skips them unless explicitly asked.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List

from .enrich import _Worker, is_private

USER_AGENT = "NetSour/0.3 (+https://github.com/thegoodduck/NetSour)"
HTTP_TIMEOUT = 8


@dataclass(frozen=True)
class Source:
    """Metadata for one OSINT probe."""

    key: str
    title: str
    active: bool                 # does it connect to the target itself?
    applies: str                 # "ip" | "host" | "both"
    note: str = ""

    def supports(self, target: str) -> bool:
        kind = target_kind(target)
        if self.applies == "both":
            return kind in ("ip", "host")
        return self.applies == kind


SOURCES: List[Source] = [
    Source("rdns", "Reverse DNS", False, "ip",
           "PTR record from the resolver"),
    Source("geo", "Geolocation & ASN", False, "ip",
           "ip-api.com lookup"),
    Source("rdap", "RDAP registry", False, "both",
           "network or domain registration, via rdap.org"),
    Source("dns", "DNS records", False, "host",
           "A / AAAA / MX / NS / TXT from the resolver"),
    Source("tls", "TLS certificate", True, "both",
           "opens a TLS connection to port 443"),
    Source("http", "HTTP headers", True, "both",
           "sends one HEAD request"),
    Source("trace", "Network path", True, "both",
           "traces the route to the target"),
    Source("social", "Social activity", False, "ip",
           "platforms this host contacted, from captured traffic"),
    Source("username", "Account lookup", True, "username",
           "checks public profile URLs on several platforms"),
]

SOURCES_BY_KEY = {source.key: source for source in SOURCES}

# Headers worth calling out, and whether their absence is a finding.
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy",
                    "x-frame-options", "x-content-type-options",
                    "referrer-policy", "permissions-policy")
REVEALING_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                     "x-generator", "via", "x-served-by")


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def target_kind(target: str) -> str:
    """Classify a target as an address, a hostname, or a bare account name."""
    if not target:
        return "host"
    if _is_ip(target):
        return "ip"
    return "host" if "." in target.strip(".") else "username"


@dataclass(frozen=True)
class ProfileSite:
    """One site to check a username against, and how to read its answer.

    Status codes alone are not enough: several sites soft-404, returning HTTP
    200 with a "no such user" page. Checking only the status reported six false
    hits out of eighteen on a username that exists nowhere, so each site that
    needs one carries an explicit verification rule.
    """

    name: str
    url: str
    absent_markers: tuple = ()      # in the body -> the account does not exist
    present_markers: tuple = ()     # in the body -> it does
    absent_url: str = ""            # redirected here -> it does not
    title_has_user: bool = False    # the <title> names the account when it exists
    blocked_markers: tuple = ()     # bot protection -> inconclusive, never a guess


USERNAME_SITES = (
    ProfileSite("GitHub", "https://github.com/{}"),
    ProfileSite("GitLab", "https://gitlab.com/{}"),
    ProfileSite("Reddit", "https://www.reddit.com/user/{}/about.json"),
    ProfileSite("Telegram", "https://t.me/{}",
                present_markers=("tgme_page_title",)),
    ProfileSite("Twitch", "https://www.twitch.tv/{}", title_has_user=True),
    ProfileSite("Steam", "https://steamcommunity.com/id/{}",
                absent_markers=("An error was encountered",
                                "The specified profile could not be found")),
    ProfileSite("Tumblr", "https://{}.tumblr.com"),
    ProfileSite("Substack", "https://{}.substack.com"),
    ProfileSite("Bandcamp", "https://{}.bandcamp.com",
                absent_url="bandcamp.com/signup"),
    ProfileSite("itch.io", "https://{}.itch.io"),
    ProfileSite("Neocities", "https://{}.neocities.org"),
    ProfileSite("Dev.to", "https://dev.to/{}"),
    ProfileSite("Hacker News", "https://news.ycombinator.com/user?id={}",
                absent_markers=("No such user",)),
    ProfileSite("Last.fm", "https://www.last.fm/user/{}"),
    ProfileSite("SoundCloud", "https://soundcloud.com/{}"),
    ProfileSite("PyPI", "https://pypi.org/user/{}/",
                blocked_markers=("Client Challenge",)),
    ProfileSite("Keybase", "https://keybase.io/{}"),
    ProfileSite("Vimeo", "https://vimeo.com/{}"),
)


@dataclass
class Finding:
    """One `label: value` line in a report section."""

    label: str
    value: str
    role: str = "base"


@dataclass
class Section:
    """One source's results for one target."""

    key: str
    title: str
    status: str = "idle"          # idle | running | done | error | skipped
    findings: List[Finding] = field(default_factory=list)
    error: str = ""
    took: float = 0.0

    @property
    def summary(self) -> str:
        if self.status == "done":
            return f"{len(self.findings)} findings"
        if self.status == "error":
            return self.error[:60]
        return self.status


@dataclass
class Report:
    """Everything known about one target."""

    target: str
    sections: Dict[str, Section] = field(default_factory=dict)

    def section(self, key: str) -> Section:
        if key not in self.sections:
            source = SOURCES_BY_KEY.get(key)
            self.sections[key] = Section(key=key,
                                         title=source.title if source else key)
        return self.sections[key]

    @property
    def is_running(self) -> bool:
        return any(s.status == "running" for s in self.sections.values())


class OsintEngine:
    """Runs OSINT sources in the background and caches their reports."""

    def __init__(self, geo=None, rdns=None, social=None, enabled: bool = True):
        self.enabled = enabled
        self.geo = geo
        self.rdns = rdns
        self.social = social
        self.reports: Dict[str, Report] = {}
        self.target: str = ""
        self._lock = threading.Lock()
        self._pool = _Worker("osint", workers=3)

    # ---- public API -------------------------------------------------------

    def report(self, target: str) -> Report:
        with self._lock:
            if target not in self.reports:
                self.reports[target] = Report(target=target)
            return self.reports[target]

    def status(self, target: str, key: str) -> str:
        return self.report(target).section(key).status

    def run(self, target: str, key: str, force: bool = False) -> str:
        """Queue one source. Returns a short status for the message line."""
        if not self.enabled:
            return "OSINT lookups are disabled"
        source = SOURCES_BY_KEY.get(key)
        if source is None:
            return f"unknown source '{key}'"
        if not target:
            return "no target selected"
        if not source.supports(target):
            return f"{source.title} does not apply to {target}"

        section = self.report(target).section(key)
        with self._lock:
            if section.status == "running":
                return f"{source.title} already running"
            if section.status == "done" and not force:
                return f"{source.title} already gathered"
            section.status = "running"
            section.findings = []
            section.error = ""
        self._pool.submit(self._execute, target, source)
        return f"{source.title} started"

    def run_all(self, target: str, include_active: bool = False) -> str:
        """Queue every applicable source; passive only unless asked."""
        queued = [source.key for source in SOURCES
                  if source.supports(target)
                  and (include_active or not source.active)
                  and self.run(target, source.key).endswith("started")]
        scope = "all" if include_active else "passive"
        return (f"{len(queued)} {scope} sources started for {target}"
                if queued else f"nothing new to gather for {target}")

    def clear(self, target: str = "") -> None:
        with self._lock:
            if target:
                self.reports.pop(target, None)
            else:
                self.reports.clear()

    # ---- execution --------------------------------------------------------

    def _execute(self, target: str, source: Source) -> None:
        section = self.report(target).section(source.key)
        started = time.time()
        try:
            findings = getattr(self, f"_source_{source.key}")(target)
            section.findings = findings
            section.status = "done"
            if not findings:
                section.findings = [Finding("result", "no data returned", "dim")]
        except Exception as exc:
            section.status = "error"
            section.error = f"{exc.__class__.__name__}: {exc}"
        finally:
            section.took = time.time() - started

    # ---- passive sources --------------------------------------------------

    def _source_rdns(self, target: str) -> List[Finding]:
        try:
            name, aliases, _ = socket.gethostbyaddr(target)
        except OSError as exc:
            return [Finding("ptr", f"no PTR record ({exc.strerror or exc})", "dim")]
        out = [Finding("ptr", name, "accent")]
        out += [Finding("alias", alias, "dim") for alias in aliases]
        return out

    def _source_geo(self, target: str) -> List[Finding]:
        if self.geo is None or not self.geo.enabled:
            return [Finding("geo", "geolocation is disabled (--no-geo)", "dim")]
        if is_private(target):
            return [Finding("scope", "private address - not routable, no geo data",
                            "dim")]
        data = None
        if self.geo is not None:
            self.geo.request(target)
            for _ in range(60):
                data = self.geo.get(target)
                if data is not None:
                    break
                time.sleep(0.2)
        if data is None:
            raise RuntimeError("geolocation lookup timed out")
        if "error" in data:
            raise RuntimeError(data["error"])
        fields = (("country", "country"), ("regionName", "region"),
                  ("city", "city"), ("isp", "isp"), ("org", "organisation"),
                  ("as", "asn"), ("reverse", "reverse"))
        out = [Finding(label, str(data[key]))
               for key, label in fields if data.get(key)]
        if data.get("lat") is not None:
            out.append(Finding("coordinates", f"{data['lat']}, {data['lon']}",
                               "dim"))
        return out

    def _source_rdap(self, target: str) -> List[Finding]:
        kind = "ip" if _is_ip(target) else "domain"
        lookup = target
        if kind == "domain":
            # RDAP wants the registrable domain, not a full hostname.
            parts = target.strip(".").split(".")
            lookup = ".".join(parts[-2:]) if len(parts) > 2 else target
        if kind == "ip" and is_private(target):
            return [Finding("scope", "private address - no registry entry", "dim")]

        data = _get_json(f"https://rdap.org/{kind}/{lookup}")
        out: List[Finding] = []
        for key, label in (("handle", "handle"), ("name", "name"),
                           ("type", "type"), ("country", "country"),
                           ("startAddress", "range start"),
                           ("endAddress", "range end"),
                           ("ldhName", "domain")):
            if data.get(key):
                out.append(Finding(label, str(data[key])))
        for cidr in (data.get("cidr0_cidrs") or [])[:4]:
            prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
            if prefix:
                out.append(Finding("cidr", f"{prefix}/{cidr.get('length')}",
                                   "accent"))
        for event in (data.get("events") or [])[:4]:
            action = event.get("eventAction", "event")
            when = (event.get("eventDate") or "")[:10]
            out.append(Finding(action, when, "dim"))
        for status in (data.get("status") or [])[:4]:
            out.append(Finding("status", str(status), "dim"))
        out.extend(_rdap_contacts(data))
        for server in (data.get("nameservers") or [])[:6]:
            if server.get("ldhName"):
                out.append(Finding("nameserver", server["ldhName"], "accent"))
        return out

    def _source_dns(self, target: str) -> List[Finding]:
        resolver = _system_resolver()
        out: List[Finding] = []
        for qtype, label in (("A", "a"), ("AAAA", "aaaa"), ("MX", "mx"),
                             ("NS", "ns"), ("TXT", "txt"), ("CNAME", "cname")):
            try:
                answers = _dns_query(target, qtype, resolver)
            except Exception:
                continue
            for answer in answers[:6]:
                out.append(Finding(label, answer,
                                   "accent" if qtype in ("A", "AAAA") else "base"))
        if not out:
            out.append(Finding("dns", f"no records via {resolver}", "dim"))
        else:
            out.append(Finding("resolver", resolver, "dim"))
        return out

    def _source_social(self, target: str) -> List[Finding]:
        """What this host did with social platforms, from the capture alone."""
        if self.social is None:
            raise RuntimeError("no capture session attached")
        activity = self.social.activity_for(target)
        hints = self.social.hints_for(target)
        if not activity:
            return [Finding("result", "no social platform traffic seen from "
                            f"{target} in the buffer", "dim")]

        out: List[Finding] = []
        for entry in activity:
            when = time.strftime("%H:%M:%S", time.localtime(entry.last_ts))
            readable = "cleartext" if entry.cleartext else "encrypted"
            out.append(Finding(
                entry.platform,
                f"{entry.requests} packets · {len(entry.hostnames)} hosts · "
                f"last {when} · {readable}",
                "warn" if entry.cleartext else "base"))

        if not hints:
            out.append(Finding("", "", "dim"))
            out.append(Finding("identity", "no username visible - these "
                               "sessions are encrypted", "dim"))
            return out

        out.append(Finding("", "", "dim"))
        for hint in hints:
            role = "danger" if hint.confidence == "observed" else "warn"
            out.append(Finding(
                f"{hint.kind}",
                f"{hint.value}  ({hint.platform}) · {hint.confidence} · "
                f"{hint.method} · packet #{hint.packet_index}", role))

        correlated = self.social.correlated(target)
        if correlated:
            out.append(Finding("", "", "dim"))
            for value, platforms in correlated:
                out.append(Finding("reused", f"{value} on {', '.join(platforms)}",
                                   "danger"))

        out.append(Finding("", "", "dim"))
        out.append(Finding("note", "'observed' was read off the wire; "
                           "'inferred' was deduced from a hostname", "dim"))
        out.append(Finding("note", "encrypted sessions show the platform only - "
                           "no username is recoverable from them", "dim"))
        return out

    # ---- active sources ---------------------------------------------------

    def _source_tls(self, target: str, port: int = 443) -> List[Finding]:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((target, port), timeout=HTTP_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=target) as tls:
                    cert = tls.getpeercert()
                    proto, cipher = tls.version(), tls.cipher()
        except ssl.SSLCertVerificationError as exc:
            cert, proto, cipher, der = _tls_unverified(target, port)
            findings = [Finding("validation", f"FAILED - {exc.verify_message or exc}",
                                "danger")]
            findings += _tls_findings(cert, proto, cipher)
            findings += _openssl_findings(der)
            return findings
        except OSError as exc:
            raise RuntimeError(f"cannot reach {target}:{port} - {exc}")

        out = [Finding("validation", "certificate chain is valid", "ok")]
        out += _tls_findings(cert, proto, cipher)
        return out

    def _source_http(self, target: str) -> List[Finding]:
        """Fetch response headers, verifying TLS first and saying so if not.

        Falling back to an unverified session is necessary - appliances with
        self-signed certificates and bare-IP targets are exactly the things
        worth looking at - but it is never silent: headers from an unverified
        connection could have come from anyone in the path, and the report has
        to say so.
        """
        host = f"[{target}]" if ":" in target else target
        errors = []
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            request = urllib.request.Request(
                url, method="HEAD", headers={"User-Agent": USER_AGENT})
            try:
                with urllib.request.urlopen(request,
                                            timeout=HTTP_TIMEOUT) as response:
                    return _http_findings(scheme, response.status,
                                          response.headers)
            except ssl.SSLCertVerificationError as exc:
                try:
                    unverified = ssl._create_unverified_context()
                    with urllib.request.urlopen(
                            request, timeout=HTTP_TIMEOUT,
                            context=unverified) as response:
                        reason = exc.verify_message or str(exc)
                        return [Finding(
                            "tls", f"UNVERIFIED - {reason}. The headers below "
                            "come from an unauthenticated session and cannot "
                            "be trusted to be the real host.", "danger")] \
                            + _http_findings(scheme, response.status,
                                             response.headers)
                except Exception as inner:
                    errors.append(f"{scheme}: {inner}")
            except Exception as exc:
                errors.append(f"{scheme}: {exc}")
        raise RuntimeError("; ".join(errors)[:200])

    def _source_username(self, target: str) -> List[Finding]:
        """Check public profile URLs for an account name."""
        import concurrent.futures

        results: List[tuple] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(_probe_profile, site, target): site
                       for site in USERNAME_SITES}
            for future in concurrent.futures.as_completed(futures, timeout=90):
                site = futures[future]
                try:
                    state, detail = future.result()
                except Exception as exc:
                    state, detail = "inconclusive", exc.__class__.__name__
                results.append((site.name, state, detail))

        order = {"found": 0, "not found": 1, "inconclusive": 2, "error": 3}
        results.sort(key=lambda row: (order.get(row[1], 9), row[0]))
        found = [row for row in results if row[1] == "found"]

        unclear = [row for row in results if row[1] == "inconclusive"]
        out = [Finding("account", target, "accent"),
               Finding("found on", f"{len(found)} of {len(results)} sites"
                       + (f" · {len(unclear)} inconclusive" if unclear else ""),
                       "warn" if found else "dim"),
               Finding("", "", "dim")]
        for name, state, detail in results:
            role = {"found": "ok", "not found": "dim"}.get(state, "warn")
            out.append(Finding(name, f"{state}{'  · ' + detail if detail else ''}",
                               role))
        out.append(Finding("", "", "dim"))
        out.append(Finding("caveat", "a match means the name exists on that "
                           "site, not that it is the same person", "dim"))
        return out

    def _source_trace(self, target: str) -> List[Finding]:
        tool = shutil.which("traceroute") or shutil.which("tracepath")
        if not tool:
            raise RuntimeError("neither traceroute nor tracepath is installed")
        command = ([tool, "-n", "-q", "1", "-w", "1", "-m", "20", target]
                   if tool.endswith("traceroute") else [tool, "-n", "-m", "20",
                                                        target])
        try:
            done = subprocess.run(command, capture_output=True, text=True,
                                  timeout=60)
        except subprocess.TimeoutExpired:
            raise RuntimeError("trace timed out after 60s")
        out = []
        for line in done.stdout.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("traceroute"):
                continue
            out.append(Finding("hop", line[:120],
                               "dim" if "no reply" in line or "*" in line
                               else "base"))
        if not out and done.stderr:
            raise RuntimeError(done.stderr.strip()[:160])
        out.append(Finding("tool", os.path.basename(tool), "dim"))
        return out


# ---- helpers --------------------------------------------------------------


PROFILE_READ_BYTES = 120_000


def _probe_profile(site: "ProfileSite", username: str) -> tuple:
    """(state, detail) for one site: found / not found / inconclusive.

    Anything ambiguous is reported inconclusive rather than guessed: a false
    "found" in an OSINT report is worse than an honest "unknown".
    """
    url = site.url.format(username)
    request = urllib.request.Request(url, method="GET", headers={
        "User-Agent": USER_AGENT, "Accept": "text/html,application/json"})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            status = response.status
            final = response.geturl()
            body = response.read(PROFILE_READ_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return "not found", ""
        if exc.code in (401, 403, 429):
            return "inconclusive", f"HTTP {exc.code} · blocked or rate limited"
        return "inconclusive", f"HTTP {exc.code}"
    except Exception as exc:
        return "inconclusive", exc.__class__.__name__

    return _read_profile(site, username, status, final, body)


def _read_profile(site: "ProfileSite", username: str, status: int, final: str,
                  body: str) -> tuple:
    """Apply one site's verification rules to a fetched page."""
    lowered = body.lower()
    for marker in site.blocked_markers:
        if marker.lower() in lowered:
            return "inconclusive", "bot protection"
    if site.absent_url and site.absent_url.lower() in final.lower():
        return "not found", ""
    for marker in site.absent_markers:
        if marker.lower() in lowered:
            return "not found", ""
    if site.present_markers:
        hit = any(marker.lower() in lowered for marker in site.present_markers)
        return ("found", "") if hit else ("not found", "")
    if site.title_has_user:
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
        title = match.group(1) if match else ""
        return ("found", "") if username.lower() in title.lower() \
            else ("not found", "")
    if status != 200:
        return "inconclusive", f"HTTP {status}"
    return "found", ""


def _get_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def _rdap_contacts(data: dict) -> List[Finding]:
    """Pull abuse and registrant contacts out of RDAP's vCard nesting."""
    out: List[Finding] = []
    for entity in (data.get("entities") or [])[:6]:
        roles = ",".join(entity.get("roles") or []) or "contact"
        name, email = "", ""
        for item in (entity.get("vcardArray") or [None, []])[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue
            if item[0] == "fn":
                name = str(item[3])
            elif item[0] == "email":
                email = str(item[3])
        label = " ".join(filter(None, (name, f"<{email}>" if email else "")))
        if label:
            out.append(Finding(roles, label.strip(),
                               "warn" if "abuse" in roles else "base"))
    return out


def _system_resolver() -> str:
    """First nameserver in resolv.conf, falling back to a public resolver."""
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        return parts[1]
    except OSError:
        pass
    return "1.1.1.1"


def _dns_query(name: str, qtype: str, server: str, timeout: float = 4.0
               ) -> List[str]:
    """One DNS query over a normal UDP socket - no raw sockets, no root."""
    from scapy.layers.dns import DNS, DNSQR

    from .dissect import decode_name

    query = DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(bytes(query), (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    response = DNS(data)
    out: List[str] = []
    for index in range(int(response.ancount or 0)):
        try:
            record = response.an[index]
        except Exception:
            break
        text = _rdata_text(record.rdata, decode_name)
        if qtype == "MX":
            text = f"{getattr(record, 'preference', '')} {text}".strip()
        out.append(text)
    return out


def _rdata_text(value, decode_name) -> str:
    """Render one record's rdata. TXT arrives as a list of byte strings."""
    if isinstance(value, (list, tuple)):
        return " ".join(_rdata_text(item, decode_name) for item in value)
    if isinstance(value, bytes):
        return decode_name(value) or value.decode("latin-1", "replace")
    return str(value)


def _tls_unverified(target: str, port: int):
    """Reconnect without verification so a bad certificate can still be read."""
    context = ssl._create_unverified_context()
    with socket.create_connection((target, port), timeout=HTTP_TIMEOUT) as raw:
        with context.wrap_socket(raw, server_hostname=target) as tls:
            return (tls.getpeercert(), tls.version(), tls.cipher(),
                    tls.getpeercert(binary_form=True))


def _tls_findings(cert, proto, cipher) -> List[Finding]:
    out = [Finding("protocol", str(proto), "accent")]
    if cipher:
        out.append(Finding("cipher", f"{cipher[0]} ({cipher[2]} bit)"))
    if not cert:
        return out
    for key, label in (("subject", "subject"), ("issuer", "issuer")):
        value = _flatten_name(cert.get(key))
        if value:
            out.append(Finding(label, value))
    for key, label in (("notBefore", "valid from"), ("notAfter", "valid to")):
        if cert.get(key):
            out.append(Finding(label, cert[key],
                               _expiry_role(key, cert[key])))
    names = [value for kind, value in cert.get("subjectAltName", ())
             if kind in ("DNS", "IP Address")]
    for name in names[:8]:
        out.append(Finding("alt name", name, "dim"))
    if len(names) > 8:
        out.append(Finding("alt name", f"…and {len(names) - 8} more", "dim"))
    return out


def _expiry_role(key: str, value: str) -> str:
    if key != "notAfter":
        return "base"
    try:
        expires = ssl.cert_time_to_seconds(value)
    except Exception:
        return "base"
    remaining = expires - time.time()
    if remaining < 0:
        return "danger"
    return "warn" if remaining < 14 * 86400 else "ok"


def _flatten_name(name) -> str:
    """Turn ssl's nested RDN tuples into `CN=example.com, O=Example`."""
    if not name:
        return ""
    parts = []
    for rdn in name:
        for key, value in rdn:
            short = {"commonName": "CN", "organizationName": "O",
                     "countryName": "C", "organizationalUnitName": "OU",
                     "localityName": "L", "stateOrProvinceName": "ST"}.get(key, key)
            parts.append(f"{short}={value}")
    return ", ".join(parts)


def _openssl_findings(der: bytes) -> List[Finding]:
    """Fall back to the openssl binary when Python cannot decode the cert."""
    if not der or not shutil.which("openssl"):
        return []
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        done = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates"],
            input=pem, capture_output=True, text=True, timeout=10)
    except Exception:
        return []
    out = []
    for line in done.stdout.splitlines():
        label, _, value = line.partition("=")
        if value:
            out.append(Finding(label.strip().lower(), value.strip()))
    return out


def _http_findings(scheme: str, status: int, headers) -> List[Finding]:
    out = [Finding("url", f"{scheme}://", "dim"),
           Finding("status", str(status),
                   "ok" if status < 400 else "warn")]
    lowered = {key.lower(): value for key, value in headers.items()}
    for header in REVEALING_HEADERS:
        if header in lowered:
            out.append(Finding(header, lowered[header], "warn"))
    for header in ("location", "content-type"):
        if header in lowered:
            out.append(Finding(header, lowered[header], "base"))
    present = [h for h in SECURITY_HEADERS if h in lowered]
    missing = [h for h in SECURITY_HEADERS if h not in lowered]
    for header in present:
        out.append(Finding(header, _shorten(lowered[header]), "ok"))
    if missing and scheme == "https":
        out.append(Finding("missing", ", ".join(missing), "warn"))
    return out


def _shorten(value: str, limit: int = 70) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= limit else value[:limit - 1] + "…"
