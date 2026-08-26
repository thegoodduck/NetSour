"""Attribute observed traffic to social platforms, and surface identity hints.

What this can and cannot do, plainly:

* Social traffic is TLS. The **platform** is visible - TLS SNI, DNS questions
  and HTTP Host headers all carry the hostname in the clear - so "this device
  talked to Instagram" is reliably observable.
* The **username** inside that session is not. It sits inside the encrypted
  stream and no amount of passive capture recovers it.

Usernames are therefore only reported where they are genuinely on the wire:

* the hostname embeds one (``someuser.tumblr.com``, ``someuser.github.io``),
  which is an *inferred* hint, or
* the request is plaintext HTTP and the username appears in the path, the query
  string or a JSON body, which is an *observed* hint.

Every hint records how it was obtained and which packet it came from, so a
guess is never presented as a fact.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .enrich import is_private

# Domain -> platform. Includes the CDN and API domains that actually show up in
# capture, since the front-door domain is often not the one contacted.
PLATFORM_DOMAINS: Dict[str, str] = {}


def _register(platform: str, *domains: str) -> None:
    for domain in domains:
        PLATFORM_DOMAINS[domain] = platform


_register("Instagram", "instagram.com", "cdninstagram.com", "ig.me")
_register("Facebook", "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com",
          "messenger.com", "m.me")
_register("Threads", "threads.net")
_register("X / Twitter", "twitter.com", "x.com", "twimg.com", "t.co")
_register("Bluesky", "bsky.app", "bsky.social", "bsky.network")
_register("Mastodon", "mastodon.social", "mastodon.online", "joinmastodon.org")
_register("TikTok", "tiktok.com", "tiktokcdn.com", "tiktokv.com",
          "byteoversea.com", "muscdn.com", "ibytedtos.com")
_register("Snapchat", "snapchat.com", "snap.com", "sc-cdn.net", "snapkit.com")
_register("Reddit", "reddit.com", "redd.it", "redditmedia.com",
          "redditstatic.com")
_register("Discord", "discord.com", "discordapp.com", "discord.gg",
          "discordapp.net", "discord.media")
_register("Telegram", "telegram.org", "t.me", "telegram.me", "telesco.pe",
          "cdn-telegram.org")
_register("WhatsApp", "whatsapp.com", "whatsapp.net", "wa.me")
_register("Signal", "signal.org", "whispersystems.org", "signal.art")
_register("LinkedIn", "linkedin.com", "licdn.com", "lnkd.in")
_register("YouTube", "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
          "yt3.ggpht.com")
_register("Twitch", "twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net")
_register("GitHub", "github.com", "githubusercontent.com", "github.io",
          "githubassets.com")
_register("GitLab", "gitlab.com", "gitlab.io")
_register("Pinterest", "pinterest.com", "pinimg.com")
_register("Tumblr", "tumblr.com", "tumblr.co")
_register("VK", "vk.com", "vk.ru", "userapi.com", "vkuseraudio.net")
_register("Weibo", "weibo.com", "weibocdn.com", "sinaimg.cn")
_register("Steam", "steamcommunity.com", "steampowered.com", "steamstatic.com")
_register("Spotify", "spotify.com", "scdn.co", "spotifycdn.com")
_register("SoundCloud", "soundcloud.com", "sndcdn.com")
_register("Twitch Chat", "irc.chat.twitch.tv")
_register("Medium", "medium.com")
_register("Substack", "substack.com")
_register("Slack", "slack.com", "slack-edge.com", "slack-msgs.com")
_register("Matrix", "matrix.org")
_register("Flickr", "flickr.com", "staticflickr.com")
_register("Vimeo", "vimeo.com", "vimeocdn.com")
_register("Dev.to", "dev.to")
_register("Hacker News", "news.ycombinator.com")

# Hosts of the form <username>.<domain>. The subdomain *is* the account name,
# which makes the username visible in SNI even under TLS.
VHOST_PLATFORMS: Dict[str, str] = {
    "tumblr.com": "Tumblr",
    "github.io": "GitHub Pages",
    "gitlab.io": "GitLab Pages",
    "wordpress.com": "WordPress",
    "substack.com": "Substack",
    "bandcamp.com": "Bandcamp",
    "itch.io": "itch.io",
    "neocities.org": "Neocities",
    "livejournal.com": "LiveJournal",
    "deviantart.com": "DeviantArt",
    "blogspot.com": "Blogger",
    "newgrounds.com": "Newgrounds",
}

# Subdomains that are infrastructure, never account names.
NOT_USERNAMES = {
    "www", "api", "cdn", "static", "assets", "img", "images", "media", "m",
    "mobile", "i", "s", "t", "a", "b", "c", "help", "support", "blog", "mail",
    "smtp", "imap", "pop", "login", "accounts", "account", "auth", "oauth",
    "sso", "id", "secure", "ssl", "dev", "test", "staging", "beta", "alpha",
    "docs", "status", "shop", "store", "news", "video", "live", "chat", "app",
    "apps", "web", "upload", "uploads", "download", "downloads", "files",
    "edge", "origin", "proxy", "gateway", "ns1", "ns2", "mx", "email",
}

# Plaintext-HTTP paths that name an account.
PATH_PATTERNS = [
    (re.compile(r"^/@([A-Za-z0-9._-]{2,40})(?:[/?]|$)"), "path /@handle"),
    (re.compile(r"^/u(?:ser)?/([A-Za-z0-9._-]{2,40})(?:[/?]|$)"), "path /user/"),
    (re.compile(r"^/users/([A-Za-z0-9._-]{2,40})(?:[/?]|$)"), "path /users/"),
    (re.compile(r"^/in/([A-Za-z0-9._-]{2,40})(?:[/?]|$)"), "path /in/"),
    (re.compile(r"^/profile/([A-Za-z0-9._-]{2,40})(?:[/?]|$)"), "path /profile/"),
    (re.compile(r"^/people/([A-Za-z0-9._-]{2,40})(?:[/?]|$)"), "path /people/"),
    (re.compile(r"^/id/([A-Za-z0-9._-]{2,40})(?:[/?]|$)"), "path /id/"),
    (re.compile(r"^/([A-Za-z0-9._-]{2,40})/status/\d+"), "path /<user>/status/"),
]

# Query-string and JSON keys that carry an account name in the clear.
PARAM_KEYS = ("username", "user", "user_name", "screen_name", "login",
              "handle", "account", "nick", "nickname", "uid", "userid",
              "user_id", "email", "id_str")

PARAM_PATTERN = re.compile(
    r"[?&](" + "|".join(PARAM_KEYS) + r")=([A-Za-z0-9._%+@-]{2,64})", re.I)
JSON_PATTERN = re.compile(
    r'"(' + "|".join(PARAM_KEYS) + r')"\s*:\s*"([^"]{2,64})"', re.I)
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{2,60}\.[A-Za-z]{2,12}")
REQUEST_LINE = re.compile(
    r"^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS)\s+(\S+)\s+HTTP/", re.I)
REFERER = re.compile(r"[Rr]eferer:\s*(\S+)")

OBSERVED = "observed"        # read directly off the wire, in the clear
INFERRED = "inferred"        # deduced from a hostname, not from content


@dataclass
class IdentityHint:
    """One candidate identity, with provenance."""

    value: str
    kind: str                 # username | email | profile-url
    platform: str
    method: str               # how it was obtained
    confidence: str           # OBSERVED | INFERRED
    packet_index: int = 0
    ts: float = 0.0
    count: int = 1
    client: str = ""

    @property
    def key(self) -> tuple:
        return (self.client, self.platform, self.kind, self.value.lower())


@dataclass
class PlatformActivity:
    """What one client did with one platform."""

    platform: str
    client: str
    first_ts: float
    last_ts: float
    requests: int = 0
    bytes: int = 0
    hostnames: Set[str] = field(default_factory=set)
    cleartext: bool = False        # was any of it readable?
    packets: List[int] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


def platform_for(hostname: str) -> Optional[str]:
    """Platform owning `hostname`, matching the longest domain suffix."""
    if not hostname:
        return None
    host = hostname.lower().rstrip(".")
    parts = host.split(".")
    for start in range(len(parts)):
        candidate = ".".join(parts[start:])
        platform = PLATFORM_DOMAINS.get(candidate)
        if platform:
            return platform
    return None


def vhost_username(hostname: str) -> Optional[tuple]:
    """(username, platform) when the hostname itself names an account."""
    if not hostname:
        return None
    host = hostname.lower().rstrip(".")
    for domain, platform in VHOST_PLATFORMS.items():
        if host.endswith("." + domain):
            label = host[: -(len(domain) + 1)]
            if "." in label:                 # deeper subdomain, not an account
                continue
            if label in NOT_USERNAMES or len(label) < 2:
                continue
            return label, platform
    return None


def looks_like_username(value: str) -> bool:
    """True for a bare account name - no dots, no scheme, no address."""
    if not value or len(value) > 40 or len(value) < 2:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", value)) \
        and "." not in value


class SocialTracker:
    """Folds packets into per-client platform activity and identity hints.

    Fed from the capture thread under the session lock, exactly like the flow
    table and the alert engine.
    """

    def __init__(self, max_hints: int = 2000):
        self.max_hints = max_hints
        self.activity: Dict[tuple, PlatformActivity] = {}   # (client, platform)
        self.hints: Dict[tuple, IdentityHint] = {}
        self.cleartext_requests = 0

    # ---- ingest -----------------------------------------------------------

    def inspect(self, rec) -> None:
        """Fold one packet in. Never raises."""
        try:
            self._inspect(rec)
        except Exception:
            pass

    def _inspect(self, rec) -> None:
        hostname = rec.hostname
        platform = platform_for(hostname) if hostname else None
        vhost = vhost_username(hostname) if hostname else None
        if vhost and not platform:
            platform = vhost[1]
        if platform is None:
            return

        client = self._client_of(rec)
        entry = self.activity.get((client, platform))
        if entry is None:
            entry = PlatformActivity(platform=platform, client=client,
                                     first_ts=rec.ts, last_ts=rec.ts)
            self.activity[(client, platform)] = entry
        entry.last_ts = rec.ts
        entry.requests += 1
        entry.bytes += rec.length
        if hostname:
            entry.hostnames.add(hostname)
        if len(entry.packets) < 50:
            entry.packets.append(rec.index)

        if vhost:
            self._add(IdentityHint(
                value=vhost[0], kind="username", platform=vhost[1],
                method=f"hostname {hostname}", confidence=INFERRED,
                packet_index=rec.index, ts=rec.ts, client=client))

        if "HTTP" in rec.proto and rec.payload_text:
            entry.cleartext = True
            self.cleartext_requests += 1
            self._scan_http(rec, platform, client)

    @staticmethod
    def _client_of(rec) -> str:
        """The local end of the conversation - the device doing the browsing."""
        if rec.src and is_private(rec.src):
            return rec.src
        if rec.dst and is_private(rec.dst):
            return rec.dst
        return rec.src or rec.dst or "?"

    def _scan_http(self, rec, platform: str, client: str) -> None:
        """Pull account names out of a plaintext HTTP request."""
        text = rec.payload_text
        match = REQUEST_LINE.search(text)
        path = match.group(2) if match else ""

        if path:
            for pattern, method in PATH_PATTERNS:
                found = pattern.match(path)
                if found and looks_like_username(found.group(1)):
                    self._add(IdentityHint(
                        value=found.group(1), kind="username", platform=platform,
                        method=method, confidence=OBSERVED,
                        packet_index=rec.index, ts=rec.ts, client=client))
                    break

        for pattern, method in ((PARAM_PATTERN, "query parameter"),
                                (JSON_PATTERN, "JSON body")):
            for key, value in pattern.findall(text):
                value = urllib.parse.unquote_plus(value)
                if "@" in value or key.lower() == "email":
                    kind = "email"
                elif value.isdigit():
                    # A numeric account id is an identifier, but calling it a
                    # username would misrepresent what was seen.
                    kind = "user-id"
                elif looks_like_username(value):
                    kind = "username"
                else:
                    continue
                self._add(IdentityHint(
                    value=value, kind=kind, platform=platform,
                    method=f"{method} {key.lower()}=", confidence=OBSERVED,
                    packet_index=rec.index, ts=rec.ts, client=client))

        for address in EMAIL_PATTERN.findall(text)[:3]:
            self._add(IdentityHint(
                value=address, kind="email", platform=platform,
                method="address in cleartext payload", confidence=OBSERVED,
                packet_index=rec.index, ts=rec.ts, client=client))

        referer = REFERER.search(text)
        if referer:
            url = referer.group(1)
            host = url.split("/")[2] if url.count("/") > 2 else ""
            named = vhost_username(host)
            if named:
                self._add(IdentityHint(
                    value=named[0], kind="username", platform=named[1],
                    method="Referer header", confidence=OBSERVED,
                    packet_index=rec.index, ts=rec.ts, client=client))

    def _add(self, hint: IdentityHint) -> None:
        existing = self.hints.get(hint.key)
        if existing is not None:
            existing.count += 1
            existing.ts = hint.ts
            # An observation always outranks an inference.
            if existing.confidence == INFERRED and hint.confidence == OBSERVED:
                existing.confidence = OBSERVED
                existing.method = hint.method
                existing.packet_index = hint.packet_index
            return
        if len(self.hints) >= self.max_hints:
            return
        self.hints[hint.key] = hint

    # ---- queries ----------------------------------------------------------

    def clients(self) -> List[str]:
        return sorted({key[0] for key in self.activity})

    def activity_for(self, client: str = "") -> List[PlatformActivity]:
        entries = [entry for key, entry in self.activity.items()
                   if not client or key[0] == client]
        return sorted(entries, key=lambda e: (-e.requests, e.platform))

    def hints_for(self, client: str = "") -> List[IdentityHint]:
        found = [hint for hint in self.hints.values()
                 if not client or hint.client == client]
        return sorted(found, key=lambda h: (h.confidence != OBSERVED,
                                            -h.count, h.platform, h.value))

    def usernames(self, client: str = "") -> List[str]:
        seen = []
        for hint in self.hints_for(client):
            if hint.kind == "username" and hint.value not in seen:
                seen.append(hint.value)
        return seen

    def correlated(self, client: str = "") -> List[tuple]:
        """(value, [platforms]) for names seen on more than one platform.

        Reuse of the same handle across services is the strongest link this
        can offer - it is still a correlation, not an identification.
        """
        platforms: Dict[str, Set[str]] = {}
        for hint in self.hints_for(client):
            if hint.kind not in ("username", "email"):
                continue
            platforms.setdefault(hint.value, set()).add(hint.platform)
        return sorted(((value, sorted(found))
                       for value, found in platforms.items() if len(found) > 1),
                      key=lambda row: (-len(row[1]), row[0]))

    def summary(self, client: str = "") -> dict:
        entries = self.activity_for(client)
        hints = self.hints_for(client)
        return {
            "platforms": len(entries),
            "requests": sum(e.requests for e in entries),
            "bytes": sum(e.bytes for e in entries),
            "cleartext_platforms": sum(1 for e in entries if e.cleartext),
            "usernames": len([h for h in hints if h.kind == "username"]),
            "emails": len([h for h in hints if h.kind == "email"]),
        }

    def clear(self) -> None:
        self.activity.clear()
        self.hints.clear()
        self.cleartext_requests = 0
