# NetSour

Live packet capture, protocol analysis and network reconnaissance in a terminal
UI. NetSour dissects traffic as it arrives, tracks every conversation, watches
for attack patterns, and lets you drill from a packet list down to the bytes on
the wire without leaving the keyboard.

```
 NetSour  │  wlp41s0 192.168.2.95  │  ● LIVE            12,904 pkts · 18.3M · 214 p/s · 1.4M/s · 04:21
  1 Packets   2 Flows   3 Stats   4 Alerts 3   5 Hosts   6 Recon                              follow on
╭─ Packets ──────────────────────────────────────────────────────────── 12,904 shown of 12,904 ╮
│ #      Time         Source                 Destination            Proto     Len   Info       │
│ 12901  09:14:22.104 192.168.2.95:51100     93.184.216.34:443      TCP/TLS   571   ClientHe…  │
│ 12902  09:14:22.118 192.168.2.95:40001     1.1.1.1:53             UDP/DNS   84    Query A …  │
│•12903  09:14:22.140 192.168.2.95:51100     203.0.113.7:80         TCP/HTTP  144   POST /lo…  │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Detail · hex ─────────────────────────────────────────────── tree [hex] stream geo nmap ────╮
│ 00000070  3a 20 42 61 73 69 63 20  59 57 52 74 61 57 34 36  : Basic YWRtaW46               │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Features

**Capture and dissection**
- Live capture on any interface, with an optional BPF filter set at startup or
  changed from inside the UI
- Offline pcap replay (`-r file.pcap`) — no root needed
- Protocol dissection down to the application layer: DNS and mDNS questions and
  answers, TLS SNI, HTTP request lines and Host headers, ICMP types, ARP
  request/reply semantics, and service names for ~90 well-known ports
- Bounded ring buffer, so a long capture never exhausts memory
- Export the buffer — or only what your filter shows — back out to pcap

**Nine views**
| View | What it shows |
| --- | --- |
| Packets | Scrolling table plus a detail pane: dissection tree, hex dump, reassembled stream, geolocation, Nmap results |
| Devices | Every device on your LAN, identified — as an address list beside an identity pane, or as a wall of cards (`v` switches) — pick one to see only its traffic |
| Flows | Every conversation, bidirectionally merged, with byte counts per direction, rate, duration and TCP state |
| Stats | Throughput sparklines, protocol mix, packet-size distribution, top talkers, top services, resolved names |
| Alerts | Security findings, sorted by time or severity — press Enter to pivot to the flow, the packet, a filter, OSINT or a scan |
| Hosts | Every endpoint seen — address, rDNS name, MAC, hardware vendor, traffic totals |
| Recon | ARP sweep of the local /24, drawn as a topology tree |
| OSINT | Everything known about one target: registry, DNS, TLS, HTTP, path, ports |
| Dash | Your dashboard: a board of cards you choose, plus anything your addons draw |

**Threat detection**, running live over the capture stream:
port scans · host sweeps · SYN floods · traffic and ICMP floods · ARP spoofing
(MAC changes for a known IP) · cleartext credentials (HTTP Basic, FTP, IMAP,
credentials in URLs and JSON bodies) · DNS tunnelling · NXDOMAIN storms ·
oversized ICMP payloads · connections to known backdoor ports · new hosts
appearing on the segment.

**Devices** — the Devices view answers "what is actually on this network". The
left pane is one row per address; the right pane is the identity of whichever
one is selected:

```
 3 DEVICES   3 online   1 offline hidden ('o')

 ● 192.168.2.1    router.lan          │  ╭────╮   viktors-iphone
 ● 192.168.2.23   viktors-iphone      │  │▒▒▒▒│   Phone / Tablet  (confirmed)
 ● 192.168.2.44   Printer             │  ╰─▭──╯   ONLINE
                                      │
                                      │ address    192.168.2.23
                                      │ hardware   3c:2e:f9:11:04:8a · Apple
                                      │ evidence   advertises _companion-link
                                      │ presence   ARP reply
```

Press `v` for the other layout: the same devices as a grid of cards, each with
an icon for its kind, its name, vendor and traffic, and the detail along the
foot of the pane.

```
╭───────────────────────────────────╮ ╭───────────────────────────────────╮
│ ╭──────╮  router.lan              │ │  ╭────╮   viktors-iphone          │
│ │ ((•))│  192.168.2.1             │ │  │▒▒▒▒│   192.168.2.23            │
│ ╰─┬┬┬┬─╯  Router / Gateway · TP-L…│ │  ╰─▭──╯   Phone / Tablet · Apple  │
╰─▲5.4K ▼4.3K 16p────────────GATEWAY╯ ╰─▲4.3K ▼1.9K 14p──────────confirmed╯
```

A device drops off the list once nothing has been heard from it for five
minutes — no packet, no reply to the last ARP sweep. Presence is measured
against the capture's own clock, so a pcap replay reports what was true while
it was recorded rather than marking every host dead. Press `o` to show the
ones that have gone quiet, with how long ago each was last seen.

An address only counts as a device once something proves it exists — a frame it
sent, or a reply to an ARP sweep. Being *addressed* is not proof: the sweep asks
all 254 hosts of a /24 whether or not anything is there.

Kind is inferred from what the device advertises over mDNS/DNS-SD, the name it
claims for itself, the ports it *serves*, its IP TTL, its MAC vendor, and
whether it is your default gateway. Signals vote **by weight**, not by count — a
self-declared `_googlecast._tcp` advert outranks a Samsung OUI, because a
manufacturer makes phones and TVs alike. The identity pane shows `confirmed`,
`likely` or `unknown`, and lists every signal that contributed, heaviest first,
so no guess is silent.

A device is only ever named by something it says about **itself** — a DHCP
option-12 hostname, or an mDNS A record pointing at its own address. Names seen
in passing traffic (a DNS answer, a TLS SNI, an HTTP Host) describe what a
packet is *about*, never who sent it.

**Press Enter or click an address and the packet list filters to that device.**
That is the fastest way to answer "what is this thing talking to". `Esc` or `F`
clears it again.

On a switched network passive capture only reveals devices that broadcast, so
press `S` to ARP-sweep the subnet — that asks every address directly and fills
the list in.

**Filtering** — toggle protocols with single keys, or type `/` and search across
addresses, ports, protocol labels, dissected info *and packet payloads*.

**Scanning** — press `n` in any view and NetSour offers every address the
selected row references: packet source *and* destination, both ends of a flow,
the selected host, a swept host, a hostname seen in DNS or TLS — or type one.
Ten Nmap profiles (`N`):

| | | |
| --- | --- | --- |
| `fast` | top 100 ports | `stealth` | SYN scan, no handshake (root) |
| `top1000` | top 1000 ports | `udp` | top 50 UDP ports (root) |
| `service` | versions | `os` | OS fingerprint (root) |
| `vuln` | NSE vulnerability scripts | `aggressive` | everything (root) |
| `full` | all 65535 ports | `ping` | discovery only |

Profiles needing root are shown greyed with the reason when you are not.

**OSINT** — press `O` to pick a target and open the OSINT view, which assembles:

| Source | Kind | What it does |
| --- | --- | --- |
| Reverse DNS | passive | PTR record |
| Geolocation & ASN | passive | country, city, ISP, org, AS number |
| RDAP registry | passive | network/domain registration, CIDR, **abuse contacts** |
| DNS records | passive | A, AAAA, MX, NS, TXT, CNAME |
| TLS certificate | active | subject, issuer, SANs, validity, chain result |
| HTTP headers | active | server banner, redirect, **missing security headers** |
| Network path | active | traceroute to the target |
| Social activity | passive | platforms this host used, and identity hints (below) |
| Account lookup | active | checks a username against 18 public profile pages |
| Open ports | active | the Nmap results for this host |

**Passive** sources only ever query public registries and resolvers — the target
never sees them. **Active** sources connect to the target itself and are always
confirmed first; `r` runs the passive set, `R` runs everything.

An OSINT target can be an **IP**, a **hostname**, or a bare **account name** —
NetSour picks the applicable sources from the shape of what you give it.

### Social attribution — and what it honestly cannot do

Social traffic is TLS. The **platform** is visible, because SNI, DNS questions
and HTTP Host headers all carry the hostname in the clear. The **username inside
that session is not**, and no amount of passive capture recovers it.

So NetSour reports usernames only where they are genuinely on the wire, and
labels how each one was obtained:

- **`observed`** — read out of plaintext HTTP: a `/u/<name>` path, a
  `?username=` parameter, a JSON body, a `Referer` naming a profile.
- **`inferred`** — the hostname itself is the account (`someone.tumblr.com`,
  `devpages.github.io`), so TLS SNI leaks it.

Encrypted sessions are shown as platform activity with `no username visible`.
Reuse of one handle across platforms is called out as `reused`, which is a
correlation, not an identification. Every hint cites the packet it came from.

```
Social activity   [passive]
  Instagram      13 packets · 2 hosts · encrypted
  X / Twitter    12 packets · 2 hosts · cleartext
  Reddit          9 packets · 1 hosts · cleartext
  username       nightowl_dev  (Reddit) · observed · path /user/ · packet #113
  username       nightowl_dev  (X / Twitter) · observed · JSON body screen_name=
  username       devdotpages   (GitHub Pages) · inferred · hostname · packet #106
  reused         nightowl_dev on Reddit, X / Twitter
```

Account names found this way are offered as OSINT targets in the `O` picker, so
you can pivot from traffic straight to an account lookup.

Account lookup checks 18 public profile pages. Several soft-404 — returning HTTP
200 for a name that does not exist — so each site carries an explicit
verification rule (a body marker, a redirect, or the page title). A name that
exists nowhere returns **zero** hits; sites behind bot protection are reported
`inconclusive` rather than guessed at. A match means the *name* exists there,
not that it is the same person.

**Dashboard and addons** — the Dash view (`9`) is a board of cards. `Enter`
picks which ones it shows; the choice is remembered. Anything an addon
contributes lands on the same board.

An addon is one Python file in `~/.config/netsour/addons`. `netsour --new-addon
NAME` writes a working starter, or press `A` → *New addon…* from inside the UI
and `A` → *Reload* after editing — no restart, no capture lost.

```python
from netsour.addon import alert, key, on_packet, panel

queries = {}


@on_packet                       # capture thread, once per packet
def watch(pkt):
    if pkt.proto.endswith("DNS") and pkt.hostname:
        queries[pkt.hostname] = queries.get(pkt.hostname, 0) + 1
    if pkt.dport == 23:
        alert("Telnet in use", f"{pkt.src} → {pkt.dst}", "medium", pkt)


@panel("Busiest lookups")        # one card on the dashboard
def card(ctx):
    top = sorted(queries.items(), key=lambda kv: -kv[1])[:5]
    peak = max([n for _, n in top], default=1)
    return [f"{host[:20]:<20} {ctx.bar(n, peak, 8)} {n}" for host, n in top] \
        or [("nothing yet", "dim")]


@key("z", "reset the counts")    # UI thread, when 'z' is pressed
def reset(ui):
    queries.clear()
    ui.notify("lookup counts cleared", "ok")
```

Hooks run inside the session lock, which is what makes reading capture state
from a panel safe, and everything an addon raises is caught: a panel that throws
shows its error on its own card, and an addon that keeps throwing is switched
off with its traceback kept in the `A` menu. A broken addon cannot stop capture
or take down the UI, and addon key bindings are tried last, so they can never
shadow a NetSour key.

## Install

```bash
pip install -e .              # core: live capture, analysis, everything but Nmap
pip install -e '.[scan]'      # ...plus the 'n' key's Nmap integration
sudo apt install nmap         # the Nmap binding also needs the binary
```

The Nmap feature needs **both** the `python-nmap` binding (the `scan` extra) and
the `nmap` binary. If either is missing the `n` key says so and the rest of
NetSour is unaffected.

Capture needs raw socket access. Either run under `sudo`, or grant the
capability once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

Working in a virtualenv? `sudo` resets `PATH`, so point it at the venv's
interpreter explicitly — `sudo .venv/bin/netsour` — or activate the venv first.

## Usage

```bash
sudo netsour                          # pick an interface interactively
sudo netsour -i eth0                  # straight to an interface
sudo netsour -i eth0 -f 'tcp port 443'   # with a BPF capture filter
netsour -r capture.pcap               # replay a file, no privileges needed
netsour --list-interfaces
```

| Option | Meaning |
| --- | --- |
| `-i, --interface` | interface to capture on |
| `-r, --read` | replay a pcap instead of capturing |
| `-f, --filter` | BPF capture filter |
| `-b, --buffer` | packets held in memory (default 20000) |
| `--theme` | `midnight`, `nord`, `matrix`, `amber` or `paper` |
| `--fps` | UI refresh rate (default 12) |
| `--no-promisc` | leave the interface out of promiscuous mode |
| `--no-rdns` / `--no-geo` | disable background name / geolocation lookups |
| `--addon-dir` | load addons from somewhere other than `~/.config/netsour/addons` |
| `--no-addons` | do not load addons at all |
| `--list-addons` | list what would load (and what is broken), then exit |
| `--new-addon NAME` | write a starter addon called NAME, then exit |

## Keys

Press `?` in the app for the full reference.

| | |
| --- | --- |
| `1`–`9`, `←` `→` | switch views (arrows move within the device list) |
| `↑` `↓` `j` `k`, `PgUp` `PgDn`, `g` `G` | navigate |
| `Tab` | move focus between the packet list and the detail pane |
| `d` | cycle the detail pane: tree → hex → stream → geo → nmap |
| `/` | text filter (`Esc` clears) |
| `t` `u` `i` `a` `o` | toggle TCP / UDP / ICMP / ARP / other |
| `!` | show only flagged packets · `F` reset all filters |
| `Space` | pause or resume capture |
| `f` | follow mode — stick to the newest packet |
| `w` `W` | write all / filtered packets to a pcap |
| `b` | change the BPF capture filter |
| `c` | clear the buffer, stats, flows and alerts |
| `s` | cycle the sort key (flows, alerts, hosts) |
| `n` `N` | pick an address to Nmap · choose the scan profile |
| `O` | pick an address and open it in the OSINT view |
| `G` | geolocate an address |
| `S` | ARP-sweep the local /24 |
| click | select a row; click again for its actions |
| `Enter` | in Devices: show only that device's traffic |
| `Enter` | in Alerts: pivot to the flow, packet, filter, OSINT or a scan |
| `r` `R` `x` | in OSINT: run passive · run everything · set the target |
| `Enter` | in Dash: choose which cards the board shows |
| `A` | addons: reload from disk, scaffold a new one, read an addon's error |
| `T` | choose a colour theme · `q` quit |

## Design notes

Capture runs on its own thread and does all dissection there, appending
render-ready records to a ring buffer under one lock. The UI is single-threaded
and draws from one snapshot per frame, so a redraw can never race an arriving
packet. Display filters are applied incrementally as packets arrive and rebuilt
in full only when the filter itself changes.

The UI reads capture state through exactly one door — `Session.derive()` returns
one immutable bundle per refresh, built under a single lock. Iterating a live
counter or the record buffer mid-capture is what makes a sniffer TUI crash on a
busy link, so no view is allowed to touch them.

Nothing reaches out to the network unless you ask it to. Reverse DNS runs in the
background (disable with `--no-rdns`). Everything else — geolocation, OSINT,
Nmap, ARP sweeps — is key-triggered, and anything that sends packets to a host
asks for confirmation naming the host first.

## Testing

```bash
python -m unittest discover -s tests -t .
```

358 tests covering dissection, the detectors, session and buffer behaviour,
pcap round-trips, device identification and its evidence rules, OSINT gating and
parsing, social attribution and its observed/inferred boundary,
profile-verification rules, menu navigation, addon loading and isolation,
dashboard layout, a
headless curses pass that draws every view at four terminal sizes in every
theme, and a concurrency test that renders while a writer thread floods the
session.

## Note

For educational use, network administration and authorised security testing
only. Capturing traffic and scanning hosts on networks you do not own or
administer is illegal in most jurisdictions. Get permission first.

Social attribution deserves its own line. It analyses traffic you are already
authorised to capture, and it is genuinely useful for the questions network
operators have to answer — what is this device doing, is anything sending
credentials in the clear, which account was compromised. It is not a
people-search tool, and pointing it at someone whose network you do not run is
both a privacy violation and, in most places, a crime.

## License

GPL v3
