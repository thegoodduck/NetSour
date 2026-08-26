# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**NetSour** is a terminal packet sniffer, protocol analyzer and network recon
tool built on Python + Scapy + curses. It captures live traffic (root required),
dissects it down to the application layer, tracks conversations and hosts, runs
live threat detection, and presents all of it in a nine-view TUI — the last of
which is a dashboard of cards that single-file addons can add to.

## Commands

```bash
# Install (editable). The Nmap integration is an optional extra and needs the
# nmap binary too; without both, NmapScanner.available is False and the 'n' key
# reports that rather than failing.
pip install -e .
pip install -e '.[scan]'       # adds python-nmap
sudo apt install nmap

# Run
sudo netsour                   # interactive interface picker
sudo netsour -i eth0 -f 'tcp port 443'
netsour -r capture.pcap        # offline replay, no root needed
netsour --new-addon dnstop     # scaffold an addon, then edit it
netsour --list-addons          # what loads, and what is broken
netsour --no-addons            # load none of it
python -m netsour --help
sudo python main.py            # legacy shim, still works

# Tests
python -m unittest discover -s tests -t .
python -m unittest tests.test_security -v
python -m unittest tests.test_security.TestReconDetectors.test_port_scan_is_detected
```

Development without root: replay a pcap with `-r`. Every code path except the
live sniffer runs unprivileged, and `tests/factory.py` builds synthetic packets
for any protocol the dissector understands.

## Architecture

```
netsour/
  cli.py         argparse, interface picker, root check, curses bootstrap
  capture.py     CaptureEngine (sniffer thread / pcap replay), pcap writing
  dissect.py     scapy packet -> PacketRecord (the render-ready row)
  session.py     Session: ring buffer, display filter, wires everything together
  flows.py       FlowTable: bidirectional conversation aggregation
  stats.py       counters, per-second history, byte/duration formatting
  security.py    AlertEngine: the live threat detectors
  addons.py      AddonRegistry: loads addon files, owns every contribution
  addon.py       the decorators an addon file imports (the public API)
  dashboard.py   the built-in dashboard cards, written against that same API
  enrich.py      async rDNS / geo-IP / MAC vendor / Nmap, plus arp_sweep
  osint.py       OsintEngine: rDNS, geo, RDAP, DNS, TLS, HTTP, traceroute,
                 social attribution, username lookup
  social.py      SocialTracker: platform attribution and identity hints
  devices.py     DeviceRegistry: identify and classify hosts on the LAN
  detail.py      protocol tree, hex bytes, stream reassembly for the detail pane
  services.py    port -> service name
  ui/
    theme.py     ThemeSpec -> generated role table; 256 -> 8 -> mono fallback
    render.py    clipped drawing, boxes, bars, sparklines, column layout
    menu.py      the modal chooser used by every picker
    views.py     one renderer per view
    app.py       App: layout, chrome, key handling, prompts, menus
```

### Threading model

One capture thread, one UI thread, plus small worker pools for enrichment.

- The capture thread calls `Session._on_packet`, which dissects and folds the
  packet into flows/stats/alerts under `Session.lock`, then appends to the ring
  buffer and (if it passes the filter) to `Session.view`.
- The UI thread is the main thread. There is no input thread — `getch` is
  non-blocking with a timeout, so input and rendering are one loop.
- **The UI reads capture state only through `Session.derive()`**, which builds
  the whole frame's data — packet list, flows, alerts, hosts, stats, recon — as
  one immutable `Derived` bundle under a single lock acquisition. `App.derived`
  holds it; `App.visible` / `flow_rows` / `alert_rows` / `host_rows` are
  properties over it, and views must never reach past them to `session.records`,
  `session.flows`, `session.stats` or the recon fields.
- Addon code runs on both threads but never concurrently: packet hooks are
  called from `Session._on_packet` and panels from `Session.derive()`, and both
  hold `Session.lock`. That is what lets a panel read `session.records` or the
  flow table directly — and why a slow panel costs capture throughput.
- Enrichment (rDNS, geo, Nmap) runs on bounded `_Worker` pools in `enrich.py`.
  These are the only things that touch the network beyond capture, and none of
  them is ever called from a render path.

### Invariants worth preserving

- **Dissection happens once, on the capture thread.** `PacketRecord` holds plain
  strings and ints. If a view needs a scapy object to draw a row, that is a bug.
- **`Session.view` is always a subsequence of `Session.records`.** Ring-buffer
  rotation pops from both.
- **Never iterate a live capture structure from the render path.** The capture
  thread appends to the record deque, the flow dict, the alert list and the
  stats Counters continuously; iterating any of them mid-mutation raises
  RuntimeError and kills the UI. This is why `Stats.snapshot()` returns a
  `StatsView` of copied lists rather than the Counters themselves, and why
  stream reassembly goes through `Session.stream_for()`. Adding a view that
  reads a counter directly reintroduces the bug — it will look fine on a pcap
  replay that has already finished and crash on live capture.
- **Nothing probes without being asked.** Auto-scanning every source IP is what
  the old version did; it is both noisy and legally hazardous. Nmap, geo and ARP
  sweep are key-triggered, and the two that emit packets confirm first.
- **All drawing goes through `render.addstr`**, which clips to the window and
  sanitizes control characters. Packet payloads are attacker-controlled text;
  writing them to the screen unsanitized corrupts the frame.
- **Detectors must never raise.** `AlertEngine.inspect` and
  `SocialTracker.inspect` swallow exceptions by design — a bug in either must
  not stop capture.
- **Addons are untrusted the same way.** Every call into addon code goes through
  `AddonRegistry._call` or the `try` in `render_panels`, which record the
  traceback and disable the addon after `MAX_FAILURES`. Calling an addon hook
  directly anywhere reintroduces the crash it exists to prevent. A panel returns
  plain strings; nothing live may escape a card into the render path.
- **`PacketRecord.hostname` is a target, never an identity.** It holds whatever
  the packet is *about* — a TLS SNI, a DNS question, an HTTP Host. Naming a
  device with it labelled a router `api.anthropic.com`, because the router was
  the DNS resolver answering that lookup. Only `PacketRecord.device_name` — a
  DHCP option-12 hostname, or an mDNS A record whose rdata is the sender's own
  address — may name a device. `PacketRecord.services` carries DNS-SD
  advertisements, which are classification evidence, not names.
- **Never present an inference as an observation.** `SocialTracker` labels every
  identity hint `observed` (read from cleartext) or `inferred` (deduced from a
  hostname) and records the packet index. TLS carries the platform and nothing
  more; any code path that reports a username from an encrypted session is a
  bug, and the tests in `test_social.py` exist to catch exactly that.

### Performance

Ingest runs at roughly 14k packets/sec single-threaded. The hot path is
`dissect()`; the two things that matter are `layer_map()` (walks the scapy layer
chain once instead of asking `X in packet` a dozen times) and `wire_length()`
(reads the captured bytes instead of re-serialising the packet). Re-introducing
repeated `packet[Layer]` lookups roughly halves throughput.

## Adding things

**A view**: append to `VIEWS` in `ui/app.py` **and add a constant to the
`range(len(VIEWS))` unpacking below it** — every conditional refers to views by
name, never by number, because renumbering by hand is how `7` silently stopped
working once already. Then add a renderer in `ui/views.py`, register it in the
`renderer` dict in `_draw_view`, give it a row count in `_row_count` and a
hit-area row offset in the `header_rows` dict. The digit keys size themselves
off `len(VIEWS)`. Tests must use the constants too.

**An addon**: nothing in the codebase — that is the point. It is one file in
`~/.config/netsour/addons` importing `netsour.addon`; `AddonRegistry.scaffold`
writes the template, and `A` → Reload in the UI re-executes it. Extending what
addons *can* do means adding a decorator to `addon.py`, a list on `Addon`, and a
dispatch point in `AddonRegistry` — keep the three in step, and keep the
decorator working when no registry is loading (an addon file must stay
importable on its own, which is what makes it testable).

**A dashboard card**: append to `BUILTINS` in `dashboard.py` — a key, a title, a
function `(ctx) -> lines` and a sort order. Built-in cards go through the addon
registry like any other panel, so anything a card needs from `PanelContext`
becomes API for addons too; add it there rather than reaching around it. Cards
render before the board is laid out, so `ctx.width` is all a card knows about
its size.

**A device signal**: add to `SERVICE_KINDS`, `VENDOR_KINDS`, `NAME_KINDS` or
`PORT_KINDS` in `devices.py`. Signals vote in `classify()` **by weight**
(`WEIGHT_SERVICE` > `WEIGHT_HOSTNAME` = `WEIGHT_PORT` > `WEIGHT_VENDOR`), and
each one that fires appends to `Device.evidence`. A MAC OUI is deliberately the
weakest signal: Samsung makes both phones and TVs, so anything the device
declares about itself must outrank it. Ports only count for the side that was
*connected to*, not the client.

**A theme**: add a `ThemeSpec` to `THEME_SPECS` in `ui/theme.py` — a dozen
colour numbers. The role table, the 8-colour fallback and the `--theme` choices
all derive from it; do not hand-write role dictionaries.

**An OSINT source**: add a `Source` to `SOURCES` in `osint.py` and a matching
`_source_<key>` method returning `list[Finding]`. Set `active=True` if it
connects to the target — the UI confirms those and excludes them from `run_all`
unless asked. `applies` is `ip`, `host`, `username` or `both`, matched against
`target_kind()`. Raise on failure; `_execute` records it as an error section.

**A username-lookup site**: add a `ProfileSite` to `USERNAME_SITES`. Check it
against a name that exists *and* one that does not before trusting the status
code — six of the first eighteen sites soft-404 (HTTP 200 with a "no such user"
page). Give those a verification rule: `absent_markers`, `present_markers`,
`absent_url`, or `title_has_user`. Anything you cannot verify must report
`inconclusive`; a false "found" in an OSINT report is worse than no answer.

**A social platform**: call `_register(name, *domains)` in `social.py` with the
CDN and API domains too — the front-door domain is often not the one contacted.
Hosts of the form `<user>.<domain>` go in `VHOST_PLATFORMS` instead.

**An Nmap profile**: add to `NmapScanner.PROFILES` as
`(args, description, needs_root, duration)`. Root-only profiles are greyed out
with a reason in the picker and refused in `request()`.

**A picker**: build `MenuItem`s and call `App.open_menu`. A `MenuItem` with
`value=None` is a heading; one with `enabled=False` is a disabled option that
still shows its hint. Do not use `value=None` to disable — that turns it into a
heading and loses the hint.

## Testing

`tests/` mirrors the modules: `test_dissect`, `test_security`, `test_session`,
`test_osint`, `test_menu`, `test_ui`, `test_cli`, `test_addons`. `tests/factory.py` builds packets and round-trips them
through bytes so they behave like captured frames rather than unbuilt scapy
objects.

`test_ui.py` runs real curses against a pseudo-terminal (`_HeadlessTerminal`)
and draws every view at four terminal sizes. That screen is a module-level
singleton resized between tests — repeatedly entering `initscr` leaves drain
threads blocked on closed descriptors, which hangs the suite.

`test_addons.py` writes addon files into a temporary directory and points
`NETSOUR_CONFIG_HOME` at it — the registry persists the dashboard layout to
disk, so any test that toggles a card must do the same or it edits the
developer's own configuration.

Detector tests supply timestamps explicitly, so none of them depends on the
wall clock. When adding a detector, add both a positive case and a
negative one showing ordinary traffic does not trip it.

`test_osint.py` mocks every source — the suite must never make a network
request. `TestConcurrentRendering` in `test_ui.py` renders every view while a
writer thread floods the session; it is the regression guard for the whole class
of "iterated a live structure" crashes and must keep passing.

## Release

```bash
git tag v0.X.X && git push origin v0.X.X
```

`.github/workflows/python-publish.yml` builds and publishes to PyPI on a GitHub
release, using the `PYPI_PASSWORD` secret. Version lives in `pyproject.toml` and
`netsour/__init__.py` — keep them in sync.

## Common issues

- **Permission denied on capture** — run with sudo, or
  `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`.
- **Nmap keys do nothing** — needs both `python-nmap` and the `nmap` binary;
  `NmapScanner.available` reflects that check. `pip install -e .` alone does
  *not* pull the binding: it lives in the `scan` extra.
- **ModuleNotFoundError: scapy under sudo** — `sudo` resets `PATH` to the system
  interpreter. Use `sudo .venv/bin/netsour`, or activate the venv first.
- **Scapy warnings corrupting the screen** — `cli._silence_scapy()` must run
  before curses starts. Anything that prints to stdout while curses owns the
  terminal will scramble the display; use the message line (`App.notify`).
- **Terminal too small** — the UI needs 60x12 and says so rather than crashing.
- **Devices view is empty or thin** — passive capture on a switch only sees
  broadcast traffic, so most devices never appear until they speak. `S` runs an
  ARP sweep, which is what actually populates the list. Devices quiet for more
  than `devices.IDLE_SECONDS` are hidden until `o` asks for them, and `v`
  switches between the address-list layout and the card grid.
  `DeviceRegistry.build` only counts an address that *sent* something, carries a
  MAC, or answered the sweep — a destination address is not a device, or the
  sweep itself would invent one per empty address.
  `DeviceRegistry` also filters to the local /24 and drops multicast, network
  and broadcast addresses — they are private-looking but are not devices.
- **An addon does not show up** — `netsour --list-addons` prints its status and
  traceback without starting curses; inside the UI, `A` lists the same thing and
  reloads. Files starting with `_` are skipped, and an addon that raised
  `MAX_FAILURES` times is disabled until the next reload, not silently ignored.
- **A dashboard card vanished** — the layout is remembered in
  `~/.config/netsour/dashboard.json`; `Enter` on the Dash view brings it back.
- **OSINT source always errors** — check `Source.applies`: DNS records only make
  sense for a hostname, reverse DNS only for an IP. The picker greys out
  inapplicable sources rather than letting them fail.
