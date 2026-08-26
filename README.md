# NetSour

A packet sniffer that lives in your terminal. It captures traffic, takes it
apart down to the application layer, keeps track of every conversation and every
device on the network, and shouts when something looks wrong — all in one curses
UI you drive from the keyboard.

Think Wireshark's questions, answered without leaving the shell.

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Packets ────────────────────────────────────────────────────────────────────── 299 shown of 299 ╮
│ Time         Source              Destination         Proto     Len   Info                        │
│ 15:41:24.460 192.168.1.1:53      192.168.1.10:40000  UDP/DNS   106   Response NOERROR cdn.ex…   ▐│
│ 15:41:24.810 192.168.1.10:51101  198.51.100.24:443   TCP/TLS   130   ClientHello SNI=cdn.exa…   ┆│
│ 15:41:25.160 192.168.1.10:51101  198.51.100.24:443   TCP/TLS   387   Application Data len=333   ┆│
│ 15:41:25.510 198.51.100.24:443   192.168.1.10:51101  TCP/TLS   714   Application Data len=660   ┆│
│ 15:41:25.860 192.168.1.10:40000  192.168.1.1:53      UDP/DNS   75    Query A api.example.org    ┆│
│ 15:41:26.210 192.168.1.1:53      192.168.1.10:40000  UDP/DNS   106   Response NOERROR api.ex…   ┆│
│ 15:41:26.560 192.168.1.10:51102  203.0.113.90:443    TCP/TLS   130   ClientHello SNI=api.exa…   ┆│
│ 15:41:26.910 192.168.1.10:51102  203.0.113.90:443    TCP/TLS   577   Application Data len=523   ┆│
│ 15:41:27.260 203.0.113.90:443    192.168.1.10:51102  TCP/TLS   954   Application Data len=900   ┆│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Detail · tree ────────────────────────────────────────────────────── [tree] hex stream geo nmap ╮
│ Frame                                                                                           ▐│
│   captured   954 bytes                                                                          ┆│
│   number     #25                                                                                ┆│
│   epoch      1787773287.260913                                                                  ┆│
│ Ethernet                                                                                        ┆│
│   src        aa:bb:cc:00:00:01                                                                  ┆│
│   dst        aa:bb:cc:00:00:02                                                                  ┆│
│   type       IPv4                                                                               ┆│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

 ? help   q quit   1-9 views   / filter   d detail   f follow   t/u/i/a protos   n nmap   w save
```

Every screen in this README is a real render, not a mock-up: NetSour replaying a
small synthetic capture with `netsour -r`. The addresses are all from the
documentation ranges, so nothing here belongs to anyone.

## Install

```bash
pip install -e .              # everything except the Nmap integration
pip install -e '.[scan]'      # ...and the 'n' key too
sudo apt install nmap         # the Python binding needs the binary as well
```

Capturing raw packets needs privileges. Run it with `sudo`, or hand the
capability to your interpreter once and forget about it:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

Working inside a virtualenv? `sudo` throws away your `PATH`, so point it at the
venv directly — `sudo .venv/bin/netsour` — or activate the venv first. This
trips up everyone once.

## Getting started

```bash
sudo netsour                             # asks which interface
sudo netsour -i eth0                     # or just tell it
sudo netsour -i eth0 -f 'tcp port 443'   # with a BPF capture filter
netsour -r capture.pcap                  # replay a file — no root needed
```

If you want to poke around before pointing it at a live network, `-r` is the way
in. Everything except the sniffer itself works on a saved capture.

| Option | What it does |
| --- | --- |
| `-i, --interface` | interface to capture on |
| `-r, --read` | replay a pcap instead of capturing |
| `-f, --filter` | BPF capture filter |
| `-b, --buffer` | how many packets to keep in memory (default 20000) |
| `--theme` | `midnight`, `nord`, `matrix`, `amber` or `paper` |
| `--fps` | UI refresh rate (default 12) |
| `--no-promisc` | leave the interface out of promiscuous mode |
| `--no-rdns` / `--no-geo` | turn off background name / location lookups |
| `--addon-dir` | load addons from somewhere other than `~/.config/netsour/addons` |
| `--no-addons` | don't load addons at all |
| `--list-addons` | print what would load, and what's broken, then exit |
| `--new-addon NAME` | write a starter addon called NAME, then exit |
| `-l, --list-interfaces` | list interfaces and exit |

## Nine views

Number keys jump between them, arrows step through them, `?` shows every
binding.

### 1 · Packets

The list you'd expect, and a detail pane that cycles with `d` through five ways
of looking at the selected packet: the dissection tree, a hex dump, the
reassembled stream, geolocation, and any Nmap results for that host.

Here's the hex of an HTTP request that NetSour flagged — the marker in the left
margin means it found something in the clear:

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Packets ────────────────────────────────────────────────────────────────────── 299 shown of 299 ╮
│ Time         Source              Destination         Proto     Len   Info                        │
│ 15:42:51.960 203.0.113.90:443    192.168.1.10:51146  TCP/TLS   1471  Application Data len=14…   ┆│
│ 15:42:52.310 192.168.1.10:40000  192.168.1.1:53      UDP/DNS   76    Query A news.example.net   ┆│
│ 15:42:52.660 192.168.1.1:53      192.168.1.10:40000  UDP/DNS   108   Response NOERROR news.e…   ┆│
│ 15:42:53.010 192.168.1.10:51147  198.51.100.77:443   TCP/TLS   131   ClientHello SNI=news.ex…   ┆│
│ 15:42:53.360 192.168.1.10:51147  198.51.100.77:443   TCP/TLS   1108  Application Data len=10…   ┆│
│ 15:42:53.710 198.51.100.77:443   192.168.1.10:51147  TCP/TLS   1711  Application Data len=16…   ┆│
│ 15:42:54.060 192.168.1.23:40000  192.168.1.1:123     UDP/NTP   43    40000 → 123(ntp)  len=1    ┆│
│ 15:42:54.410 192.168.1.10        192.168.1.1         ICMP      42    echo-request id=0 seq=0    ▐│
│•15:42:54.760 192.168.1.10:51200  203.0.113.7:80      TCP/HTTP  169   POST /login HTTP/1.1  H…   ┆│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Detail · hex ─────────────────────────────────────────────────────── tree [hex] stream geo nmap ╮
│ 00000000  aa bb cc 00 00 02 aa bb  cc 00 00 01 08 00 45 00  ..............E.                    ▐│
│ 00000010  00 9b 00 01 00 00 40 06  7c a2 c0 a8 01 0a cb 00  ......@.|.......                    ▐│
│ 00000020  71 07 c8 00 00 50 00 00  00 00 00 00 00 00 50 18  q....P........P.                    ▐│
│ 00000030  20 00 c9 fe 00 00 50 4f  53 54 20 2f 6c 6f 67 69   .....POST /logi                    ▐│
│ 00000040  6e 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  n HTTP/1.1..Host                    ▐│
│ 00000050  3a 20 69 6e 74 72 61 6e  65 74 2e 65 78 61 6d 70  : intranet.examp                    ┆│
│ 00000060  6c 65 0d 0a 55 73 65 72  2d 41 67 65 6e 74 3a 20  le..User-Agent:                     ┆│
│ 00000070  63 75 72 6c 2f 38 2e 35  2e 30 0d 0a 41 75 74 68  curl/8.5.0..Auth                    ┆│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

 ? help   q quit   1-9 views   / filter   d detail   f follow   t/u/i/a protos   n nmap   w save
```

Same packet, `d` pressed twice more, following the whole conversation:

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Packets ────────────────────────────────────────────────────────────────────── 299 shown of 299 ╮
│ Time         Source              Destination         Proto     Len   Info                        │
│ 15:42:52.310 192.168.1.10:40000  192.168.1.1:53      UDP/DNS   76    Query A news.example.net   ┆│
│ 15:42:52.660 192.168.1.1:53      192.168.1.10:40000  UDP/DNS   108   Response NOERROR news.e…   ┆│
│ 15:42:53.010 192.168.1.10:51147  198.51.100.77:443   TCP/TLS   131   ClientHello SNI=news.ex…   ┆│
│ 15:42:53.360 192.168.1.10:51147  198.51.100.77:443   TCP/TLS   1108  Application Data len=10…   ┆│
│ 15:42:53.710 198.51.100.77:443   192.168.1.10:51147  TCP/TLS   1711  Application Data len=16…   ┆│
│ 15:42:54.060 192.168.1.23:40000  192.168.1.1:123     UDP/NTP   43    40000 → 123(ntp)  len=1    ┆│
│ 15:42:54.410 192.168.1.10        192.168.1.1         ICMP      42    echo-request id=0 seq=0    ▐│
│•15:42:54.760 192.168.1.10:51200  203.0.113.7:80      TCP/HTTP  169   POST /login HTTP/1.1  H…   ┆│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Detail · stream ──────────────────────────────────────────────────── tree hex [stream] geo nmap ╮
│ Following TCP 192.168.1.10:51200 ↔ 203.0.113.7:80                                               ▐│
│                                                                                                 ▐│
│ → POST /login HTTP/1.1                                                                          ▐│
│ → Host: intranet.example                                                                        ┆│
│ → User-Agent: curl/8.5.0                                                                        ┆│
│ → Authorization: Basic YWRtaW46aHVudGVyMg==                                                     ┆│
│ →                                                                                               ┆│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

 ? help   q quit   1-9 views   / filter   d detail   f follow   t/u/i/a protos   n nmap   w save
```

Filtering is two keys away. `t` `u` `i` `a` toggle whole protocols, `!` narrows
to just the flagged packets, and `/` searches across addresses, ports, protocol
labels, the dissected summary **and the payload bytes** — which is how you find
the one request that mentioned a hostname three thousand packets ago.

### 2 · Devices

This one answers "what is actually on this network". The left pane is one row
per address; the right pane is whatever NetSour has worked out about the one you
have selected.

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Devices on this network ─────────────────────────────────────────────────────────────── 6 found ╮
│ 6 DEVICES   6 online   ARP sweep found 6      Enter or click an address to see only its traffic  │
│                                                                                                  │
│ ● 192.168.1.1     Router / Ga… │ ╭──────╮  workshop-laptop                                       │
│ ● 192.168.1.10    workshop-la… │ │▒▒▒▒▒▒│  Computer  (confirmed)                                 │
│ ● 192.168.1.23    pixel-7      │ ╰──▬▬──╯  ONLINE                                                │
│ ● 192.168.1.44    Printer      │                                                                 │
│ ● 192.168.1.55    TV / Stream… │ address    192.168.1.10                                         │
│ ● 192.168.1.66    Unidentified │ hardware   aa:bb:cc:00:00:01                                    │
│                                │ hostname   workshop-laptop                                      │
│                                │ evidence   hostname workshop-laptop; serves port 22             │
│                                │ os guess   Linux / Android / macOS                              │
│                                │ services   21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 44… │
│                                │ presence   ARP reply                                            │
│                                │ traffic    41.2K sent · 57.6K received · 284 packets            │
│                                │                                                                 │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   1-9 views   Enter show its traffic   v layout   S ARP sweep   o offline
```

Press `v` and the same devices become a wall of cards, each with an icon for
what it thinks the thing is:

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Devices on this network ─────────────────────────────────────────────────────────────── 6 found ╮
│ 6 DEVICES   6 online   ARP sweep found 6      Enter or click an address to see only its traffic  │
│                                                                                                  │
│ ╭───────────────────────────────────╮ ╭───────────────────────────────────╮                     ▐│
│ │ ╭──────╮  192.168.1.1             │ │ ╭──────╮  workshop-laptop         │                     ▐│
│ │ │ ((•))│  Router / Gateway · Linu…│ │ │▒▒▒▒▒▒│  192.168.1.10            │                     ▐│
│ │ ╰─┬┬┬┬─╯  Linux / Android / macOS │ │ ╰──▬▬──╯  Computer · Linux / Andr…│                     ▐│
│ ╰─▲4.9K ▼4.5K 121p───────────GATEWAY╯ ╰─▲41.2K ▼57.6K 284p───────confirmed╯                     ▐│
│                                                                                                 ▐│
│ ╭───────────────────────────────────╮ ╭───────────────────────────────────╮                     ▐│
│ │  ╭────╮   pixel-7                 │ │ ╭──────╮  192.168.1.44            │                     ▐│
│ │  │▒▒▒▒│   192.168.1.23            │ │ │▤▤▤▤▤▤│  Printer · Linux / Andro…│                     ┆│
│ │  ╰─▭──╯   Phone / Tablet · Linux …│ │ ╰─┤▬▬├─╯  Linux / Android / macOS │                     ┆│
│ ╰─▲821B ▼0B 15p────────────confirmed╯ ╰─▲168B ▼0B 2p────────────────likely╯                     ┆│
│                                                                                                 ┆│
│                                                                                                  │
│                                                                                                  │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   1-9 views   Enter show its traffic   v layout   S ARP sweep   o offline
```

A few things worth knowing about how this list is built:

- **An address only counts as a device once something proves it exists** — a
  frame it sent, or a reply to an ARP sweep. Being *addressed* proves nothing;
  a sweep asks all 254 hosts of a /24 whether or not anyone's home.
- **Kind is a vote, weighted.** What a device advertises over mDNS/DNS-SD beats
  the name it claims, which beats the ports it serves, which beats its MAC
  vendor. Samsung makes phones *and* TVs, so an OUI is the weakest evidence
  there is. The identity pane lists every signal that contributed, so no guess
  is silent.
- **A device is only ever named by something it says about itself** — a DHCP
  option-12 hostname, or an mDNS record pointing at its own address. Names that
  merely appear in traffic (a DNS answer, a TLS SNI, an HTTP Host) describe what
  a packet is *about*. Use those to name devices and you end up labelling your
  router `api.anthropic.com`, because the router answered the lookup.
- **Quiet devices drop off** after five minutes and come back with `o`. Presence
  is measured against the capture's own clock, so replaying an old pcap doesn't
  declare everything dead.

Press `Enter` on an address and the packet list filters to that device. That is
the fastest way to answer "what is this thing talking to". `Esc` clears it.

On a switched network you'll only passively see devices that broadcast, so press
`S` to ARP-sweep the subnet and fill in the rest.

### 3 · Flows, and 6 · Hosts

Conversations, merged in both directions, with bytes each way, duration, rate
and a rough TCP state. `s` cycles the sort.

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Conversations ───────────────────────────────────────────────────────────────── sorted by bytes ╮
│ Proto    Endpoint A                Endpoint B                Pkts    Bytes    Dur     State      │
│ UDP      192.168.1.1:53            192.168.1.10:40000        96      8.4K     01:30   -         ▐│
│ TCP      192.168.1.10:51147        198.51.100.77:443         3       2.9K     00:00   open      ┆│
│ TCP      192.168.1.10:51143        198.51.100.77:443         3       2.8K     00:00   open      ┆│
│ TCP      192.168.1.10:51139        198.51.100.77:443         3       2.7K     00:00   open      ┆│
│ TCP      192.168.1.10:51135        198.51.100.77:443         3       2.7K     00:00   open      ┆│
│ TCP      192.168.1.10:51131        198.51.100.77:443         3       2.6K     00:00   open      ┆│
│ TCP      192.168.1.10:51127        198.51.100.77:443         3       2.5K     00:00   open      ┆│
│ TCP      192.168.1.10:51146        203.0.113.90:443          3       2.5K     00:00   open      ┆│
│ TCP      192.168.1.10:51123        198.51.100.77:443         3       2.4K     00:00   open      ┆│
│ TCP      192.168.1.10:51142        203.0.113.90:443          3       2.4K     00:00   open      ┆│
│ TCP      192.168.1.10:51119        198.51.100.77:443         3       2.3K     00:00   open      ┆│
│ TCP      192.168.1.10:51138        203.0.113.90:443          3       2.3K     00:00   open      ┆│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   1-9 views   s sort   ↑↓ select
```

Hosts is the flatter view of the same traffic: every endpoint seen, with its
name, MAC, vendor and totals.

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Hosts ─────────────────────────────────────────────────────────────────────── sorted by traffic ╮
│ Address           Hostname                MAC                Sent     Recv     Pkts    Scope     │
│ 192.168.1.10                              aa:bb:cc:00:00:01  41.2K    57.6K    284     private  ▐│
│ 198.51.100.77                             aa:bb:cc:00:00:01  17.0K    12.5K    36      private  ▐│
│ 203.0.113.90                              aa:bb:cc:00:00:01  14.2K    10.3K    36      private  ▐│
│ 198.51.100.24                             aa:bb:cc:00:00:01  11.4K    8.1K     36      private  ▐│
│ 93.184.216.34                             aa:bb:cc:00:00:01  8.6K     5.8K     36      public   ▐│
│ 192.168.1.1                               aa:bb:cc:00:00:02  4.9K     4.5K     121     private  ▐│
│ 192.168.1.66                              aa:bb:cc:00:00:01  1.2K     0B       22      private  ▐│
│ 192.168.1.23                              aa:bb:cc:00:00:01  821B     0B       15      private  ▐│
│ 224.0.0.251                                                  0B       536B     4       private  ▐│
│ 255.255.255.255                                              0B       303B     1       private  ▐│
│ 203.0.113.7                               aa:bb:cc:00:00:01  115B     169B     2       private  ┆│
│ 192.168.1.55                              aa:bb:cc:00:00:37  189B     0B       2       private  ┆│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   1-9 views   s sort   n nmap host
```

### 4 · Stats

Throughput sparklines, protocol mix, packet sizes, who's talking, what they're
talking to, and which services are busy.

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Statistics ─────────────────────────────────────────────────────────────────────────────── live ╮
│ OVERVIEW                                         TOP TALKERS (sent)                              │
│  captured  299 packets  ·  99.7K                  192.168.1.10              ██████████    41.2K  │
│  uptime    01:36  ·  avg 3.1 pkt/s                198.51.100.77             ████▎         17.0K  │
│  current   6 pkt/s  ·  949B/s  (peak 23 pkt/s)    203.0.113.90              ███▌          14.2K  │
│  buffer    299 held  ·  0 rotated out             198.51.100.24             ██▉           11.4K  │
│  flows     84 conversations                       93.184.216.34             ██▏            8.6K  │
│                                                   192.168.1.1               █▎             4.9K  │
│ THROUGHPUT                                                                                       │
│  pkt/s     ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁█▁  TOP DESTINATIONS                                │
│  bytes/s   ▃▇▁▁▃▂▃▆▁▇▁▁▂▅▁▆▃▄▁▄▁▅▃▄▃▄▁▄▂▃▆▁█▁▃▁   192.168.1.10              ██████████    57.6K  │
│                                                   198.51.100.77             ██▎           12.5K  │
│ PROTOCOL MIX                                      203.0.113.90              █▉            10.3K  │
│  TCP        56.5% ██████████████████       169    198.51.100.24             █▌             8.1K  │
│  UDP        37.8% ████████████             113    93.184.216.34             █              5.8K  │
│  ICMP        4.0% █▍                        12    192.168.1.1               ▉              4.5K  │
│  ARP         1.7% ▋                          5                                                   │
│                                                  TOP SERVICES                                    │
│ PACKET SIZES                                      443 https                 ██████████       97  │
│  ≤64       ███████████▎                     52    53 dns                    █████▏           49  │
│  65-128    ████████████████████████        111    40000                     █████            48  │
│  129-256   ████████▉                        41    123 ntp                   █▎               12  │
│  257-512   ███▌                             16    5353 mdns                 ▌                 4  │
│  513-1K    ██████████▋                      49    80 http                   ▎                 2  │
│  1K-1514   █████▌                           25                                                   │
│  >1514     █▏                                5                                                   │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   1-9 views   T theme
```

### 5 · Alerts

The detectors run live over the capture stream. They flag *suspicion*, not
proof, and they're deliberately cheap — sliding windows keyed by source, all
evaluated on the capture thread.

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Security alerts ──────────────────────────────────────────────────────────────── sorted by time ╮
│ SEVERITY  • high 2    • medium 2    • low 0    • info 0                sort: time                │
│                                                                                                  │
│ 15:46:18 MED  Suspicious   Connection to port 31337 (Back Orifice)                               │
│ 15:46:18 HIGH Recon        Port scan 192.168.1.66 → 192.168.1.10  (×3)  20 distinct ports in 1…  │
│ 15:46:18 MED  Addon        Telnet in use  192.168.1.66 → 192.168.1.10                            │
│ 15:46:18 HIGH Credentials  HTTP Basic auth in the clear  192.168.1.10 → 203.0.113.7:80 · YWRta…  │
│                                                                                                  │
│                                                                                                  │
│                                                                                                  │
│                                                                                                  │
│                                                                                                  │
│                                                                                                  │
│ Connection to port 31337 (Back Orifice): 192.168.1.10 → 198.51.100.9:31337   (packet #299)       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   1-9 views   Enter pivot   s sort   O osint   n nmap
```

Currently watching for: port scans · host sweeps · SYN floods · traffic and ICMP
floods · ARP spoofing (a known IP changing MAC) · credentials in the clear (HTTP
Basic, FTP, IMAP, and secrets in URLs or JSON bodies) · DNS tunnelling ·
NXDOMAIN storms · oversized ICMP payloads · connections to known backdoor
ports · hosts appearing on the segment for the first time.

Press `Enter` on an alert and you can pivot straight to the flow, the packet,
a filter on those two hosts, an OSINT lookup or a scan.

### 7 · Recon

`S` sweeps the local /24 with ARP and draws what answered.

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Network recon ─────────────────────────────────────────────────────────────────────── ARP sweep ╮
│ LOCAL SEGMENT                                                                                    │
│  interface -   address none                                                                      │
│                                                                                                  │
│  6 hosts responded  ·  swept at 15:42:56                                                         │
│                                                                                                  │
│  ● 192.168.1.1 (lowest address - likely gateway)                                                 │
│   ├──  192.168.1.10      aa:bb:cc:00:00:0a                                                       │
│   ├──  192.168.1.23      aa:bb:cc:00:00:17                                                       │
│   ├──  192.168.1.44      aa:bb:cc:00:00:2c                                                       │
│   ├──  192.168.1.55      aa:bb:cc:00:00:37                                                       │
│   ╰──  192.168.1.66      aa:bb:cc:00:00:42                                                       │
│                                                                                                  │
│                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   1-9 views   S ARP sweep   n nmap host
```

That's the one active thing NetSour does to your own network, and it asks first.

### 8 · OSINT

Pick a target — an IP, a hostname, or a bare account name — and NetSour
assembles what's publicly known about it.

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ OSINT ───────────────────────────────────────────────────────────────────────────── example.com ╮
│  example.com · hostname                                                                   idle   │
│                                                                                                  │
│  · RDAP registry   [passive]                                                                    ▐│
│    not gathered - press Enter to choose a source                                                ▐│
│                                                                                                 ▐│
│  · DNS records   [passive]                                                                      ▐│
│    not gathered - press Enter to choose a source                                                ▐│
│                                                                                                 ▐│
│  · TLS certificate   [ACTIVE]                                                                   ▐│
│    not gathered - press Enter to choose a source                                                ▐│
│                                                                                                 ▐│
│  · HTTP headers   [ACTIVE]                                                                      ┆│
│    not gathered - press Enter to choose a source                                                ┆│
│                                                                                                 ┆│
│  · Network path   [ACTIVE]                                                                      ┆│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   1-9 views   r passive   R all   x target   Enter source   n nmap
```

| Source | Kind | What it gets |
| --- | --- | --- |
| Reverse DNS | passive | PTR record |
| Geolocation & ASN | passive | country, city, ISP, org, AS number |
| RDAP registry | passive | registration, CIDR, **abuse contacts** |
| DNS records | passive | A, AAAA, MX, NS, TXT, CNAME |
| TLS certificate | active | subject, issuer, SANs, validity, chain |
| HTTP headers | active | server banner, redirects, **missing security headers** |
| Network path | active | traceroute |
| Social activity | passive | platforms this host used, and identity hints |
| Account lookup | active | checks a name against 18 public profile pages |
| Open ports | active | the Nmap results for this host |

**Passive** sources only ever ask registries and resolvers — the target never
sees you. **Active** sources connect to the target, so they're confirmed first
and excluded from the run-everything shortcut unless you ask. `r` runs the
passive set, `R` runs the lot.

#### About usernames, honestly

Social traffic is TLS. The **platform** is visible, because SNI, DNS questions
and Host headers carry hostnames in the clear. The **username inside that
session is not**, and no amount of passive capture will get it.

So NetSour only reports a username where it's genuinely on the wire, and always
says how it got there:

- **`observed`** — read out of plaintext HTTP: a `/u/<name>` path, a
  `?username=` parameter, a JSON body, a `Referer` pointing at a profile.
- **`inferred`** — the hostname *is* the account (`someone.tumblr.com`), so the
  SNI gives it away.

Encrypted sessions are reported as platform activity with `no username visible`,
and that's the end of it. One handle seen on several platforms is called
`reused` — a correlation, not an identification. Every hint cites the packet it
came from.

Account lookup checks 18 sites. Six of them soft-404 — HTTP 200 with a "no such
user" page — so those carry an explicit verification rule instead of trusting the
status code.
A name that exists nowhere returns **zero** hits, and anything behind bot
protection comes back `inconclusive` rather than guessed at. A match means the
*name* exists there, not that it's the same person.

### 9 · Dash

Your dashboard. A board of cards, laid out in one to three columns depending on
how wide your terminal is:

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Dashboard ───────────────────────────────────────────────────────────── 7 cards · 1 from addons ╮
│╭─ Capture ────────────────────────────────────╮ ╭─ Throughput ─────────────────────────────────╮ │
││ source                     workshop-lan.pcap │ │ ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁█▁   │ │
││ state                          file replayed │ │       6 pkt/s   peak 23                      │ │
││ uptime                                 01:36 │ │                                              │ │
││ packets                                  299 │ │ ▄▁▃▁▄▂▃▇▁▁▃▂▃▆▁▇▁▁▂▅▁▆▃▄▁▄▁▅▃▄▃▄▁▄▂▃▆▁█▁▃▁   │ │
││ volume                                 99.7K │ │    949B/s                                    │ │
│╰──────────────────────────────────────────────╯ ╰──────────────────────────────────────────────╯ │
│                                                                                                  │
│╭─ Protocol mix ───────────────────────────────╮ ╭─ Alerts ─────────────────────────────────────╮ │
││ TCP                         ████████   57%   │ │ high 2  medi 2  low 0  info 0                │ │
││ UDP                         █████▍     38%   │ │ 15:46:18 Connection to port 31337 (Back Orif │ │
││ ICMP                        ▋           4%   │ │ 15:46:18 Port scan 192.168.1.66 → 192.168.1. │ │
││ ARP                         ▎           2%   │ │ 15:46:18 Telnet in use                       │ │
│╰──────────────────────────────────────────────╯ │ 15:46:18 HTTP Basic auth in the clear        │ │
│                                                 ╰──────────────────────────────────────────────╯ │
│╭─ Top talkers ────────────────────────────────╮                                                  │
││ 192.168.1.10                 ████████ 41.2K  │ ╭─ Services ───────────────────────────────────╮ │
││ 198.51.100.77                ███▍     17.0K  │ │ 443 https                       ████████ 97  │ │
││ 203.0.113.90                 ██▉      14.2K  │ │ 53 dns                          ████     49  │ │
││ 198.51.100.24                ██▎      11.4K  │ │ 40000                           ████     48  │ │
││ 93.184.216.34                █▊        8.6K  │ │ 123 ntp                         █        12  │ │
││ 192.168.1.1                  █         4.9K  │ │ 5353 mdns                       ▍         4  │ │
│╰──────────────────────────────────────────────╯ │ 80 http                         ▎         2  │ │
│                                                 ╰──────────────────────────────────────────────╯ │
│╭─ Busiest lookups ────────────────────────────╮                                                  │
││ example.com          ████████ 24             │                                                  │
││ cdn.example.net      ████████ 24             │                                                  │
││ api.example.org      ████████ 24             │                                                  │
││ news.example.net     ████████ 24             │                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   1-9 views   Enter cards   A addons   ↑↓ scroll
```

`Enter` picks which cards you want. Hide the ones you never read; the layout is
remembered between runs.

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Dashboard ───────────────────────────────────────────────────────────── 7 cards · 1 from addons ╮
│╭─ Capture ────────────────────────────────────╮ ╭─ Throughput ─────────────────────────────────╮ │
││ source                     workshop-lan.pcap │ │ ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁█▁   │ │
││ state       ╭─ Dashboard ───────────────────────────────────────────────────────╮             │ │
││ uptime      │ Cards — Enter shows or hides one                                  │             │ │
││ packets     │ 1.  ✓ Capture                         built-in                    │▁▄▂▃▆▁█▁▃▁   │ │
││ volume      │ 2.  ✓ Throughput                      built-in                    │             │ │
│╰─────────────│ 3.  ✓ Protocol mix                    built-in                    │─────────────╯ │
│              │ 4.  ✓ Alerts                          built-in                    │               │
│╭─ Protocol mi│ 5.  ✓ Top talkers                     built-in                    │─────────────╮ │
││ TCP         │ 6.  ✓ Services                        built-in                    │             │ │
││ UDP         │ 7.    Busiest flows                   built-in                    │7 (Back Orif │ │
││ ICMP        │ 8.    Names asked for                 built-in                    │→ 192.168.1. │ │
││ ARP         │ 9.  ✓ Busiest lookups                 lookups                     │             │ │
│╰─────────────│                                                                   │clear        │ │
│              │  •  Addons…                           reload, scaffold, inspect   │─────────────╯ │
│╭─ Top talkers│                                                                   │               │
││ 192.168.1.10│ Esc closes · the layout is saved                                  │─────────────╮ │
││ 198.51.100.7╰───────────────────────────────────────────────────────────────────╯████████ 97  │ │
││ 203.0.113.90                 ██▉      14.2K  │ │ 53 dns                          ████     49  │ │
││ 198.51.100.24                ██▎      11.4K  │ │ 40000                           ████     48  │ │
││ 93.184.216.34                █▊        8.6K  │ │ 123 ntp                         █        12  │ │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   1-9 views   Enter cards   A addons   ↑↓ scroll
```

The card at the bottom of that board isn't built in — it came from an addon.

## Addons

An addon is **one Python file** in `~/.config/netsour/addons`. There's no
plugin manifest, no registration step, no restart. `netsour --new-addon NAME`
writes you a working starter (or press `A` → *New addon…* from inside the UI),
and `A` → *Reload* picks up your edits without losing the capture you're
watching.

Three decorators cover almost everything — there are `on_start` and
`on_clear` too, if you need them:

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

That file is exactly what drew the *Busiest lookups* card above, and the
`Telnet in use` line in the Alerts screenshot.

State is just module state — hooks and panels both run under the session lock,
so you never have to think about the capture thread. `pkt` is a flat record of
strings and ints, already dissected. `ctx` hands you the card width, a stats
snapshot, and small helpers like `ctx.bar()` and `ctx.spark()` so your card
looks like the built-in ones.

Addons are treated as untrusted, because they're your Tuesday-afternoon code:

- a panel that throws shows the error on its own card and the board keeps going
- an addon that keeps throwing gets switched off, with its traceback waiting in
  the `A` menu
- a broken addon can't stop capture or take down the UI
- addon key bindings are tried **last**, so they can't shadow a NetSour key

The built-in dashboard cards are written against the same API, through the same
registry. If the API is good enough for them, it's good enough for you.

## Scanning

Press `n` in any view and NetSour offers every address the selected row
references — packet source *and* destination, both ends of a flow, the selected
host, a swept host, a hostname seen in DNS or TLS — or you can just type one.

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Packets ────────────────────────────────────────────────────────────────────── 299 shown of 299 ╮
│ Time         Source              Destination         Proto     Len   Info                        │
│ 15:42:52.310 192.168.1.10:40000  192.168.1.1:53      UDP/DNS   76    Query A news.example.net   ┆│
│ 15:42:52.660 192.168.1.1:53      192.168.1.10:40000  UDP/DNS   108   Response NOERROR news.e…   ┆│
│ 15:42:53.010 192.168.1.10:51147  198.51.100.77:443   TCP/TLS   131   ClientHello SNI=news.ex…   ┆│
│ 15:42:53.360 192.168.1.10:51147  198.51.100.77:443   TCP/TLS   1108  Application Data len=10…   ┆│
│ 15:42:53.710 198.╭─ Nmap target  (fast: Top 100 ports) ───────────────────────╮n Data len=16…   ┆│
│ 15:42:54.060 192.│ 1.  203.0.113.7       packet destination  · private        │3(ntp)  len=1    ┆│
│ 15:42:54.410 192.│ 2.  192.168.1.10      packet source  · private             │st id=0 seq=0    ▐│
│•15:42:54.760 192.│ 3.  intranet.example  hostname seen                        │n HTTP/1.1  H…   ┆│
╰──────────────────│ 4.  Type an address…  enter any host or IP                 │──────────────────╯
╭─ Detail · tree ──│                                                            │x stream geo nmap ╮
│ Frame            │ N changes the profile · scanning sends packets to the host │                 ▐│
│   captured   169 ╰────────────────────────────────────────────────────────────╯                 ┆│
│   number     #275                                                                               ┆│
│   epoch      1787773374.760889                                                                  ┆│
│   flagged    cleartext                                                                          ┆│
│ Ethernet                                                                                        ┆│
│   src        aa:bb:cc:00:00:01                                                                  ┆│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

 ? help   q quit   1-9 views   / filter   d detail   f follow   t/u/i/a protos   n nmap   w save
```

Ten profiles, picked with `N`:

| | | |
| --- | --- | --- |
| `fast` | top 100 ports | `stealth` | SYN scan, no handshake (root) |
| `top1000` | top 1000 ports | `udp` | top 50 UDP ports (root) |
| `service` | version detection | `os` | OS fingerprint (root) |
| `vuln` | NSE vulnerability scripts | `aggressive` | everything (root) |
| `full` | all 65535 ports | `ping` | discovery only |

Profiles that need root are greyed out with the reason when you don't have it.
Anything that sends packets to a host names the host and asks first.

## Keys

`?` in the app is the real reference. The short version:

```
 NetSour  │  workshop-lan.pcap  │  FILE EOF              299 pkts · 99.7K · 6 p/s · 949B/s · 01:36
  1 Packets   2 Devices   3 Flows   4 Stats   5 Alerts 4   6 Hosts   7 Recon   8 OSINT   9 Dash
╭─ Packets ╭─ Help ─────────────────────────────────────────────────────────────────────╮wn of 299 ╮
│ Time     │ NetSour — keyboard reference                                               │          │
│ 15:41:18.│                                                                            │)  le…   ▐│
│ 15:41:19.│ VIEWS                                                                      │ww.ex…   ┆│
│ 15:41:19.│   1 – 9            jump straight to a view                                 │compa…   ┆│
│ 15:41:19.│   ← / →            previous / next view                                    │googl…   ┆│
│ 15:41:20.│   Tab              move focus between the packet list and the detail pane  │ipp._…   ┆│
│ 15:41:20.│   ?                show or hide this help                                  │aa:bb…   ┆│
│ 15:41:20.│   q                quit                                                    │ aa:b…   ┆│
│ 15:41:21.│                                                                            │ aa:b…   ┆│
│ 15:41:21.│ NAVIGATION                                                                 │ aa:b…   ┆│
│ 15:41:22.│   ↑ ↓ / k j        move the selection                                      │ aa:b…   ┆│
╰──────────│   PgUp PgDn        page through the list                                   │──────────╯
╭─ Detail ·│   Home End / g G   jump to the first or last row                           │ geo nmap ╮
│ Frame    │   f                follow mode - stick to the newest packet                │         ▐│
│   capture│   Enter            focus the detail pane on the selected row               │         ┆│
│   number │                                                                            │         ┆│
│   epoch  │ CAPTURE                                                                    │         ┆│
│ Ethernet │   Space            pause or resume capture (the interface keeps running)   │         ┆│
│   src    │   c                clear the buffer, statistics, flows and alerts          │         ┆│
│   dst    │   w                write the buffer to a pcap file                         │         ┆│
│   type   │   W                write only the packets matching the current filter      │         ┆│
│ IP       │   b                set a BPF capture filter and restart capture            │         ┆│
╰──────────╰────────────────────────────────────────────────────────────────────────────╯──────────╯

 ? help   q quit   1-9 views   / filter   d detail   f follow   t/u/i/a protos   n nmap   w save
```

| | |
| --- | --- |
| `1`–`9`, `←` `→` | switch views (arrows move inside the device list) |
| `↑` `↓` `j` `k`, `PgUp` `PgDn`, `g` `G` | move around |
| `Tab` | swap focus between the list and the detail pane |
| `d` | cycle the detail pane: tree → hex → stream → geo → nmap |
| `/` | text filter (`Esc` clears it) |
| `t` `u` `i` `a` `o` | toggle TCP / UDP / ICMP / ARP / other |
| `!` | flagged packets only · `F` resets every filter |
| `Space` | pause and resume capture |
| `f` | follow mode — stick to the newest packet |
| `w` `W` | write all / filtered packets to a pcap |
| `b` | change the BPF capture filter |
| `c` | clear the buffer, stats, flows and alerts |
| `s` | cycle the sort key (flows, alerts, hosts) |
| `n` `N` | pick an address to Nmap · choose the profile |
| `O` `G` | OSINT an address · geolocate one |
| `S` | ARP-sweep the local /24 |
| `Enter` | Devices: filter to that device · Alerts: pivot · Dash: choose cards |
| `A` | addons — reload, scaffold, read an addon's traceback |
| `T` `q` | theme · quit |
| click | select a row; click it again for its actions |

## How it's put together

One capture thread, one UI thread, and a couple of small worker pools for
lookups. The capture thread does *all* the dissection and appends flat records
to a ring buffer under a single lock — by the time the UI sees a packet it's
plain strings and ints.

The UI reads capture state through exactly one door: `Session.derive()` hands
back an immutable bundle for the frame, built under one lock acquisition. This
isn't ceremony. Iterating a live `Counter` or a deque while the sniffer appends
to it raises `RuntimeError` and kills the display, and it only ever happens on a
busy link — never on the pcap you tested with. So no view is allowed anywhere
near the live structures.

Nothing touches the network unless you ask. Reverse DNS runs in the background
and `--no-rdns` turns it off; geolocation, OSINT, Nmap and ARP sweeps are all
key-triggered, and everything that emits a packet confirms first, naming the
host. Auto-scanning every address you happen to see is both noisy and legally
hazardous.

Ingest runs at roughly 14k packets/sec on one thread. If you're changing
`dissect()`, that's the number to keep an eye on.

## Tests

```bash
python -m unittest discover -s tests -t .
```

359 of them. Dissection, the detectors, session and buffer behaviour, pcap
round-trips, device identification and its evidence rules, OSINT gating and
parsing, the observed/inferred boundary in social attribution, the
profile-verification rules, menu navigation, addon loading and isolation,
dashboard layout — plus a headless curses pass that draws every view at four
terminal sizes, and a concurrency test that renders every view while a writer
thread floods the session. That last one exists because the crash it guards
against shipped once.

## The fine print

For education, network administration and authorised security testing. Capturing
traffic on a network you don't own or administer is illegal in most places, and
scanning hosts you haven't been asked to scan is worse. Get permission first.

The social attribution deserves its own paragraph. It analyses traffic you're
already authorised to capture, and it's genuinely useful for the questions
operators have to answer — what is this device doing, is anything leaking
credentials, which account got compromised. It is not a people-search tool.
Pointing it at someone whose network you don't run is a privacy violation and,
in most jurisdictions, a crime.

## License

GPL v3
