"""Command line entry point: argument parsing, interface selection, startup."""

from __future__ import annotations

import argparse
import curses
import logging
import os
import sys
from typing import List, Optional

from . import __version__

BANNER = r"""
   _  __     __  _____
  / |/ /__ _/ /_/ __/ /  _ _ ____
 /    / -_) __/\ \/ /_/| ' \/ __/   NetSour {version}
/_/|_/\__/\__/___/____/|_|_|_\_/    terminal packet analyzer
"""


def _silence_scapy() -> None:
    """Keep scapy's warnings off the terminal - they corrupt the curses screen."""
    logging.getLogger("scapy").setLevel(logging.CRITICAL)
    for name in ("scapy.runtime", "scapy.loading", "scapy.interactive"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        from scapy.config import conf

        conf.verb = 0
    except Exception:
        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsour",
        description="NetSour - live packet capture, analysis and network recon "
                    "in the terminal.",
        epilog="Capture requires root, or CAP_NET_RAW on the Python binary. "
               "Only monitor networks you are authorised to monitor.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--interface", default="",
                        help="interface to capture on (prompts when omitted)")
    parser.add_argument("-r", "--read", dest="pcap", default="",
                        help="replay a pcap file instead of capturing live")
    parser.add_argument("-f", "--filter", dest="bpf", default="",
                        help="BPF capture filter, e.g. 'tcp port 443'")
    parser.add_argument("-b", "--buffer", type=int, default=20000,
                        metavar="N", help="packets to keep in memory "
                                          "(default: 20000)")
    from .ui.theme import THEMES

    parser.add_argument("--theme", default="midnight", choices=tuple(THEMES),
                        metavar="NAME",
                        help=f"colour theme: {', '.join(THEMES)}")
    parser.add_argument("--fps", type=int, default=12, metavar="N",
                        help="UI refresh rate (default: 12)")
    parser.add_argument("--no-promisc", action="store_true",
                        help="do not put the interface in promiscuous mode")
    parser.add_argument("--no-rdns", action="store_true",
                        help="disable background reverse-DNS lookups")
    parser.add_argument("--no-geo", action="store_true",
                        help="disable geolocation and OSINT lookups entirely")
    parser.add_argument("-l", "--list-interfaces", action="store_true",
                        help="list capture interfaces and exit")
    parser.add_argument("--addon-dir", default="", metavar="PATH",
                        help="load addons from PATH instead of "
                             "~/.config/netsour/addons")
    parser.add_argument("--no-addons", action="store_true",
                        help="do not load addons at all")
    parser.add_argument("--list-addons", action="store_true",
                        help="list the addons that would load, and exit")
    parser.add_argument("--new-addon", default="", metavar="NAME",
                        help="write a starter addon called NAME and exit")
    parser.add_argument("-V", "--version", action="version",
                        version=f"NetSour {__version__}")
    return parser


def choose_interface(interfaces: List[str]) -> Optional[str]:
    """Interactive picker used when no interface was given on the command line."""
    if not interfaces:
        print("No capture interfaces found.", file=sys.stderr)
        return None
    print(BANNER.format(version=__version__))
    print("  Available interfaces:\n")
    from .capture import interface_address

    for index, name in enumerate(interfaces, 1):
        address = interface_address(name)
        marker = "  " if address else "  "
        print(f"   {index:>2}. {name:<14}{marker}{address or 'no address'}")
    print()
    default = interfaces[0]
    try:
        answer = input(f"  Interface [{default}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not answer:
        return default
    if answer.isdigit() and 1 <= int(answer) <= len(interfaces):
        return interfaces[int(answer) - 1]
    if answer in interfaces:
        return answer
    print(f"  Unknown interface '{answer}'.", file=sys.stderr)
    return None


def build_registry(args):
    """The addon registry the session and the dashboard will share."""
    from .addons import AddonRegistry, addon_dir

    directories = [args.addon_dir] if args.addon_dir else [addon_dir()]
    registry = AddonRegistry(directories=directories,
                             enabled=not args.no_addons)
    registry.load()
    return registry


def list_addons(registry) -> int:
    """`--list-addons`: what would load, and what is broken. Never starts curses."""
    print(f"Addon directory: {registry.directory}")
    if not registry.addons:
        print("  no addons found - 'netsour --new-addon NAME' writes a starter")
    for addon in registry.addons:
        print(f"  {addon.name:<20} {addon.status:<7} {addon.summary()}")
        if addon.error:
            for line in addon.error.strip().split("\n"):
                print(f"      {line}")
    cards = registry.panel_specs(include_hidden=True)
    print(f"Dashboard cards: {len(cards)} "
          f"({sum(1 for c in cards if c.source != 'built-in')} from addons)")
    return 1 if any(a.status == "failed" for a in registry.addons) else 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _silence_scapy()

    from .capture import is_root, list_interfaces
    from .session import Session
    from .ui.app import App

    registry = build_registry(args)
    if args.new_addon:
        try:
            print(f"Wrote {registry.scaffold(args.new_addon)}")
        except FileExistsError as exc:
            print(f"{exc} already exists", file=sys.stderr)
            return 1
        return 0
    if args.list_addons:
        return list_addons(registry)

    interfaces = list_interfaces()
    if args.list_interfaces:
        from .capture import interface_address

        for name in interfaces:
            print(f"{name:<16}{interface_address(name) or '-'}")
        return 0

    iface = args.interface
    if not args.pcap:
        if not iface:
            iface = choose_interface(interfaces) or ""
            if not iface:
                return 1
        elif iface not in interfaces and interfaces:
            print(f"Warning: '{iface}' is not in {interfaces}", file=sys.stderr)
        if not is_root():
            print("\n  NetSour needs raw socket access to capture packets.\n"
                  "  Re-run with sudo, or grant the capability once:\n"
                  "    sudo setcap cap_net_raw,cap_net_admin=eip "
                  f"$(readlink -f {sys.executable})\n", file=sys.stderr)
            return 1
    elif not os.path.exists(args.pcap):
        print(f"No such capture file: {args.pcap}", file=sys.stderr)
        return 1

    session = Session(iface=iface, bpf=args.bpf, pcap_path=args.pcap,
                      buffer_size=max(100, args.buffer),
                      promisc=not args.no_promisc,
                      enable_rdns=not args.no_rdns,
                      enable_geo=not args.no_geo,
                      addons=registry)
    session.start()

    crash = None
    try:
        curses.wrapper(lambda stdscr: App(stdscr, session, theme=args.theme,
                                          refresh_hz=args.fps).run())
    except KeyboardInterrupt:
        pass
    except Exception as exc:                  # the terminal is restored by now
        crash = exc
    finally:
        session.stop()

    if crash is not None:
        import traceback

        print("NetSour hit an unexpected error and shut down cleanly:",
              file=sys.stderr)
        traceback.print_exception(type(crash), crash, crash.__traceback__)
        return 3

    stats = session.stats
    print(f"NetSour captured {stats.total_packets:,} packets "
          f"({stats.total_bytes / 1024:.1f} KiB) in "
          f"{stats.elapsed:.0f}s across "
          f"{len(session.flows.flows):,} conversations.")
    high = session.alerts.counts().get("high", 0)
    if high:
        print(f"{high} high-severity alert(s) were raised during this session.")
    if session.capture.error:
        print(f"Capture ended with an error: {session.capture.error}",
              file=sys.stderr)
        return 2
    return 0
