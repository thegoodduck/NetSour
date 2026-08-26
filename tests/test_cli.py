"""Command line surface and the enrichment helpers' offline behaviour."""

import unittest
from unittest import mock

from netsour.capture import interface_address, is_root, list_interfaces
from netsour.cli import build_parser, main
from netsour.enrich import GeoIP, MacVendor, NmapScanner, ReverseDNS, is_private
from netsour.services import port_label, service_name


class TestArgumentParsing(unittest.TestCase):

    def test_defaults(self):
        args = build_parser().parse_args([])
        self.assertEqual(args.interface, "")
        self.assertEqual(args.buffer, 20000)
        self.assertEqual(args.theme, "midnight")
        self.assertFalse(args.no_geo)

    def test_short_and_long_forms_agree(self):
        parser = build_parser()
        short = parser.parse_args(["-i", "eth0", "-f", "tcp port 80", "-b", "50"])
        long = parser.parse_args(["--interface", "eth0", "--filter", "tcp port 80",
                                  "--buffer", "50"])
        self.assertEqual(vars(short), vars(long))

    def test_invalid_theme_is_rejected(self):
        import contextlib
        import io

        with self.assertRaises(SystemExit), \
                contextlib.redirect_stderr(io.StringIO()):
            build_parser().parse_args(["--theme", "neon"])

    def test_every_theme_is_accepted_on_the_command_line(self):
        from netsour.ui.theme import THEMES

        for name in THEMES:
            self.assertEqual(build_parser().parse_args(["--theme", name]).theme,
                             name)

    def test_listing_interfaces_exits_cleanly(self):
        with mock.patch("sys.stdout"):
            self.assertEqual(main(["--list-interfaces"]), 0)

    def test_missing_pcap_is_reported(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(main(["-r", "/definitely/not/here.pcap"]), 1)

    def test_capture_without_root_is_refused_before_curses(self):
        with mock.patch("netsour.capture.is_root", return_value=False), \
             mock.patch("netsour.cli.curses") as fake_curses, \
             mock.patch("sys.stderr"):
            result = main(["-i", "lo"])
        self.assertEqual(result, 1)
        fake_curses.wrapper.assert_not_called()


class TestCaptureHelpers(unittest.TestCase):

    def test_interface_listing_puts_loopback_last(self):
        interfaces = list_interfaces()
        if "lo" in interfaces:
            self.assertEqual(interfaces[-1], "lo")

    def test_is_root_reflects_euid(self):
        with mock.patch("os.geteuid", return_value=0):
            self.assertTrue(is_root())
        with mock.patch("os.geteuid", return_value=1000):
            self.assertFalse(is_root())

    def test_unknown_interface_address_is_empty(self):
        self.assertEqual(interface_address("definitely-not-an-iface"), "")


class TestServices(unittest.TestCase):

    def test_well_known_ports_are_named(self):
        self.assertEqual(service_name(443), "https")
        self.assertEqual(service_name(22), "ssh")

    def test_unknown_ports_render_as_bare_numbers(self):
        self.assertEqual(port_label(64999), "64999")

    def test_known_ports_render_with_the_name(self):
        self.assertEqual(port_label(53), "53(dns)")


class TestEnrichment(unittest.TestCase):

    def test_private_ranges_are_recognised(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1",
                   "169.254.1.1", "not-an-ip"):
            self.assertTrue(is_private(ip), ip)
        for ip in ("8.8.8.8", "93.184.216.34"):
            self.assertFalse(is_private(ip), ip)

    def test_geo_never_queries_private_or_disabled(self):
        geo = GeoIP(enabled=True)
        self.assertEqual(geo.request("10.0.0.1"), "private")
        self.assertEqual(geo.status("10.0.0.1"), "private")
        disabled = GeoIP(enabled=False)
        self.assertEqual(disabled.request("8.8.8.8"), "disabled")
        self.assertEqual(disabled.cache, {})

    def test_geo_lookup_failure_is_cached_not_raised(self):
        geo = GeoIP(enabled=True)
        with mock.patch("urllib.request.urlopen", side_effect=OSError("offline")):
            geo._lookup("8.8.8.8")
        self.assertIn("error", geo.cache["8.8.8.8"])

    def test_rdns_disabled_returns_nothing(self):
        self.assertEqual(ReverseDNS(enabled=False).get("8.8.8.8"), "")

    def test_rdns_caches_failures(self):
        resolver = ReverseDNS(enabled=True)
        with mock.patch("socket.gethostbyaddr", side_effect=OSError):
            resolver._resolve("203.0.113.1")
        self.assertEqual(resolver.cache["203.0.113.1"], "")

    def test_mac_vendor_handles_missing_database(self):
        vendors = MacVendor()
        with mock.patch("os.path.exists", return_value=False):
            self.assertEqual(vendors.get("00:1a:2b:00:00:00"), "")
        self.assertEqual(vendors.get(""), "")

    def test_nmap_refuses_to_scan_when_unavailable(self):
        scanner = NmapScanner()
        scanner.available = False
        message = scanner.request("192.168.1.1")
        self.assertIn("not installed", message)
        self.assertEqual(scanner.status, {})

    def test_nmap_summary_reports_a_failed_scan(self):
        scanner = NmapScanner()
        scanner.status["10.0.0.1"] = "failed: nmap not found"
        self.assertIn("failed", scanner.summary_lines("10.0.0.1")[0])

    def test_nmap_summary_formats_open_ports(self):
        scanner = NmapScanner()
        scanner.status["10.0.0.1"] = "done"
        scanner.results["10.0.0.1"] = {
            "data": {"status": {"state": "up"},
                     "tcp": {22: {"state": "open", "name": "ssh",
                                  "product": "OpenSSH", "version": "9.6"},
                             23: {"state": "closed", "name": "telnet"}}},
            "profile": "fast", "elapsed": 1.5, "args": "-F",
        }
        body = "\n".join(scanner.summary_lines("10.0.0.1"))
        self.assertIn("22/tcp", body)
        self.assertIn("OpenSSH 9.6", body)
        self.assertNotIn("23/tcp", body)


if __name__ == "__main__":
    unittest.main()
