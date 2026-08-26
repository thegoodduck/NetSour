"""Detector behaviour: each heuristic must fire on its case and stay quiet
otherwise. Timestamps are supplied explicitly so no test depends on wall clock.
"""

import unittest

from netsour.dissect import dissect
from netsour.security import HIGH, MEDIUM, AlertEngine, Thresholds

from . import factory


class DetectorCase(unittest.TestCase):

    def setUp(self):
        self.engine = AlertEngine(Thresholds(scan_ports=10, sweep_hosts=8,
                                             flood_packets=50, syn_flood=20,
                                             icmp_flood=15, dns_nxdomain=5))
        self.clock = 1000.0

    def feed(self, packet, step=0.01):
        record = dissect(packet, 1, self.clock)
        self.clock += step
        self.engine.inspect(record)
        return record

    def categories(self):
        return {alert.category for alert in self.engine.alerts}

    def titles(self):
        return " | ".join(alert.title for alert in self.engine.alerts)


class TestReconDetectors(DetectorCase):

    def test_port_scan_is_detected(self):
        for port in range(1, 30):
            self.feed(factory.tcp(src="10.0.0.9", dst="10.0.0.1", dport=port,
                                  flags="S"))
        self.assertIn("Recon", self.categories())
        self.assertIn("Port scan", self.titles())

    def test_host_sweep_is_detected(self):
        for host in range(1, 20):
            self.feed(factory.tcp(src="10.0.0.9", dst=f"10.0.0.{host}",
                                  dport=445, flags="S"))
        self.assertIn("Host sweep", self.titles())

    def test_normal_browsing_raises_nothing(self):
        for i in range(30):
            self.feed(factory.tcp(src="10.0.0.5", dst="93.184.216.34",
                                  sport=40000 + i, dport=443, flags="S"), step=1.0)
            self.feed(factory.tcp(src="93.184.216.34", dst="10.0.0.5",
                                  sport=443, dport=40000 + i, flags="SA"), step=0.1)
        self.assertEqual(self.engine.alerts, [])

    def test_established_traffic_is_not_a_scan(self):
        for port in range(1, 40):
            self.feed(factory.tcp(src="10.0.0.9", dst="10.0.0.1", dport=port,
                                  flags="PA", payload=b"data"))
        self.assertNotIn("Recon", self.categories())


class TestDosDetectors(DetectorCase):

    def test_syn_flood_against_one_service(self):
        for i in range(40):
            self.feed(factory.tcp(src="10.0.0.9", dst="10.0.0.1", sport=1000 + i,
                                  dport=80, flags="S"), step=0.001)
        self.assertIn("SYN flood", self.titles())

    def test_answered_syns_are_not_a_flood(self):
        for i in range(40):
            self.feed(factory.tcp(src="10.0.0.9", dst="10.0.0.1",
                                  sport=1000 + i, dport=80, flags="S"), step=0.001)
            self.feed(factory.tcp(src="10.0.0.1", dst="10.0.0.9", sport=80,
                                  dport=1000 + i, flags="SA"), step=0.001)
        self.assertNotIn("SYN flood", self.titles())

    def test_packet_flood_from_one_source(self):
        for i in range(60):
            self.feed(factory.udp(src="10.0.0.9", dport=9), step=0.001)
        self.assertIn("Traffic flood", self.titles())

    def test_icmp_flood(self):
        for _ in range(20):
            self.feed(factory.icmp(src="10.0.0.9"), step=0.001)
        self.assertIn("ICMP flood", self.titles())

    def test_oversized_icmp_suggests_a_tunnel(self):
        self.feed(factory.icmp(src="10.0.0.9", payload=b"A" * 1200))
        self.assertIn("Oversized ICMP", self.titles())


class TestMitmAndCredentials(DetectorCase):

    def test_arp_mac_change_is_flagged_as_spoofing(self):
        self.feed(factory.arp(psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:aa"))
        self.feed(factory.arp(psrc="192.168.1.1", hwsrc="de:ad:be:ef:00:01"))
        self.assertIn("MITM", self.categories())
        alert = next(a for a in self.engine.alerts if a.category == "MITM")
        self.assertEqual(alert.severity, HIGH)

    def test_stable_arp_is_not_flagged(self):
        for _ in range(5):
            self.feed(factory.arp(psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:aa"))
        self.assertNotIn("MITM", self.categories())

    def test_http_basic_auth_is_caught(self):
        self.feed(factory.tcp(dport=80, flags="PA",
                              payload=b"GET /admin HTTP/1.1\r\n"
                                      b"Authorization: Basic YWRtaW46cA==\r\n\r\n"))
        self.assertIn("Credentials", self.categories())

    def test_ftp_password_is_caught(self):
        self.feed(factory.tcp(dport=21, flags="PA", payload=b"PASS hunter2\r\n"))
        self.assertIn("FTP password", self.titles())

    def test_credential_in_url_is_caught(self):
        self.feed(factory.tcp(dport=80, flags="PA",
                              payload=b"GET /a?user=x&password=hunter2 HTTP/1.1\r\n"
                                      b"Host: h\r\n\r\n"))
        self.assertIn("credential in URL", self.titles())

    def test_encrypted_traffic_raises_no_credential_alert(self):
        self.feed(factory.tls_client_hello())
        self.assertNotIn("Credentials", self.categories())


class TestDnsDetectors(DetectorCase):

    def test_long_labels_suggest_tunnelling(self):
        self.feed(factory.dns_query("a" * 60 + ".exfil.example.net"))
        self.assertIn("Exfiltration", self.categories())

    def test_ordinary_names_are_ignored(self):
        for name in ("example.com", "cdn.example.co.uk", "api.service.internal"):
            self.feed(factory.dns_query(name))
        self.assertEqual(self.engine.alerts, [])

    def test_nxdomain_storm(self):
        for i in range(10):
            self.feed(factory.dns_response(f"x{i}.example.com", rcode=3), step=0.1)
        self.assertIn("NXDOMAIN storm", self.titles())


class TestSuspiciousPorts(DetectorCase):

    def test_known_backdoor_port(self):
        self.feed(factory.tcp(dport=31337, flags="S"))
        alert = next(a for a in self.engine.alerts if a.category == "Suspicious")
        self.assertEqual(alert.severity, MEDIUM)
        self.assertIn("Back Orifice", alert.title)


class TestAlertBookkeeping(DetectorCase):

    def test_repeats_are_coalesced_not_duplicated(self):
        for _ in range(3):
            for port in range(1, 30):
                self.feed(factory.tcp(src="10.0.0.9", dst="10.0.0.1",
                                      dport=port, flags="S"))
        scans = [a for a in self.engine.alerts if a.title.startswith("Port scan")]
        self.assertEqual(len(scans), 1)
        self.assertGreater(scans[0].count, 1)

    def test_severity_sort_puts_high_first(self):
        self.feed(factory.tcp(dport=31337, flags="S"))
        self.feed(factory.tcp(dport=21, flags="PA", payload=b"PASS x\r\n"))
        ordered = self.engine.sorted_alerts("severity")
        self.assertEqual(ordered[0].severity, HIGH)

    def test_counts_summarise_by_severity(self):
        self.feed(factory.tcp(dport=31337, flags="S"))
        self.assertEqual(self.engine.counts()[MEDIUM], 1)

    def test_clear_empties_everything(self):
        self.feed(factory.tcp(dport=31337, flags="S"))
        self.engine.clear()
        self.assertEqual(self.engine.alerts, [])

    def test_a_broken_detector_cannot_stop_capture(self):
        engine = AlertEngine()
        engine._arp_watch = lambda rec: (_ for _ in ()).throw(RuntimeError("x"))
        engine.inspect(dissect(factory.arp(), 1, 1000.0))   # must not raise


if __name__ == "__main__":
    unittest.main()
