"""Device identification: what counts as a device, and how it is classified."""

import unittest

from netsour.devices import (COMPUTER, IDLE_SECONDS, IOT, PRINTER, ROUTER,
                             UNKNOWN, Device, DeviceRegistry, classify,
                             describe, icon_for, ttl_os_hint)
from netsour.session import Session

from . import factory


class TestLocality(unittest.TestCase):
    """A device is a host you could point at, not any private-looking address."""

    def setUp(self):
        self.registry = DeviceRegistry(local_prefix="192.168.2.")

    def test_hosts_on_the_segment_count(self):
        for ip in ("192.168.2.1", "192.168.2.95", "192.168.2.254"):
            self.assertTrue(self.registry._is_local(ip), ip)

    def test_multicast_and_broadcast_do_not(self):
        for ip in ("224.0.0.251", "239.255.255.250", "192.168.2.255",
                   "192.168.2.0"):
            self.assertFalse(self.registry._is_local(ip), ip)

    def test_other_subnets_and_public_addresses_do_not(self):
        for ip in ("192.168.9.5", "8.8.8.8", "127.0.0.1", "169.254.1.1", ""):
            self.assertFalse(self.registry._is_local(ip), ip)

    def test_ipv6_is_out_of_scope_for_the_grid(self):
        self.assertFalse(self.registry._is_local("fe80::1"))

    def test_without_a_prefix_any_private_host_counts(self):
        loose = DeviceRegistry()
        self.assertTrue(loose._is_local("10.1.2.3"))
        self.assertFalse(loose._is_local("224.0.0.251"))


class TestClassification(unittest.TestCase):

    def classify(self, **kwargs):
        device = Device(ip="192.168.2.5", **kwargs)
        classify(device)
        return device

    def test_the_gateway_is_a_router(self):
        device = self.classify(is_gateway=True)
        self.assertEqual(device.kind, ROUTER)
        self.assertIn("default gateway for this network", device.evidence)

    def test_vendor_alone_identifies_common_hardware(self):
        self.assertEqual(self.classify(vendor="Espressif Inc.").kind, IOT)
        self.assertEqual(self.classify(vendor="Hewlett Packard").kind, PRINTER)
        self.assertEqual(self.classify(vendor="Raspberry Pi Foundation").kind,
                         COMPUTER)

    def test_hostname_alone_identifies_a_device(self):
        self.assertEqual(self.classify(hostname="viktors-iphone").kind, "phone")
        self.assertEqual(self.classify(hostname="LIVINGROOM-TV").kind, "tv")

    def test_served_ports_identify_a_device(self):
        self.assertEqual(self.classify(services={9100}).kind, PRINTER)
        self.assertEqual(self.classify(services={554}).kind, "camera")

    def test_agreeing_signals_raise_confidence(self):
        weak = self.classify(vendor="Espressif Inc.")
        strong = self.classify(vendor="Espressif Inc.",
                               hostname="esp-plug-kitchen")
        self.assertEqual(weak.confidence, "likely")
        self.assertEqual(strong.confidence, "confirmed")
        self.assertEqual(len(strong.evidence), 2)

    def test_a_disagreement_is_settled_by_weight_of_evidence(self):
        """Vendor says router, hostname and port say TV - TV should win."""
        device = self.classify(vendor="TP-LINK TECHNOLOGIES CO.,LTD.",
                               hostname="LIVINGROOM-TV", services={8060})
        self.assertEqual(device.kind, "tv")          # two votes for TV, one router
        self.assertEqual(len(device.evidence), 3)    # all three are recorded
        self.assertEqual(device.confidence, "confirmed")

    def test_nothing_known_stays_unknown(self):
        device = self.classify()
        self.assertEqual(device.kind, UNKNOWN)
        self.assertEqual(device.confidence, "unknown")
        self.assertEqual(device.evidence, [])

    def test_serving_an_unrecognised_port_still_implies_a_computer(self):
        device = self.classify(services={12345})
        self.assertEqual(device.kind, COMPUTER)
        self.assertEqual(device.confidence, "likely")

    def test_classification_is_idempotent(self):
        device = self.classify(vendor="Espressif Inc.")
        classify(device)
        classify(device)
        self.assertEqual(len(device.evidence), 1)


class TestOsHints(unittest.TestCase):

    def test_common_initial_ttls(self):
        self.assertIn("Linux", ttl_os_hint(64))
        self.assertIn("Linux", ttl_os_hint(57))       # a few hops away
        self.assertEqual(ttl_os_hint(128), "Windows")
        self.assertIn("appliance", ttl_os_hint(255))

    def test_implausible_values_give_nothing(self):
        self.assertEqual(ttl_os_hint(0), "")
        self.assertEqual(ttl_os_hint(20), "")         # too far below any initial


class TestPresentation(unittest.TestCase):

    def test_every_kind_has_an_icon_in_both_glyph_sets(self):
        from netsour.devices import KIND_LABELS

        for kind in KIND_LABELS:
            for unicode_ok in (True, False):
                icon = icon_for(kind, unicode_ok)
                self.assertEqual(len(icon), 3, kind)
                self.assertTrue(all(line for line in icon), kind)

    def test_icons_are_a_uniform_width(self):
        from netsour.devices import ICON_WIDTH, KIND_LABELS

        for kind in KIND_LABELS:
            for line in icon_for(kind, True):
                self.assertEqual(len(line), ICON_WIDTH, f"{kind}: {line!r}")

    def test_an_unknown_kind_falls_back_to_the_placeholder(self):
        self.assertEqual(icon_for("spaceship"), icon_for(UNKNOWN))

    def test_description_names_the_kind_and_vendor(self):
        device = Device(ip="1.1.1.1", vendor="Apple, Inc.")
        classify(device)
        self.assertIn("Apple", describe(device))

    def test_presence_reflects_the_strongest_evidence(self):
        self.assertEqual(Device(ip="x", responded_to_arp=True).presence,
                         "ARP reply")
        self.assertEqual(Device(ip="x", mac="aa:bb").presence,
                         "seen on the wire")
        self.assertEqual(Device(ip="x").presence, "address only")


class TestRegistryBuild(unittest.TestCase):

    def _session(self):
        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session.devices = DeviceRegistry(local_prefix="192.168.1.",
                                         gateway="192.168.1.1")
        return session

    def test_devices_are_built_from_observed_traffic(self):
        session = self._session()
        session._on_packet(factory.tcp(src="192.168.1.10", dst="192.168.1.20",
                                       dport=9100, flags="PA", payload=b"x"))
        session._on_packet(factory.tcp(src="192.168.1.20", dst="192.168.1.10",
                                       sport=9100, dport=40000, flags="PA",
                                       payload=b"y"))
        devices = session.derive(want_devices=True).devices
        addresses = [d.ip for d in devices]
        self.assertIn("192.168.1.10", addresses)
        self.assertIn("192.168.1.20", addresses)

    def test_an_address_that_only_ever_receives_is_not_a_device(self):
        """Regression: an ARP sweep invented a device per empty address.

        The sweep addresses all 254 hosts of the /24 whether anything is there
        or not, and every destination used to be counted as a host.
        """
        session = self._session()
        for last in range(2, 20):
            session._on_packet(factory.arp(psrc="192.168.1.10", op=1,
                                           pdst=f"192.168.1.{last}"))
        addresses = [d.ip for d in session.derive(want_devices=True).devices]
        self.assertEqual(addresses, ["192.168.1.10"])

    def test_a_served_port_is_attributed_to_the_server_not_the_client(self):
        session = self._session()
        session._on_packet(factory.tcp(src="192.168.1.10", dst="192.168.1.20",
                                       sport=40000, dport=9100, flags="PA",
                                       payload=b"x"))
        session._on_packet(factory.tcp(src="192.168.1.20", dst="192.168.1.10",
                                       sport=9100, dport=40000, flags="PA",
                                       payload=b"y"))
        devices = {d.ip: d for d in session.derive(want_devices=True).devices}
        self.assertIn(9100, devices["192.168.1.20"].services)
        self.assertNotIn(9100, devices["192.168.1.10"].services)

    def test_an_arp_sweep_adds_devices_that_never_spoke(self):
        session = self._session()
        session.recon_hosts = [("192.168.1.77", "aa:bb:cc:dd:ee:ff")]
        devices = {d.ip: d for d in session.derive(want_devices=True).devices}
        self.assertIn("192.168.1.77", devices)
        self.assertTrue(devices["192.168.1.77"].responded_to_arp)
        self.assertEqual(devices["192.168.1.77"].presence, "ARP reply")

    def test_the_gateway_is_marked_and_sorted_first(self):
        session = self._session()
        session.recon_hosts = [("192.168.1.50", "aa:bb:cc:00:00:02"),
                               ("192.168.1.1", "aa:bb:cc:00:00:01")]
        devices = session.derive(want_devices=True).devices
        self.assertTrue(devices[0].is_gateway)
        self.assertEqual(devices[0].ip, "192.168.1.1")

    def test_remote_and_multicast_addresses_are_excluded(self):
        session = self._session()
        session._on_packet(factory.tcp(src="192.168.1.10", dst="93.184.216.34",
                                       dport=443))
        session._on_packet(factory.dns_query(src="192.168.1.10",
                                             dst="224.0.0.251", dport=5353))
        addresses = [d.ip for d in session.derive(want_devices=True).devices]
        self.assertEqual(addresses, ["192.168.1.10"])

    def test_ttl_produces_an_os_hint(self):
        session = self._session()
        session._on_packet(factory.tcp(src="192.168.1.10", dst="192.168.1.20"))
        devices = {d.ip: d for d in session.derive(want_devices=True).devices}
        self.assertIn("Linux", devices["192.168.1.10"].os_hint)

    def test_traffic_totals_are_carried_through(self):
        session = self._session()
        for _ in range(4):
            session._on_packet(factory.tcp(src="192.168.1.10",
                                           dst="192.168.1.20", flags="PA",
                                           payload=b"x" * 100))
        devices = {d.ip: d for d in session.derive(want_devices=True).devices}
        self.assertGreater(devices["192.168.1.10"].bytes_sent, 0)
        self.assertEqual(devices["192.168.1.10"].packets, 4)

    def test_devices_are_only_built_when_asked_for(self):
        session = self._session()
        session._on_packet(factory.tcp(src="192.168.1.10", dst="192.168.1.20"))
        self.assertEqual(session.derive().devices, [])
        self.assertTrue(session.derive(want_devices=True).devices)


if __name__ == "__main__":
    unittest.main()


class TestPresence(unittest.TestCase):
    """A device that stopped talking minutes ago is not on the network now."""

    def test_recent_traffic_is_online(self):
        device = Device(ip="192.168.1.10", last_ts=1000.0, observed_at=1010.0)
        self.assertEqual(device.status, "online")
        self.assertTrue(device.online)

    def test_a_long_silence_is_offline(self):
        device = Device(ip="192.168.1.10", last_ts=1000.0,
                        observed_at=1000.0 + IDLE_SECONDS + 1)
        self.assertEqual(device.status, "offline")
        self.assertIn("last seen", device.presence)

    def test_an_arp_reply_counts_as_being_seen(self):
        device = Device(ip="192.168.1.10", last_ts=1000.0, responded_to_arp=True,
                        arp_ts=1600.0, observed_at=1610.0)
        self.assertEqual(device.status, "online")

    def test_nothing_timestamped_is_unknown_not_offline(self):
        """A host known only from a MAC table has no time to judge it by."""
        device = Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff",
                        observed_at=5000.0)
        self.assertEqual(device.status, "unknown")

    def test_presence_is_measured_against_the_capture_not_the_wall_clock(self):
        """An old pcap replays as it was, rather than as one dead network."""
        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session.devices = DeviceRegistry(local_prefix="192.168.1.")
        session._on_packet(factory.tcp(src="192.168.1.10", dst="192.168.1.20"))
        session._on_packet(factory.tcp(src="192.168.1.30", dst="192.168.1.20"))
        records = list(session.records)
        for record in records:
            record.ts -= 86400                       # a capture from yesterday
        records[0].ts -= IDLE_SECONDS + 60           # .10 fell quiet before it

        by_ip = {d.ip: d for d in session.derive(want_devices=True).devices}
        self.assertEqual(by_ip["192.168.1.30"].status, "online")
        self.assertEqual(by_ip["192.168.1.10"].status, "offline")

    def test_offline_devices_sort_below_the_live_ones(self):
        live = Device(ip="192.168.1.90", last_ts=1000.0, observed_at=1000.0)
        gone = Device(ip="192.168.1.20", last_ts=0.0, arp_ts=1.0,
                      observed_at=1000.0)
        self.assertLess(live.sort_key(), gone.sort_key())


class TestDeviceNaming(unittest.TestCase):
    """A device may only be named by something it says about *itself*.

    Regression test for a router being labelled `api.anthropic.com`: it was
    acting as the DNS resolver, and the name it was resolving on someone else's
    behalf was taken as its own identity.
    """

    def _session(self):
        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session.devices = DeviceRegistry(local_prefix="192.168.2.",
                                         gateway="192.168.2.1")
        return session

    def _devices(self, session):
        return {d.ip: d for d in session.derive(want_devices=True).devices}

    def test_a_resolver_is_not_named_after_what_it_resolves(self):
        session = self._session()
        session._on_packet(factory.dns_response_from(
            "192.168.2.1", "192.168.2.95", "api.anthropic.com",
            "160.79.104.10"))
        devices = self._devices(session)
        self.assertIn("192.168.2.1", devices)
        self.assertEqual(devices["192.168.2.1"].hostname, "")

    def test_a_client_is_not_named_after_the_site_it_visits(self):
        session = self._session()
        session._on_packet(factory.tls_client_hello(
            "www.example.com", dst="93.184.216.34"))
        session._on_packet(factory.dns_query("news.example.org",
                                             src="192.168.2.50"))
        devices = self._devices(session)
        for device in devices.values():
            self.assertNotIn("example", device.hostname)

    def test_an_mdns_self_announcement_does_name_the_device(self):
        session = self._session()
        session._on_packet(factory.mdns_announce("192.168.2.14", "Galaxy-S6"))
        self.assertEqual(self._devices(session)["192.168.2.14"].hostname,
                         "Galaxy-S6")

    def test_a_dhcp_request_names_the_device(self):
        session = self._session()
        session._on_packet(factory.dhcp_request("192.168.2.60",
                                                "viktors-laptop"))
        devices = self._devices(session)
        self.assertEqual(devices["192.168.2.60"].hostname, "viktors-laptop")

    def test_a_service_advert_is_evidence_not_a_name(self):
        session = self._session()
        session._on_packet(factory.mdns_service("192.168.2.13", "_googlecast"))
        device = self._devices(session)["192.168.2.13"]
        self.assertEqual(device.hostname, "")
        self.assertIn("_googlecast", device.advertised)
        self.assertEqual(device.kind, "tv")
        self.assertIn("advertises _googlecast", device.evidence)


class TestEvidenceWeighting(unittest.TestCase):
    """Self-declared signals must outrank a guess from the MAC vendor."""

    def classify(self, **kwargs):
        device = Device(ip="192.168.2.5", **kwargs)
        classify(device)
        return device

    def test_a_service_advert_beats_the_vendor(self):
        device = self.classify(advertised={"_googlecast"},
                               vendor="Samsung Electronics")
        self.assertEqual(device.kind, "tv")          # not "phone"

    def test_airplay_audio_beats_an_apple_oui(self):
        device = self.classify(advertised={"_raop"}, vendor="Apple, Inc.")
        self.assertEqual(device.kind, "speaker")     # not "phone"

    def test_a_self_claimed_hostname_beats_the_vendor(self):
        device = self.classify(vendor="TP-LINK TECHNOLOGIES CO.,LTD.",
                               hostname="LIVINGROOM-TV")
        self.assertEqual(device.kind, "tv")          # not "router"

    def test_being_the_gateway_outranks_everything(self):
        device = self.classify(is_gateway=True, vendor="Apple, Inc.",
                               hostname="somebodys-iphone")
        self.assertEqual(device.kind, ROUTER)

    def test_evidence_is_ordered_by_weight(self):
        device = self.classify(advertised={"_ipp"}, vendor="Hewlett Packard")
        self.assertEqual(device.evidence[0], "advertises _ipp")
        self.assertIn("MAC vendor", device.evidence[1])

    def test_the_vendor_still_decides_when_nothing_else_speaks(self):
        self.assertEqual(self.classify(vendor="Espressif Inc.").kind, IOT)
