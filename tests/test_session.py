"""Session behaviour: ring buffer, display filtering, flows, stats, pcap I/O."""

import os
import tempfile
import unittest

from netsour.capture import CaptureEngine, write_pcap
from netsour.flows import FlowTable
from netsour.session import Session
from netsour.stats import Stats, human_bytes, human_duration

from . import factory


def feed(session, packets):
    for packet in packets:
        session._on_packet(packet)


class TestDisplayFilter(unittest.TestCase):

    def setUp(self):
        self.session = Session(iface="", enable_rdns=False, enable_geo=False)
        feed(self.session, [
            factory.tcp(dport=80, flags="PA", payload=b"GET / HTTP/1.1\r\n"
                                                      b"Host: a\r\n\r\n"),
            factory.udp(dport=123),
            factory.icmp(),
            factory.arp(),
        ])

    def test_everything_is_visible_by_default(self):
        self.assertEqual(len(self.session.view), 4)
        self.assertFalse(self.session.filter.active())

    def test_protocol_toggle_rebuilds_the_view(self):
        self.session.toggle_protocol("UDP")
        self.assertEqual([r.proto_base for r in self.session.view],
                         ["TCP", "ICMP", "ARP"])
        self.session.toggle_protocol("UDP")
        self.assertEqual(len(self.session.view), 4)

    def test_text_filter_matches_metadata_and_payload(self):
        self.session.set_text_filter("http")
        self.assertEqual(len(self.session.view), 1)
        self.session.set_text_filter("icmp")
        self.assertEqual(len(self.session.view), 1)

    def test_flagged_only_filter(self):
        self.session.toggle_only_alerts()
        self.assertTrue(all(r.tags for r in self.session.view))

    def test_new_packets_respect_the_active_filter(self):
        self.session.toggle_protocol("UDP")
        before = len(self.session.view)
        feed(self.session, [factory.udp(dport=123)])
        self.assertEqual(len(self.session.view), before)
        feed(self.session, [factory.tcp()])
        self.assertEqual(len(self.session.view), before + 1)

    def test_reset_restores_everything(self):
        self.session.toggle_protocol("TCP")
        self.session.set_text_filter("nothing-matches-this")
        self.session.reset_filter()
        self.assertEqual(len(self.session.view), 4)
        self.assertFalse(self.session.filter.active())

    def test_describe_reports_the_active_filter(self):
        self.session.toggle_protocol("ARP")
        self.session.set_text_filter("dns")
        description = self.session.filter.describe()
        self.assertIn("ARP", description)
        self.assertIn("dns", description)


class TestRingBuffer(unittest.TestCase):

    def test_oldest_packets_rotate_out_of_both_lists(self):
        session = Session(iface="", buffer_size=10, enable_rdns=False,
                          enable_geo=False)
        feed(session, [factory.tcp(sport=i) for i in range(1000, 1040)])
        self.assertEqual(len(session.records), 10)
        self.assertEqual(len(session.view), 10)
        self.assertEqual(session.stats.dropped, 30)
        self.assertEqual(session.records[0].index, 31)

    def test_view_stays_a_subset_of_the_buffer(self):
        session = Session(iface="", buffer_size=8, enable_rdns=False,
                          enable_geo=False)
        session.toggle_protocol("UDP")
        feed(session, [factory.tcp(), factory.udp()] * 20)
        held = {id(r) for r in session.records}
        self.assertTrue({id(r) for r in session.view}.issubset(held))

    def test_clear_resets_every_derived_table(self):
        session = Session(iface="", enable_rdns=False, enable_geo=False)
        feed(session, [factory.tcp(dport=31337, flags="S")] * 3)
        session.clear()
        self.assertEqual(len(session.records), 0)
        self.assertEqual(len(session.flows.flows), 0)
        self.assertEqual(session.alerts.alerts, [])
        self.assertEqual(session.stats.total_packets, 0)


class TestFlowTable(unittest.TestCase):

    def test_both_directions_land_in_one_flow(self):
        session = Session(iface="", enable_rdns=False, enable_geo=False)
        feed(session, [
            factory.tcp(src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=80),
            factory.tcp(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=5000,
                        flags="SA"),
        ])
        self.assertEqual(len(session.flows.flows), 1)
        flow = next(iter(session.flows.flows.values()))
        self.assertEqual(flow.packets, 2)
        self.assertEqual(flow.packets_ab, 1)
        self.assertEqual(flow.packets_ba, 1)

    def test_state_reflects_the_flags_seen(self):
        session = Session(iface="", enable_rdns=False, enable_geo=False)
        feed(session, [factory.tcp(sport=5000, dport=80, flags="S")])
        flow = next(iter(session.flows.flows.values()))
        self.assertEqual(flow.state(), "unanswered")
        feed(session, [factory.tcp(src="192.168.1.20", dst="192.168.1.10",
                                   sport=80, dport=5000, flags="R")])
        self.assertEqual(flow.state(), "reset")

    def test_eviction_keeps_the_table_bounded(self):
        table = FlowTable(max_flows=20)
        from netsour.dissect import dissect

        for i in range(200):
            table.add(dissect(factory.tcp(sport=i, dport=i + 1), i, 1000.0 + i))
        self.assertLessEqual(len(table.flows), 20)
        self.assertGreater(table.evicted, 0)

    def test_sorting_by_bytes_puts_the_heaviest_first(self):
        session = Session(iface="", enable_rdns=False, enable_geo=False)
        feed(session, [factory.tcp(sport=1, dport=80, flags="PA",
                                   payload=b"x" * 500)])
        feed(session, [factory.tcp(sport=2, dport=80)])
        ordered = session.flows.sorted_flows("bytes")
        self.assertGreater(ordered[0].bytes, ordered[-1].bytes)


class TestStats(unittest.TestCase):

    def test_counters_track_protocols_and_talkers(self):
        stats = Stats()
        from netsour.dissect import dissect

        for i in range(5):
            stats.add(dissect(factory.tcp(src="10.0.0.1"), i, 1000.0 + i))
        self.assertEqual(stats.total_packets, 5)
        self.assertEqual(stats.proto_packets["TCP"], 5)
        self.assertEqual(stats.talkers_sent.most_common(1)[0][0], "10.0.0.1")

    def test_history_buckets_by_second(self):
        stats = Stats()
        from netsour.dissect import dissect

        for i in range(6):
            stats.add(dissect(factory.tcp(), i, 1000.0 + i))
        history = stats.history(10)
        self.assertGreaterEqual(len(history), 6)
        self.assertTrue(all(bucket[1] <= 1 for bucket in history))

    def test_human_bytes_scales(self):
        self.assertEqual(human_bytes(12), "12B")
        self.assertEqual(human_bytes(1536), "1.5K")
        self.assertEqual(human_bytes(1024 ** 2 * 3), "3.0M")

    def test_human_duration_shows_hours_only_when_needed(self):
        self.assertEqual(human_duration(75), "01:15")
        self.assertEqual(human_duration(3725), "1:02:05")


class TestPcapIO(unittest.TestCase):

    def test_write_then_replay_round_trips(self):
        packets = [factory.tcp(sport=i) for i in range(5)] + [factory.dns_query()]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.pcap")
            self.assertEqual(write_pcap(path, packets), 6)

            replayed = []
            engine = CaptureEngine(iface="", on_packet=replayed.append,
                                   pcap_path=path)
            engine._run_offline()
            self.assertEqual(len(replayed), 6)
            self.assertTrue(engine.finished)
            self.assertIsNone(engine.error)

    def test_saving_a_session_reports_the_count(self):
        session = Session(iface="", enable_rdns=False, enable_geo=False)
        feed(session, [factory.tcp(), factory.udp(), factory.arp()])
        session.toggle_protocol("ARP")
        with tempfile.TemporaryDirectory() as tmp:
            everything = session.save_pcap(os.path.join(tmp, "all.pcap"))
            filtered = session.save_pcap(os.path.join(tmp, "some.pcap"),
                                         visible_only=True)
        self.assertIn("3 captured", everything)
        self.assertIn("2 filtered", filtered)

    def test_missing_file_is_reported_not_raised(self):
        engine = CaptureEngine(iface="", on_packet=lambda p: None,
                               pcap_path="/nonexistent/x.pcap")
        engine._run_offline()
        self.assertIn("No such capture file", engine.error)


class TestCaptureEngine(unittest.TestCase):

    def test_pause_drops_packets_without_stopping(self):
        seen = []
        engine = CaptureEngine(iface="", on_packet=seen.append)
        engine._deliver(factory.tcp())
        self.assertTrue(engine.toggle_pause())
        engine._deliver(factory.tcp())
        self.assertEqual(len(seen), 1)
        self.assertFalse(engine.toggle_pause())
        engine._deliver(factory.tcp())
        self.assertEqual(len(seen), 2)


if __name__ == "__main__":
    unittest.main()
