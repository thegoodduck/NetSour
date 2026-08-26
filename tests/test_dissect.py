"""Dissection: protocol identification, application labelling, tagging."""

import unittest

from netsour.dissect import (decode_name, dissect, parse_http, parse_tls_sni,
                             tcp_flag_str)

from . import factory


def rec(packet, index=1, ts=1000.0):
    return dissect(packet, index, ts)


class TestTransportDissection(unittest.TestCase):

    def test_tcp_endpoints_and_flags(self):
        record = rec(factory.tcp(sport=1234, dport=80, flags="S"))
        self.assertEqual(record.proto, "TCP")
        self.assertEqual((record.src, record.sport), ("192.168.1.10", 1234))
        self.assertEqual((record.dst, record.dport), ("192.168.1.20", 80))
        self.assertEqual(record.flags, "S")
        self.assertIn("syn", record.tags)

    def test_udp_is_labelled_with_the_service(self):
        record = rec(factory.udp(dport=123))
        self.assertEqual(record.proto_base, "UDP")
        self.assertIn("ntp", record.info)

    def test_icmp_type_is_named(self):
        record = rec(factory.icmp())
        self.assertEqual(record.proto, "ICMP")
        self.assertIn("echo-request", record.info)

    def test_arp_request_and_reply_read_differently(self):
        request = rec(factory.arp(op=1, psrc="192.168.1.5"))
        reply = rec(factory.arp(op=2, psrc="192.168.1.5"))
        self.assertEqual(request.proto, "ARP")
        self.assertIn("Who has", request.info)
        self.assertIn("is at", reply.info)

    def test_reset_is_tagged(self):
        record = rec(factory.tcp(flags="RA"))
        self.assertIn("reset", record.tags)

    def test_length_is_the_wire_length(self):
        packet = factory.tcp(payload=b"0123456789")
        self.assertEqual(rec(packet).length, len(bytes(packet)))

    def test_malformed_packets_do_not_raise(self):
        class Exploding:
            def __init__(self):
                self.time = 0.0

            @property
            def payload(self):
                raise ValueError("boom")

            def __len__(self):
                raise ValueError("boom")

        record = dissect(Exploding(), 1, 0.0)
        self.assertIsNotNone(record)
        self.assertEqual(record.index, 1)


class TestApplicationLayer(unittest.TestCase):

    def test_dns_query_names_the_question(self):
        record = rec(factory.dns_query("example.com"))
        self.assertEqual(record.proto, "UDP/DNS")
        self.assertEqual(record.hostname, "example.com")
        self.assertIn("Query A example.com", record.info)

    def test_dns_response_reports_rcode_and_answer(self):
        record = rec(factory.dns_response())
        self.assertIn("NOERROR", record.info)
        self.assertIn("93.184.216.34", record.info)

    def test_nxdomain_is_visible_to_the_detector(self):
        record = rec(factory.dns_response(rcode=3))
        self.assertIn("NXDOMAIN", record.info)

    def test_mdns_is_distinguished_from_dns(self):
        record = rec(factory.dns_query(dport=5353))
        self.assertEqual(record.proto, "UDP/MDNS")

    def test_tls_sni_is_extracted(self):
        record = rec(factory.tls_client_hello("secure.example.org"))
        self.assertEqual(record.proto, "TCP/TLS")
        self.assertEqual(record.hostname, "secure.example.org")

    def test_http_request_is_summarised_and_flagged(self):
        record = rec(factory.tcp(dport=80, flags="PA",
                                 payload=b"GET /index HTTP/1.1\r\n"
                                         b"Host: intranet.local\r\n\r\n"))
        self.assertEqual(record.proto, "TCP/HTTP")
        self.assertEqual(record.hostname, "intranet.local")
        self.assertIn("cleartext", record.tags)

    def test_payload_prefix_is_searchable(self):
        record = rec(factory.tcp(dport=80, flags="PA",
                                 payload=b"POST / HTTP/1.1\r\n"
                                         b"Authorization: Basic QQ==\r\n\r\n"))
        self.assertTrue(record.matches("basic"))
        self.assertFalse(record.matches("kerberos"))


class TestRecordHelpers(unittest.TestCase):

    def test_conversation_key_is_direction_agnostic(self):
        forward = rec(factory.tcp(src="10.0.0.1", dst="10.0.0.2",
                                  sport=1111, dport=80))
        reverse = rec(factory.tcp(src="10.0.0.2", dst="10.0.0.1",
                                  sport=80, dport=1111, flags="SA"))
        self.assertEqual(forward.key, reverse.key)

    def test_proto_base_strips_the_application_label(self):
        self.assertEqual(rec(factory.dns_query()).proto_base, "UDP")
        self.assertEqual(rec(factory.tls_client_hello()).proto_base, "TCP")

    def test_matches_searches_every_visible_field(self):
        record = rec(factory.tcp(src="10.9.8.7", dport=443))
        self.assertTrue(record.matches("10.9.8"))
        self.assertTrue(record.matches("tcp"))
        self.assertTrue(record.matches("443"))
        self.assertFalse(record.matches("zzz"))


class TestParsers(unittest.TestCase):

    def test_tcp_flag_letters(self):
        self.assertEqual(tcp_flag_str(0x02), "S")
        self.assertEqual(tcp_flag_str(0x12), "SA")
        self.assertEqual(tcp_flag_str(0x18), "PA")
        self.assertEqual(tcp_flag_str(0), "-")

    def test_sni_parser_rejects_non_tls(self):
        self.assertEqual(parse_tls_sni(b"GET / HTTP/1.1\r\n\r\n"), "")
        self.assertEqual(parse_tls_sni(b""), "")
        self.assertEqual(parse_tls_sni(b"\x16" + b"\x00" * 200), "")

    def test_http_parser_rejects_non_http(self):
        self.assertEqual(parse_http(b"\x16\x03\x01binary"), ("", ""))

    def test_decode_name_rejects_implausible_hostnames(self):
        self.assertEqual(decode_name(b"example.com."), "example.com")
        self.assertEqual(decode_name(b"\xff\xfe\x00garbage"), "")
        self.assertEqual(decode_name(b"a" * 300), "")


if __name__ == "__main__":
    unittest.main()
