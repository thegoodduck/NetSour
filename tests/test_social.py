"""Social attribution: platform matching, identity extraction, honesty.

The central claim this suite defends is that a username is only ever reported
when it was genuinely on the wire - read out of cleartext, or embedded in a
hostname - and that the two are never confused.
"""

import unittest

from netsour.dissect import dissect
from netsour.social import (INFERRED, OBSERVED, SocialTracker,
                            looks_like_username, platform_for, vhost_username)

from . import factory


def rec(packet, index=1, ts=1000.0):
    return dissect(packet, index, ts)


def http(payload, host="192.168.1.10", dst="151.101.1.140", index=1):
    return rec(factory.tcp(src=host, dst=dst, dport=80, flags="PA",
                           payload=payload), index=index)


class TestPlatformMatching(unittest.TestCase):

    def test_front_door_and_cdn_domains_both_match(self):
        self.assertEqual(platform_for("www.instagram.com"), "Instagram")
        self.assertEqual(platform_for("scontent.cdninstagram.com"), "Instagram")
        self.assertEqual(platform_for("gateway.discord.gg"), "Discord")
        self.assertEqual(platform_for("abs.twimg.com"), "X / Twitter")

    def test_unrelated_hosts_do_not_match(self):
        for host in ("example.com", "kernel.org", "", "notinstagram.evil.com"):
            self.assertIsNone(platform_for(host), host)

    def test_matching_is_suffix_anchored_not_substring(self):
        self.assertIsNone(platform_for("reddit.com.phishing.example"))

    def test_case_and_trailing_dot_are_tolerated(self):
        self.assertEqual(platform_for("WWW.Reddit.COM."), "Reddit")


class TestVhostUsernames(unittest.TestCase):

    def test_account_bearing_hostnames_yield_a_name(self):
        self.assertEqual(vhost_username("someuser.tumblr.com"),
                         ("someuser", "Tumblr"))
        self.assertEqual(vhost_username("devpages.github.io"),
                         ("devpages", "GitHub Pages"))

    def test_infrastructure_subdomains_are_not_usernames(self):
        for host in ("www.tumblr.com", "api.tumblr.com", "cdn.tumblr.com",
                     "static.github.io", "assets.wordpress.com"):
            self.assertIsNone(vhost_username(host), host)

    def test_deeper_subdomains_are_rejected(self):
        self.assertIsNone(vhost_username("a.b.tumblr.com"))

    def test_the_bare_domain_is_not_a_username(self):
        self.assertIsNone(vhost_username("tumblr.com"))


class TestUsernameShape(unittest.TestCase):

    def test_plausible_names(self):
        for name in ("jdoe", "night_owl", "user-42", "a1"):
            self.assertTrue(looks_like_username(name), name)

    def test_implausible_names(self):
        for name in ("", "x", "a.b", "has space", "x" * 60, "-lead"):
            self.assertFalse(looks_like_username(name), name)

    def test_single_character_names_are_rejected_as_too_noisy(self):
        """`/u/a` is far more often a route than an account."""
        tracker = SocialTracker()
        tracker.inspect(http(b"GET /u/a HTTP/1.1\r\nHost: www.reddit.com\r\n\r\n"))
        self.assertEqual(tracker.usernames(), [])


class TestEncryptedTraffic(unittest.TestCase):
    """The core honesty property: TLS yields a platform and nothing more."""

    def test_tls_gives_the_platform_but_no_username(self):
        tracker = SocialTracker()
        tracker.inspect(rec(factory.tls_client_hello("i.instagram.com")))
        activity = tracker.activity_for()
        self.assertEqual(len(activity), 1)
        self.assertEqual(activity[0].platform, "Instagram")
        self.assertFalse(activity[0].cleartext)
        self.assertEqual(tracker.usernames(), [])

    def test_dns_alone_attributes_a_platform(self):
        tracker = SocialTracker()
        tracker.inspect(rec(factory.dns_query("gateway.discord.gg")))
        self.assertEqual(tracker.activity_for()[0].platform, "Discord")
        self.assertEqual(tracker.usernames(), [])

    def test_a_username_bearing_sni_is_marked_inferred_not_observed(self):
        tracker = SocialTracker()
        tracker.inspect(rec(factory.tls_client_hello("someuser.tumblr.com")))
        hint = tracker.hints_for()[0]
        self.assertEqual(hint.value, "someuser")
        self.assertEqual(hint.confidence, INFERRED)
        self.assertIn("hostname", hint.method)

    def test_non_social_traffic_is_ignored_entirely(self):
        tracker = SocialTracker()
        tracker.inspect(rec(factory.tls_client_hello("example.com")))
        tracker.inspect(rec(factory.udp(dport=123)))
        tracker.inspect(rec(factory.arp()))
        self.assertEqual(tracker.activity_for(), [])
        self.assertEqual(tracker.hints_for(), [])


class TestCleartextExtraction(unittest.TestCase):

    def test_username_in_a_path(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"GET /u/nightowl/comments HTTP/1.1\r\n"
                             b"Host: www.reddit.com\r\n\r\n"))
        hint = tracker.hints_for()[0]
        self.assertEqual(hint.value, "nightowl")
        self.assertEqual(hint.confidence, OBSERVED)

    def test_handle_in_an_at_path(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"GET /@someone HTTP/1.1\r\nHost: medium.com\r\n\r\n",
                             dst="162.159.153.4"))
        self.assertIn("someone", tracker.usernames())

    def test_username_in_a_query_parameter(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"POST /login?username=jdoe HTTP/1.1\r\n"
                             b"Host: www.reddit.com\r\n\r\n"))
        self.assertEqual(tracker.usernames(), ["jdoe"])

    def test_url_encoded_values_are_decoded(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"POST /l?email=a%40b.com HTTP/1.1\r\n"
                             b"Host: www.reddit.com\r\n\r\n"))
        emails = [h.value for h in tracker.hints_for() if h.kind == "email"]
        self.assertIn("a@b.com", emails)

    def test_username_in_a_json_body(self):
        tracker = SocialTracker()
        tracker.inspect(http(b'POST /1.1/account.json HTTP/1.1\r\n'
                             b'Host: api.twitter.com\r\n\r\n'
                             b'{"screen_name":"nightowl"}',
                             dst="104.244.42.1"))
        self.assertIn("nightowl", tracker.usernames())

    def test_numeric_ids_are_not_called_usernames(self):
        tracker = SocialTracker()
        tracker.inspect(http(b'POST /a HTTP/1.1\r\nHost: api.twitter.com\r\n\r\n'
                             b'{"id_str":"99182"}', dst="104.244.42.1"))
        kinds = {h.kind for h in tracker.hints_for()}
        self.assertIn("user-id", kinds)
        self.assertNotIn("username", kinds)

    def test_referer_reveals_a_profile_on_another_platform(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"GET / HTTP/1.1\r\nHost: www.reddit.com\r\n"
                             b"Referer: https://mygamerhandle.tumblr.com/\r\n\r\n"))
        hints = {h.value: h for h in tracker.hints_for()}
        self.assertIn("mygamerhandle", hints)
        self.assertEqual(hints["mygamerhandle"].platform, "Tumblr")

    def test_cleartext_is_flagged_on_the_activity_row(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"GET /u/x HTTP/1.1\r\nHost: www.reddit.com\r\n\r\n"))
        self.assertTrue(tracker.activity_for()[0].cleartext)

    def test_hints_record_the_packet_they_came_from(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"GET /u/nightowl HTTP/1.1\r\n"
                             b"Host: www.reddit.com\r\n\r\n", index=42))
        self.assertEqual(tracker.hints_for()[0].packet_index, 42)


class TestAggregation(unittest.TestCase):

    def test_repeats_increment_a_count_rather_than_duplicating(self):
        tracker = SocialTracker()
        for i in range(4):
            tracker.inspect(http(b"GET /u/jdoe HTTP/1.1\r\n"
                                 b"Host: www.reddit.com\r\n\r\n", index=i))
        hints = tracker.hints_for()
        self.assertEqual(len(hints), 1)
        self.assertEqual(hints[0].count, 4)

    def test_an_observation_upgrades_an_earlier_inference(self):
        tracker = SocialTracker()
        tracker.inspect(rec(factory.tls_client_hello("jdoe.tumblr.com")))
        self.assertEqual(tracker.hints_for()[0].confidence, INFERRED)
        tracker.inspect(http(b"GET / HTTP/1.1\r\nHost: www.reddit.com\r\n"
                             b"Referer: https://jdoe.tumblr.com/\r\n\r\n"))
        upgraded = [h for h in tracker.hints_for() if h.value == "jdoe"]
        self.assertEqual(upgraded[0].confidence, OBSERVED)

    def test_the_local_endpoint_is_treated_as_the_client(self):
        tracker = SocialTracker()
        tracker.inspect(rec(factory.tcp(src="93.184.216.34", dst="192.168.1.10",
                                        sport=443, dport=40000, flags="PA",
                                        payload=b"")))
        tracker.inspect(rec(factory.tls_client_hello("i.instagram.com")))
        self.assertEqual(tracker.clients(), ["192.168.1.10"])

    def test_activity_is_scoped_per_client(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"GET /u/alice HTTP/1.1\r\n"
                             b"Host: www.reddit.com\r\n\r\n",
                             host="192.168.1.10"))
        tracker.inspect(http(b"GET /u/bob HTTP/1.1\r\n"
                             b"Host: www.reddit.com\r\n\r\n",
                             host="192.168.1.20"))
        self.assertEqual(tracker.usernames("192.168.1.10"), ["alice"])
        self.assertEqual(tracker.usernames("192.168.1.20"), ["bob"])
        self.assertEqual(sorted(tracker.clients()),
                         ["192.168.1.10", "192.168.1.20"])

    def test_reuse_across_platforms_is_correlated(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"GET /u/nightowl HTTP/1.1\r\n"
                             b"Host: www.reddit.com\r\n\r\n"))
        tracker.inspect(http(b'POST /a HTTP/1.1\r\nHost: api.twitter.com\r\n\r\n'
                             b'{"screen_name":"nightowl"}', dst="104.244.42.1"))
        correlated = tracker.correlated()
        self.assertEqual(correlated[0][0], "nightowl")
        self.assertEqual(correlated[0][1], ["Reddit", "X / Twitter"])

    def test_a_name_on_one_platform_is_not_correlated(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"GET /u/solo HTTP/1.1\r\n"
                             b"Host: www.reddit.com\r\n\r\n"))
        self.assertEqual(tracker.correlated(), [])

    def test_summary_counts(self):
        tracker = SocialTracker()
        tracker.inspect(rec(factory.tls_client_hello("i.instagram.com")))
        tracker.inspect(http(b"GET /u/jdoe HTTP/1.1\r\n"
                             b"Host: www.reddit.com\r\n\r\n"))
        summary = tracker.summary()
        self.assertEqual(summary["platforms"], 2)
        self.assertEqual(summary["usernames"], 1)
        self.assertEqual(summary["cleartext_platforms"], 1)

    def test_hint_storage_is_bounded(self):
        tracker = SocialTracker(max_hints=5)
        for i in range(50):
            tracker.inspect(http(f"GET /u/user{i} HTTP/1.1\r\n"
                                 f"Host: www.reddit.com\r\n\r\n".encode(),
                                 index=i))
        self.assertLessEqual(len(tracker.hints), 5)

    def test_clear_empties_everything(self):
        tracker = SocialTracker()
        tracker.inspect(http(b"GET /u/x HTTP/1.1\r\nHost: www.reddit.com\r\n\r\n"))
        tracker.clear()
        self.assertEqual(tracker.activity_for(), [])
        self.assertEqual(tracker.hints_for(), [])

    def test_a_malformed_packet_cannot_break_the_tracker(self):
        tracker = SocialTracker()

        class Broken:
            proto = "TCP/HTTP"

            def __getattr__(self, name):
                raise ValueError("boom")

        tracker.inspect(Broken())          # must not raise


class TestSessionIntegration(unittest.TestCase):

    def test_the_session_feeds_the_tracker(self):
        from netsour.session import Session

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session._on_packet(factory.tls_client_hello("i.instagram.com"))
        session._on_packet(factory.tcp(dport=80, flags="PA",
                                       payload=b"GET /u/jdoe HTTP/1.1\r\n"
                                               b"Host: www.reddit.com\r\n\r\n"))
        self.assertEqual(session.social.summary()["platforms"], 2)
        self.assertIn("jdoe", session.social.usernames())

    def test_clearing_the_session_clears_social_state(self):
        from netsour.session import Session

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session._on_packet(factory.tls_client_hello("i.instagram.com"))
        session.clear()
        self.assertEqual(session.social.activity_for(), [])

    def test_the_social_source_reports_encryption_honestly(self):
        from netsour.session import Session

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        session._on_packet(factory.tls_client_hello("i.instagram.com"))
        rendered = " ".join(f.value for f in
                            session.osint._source_social("192.168.1.10"))
        self.assertIn("encrypted", rendered)
        self.assertIn("no username visible", rendered)

    def test_the_social_source_handles_a_host_with_no_activity(self):
        from netsour.session import Session

        session = Session(iface="", enable_rdns=False, enable_geo=False)
        findings = session.osint._source_social("10.9.9.9")
        self.assertIn("no social platform traffic", findings[0].value)


if __name__ == "__main__":
    unittest.main()
