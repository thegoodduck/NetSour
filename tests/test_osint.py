"""OSINT engine: gating, lifecycle, and the parsing helpers.

Nothing here touches the network - every source that would is mocked. The point
is that the engine queues the right work, records failures instead of raising,
and never contacts a target the caller did not ask for.
"""

import time
import unittest
from unittest import mock

from netsour.osint import (SOURCES, SOURCES_BY_KEY, Finding, OsintEngine,
                           _flatten_name, _http_findings, _is_ip, _rdap_contacts,
                           _rdata_text, _shorten, _system_resolver)


class FakeHeaders(dict):
    def items(self):
        return dict.items(self)


class TestSourceMetadata(unittest.TestCase):

    def test_every_source_declares_its_reach(self):
        for source in SOURCES:
            self.assertIn(source.applies, ("ip", "host", "both", "username"),
                          source.key)
            self.assertIsInstance(source.active, bool)
            self.assertTrue(source.note, source.key)

    def test_passive_sources_never_contact_the_target(self):
        passive = {s.key for s in SOURCES if not s.active}
        self.assertEqual(passive, {"rdns", "geo", "rdap", "dns", "social"})

    def test_active_sources_are_the_ones_that_connect(self):
        active = {s.key for s in SOURCES if s.active}
        self.assertEqual(active, {"tls", "http", "trace", "username"})

    def test_traffic_attribution_is_purely_local(self):
        """Reading the capture buffer sends nothing, so it must be passive."""
        self.assertFalse(SOURCES_BY_KEY["social"].active)

    def test_applicability_follows_the_target_kind(self):
        self.assertTrue(SOURCES_BY_KEY["rdns"].supports("8.8.8.8"))
        self.assertFalse(SOURCES_BY_KEY["rdns"].supports("example.com"))
        self.assertTrue(SOURCES_BY_KEY["dns"].supports("example.com"))
        self.assertFalse(SOURCES_BY_KEY["dns"].supports("8.8.8.8"))
        self.assertTrue(SOURCES_BY_KEY["rdap"].supports("8.8.8.8"))
        self.assertTrue(SOURCES_BY_KEY["rdap"].supports("example.com"))


class TestEngineGating(unittest.TestCase):

    def setUp(self):
        self.engine = OsintEngine()

    def test_disabled_engine_runs_nothing(self):
        engine = OsintEngine(enabled=False)
        self.assertIn("disabled", engine.run("8.8.8.8", "rdns"))
        self.assertEqual(engine.reports, {})

    def test_unknown_source_is_rejected(self):
        self.assertIn("unknown source", self.engine.run("8.8.8.8", "telepathy"))

    def test_empty_target_is_rejected(self):
        self.assertIn("no target", self.engine.run("", "rdns"))

    def test_inapplicable_source_is_refused(self):
        message = self.engine.run("8.8.8.8", "dns")
        self.assertIn("does not apply", message)

    def test_run_all_defaults_to_passive_only(self):
        started = []
        with mock.patch.object(self.engine, "_pool") as pool:
            pool.submit.side_effect = lambda fn, *a: started.append(a[1].key)
            self.engine.run_all("8.8.8.8")
        self.assertEqual(set(started), {"rdns", "geo", "rdap", "social"})
        self.assertNotIn("tls", started)
        self.assertNotIn("username", started)

    def test_run_all_can_include_active_sources(self):
        started = []
        with mock.patch.object(self.engine, "_pool") as pool:
            pool.submit.side_effect = lambda fn, *a: started.append(a[1].key)
            self.engine.run_all("8.8.8.8", include_active=True)
        self.assertIn("tls", started)
        self.assertIn("trace", started)

    def test_a_completed_source_is_not_rerun_without_force(self):
        section = self.engine.report("8.8.8.8").section("rdns")
        section.status = "done"
        self.assertIn("already gathered", self.engine.run("8.8.8.8", "rdns"))
        with mock.patch.object(self.engine, "_pool") as pool:
            self.engine.run("8.8.8.8", "rdns", force=True)
            pool.submit.assert_called_once()

    def test_a_running_source_is_not_queued_twice(self):
        self.engine.report("8.8.8.8").section("rdns").status = "running"
        self.assertIn("already running", self.engine.run("8.8.8.8", "rdns"))


class TestEngineExecution(unittest.TestCase):

    def setUp(self):
        self.engine = OsintEngine()

    def test_a_failing_source_records_the_error(self):
        with mock.patch.object(OsintEngine, "_source_rdns",
                               side_effect=OSError("no resolver")):
            self.engine._execute("8.8.8.8", SOURCES_BY_KEY["rdns"])
        section = self.engine.report("8.8.8.8").section("rdns")
        self.assertEqual(section.status, "error")
        self.assertIn("no resolver", section.error)

    def test_a_successful_source_stores_findings(self):
        with mock.patch.object(OsintEngine, "_source_rdns",
                               return_value=[Finding("ptr", "dns.google")]):
            self.engine._execute("8.8.8.8", SOURCES_BY_KEY["rdns"])
        section = self.engine.report("8.8.8.8").section("rdns")
        self.assertEqual(section.status, "done")
        self.assertEqual(section.findings[0].value, "dns.google")

    def test_an_empty_result_still_completes(self):
        with mock.patch.object(OsintEngine, "_source_rdns", return_value=[]):
            self.engine._execute("8.8.8.8", SOURCES_BY_KEY["rdns"])
        section = self.engine.report("8.8.8.8").section("rdns")
        self.assertEqual(section.status, "done")
        self.assertTrue(section.findings)

    def test_reports_are_isolated_per_target(self):
        self.engine.report("1.1.1.1").section("rdns").status = "done"
        self.assertEqual(self.engine.status("8.8.8.8", "rdns"), "idle")

    def test_clear_drops_one_target_or_all(self):
        self.engine.report("1.1.1.1")
        self.engine.report("8.8.8.8")
        self.engine.clear("1.1.1.1")
        self.assertNotIn("1.1.1.1", self.engine.reports)
        self.engine.clear()
        self.assertEqual(self.engine.reports, {})

    def test_private_targets_short_circuit_geo_and_rdap(self):
        from netsour.enrich import GeoIP

        engine = OsintEngine(geo=GeoIP(enabled=True))
        self.assertIn("private", engine._source_geo("192.168.1.1")[0].value)
        self.assertIn("private", engine._source_rdap("10.0.0.1")[0].value)

    def test_geo_reports_when_it_is_switched_off(self):
        from netsour.enrich import GeoIP

        engine = OsintEngine(geo=GeoIP(enabled=False))
        self.assertIn("disabled", engine._source_geo("8.8.8.8")[0].value)
        self.assertIn("disabled", OsintEngine()._source_geo("8.8.8.8")[0].value)

    def test_the_social_source_needs_a_capture_session(self):
        with self.assertRaises(RuntimeError):
            OsintEngine()._source_social("192.168.1.5")

    def test_is_running_reflects_section_state(self):
        report = self.engine.report("8.8.8.8")
        self.assertFalse(report.is_running)
        report.section("rdns").status = "running"
        self.assertTrue(report.is_running)


class TestParsingHelpers(unittest.TestCase):

    def test_ip_detection(self):
        self.assertTrue(_is_ip("192.168.1.1"))
        self.assertTrue(_is_ip("2606:4700::1"))
        self.assertFalse(_is_ip("example.com"))

    def test_txt_records_flatten_from_byte_lists(self):
        decode = lambda raw: raw.decode("ascii", "replace")
        self.assertEqual(_rdata_text([b"v=spf1", b"-all"], decode),
                         "v=spf1 -all")
        self.assertEqual(_rdata_text(b"mail.example.com", decode),
                         "mail.example.com")
        self.assertEqual(_rdata_text(10, decode), "10")

    def test_certificate_names_flatten_to_rdn_notation(self):
        name = ((("commonName", "example.com"),),
                (("organizationName", "Example Ltd"),))
        self.assertEqual(_flatten_name(name), "CN=example.com, O=Example Ltd")
        self.assertEqual(_flatten_name(None), "")

    def test_rdap_contacts_pull_abuse_addresses_out_of_vcards(self):
        data = {"entities": [{
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Desk"],
                                     ["email", {}, "text", "abuse@example.com"]]],
        }]}
        findings = _rdap_contacts(data)
        self.assertEqual(findings[0].label, "abuse")
        self.assertIn("abuse@example.com", findings[0].value)
        self.assertEqual(findings[0].role, "warn")

    def test_rdap_contacts_tolerate_missing_vcards(self):
        self.assertEqual(_rdap_contacts({"entities": [{"roles": ["tech"]}]}), [])
        self.assertEqual(_rdap_contacts({}), [])

    def test_http_findings_flag_revealing_and_missing_headers(self):
        findings = _http_findings("https", 200, FakeHeaders({
            "Server": "nginx/1.2.3",
            "Strict-Transport-Security": "max-age=31536000"}))
        rendered = {f.label: f for f in findings}
        self.assertEqual(rendered["server"].role, "warn")
        self.assertEqual(rendered["strict-transport-security"].role, "ok")
        self.assertIn("content-security-policy", rendered["missing"].value)

    def test_http_findings_mark_error_statuses(self):
        findings = _http_findings("http", 503, FakeHeaders({}))
        status = next(f for f in findings if f.label == "status")
        self.assertEqual(status.role, "warn")

    def test_shorten_collapses_whitespace(self):
        self.assertEqual(_shorten("a   b\n c"), "a b c")
        self.assertTrue(_shorten("x" * 200).endswith("…"))

    def test_resolver_falls_back_when_resolv_conf_is_unreadable(self):
        with mock.patch("builtins.open", side_effect=OSError):
            self.assertEqual(_system_resolver(), "1.1.1.1")


class TestCertificateExpiry(unittest.TestCase):

    def test_expiry_colouring(self):
        from netsour.osint import _expiry_role

        past = time.strftime("%b %d %H:%M:%S %Y GMT",
                             time.gmtime(time.time() - 86400))
        soon = time.strftime("%b %d %H:%M:%S %Y GMT",
                             time.gmtime(time.time() + 3 * 86400))
        later = time.strftime("%b %d %H:%M:%S %Y GMT",
                              time.gmtime(time.time() + 200 * 86400))
        self.assertEqual(_expiry_role("notAfter", past), "danger")
        self.assertEqual(_expiry_role("notAfter", soon), "warn")
        self.assertEqual(_expiry_role("notAfter", later), "ok")
        self.assertEqual(_expiry_role("notBefore", later), "base")

    def test_unparseable_dates_do_not_raise(self):
        from netsour.osint import _expiry_role

        self.assertEqual(_expiry_role("notAfter", "not a date"), "base")


if __name__ == "__main__":
    unittest.main()


class TestProfileVerification(unittest.TestCase):
    """Status codes alone produce false hits; these are the rules that fix it.

    Six of eighteen sites returned HTTP 200 for a username that exists nowhere,
    so `_read_profile` must decide from content, redirects or the title - and
    say "inconclusive" whenever it genuinely cannot tell.
    """

    def site(self, **kwargs):
        from netsour.osint import ProfileSite

        return ProfileSite(name="Test", url="https://x/{}", **kwargs)

    def read(self, site, username="jdoe", status=200, final="https://x/jdoe",
             body=""):
        from netsour.osint import _read_profile

        return _read_profile(site, username, status, final, body)

    def test_a_plain_200_counts_as_found(self):
        self.assertEqual(self.read(self.site())[0], "found")

    def test_a_non_200_status_is_inconclusive_not_found(self):
        self.assertEqual(self.read(self.site(), status=203)[0], "inconclusive")

    def test_an_absent_marker_beats_a_200(self):
        site = self.site(absent_markers=("No such user",))
        self.assertEqual(self.read(site, body="No such user.")[0], "not found")
        self.assertEqual(self.read(site, body="jdoe's profile")[0], "found")

    def test_a_redirect_to_signup_means_the_account_is_free(self):
        site = self.site(absent_url="bandcamp.com/signup")
        self.assertEqual(
            self.read(site, final="https://bandcamp.com/signup?new_domain=jdoe")[0],
            "not found")

    def test_a_present_marker_is_required_when_declared(self):
        site = self.site(present_markers=("tgme_page_title",))
        self.assertEqual(self.read(site, body="<div tgme_page_title>")[0], "found")
        self.assertEqual(self.read(site, body="<div>generic</div>")[0], "not found")

    def test_the_title_must_name_the_account_when_declared(self):
        site = self.site(title_has_user=True)
        self.assertEqual(self.read(site, body="<title>jdoe - Twitch</title>")[0],
                         "found")
        self.assertEqual(self.read(site, body="<title>Twitch</title>")[0],
                         "not found")

    def test_bot_protection_is_never_reported_as_a_result(self):
        site = self.site(blocked_markers=("Client Challenge",))
        state, detail = self.read(site, body="<title>Client Challenge</title>")
        self.assertEqual(state, "inconclusive")
        self.assertIn("bot protection", detail)

    def test_blocking_is_checked_before_anything_else(self):
        site = self.site(blocked_markers=("Client Challenge",),
                         absent_markers=("Client",))
        self.assertEqual(self.read(site, body="Client Challenge")[0],
                         "inconclusive")

    def test_marker_matching_is_case_insensitive(self):
        site = self.site(absent_markers=("no such user",))
        self.assertEqual(self.read(site, body="NO SUCH USER")[0], "not found")

    def test_every_configured_site_has_a_usable_url_template(self):
        from netsour.osint import USERNAME_SITES

        for site in USERNAME_SITES:
            self.assertIn("{}", site.url, site.name)
            self.assertTrue(site.url.startswith("https://"), site.name)

    def test_sites_known_to_soft_404_all_carry_a_verification_rule(self):
        """Regression guard: these six returned 200 for a nonexistent user."""
        from netsour.osint import USERNAME_SITES

        needs_rule = {"Bandcamp", "Hacker News", "PyPI", "Steam", "Telegram",
                      "Twitch"}
        for site in USERNAME_SITES:
            if site.name in needs_rule:
                has_rule = bool(site.absent_markers or site.present_markers
                                or site.absent_url or site.title_has_user
                                or site.blocked_markers)
                self.assertTrue(has_rule, f"{site.name} would soft-404")

    def test_http_errors_map_to_sensible_states(self):
        import urllib.error
        from netsour.osint import _probe_profile

        def raise_http(code):
            def opener(*args, **kwargs):
                raise urllib.error.HTTPError("u", code, "m", {}, None)
            return opener

        with mock.patch("urllib.request.urlopen", raise_http(404)):
            self.assertEqual(_probe_profile(self.site(), "jdoe")[0], "not found")
        for code in (403, 429):
            with mock.patch("urllib.request.urlopen", raise_http(code)):
                self.assertEqual(_probe_profile(self.site(), "jdoe")[0],
                                 "inconclusive")

    def test_a_network_failure_is_inconclusive_not_absent(self):
        from netsour.osint import _probe_profile

        with mock.patch("urllib.request.urlopen", side_effect=OSError("down")):
            state, _ = _probe_profile(self.site(), "jdoe")
        self.assertEqual(state, "inconclusive")


class TestTargetKind(unittest.TestCase):

    def test_classification(self):
        from netsour.osint import target_kind

        self.assertEqual(target_kind("192.168.1.1"), "ip")
        self.assertEqual(target_kind("2606:4700::1"), "ip")
        self.assertEqual(target_kind("example.com"), "host")
        self.assertEqual(target_kind("a.b.c.example.com"), "host")
        self.assertEqual(target_kind("nightowl"), "username")
        self.assertEqual(target_kind("night_owl-42"), "username")

    def test_sources_are_gated_by_kind(self):
        self.assertTrue(SOURCES_BY_KEY["username"].supports("nightowl"))
        self.assertFalse(SOURCES_BY_KEY["username"].supports("example.com"))
        self.assertFalse(SOURCES_BY_KEY["username"].supports("1.1.1.1"))
        self.assertTrue(SOURCES_BY_KEY["social"].supports("192.168.1.5"))
        self.assertFalse(SOURCES_BY_KEY["social"].supports("nightowl"))
        self.assertFalse(SOURCES_BY_KEY["rdap"].supports("nightowl"))

    def test_run_all_on_a_username_queues_nothing_passive(self):
        engine = OsintEngine()
        with mock.patch.object(engine, "_pool") as pool:
            message = engine.run_all("nightowl")
            pool.submit.assert_not_called()
        self.assertIn("nothing new", message)


class TestHttpTlsHandling(unittest.TestCase):
    """Headers from an unverified TLS session must be labelled as such."""

    def test_a_valid_certificate_needs_no_warning(self):
        engine = OsintEngine()
        response = mock.MagicMock()
        response.status = 200
        response.headers = {"Server": "nginx"}
        response.__enter__.return_value = response
        with mock.patch("urllib.request.urlopen", return_value=response):
            findings = engine._source_http("example.com")
        self.assertNotIn("tls", [f.label for f in findings])

    def test_a_bad_certificate_falls_back_but_flags_the_result(self):
        import ssl as ssl_mod

        engine = OsintEngine()
        response = mock.MagicMock()
        response.status = 200
        response.headers = {"Server": "nginx"}
        response.__enter__.return_value = response
        error = ssl_mod.SSLCertVerificationError("self-signed certificate")
        error.verify_message = "self-signed certificate"

        calls = []

        def urlopen(request, timeout=None, context=None):
            calls.append(context)
            if context is None:
                raise error
            return response

        with mock.patch("urllib.request.urlopen", side_effect=urlopen):
            findings = engine._source_http("10.0.0.1")

        self.assertIsNone(calls[0])              # verified attempt came first
        self.assertIsNotNone(calls[1])           # then the unverified retry
        warning = findings[0]
        self.assertEqual(warning.label, "tls")
        self.assertEqual(warning.role, "danger")
        self.assertIn("UNVERIFIED", warning.value)
        self.assertIn("cannot be trusted", warning.value)

    def test_an_unreachable_host_raises_rather_than_reporting_nothing(self):
        engine = OsintEngine()
        with mock.patch("urllib.request.urlopen", side_effect=OSError("refused")):
            with self.assertRaises(RuntimeError):
                engine._source_http("10.0.0.1")
