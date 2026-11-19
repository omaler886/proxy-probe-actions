# -*- coding: utf-8 -*-
"""Offline contract tests for multi-source egress geolocation.

Run: python -m unittest discover -s tests -v
No network: PROBE_GEO_LOOKUP stays unset, every provider is stubbed.
"""
import importlib.util
import sys
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "geo_naming.py"
SPEC = importlib.util.spec_from_file_location("geo_naming", PATH)
g = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = g
SPEC.loader.exec_module(g)


class BrandTests(unittest.TestCase):
    """The production bug: "Hong Kong Broadband Network Ltd." -> "Hong"."""

    def test_generic_first_word_is_never_a_brand(self):
        self.assertEqual(g._org_brand("Hong Kong Broadband Network Ltd."), "")
        self.assertEqual(g._org_brand("Korea Telecom"), "")
        self.assertEqual(g._org_brand("China Telecom"), "")
        self.assertEqual(g._org_brand("Hong Kong Telecommunications HKT Limited"), "HKT")

    def test_asn_table_beats_string_parsing(self):
        # Without the table "Hong Kong Broadband Network" has no usable word.
        self.assertEqual(g._org_brand("Hong Kong Broadband Network Ltd.", 9269), "HKBN")
        self.assertEqual(g._org_brand("Hong Kong Telecommunications", 4760), "HKT")
        self.assertEqual(g._org_brand("", 13335), "Cloudflare")

    def test_registry_handle_noise_is_stripped(self):
        self.assertEqual(g._org_brand("HKTIMS-AP"), "HKTIMS")
        self.assertEqual(g._org_brand("HKBNES-AS-AP"), "HKBNES")
        self.assertEqual(g._org_brand("Zenlayer Inc"), "Zenlayer")
        self.assertEqual(g._org_brand("Kaopu Cloud HK Limited"), "Kaopu")

    def test_empty_input(self):
        self.assertEqual(g._org_brand(""), "")
        self.assertEqual(g._org_brand(None), "")
        self.assertEqual(g._org_brand("   "), "")


class VoteTests(unittest.TestCase):
    def test_majority_wins(self):
        self.assertEqual(g._majority([("ipapi", "HK"), ("ipwho", "HK"), ("trace", "CN")]), "HK")

    def test_full_tie_follows_authority_order(self):
        # One vote each: ip-api is first in the list, so it anchors.
        self.assertEqual(g._majority([("ipapi", "HK"), ("ipwho", "CN"), ("trace", "TW")]), "HK")

    def test_blank_votes_are_ignored(self):
        self.assertEqual(g._majority([("ipapi", ""), ("ipwho", "US"), ("trace", "")]), "US")
        self.assertEqual(g._majority([]), "")

    def test_single_wrong_database_cannot_flip_a_country(self):
        # ip-api + ipwho agree; one bad trace vote loses.
        self.assertEqual(
            g._majority([("trace", "DE"), ("ipapi", "US"), ("ipwho", "US")]), "US")


class DisplayTests(unittest.TestCase):
    def setUp(self):
        g.RESOLVER.clear()

    def test_offline_degrades_to_country_and_unknown(self):
        self.assertEqual(g.display_name("8.8.8.8", "US"), "🇺🇸美国-Unknown")

    def test_no_fabricated_address_segment(self):
        # The old code emitted "-Unknown-未知地址"; no placeholder city now.
        self.assertNotIn("未知地址", g.display_name("8.8.8.8", "US"))

    def test_unknown_country_is_still_rendered_once(self):
        name = g.display_name("8.8.8.8", "")
        self.assertEqual(name, "未知-Unknown")

    def test_entry_is_copy_not_alias(self):
        g.RESOLVER._cache["1.2.3.4"] = dict(g._blank("HK"), asn=4760, org="HKT", city="中環")
        first = g.RESOLVER.entry("1.2.3.4")
        first["org"] = "mutated"
        self.assertEqual(g.RESOLVER.entry("1.2.3.4")["org"], "HKT")

    def test_display_uses_brand_and_city_when_present(self):
        g.RESOLVER._cache["1.2.3.4"] = dict(g._blank("HK"), asn=9269, org="HKBN", city="葵涌")
        self.assertEqual(g.display_name("1.2.3.4", "HK"), "🇭🇰香港-HKBN-葵涌")

    def test_city_equal_to_country_is_dropped(self):
        g.RESOLVER._cache["1.2.3.4"] = dict(g._blank("SG"), asn=16509, org="AWS",
                                            city="新加坡")
        self.assertEqual(g.display_name("1.2.3.4", "SG"), "🇸🇬新加坡-AWS")

    def test_no_bare_asn_number_in_name_with_city(self):
        # AS56971 style fallback was a defect; with a city, drop the brand
        # segment entirely instead of leaking "AS56971" or "Unknown".
        g.RESOLVER._cache["1.2.3.4"] = dict(g._blank("HK"), asn=56971, org="", city="九龙")
        self.assertEqual(g.display_name("1.2.3.4", "HK"), "🇭🇰香港-九龙")
        for part in g.RESOLVER.display_parts("1.2.3.4", "HK"):
            self.assertNotIn("AS56971", part)
            self.assertNotIn("Unknown", part)

    def test_no_bare_asn_number_without_location_falls_back_unknown(self):
        # No brand and no city/region: honest "Unknown" marker, never an ASN.
        g.RESOLVER._cache["1.2.3.4"] = dict(g._blank("US"), asn=64500, org="")
        self.assertEqual(g.display_name("1.2.3.4", "US"), "🇺🇸美国-Unknown")

    def test_flag_requires_two_letters(self):
        self.assertEqual(g._flag("US"), "🇺🇸")
        self.assertEqual(g._flag("usa"), "")
        self.assertEqual(g._flag(""), "")


class OfflinePrefetchTests(unittest.TestCase):
    def setUp(self):
        g.RESOLVER.clear()

    def test_no_network_when_lookup_disabled(self):
        def boom(*_a, **_k):
            raise AssertionError("network must not be touched while offline")
        original_cymru, original_ipapi, original_who = g.cymru_asn_cc, g._ipapi_batch, g._ipwho
        g.cymru_asn_cc, g._ipapi_batch, g._ipwho = boom, boom, boom
        try:
            g.prefetch([("8.8.8.8", "US"), ("1.1.1.1", "AU")])
        finally:
            g.cymru_asn_cc, g._ipapi_batch, g._ipwho = original_cymru, original_ipapi, original_who
        self.assertEqual(g.RESOLVER.entry("8.8.8.8")["cc"], "US")
        self.assertEqual(g.RESOLVER.entry("1.1.1.1")["cc"], "AU")

    def test_prefetch_caches_so_one_exit_is_queried_once(self):
        calls = []

        def fake_cymru(ip):
            calls.append(ip)
            return 9269, "HK"

        original = (g.cymru_asn_cc, g._ipapi_batch, g._ipwho, g.LOOKUP_ON)
        g.cymru_asn_cc = fake_cymru
        g._ipapi_batch = lambda ips: {}
        g._ipwho = lambda ip: None
        g.LOOKUP_ON = True
        try:
            g.prefetch([("1.2.3.4", "HK")])
            g.prefetch([("1.2.3.4", "HK")])
        finally:
            g.cymru_asn_cc, g._ipapi_batch, g._ipwho, g.LOOKUP_ON = original
        self.assertEqual(calls, ["1.2.3.4"])
        self.assertEqual(g.RESOLVER.entry("1.2.3.4")["org"], "HKBN")

    def test_failing_provider_degrades_only_that_field(self):
        original = (g.cymru_asn_cc, g._ipapi_batch, g._ipwho, g.LOOKUP_ON)
        g.cymru_asn_cc = lambda ip: (0, "")
        g._ipapi_batch = lambda ips: {"1.2.3.4": {"cc": "HK", "city": "香港",
                                                 "region": "", "asn": 4760,
                                                 "asname": "HKTIMS-AP"}}
        g._ipwho = lambda ip: None
        g.LOOKUP_ON = True
        try:
            g.prefetch([("1.2.3.4", "")])
        finally:
            g.cymru_asn_cc, g._ipapi_batch, g._ipwho, g.LOOKUP_ON = original
        entry = g.RESOLVER.entry("1.2.3.4")
        self.assertEqual(entry["cc"], "HK")
        self.assertEqual(entry["org"], "HKT")
        self.assertEqual(entry["asn"], 4760)

    def test_cymru_cc_is_deliberately_not_a_country_vote(self):
        """Cymru reports the RIR registry country, not the usage location.

        AWS registers AS16509 in the US, so a Cymru vote would label an AWS
        Sydney egress "US". Only the ASN may come from Cymru.
        """
        original = (g.cymru_asn_cc, g._ipapi_batch, g._ipwho, g.LOOKUP_ON)
        g.cymru_asn_cc = lambda ip: (16509, "US")
        g._ipapi_batch = lambda ips: {}
        g._ipwho = lambda ip: {"cc": "AU", "city": "Sydney", "region": "",
                               "zone": "", "country": "Australia", "asn": 16509,
                               "org": "Amazon.com, Inc."}
        g.LOOKUP_ON = True
        try:
            g.prefetch([("13.55.52.44", "AU")])
            entry = g.RESOLVER.entry("13.55.52.44")
        finally:
            g.cymru_asn_cc, g._ipapi_batch, g._ipwho, g.LOOKUP_ON = original
        self.assertEqual(entry["asn"], 16509)
        self.assertEqual(entry["cc"], "AU")


class CymruParseTests(unittest.TestCase):
    def test_ipv4_and_ipv6_query_names(self):
        seen = []

        def fake_doh(base, name):
            seen.append(name)
            return {"Answer": [{"data": '"4760 | 203.198.0.0/20 | HK | apnic | 1999-05-20"'}]}

        original = g._doh_json
        g._doh_json = fake_doh
        try:
            # The stub answers with a fixed record; only the query name matters.
            self.assertEqual(g.cymru_asn_cc("203.198.0.1"), (4760, "HK"))
            self.assertEqual(g.cymru_asn_cc("2606:4700:4700::1111"), (4760, "HK"))
        finally:
            g._doh_json = original
        self.assertTrue(seen[0].endswith(".origin.asn.cymru.com"), seen[0])
        self.assertTrue(seen[-1].endswith(".origin6.asn.cymru.com"), seen[-1])
        # Octets are reversed for the query, as required by in-addr.arpa.
        self.assertTrue(seen[0].startswith("1.0.198.203."), seen[0])
        # IPv6 nibble form is reversed too: 2606:4700:4700::1111 -> 1.1.1.1....
        self.assertTrue(seen[-1].startswith("1.1.1.1."), seen[-1])

    def test_garbage_and_unroutable_input(self):
        original = g._doh_json
        g._doh_json = lambda base, name: {"Answer": [{"data": '"not-an-asn"'}]}
        try:
            self.assertEqual(g.cymru_asn_cc("8.8.8.8"), (0, ""))
        finally:
            g._doh_json = original
        self.assertEqual(g.cymru_asn_cc("not-an-ip"), (0, ""))
        self.assertEqual(g.cymru_asn_cc(""), (0, ""))

    def test_next_doh_endpoint_used_when_first_fails(self):
        calls = []

        def flaky(base, name):
            calls.append(base)
            if len(calls) == 1:
                raise OSError("blocked")
            return {"Answer": [{"data": '"13335 | 104.16.0.0/20 | US | arin | 2014-03-28"'}]}

        original = g._doh_json
        g._doh_json = flaky
        try:
            self.assertEqual(g.cymru_asn_cc("104.16.0.1"), (13335, "US"))
        finally:
            g._doh_json = original
        self.assertEqual(len(calls), 2)


class DisplayPartsTests(unittest.TestCase):
    """Candidate chain: most specific geographic level first.

    This is what replaces the ``-2``/``-3`` counters: two exits of the same
    provider inside one city get separated by the next geographic level
    instead of by a sequence number.
    """

    def setUp(self):
        g.RESOLVER.clear()

    def _put(self, ip, **values):
        entry = g._blank(values.pop("cc", "HK"))
        entry.update(values)
        g.RESOLVER._cache[ip] = entry

    def test_zone_is_preferred_over_region(self):
        self._put("1.1.1.1", cc="HK", asn=4760, org="HKT", city="Hong Kong",
                  region="", zone="Central")
        self._put("2.2.2.2", cc="HK", asn=4760, org="HKT", city="Hong Kong",
                  region="", zone="Kwai Chung")
        first = g.RESOLVER.display_parts("1.1.1.1")
        second = g.RESOLVER.display_parts("2.2.2.2")
        self.assertEqual(first[0], "🇭🇰香港-HKT-Hong Kong")
        self.assertIn("🇭🇰香港-HKT-Hong Kong-Central", first)
        self.assertIn("🇭🇰香港-HKT-Hong Kong-Kwai Chung", second)

    def test_city_then_region_chain(self):
        self._put("1.1.1.1", cc="AU", asn=16509, org="AWS", city="Sydney",
                  region="New South Wales", zone="")
        parts = g.RESOLVER.display_parts("1.1.1.1")
        self.assertEqual(parts[0], "🇦🇺澳大利亚-AWS-Sydney")
        self.assertEqual(parts[1], "🇦🇺澳大利亚-AWS-Sydney-New South Wales")
        self.assertEqual(parts[-1], "🇦🇺澳大利亚-AWS")

    def test_last_candidate_is_always_country_and_brand(self):
        self._put("1.1.1.1", cc="US", asn=13335, org="Cloudflare")
        self.assertEqual(g.RESOLVER.display_parts("1.1.1.1")[-1], "🇺🇸美国-Cloudflare")

    def test_candidates_are_unique_and_ordered(self):
        self._put("1.1.1.1", cc="HK", asn=4760, org="HKT", city="Hong Kong",
                  region="Hong Kong", zone="Hong Kong")
        parts = g.RESOLVER.display_parts("1.1.1.1")
        self.assertEqual(len(parts), len(set(parts)))
        self.assertEqual(parts[-1], "🇭🇰香港-HKT")

    def test_city_equal_to_country_is_dropped(self):
        self._put("1.1.1.1", cc="SG", asn=16509, org="AWS", city="新加坡")
        self.assertEqual(g.RESOLVER.display_parts("1.1.1.1")[0], "🇸🇬新加坡-AWS")


class AsnDbTests(unittest.TestCase):
    """Local DB-IP ASN layer: the coverage fix for API-blocked runners."""

    def _db(self, rows, name="asn.csv"):
        import tempfile
        handle = tempfile.NamedTemporaryFile("w", suffix=name, delete=False,
                                             encoding="utf-8")
        handle.write(rows)
        handle.close()
        self.addCleanup(lambda: __import__("os").unlink(handle.name))
        return g.AsnDb(handle.name).load()

    def test_ipv4_and_ipv6_ranges_resolve(self):
        db = self._db(
            "203.198.0.0,203.198.15.255,4760,\"PCCW IMS Limited\"\n"
            "123.202.0.0,123.203.255.255,9269,\"Hong Kong Broadband Network Limited\"\n"
            "2606:4700::,2606:4700:ffff:ffff:ffff:ffff:ffff:ffff,13335,\"Cloudflare, Inc.\"\n")
        self.assertTrue(db.loaded)
        self.assertEqual(db.lookup("203.198.0.1"), (4760, "PCCW IMS Limited"))
        self.assertEqual(db.lookup("123.202.0.1"), (9269, "Hong Kong Broadband Network Limited"))
        self.assertEqual(db.lookup("2606:4700:4700::1111"), (13335, "Cloudflare, Inc."))
        # Outside every range: explicit miss, not a wrong answer.
        self.assertEqual(db.lookup("8.8.8.8"), (0, ""))

    def test_binary_search_boundaries_are_inclusive(self):
        db = self._db("10.0.0.0,10.0.0.255,64500,\"Edge A\"\n"
                      "10.0.1.0,10.0.1.255,64501,\"Edge B\"\n")
        self.assertEqual(db.lookup("10.0.0.0")[0], 64500)
        self.assertEqual(db.lookup("10.0.0.255")[0], 64500)
        self.assertEqual(db.lookup("10.0.1.0")[0], 64501)
        self.assertEqual(db.lookup("10.0.1.255")[0], 64501)
        self.assertEqual(db.lookup("10.0.2.1"), (0, ""))

    def test_missing_and_corrupt_sources_degrade_to_empty(self):
        missing = g.AsnDb("/nonexistent/asn.csv").load()
        self.assertFalse(missing.loaded)
        self.assertEqual(missing.error, "missing")
        self.assertEqual(missing.lookup("1.1.1.1"), (0, ""))

        corrupt = self._db("not,a,valid\n,,,\n", name="asn.csv")
        self.assertEqual(corrupt.lookup("1.1.1.1"), (0, ""))

    def test_non_ip_input_is_safe(self):
        db = self._db("1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n")
        for value in ("", "not-an-ip", "8.8.8.8/24", None):
            with self.subTest(value=value):
                self.assertEqual(db.lookup(value), (0, ""))

    def test_unset_path_means_no_offline_layer(self):
        self.assertEqual(g.AsnDb("").load().error, "missing")

    def test_local_db_feeds_the_asn_when_cymru_is_empty(self):
        """A blocked DoH endpoint must not lose ASN when the file is present."""
        db = self._db("203.198.0.0,203.198.15.255,9269,"
                      "\"Hong Kong Broadband Network Limited\"\n")
        original = (g._ASN_DB, g.cymru_asn_cc, g._ipapi_batch, g._ipwho, g.LOOKUP_ON)
        g._ASN_DB = db
        g.cymru_asn_cc = lambda ip: (0, "")
        g._ipapi_batch = lambda ips: {}
        g._ipwho = lambda ip: None
        g.LOOKUP_ON = True
        g.RESOLVER.clear()
        try:
            g.prefetch([("203.198.0.1", "")])
            entry = g.RESOLVER.entry("203.198.0.1")
        finally:
            g._ASN_DB, g.cymru_asn_cc, g._ipapi_batch, g._ipwho, g.LOOKUP_ON = original
            g.RESOLVER.clear()
        self.assertEqual(entry["asn"], 9269)
        self.assertEqual(entry["org"], "HKBN")

    def test_local_db_org_feeds_brand_when_online_apis_fail(self):
        """AS56971 is NOT in ASN_SHORT; its brand must come from DB-IP's org
        column, not degrade to a bare 'AS56971' when ip-api/ipwho are blocked."""
        db = self._db("5.144.179.0,5.144.179.255,56971,\"CGI GLOBAL LIMITED\"\n")
        original = (g._ASN_DB, g.cymru_asn_cc, g._ipapi_batch, g._ipwho, g.LOOKUP_ON)
        g._ASN_DB = db
        g.cymru_asn_cc = lambda ip: (56971, "")
        g._ipapi_batch = lambda ips: {}     # rate-limited on shared egress
        g._ipwho = lambda ip: None          # timeout
        g.LOOKUP_ON = True
        g.RESOLVER.clear()
        try:
            g.prefetch([("5.144.179.1", "")])
            entry = g.RESOLVER.entry("5.144.179.1")
            name = g.display_name("5.144.179.1", "")
        finally:
            g._ASN_DB, g.cymru_asn_cc, g._ipapi_batch, g._ipwho, g.LOOKUP_ON = original
            g.RESOLVER.clear()
        self.assertEqual(entry["org"], "CGI")
        self.assertNotIn("AS56971", name)
        self.assertIn("CGI", name)


if __name__ == "__main__":
    unittest.main()