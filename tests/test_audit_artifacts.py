# -*- coding: utf-8 -*-
"""Offline tests for the artifact auditor. All fixtures are local text."""
import importlib.util
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

import yaml

PATH = Path(__file__).resolve().parents[1] / "scripts" / "audit_artifacts.py"
SPEC = importlib.util.spec_from_file_location("audit_artifacts", PATH)
a = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = a
SPEC.loader.exec_module(a)


def node(name, server="1.2.3.4", proto="ss"):
    return {"name": name, "type": proto, "server": server, "port": 443,
            "password": "pw", "cipher": "aes-128-gcm"}


def source_file(name):
    import hashlib
    return "source-" + hashlib.sha256(name.encode()).hexdigest() + ".yaml"


class LocalLoadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def _write(self, manifest_sources, source_docs, merged_docs):
        (self.dir / "manifest.json").write_text(
            json.dumps({"sources": manifest_sources}), encoding="utf-8")
        for name, nodes in source_docs.items():
            (self.dir / source_file(name)).write_text(
                yaml.safe_dump({"proxies": nodes}, allow_unicode=True),
                encoding="utf-8")
        (self.dir / "mihomo-alive.yaml").write_text(
            yaml.safe_dump({"proxies": merged_docs}, allow_unicode=True),
            encoding="utf-8")

    def test_loads_all_local_files_without_network(self):
        src = {"name": "airport"}
        nodes = [node("🇭🇰香港-HKT-中环")]
        filename = source_file("airport")
        self._write({filename: src}, {"airport": nodes}, nodes)
        artifacts = a.Artifacts("x", directory=str(self.dir)).load()
        self.assertEqual(artifacts.errors, [])
        self.assertEqual(len(artifacts.sources), 1)
        self.assertEqual(len(artifacts.merged.get("proxies", [])), 1)

    def test_bad_yaml_is_reported_not_raised(self):
        src = {"name": "airport"}
        filename = source_file("airport")
        self._write({filename: src}, {}, [])
        (self.dir / filename).write_text("proxies: [oops", encoding="utf-8")
        artifacts = a.Artifacts("x", directory=str(self.dir)).load()
        self.assertEqual(artifacts.sources, {})
        # Any malformed file is recorded as an error, never raised. The exact
        # exception class name (ParserError/ScannerError/...) is a PyYAML detail.
        self.assertTrue(any(filename in error for error in artifacts.errors),
                        artifacts.errors)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.artifacts = a.Artifacts("test-gist")
        self.artifacts.manifest = {"sources": {}}
        self.artifacts.merged = {"proxies": []}
        self.artifacts.sources = {}
        self.artifacts.errors = []

    def _source(self, name, nodes):
        filename = source_file(name)
        self.artifacts.sources[filename] = {"proxies": nodes}
        self.artifacts.manifest["sources"][filename] = {"name": name}

    def test_detects_ordinal_counters(self):
        self._source("xhttp-cf", [node("🇺🇸美国-Oracle-Washington-2")])
        report = a.audit(self.artifacts)
        self.assertEqual(report["totals"]["counter_suffix"], 1)
        self.assertIn("counters", report["findings"])

    def test_detects_generic_brand(self):
        self._source("pokenmen", [node("🇭🇰香港-Hong-Hong Kong-3")])
        report = a.audit(self.artifacts)
        self.assertEqual(report["totals"]["generic_brand"], 1)

    def test_detects_duplicate_connection_inside_source(self):
        first = node("a", "1.2.3.4")
        second = dict(first, name="b")           # same connection, new name
        self._source("pokenmen", [first, second])
        report = a.audit(self.artifacts)
        self.assertEqual(report["totals"]["duplicate_connection_occurrences"], 1)
        self.assertEqual(report["findings"]["duplicate_egress"][0]["server"], "1.2.3.4")

    def test_distinct_servers_are_not_a_duplicate(self):
        self._source("airport", [node("a", "1.2.3.4"), node("b", "5.6.7.8")])
        report = a.audit(self.artifacts)
        self.assertEqual(report["totals"]["duplicate_connection_occurrences"], 0)

    def test_detects_merged_duplicate_names(self):
        self.artifacts.merged = {"proxies": [node("same"), node("same")]}
        report = a.audit(self.artifacts)
        self.assertEqual(report["totals"]["merged_duplicate_names"], 1)
        self.assertEqual(report["totals"]["merged_unique_names"], 1)

    def test_detects_hash_suffix_and_unknown_brand(self):
        self._source("x", [node("🇺🇸美国-AWS-39313f52"),
                           node("🇺🇸美国-Unknown-Ashburn")])
        report = a.audit(self.artifacts)
        self.assertEqual(report["totals"]["hash_suffix"], 1)
        self.assertEqual(report["totals"]["unknown_brand"], 1)

    def test_clean_names_produce_no_findings(self):
        self._source("clean", [node("🇭🇰香港-HKT-中环", "1.1.1.1"),
                               node("🇺🇸美国-AWS-Ashburn", "2.2.2.2")])
        self.artifacts.merged = {"proxies": [node("🇭🇰香港-HKT-中环", "1.1.1.1"),
                                             node("🇺🇸美国-AWS-Ashburn", "2.2.2.2")]}
        report = a.audit(self.artifacts)
        for key in ("counter_suffix", "generic_brand", "unknown_brand",
                    "duplicate_connection_occurrences", "merged_duplicate_names"):
            self.assertEqual(report["totals"][key], 0, key)

    def test_health_fails_when_geolocation_disabled(self):
        # Every name is -Unknown: the publisher clearly ran without lookups.
        nodes = [node("🇺🇸美国-Unknown") for _ in range(10)]
        self._source("broken", nodes)
        self.artifacts.merged = {"proxies": nodes}
        report = a.audit(self.artifacts)
        self.assertFalse(report["health"]["ok"])
        self.assertIn("geolocation", report["health"]["reason"])

    def test_health_ok_with_ordinal_suffixes(self):
        # "-2"/"-3" are a legitimate egress-sorted collision suffix now; they
        # must not fail health on their own (duplicate checks cover real dupes).
        nodes = [node("🇺🇸美国-AWS-Ashburn-2"),
                 node("🇭🇰香港-HKT-中环-3")]
        self._source("good", nodes)
        self.artifacts.merged = {"proxies": nodes}
        report = a.audit(self.artifacts)
        self.assertTrue(report["health"]["ok"], report["health"])
        self.assertGreater(report["totals"]["counter_suffix_merged"], 0)

    def test_health_ok_when_all_names_resolved(self):
        nodes = [node("🇺🇸美国-AWS-Ashburn"), node("🇭🇰香港-HKT-中环")]
        self._source("good", nodes)
        self.artifacts.merged = {"proxies": nodes}
        report = a.audit(self.artifacts)
        self.assertTrue(report["health"]["ok"])

    def test_report_is_renderable_as_utf8_bytes(self):
        self._source("pokenmen", [node("🇭🇰香港-Hong-Hong Kong-3")])
        rendered = a.render(a.audit(self.artifacts))
        self.assertIn("香港", rendered.encode("utf-8").decode("utf-8"))
        self.assertIn("generic word used as brand", rendered)

    def test_connection_key_ignores_display_name(self):
        first = node("alpha")
        second = dict(first, name="beta")
        self.assertEqual(a.connection_key(first), a.connection_key(second))
        third = dict(first, password="different")
        self.assertNotEqual(a.connection_key(first), a.connection_key(third))


class FetchTests(unittest.TestCase):
    def test_retries_on_rate_limit_then_succeeds(self):
        calls = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b"ok"

        def flaky(url, timeout=40):
            calls.append(url)
            if len(calls) < 3:
                raise urllib.error.HTTPError(url, 429, "rate", {}, None)
            return FakeResponse()

        original = a.urllib.request.urlopen
        original_sleep = a.time.sleep
        a.urllib.request.urlopen = flaky
        a.time.sleep = lambda seconds: None
        try:
            self.assertEqual(a.fetch("https://example.test/x"), b"ok")
        finally:
            a.urllib.request.urlopen = original
            a.time.sleep = original_sleep
        self.assertEqual(len(calls), 3)

    def test_retries_on_incomplete_read(self):
        """A truncated chunked response is a transient network failure."""
        import http.client
        calls = []

        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self): return b"complete"

        def flaky(url, timeout=40):
            calls.append(url)
            if len(calls) < 3:
                raise http.client.IncompleteRead(b"partial", 100)
            return FakeResponse()

        original = a.urllib.request.urlopen
        original_sleep = a.time.sleep
        a.urllib.request.urlopen = flaky
        a.time.sleep = lambda seconds: None
        try:
            self.assertEqual(a.fetch("https://example.test/x"), b"complete")
        finally:
            a.urllib.request.urlopen = original
            a.time.sleep = original_sleep
        self.assertEqual(len(calls), 3)

    def test_does_not_retry_on_client_error(self):
        calls = []

        def denied(url, timeout=40):
            calls.append(url)
            raise urllib.error.HTTPError(url, 404, "missing", {}, None)

        original = a.urllib.request.urlopen
        a.urllib.request.urlopen = denied
        try:
            with self.assertRaises(urllib.error.HTTPError):
                a.fetch("https://example.test/x")
        finally:
            a.urllib.request.urlopen = original
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()