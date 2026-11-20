"""Offline contract tests; no backend, Gist token, curl or kernel required.
Run: python -m unittest discover -s tests -p test_actions_probe_all.py -v
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

PATH = Path(__file__).resolve().parents[1] / "scripts" / "actions_probe_all.py"
SPEC = importlib.util.spec_from_file_location("actions_probe_all", PATH)
p = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = p
SPEC.loader.exec_module(p)


def node(name="node", proto="ss", server="example.invalid", **kwargs):
    return dict(name=name, type=proto, server=server, port=443, password="test-only", **kwargs)


def candidate(source="airport", count=1):
    """A source whose ``count`` nodes each measure a DISTINCT egress address.

    Distinct exits matter: measurement selection now collapses one surviving
    node per IPv4 egress for every source, so a fixture that reuses a single
    address cannot express "count nodes published".
    """
    config = {"proxies": [node("n" + str(i), server="s" + str(i) + ".invalid") for i in range(count)]}
    graph = p.Graph(config)
    measurements = [p.Measurement(n["name"], "8.8.8." + str(i + 1), "US") for i, n in enumerate(config["proxies"])]
    text, published = p.source_output(source, graph, measurements)
    return p.SourceResult(source, count, count, published, text, measured=count)


def dead(source="airport", input_count=10, **kwargs):
    """A source whose every node failed this round."""
    result = p.SourceResult(source, input_count, 0, 0, "proxies: []\n", **kwargs)
    result.measured = input_count
    return result


class FakeGist:
    def __init__(self, files=None, public=False):
        self.files = dict(files or {})
        self.public = public
        self.calls = []
        self.patches = []
        self.fail_patch = False
        self.truncated = set()
        self.raw_host = "gist.githubusercontent.com"

    def __call__(self, method, url, headers=None, body=None):
        self.calls.append((method, url, headers, body))
        if method == "PATCH":
            # Reproduce the real Gist endpoint: unsafe conditional headers 400.
            if any(key.lower() == "if-match" for key in (headers or {})):
                raise p.ProbeError("http_400")
            if self.fail_patch:
                raise p.ProbeError("http_failure")
            update = json.loads(body)["files"]
            self.patches.append(update)
            for key, entry in update.items():
                # Gist semantics: {"content": null} deletes the file.
                if entry is None or entry.get("content") is None:
                    self.files.pop(key, None)
                else:
                    self.files[key] = entry["content"]
            return b"{}", {}
        if url.startswith("https://" + self.raw_host + "/raw/"):
            name = url.rsplit("/", 1)[1]
            return self.files[name].encode(), {}
        files = {key: {"content": text if key not in self.truncated else "TRUNCATED", "truncated": key in self.truncated, "raw_url": "https://" + self.raw_host + "/raw/" + key} for key, text in self.files.items()}
        return json.dumps({"public": self.public, "files": files}).encode(), {"ETag": '"version"'}


class FixtureStateStore:
    """Adapt the historical in-memory Gist fixture to the private store contract.

    Only tests have this writer: production's legacy Gist interface is read-only.
    Keeping this adapter preserves all existing failure-policy regression cases.
    """

    def __init__(self, gist_id, token, transport):
        """Retain the legacy reader and fixture transport; never contact a network."""
        self.reader = p.LegacyGistReader(gist_id, token, transport)
        self.old = {}

    def current(self):
        """Read a simulated state snapshot and remember it for diff assertions."""
        self.old, version = self.reader.current()
        return self.old, version

    def save(self, files, version):
        """Commit changed fixture files together, including any policy deletions."""
        updates = {name: {"content": text} for name, text in files.items()
                   if text != self.old.get(name)}
        updates.update({name: None for name in self.old if name not in files})
        headers = dict(self.reader.headers, **{"Content-Type": "application/json"})
        self.reader.transport("PATCH", self.reader.url, headers,
                              p.json_text({"files": updates}).encode())


class FixturePublisher(p.StatePublisher):
    """Use the real policy publisher with the historical offline fixture store."""

    def __init__(self, gist_id, token, transport):
        """Build a fixture state store for existing policy scenarios."""
        super().__init__(FixtureStateStore(gist_id, token, transport))


class TraceTests(unittest.TestCase):
    GOOD = "visit_scheme=https\ntls=TLSv1.3\nfl=x\nip=8.8.8.8\nloc=US\n"

    def test_valid_public_trace(self):
        self.assertEqual(p.parse_trace(self.GOOD), ("8.8.8.8", "US"))
        self.assertEqual(p.parse_trace("visit_scheme=https\ntls=on\nip=2606:4700:4700::1111\nloc=HK")[1], "HK")
        self.assertEqual(p.parse_trace("visit_scheme=https\ntls=1.3\nip=8.8.8.8\nloc=US")[1], "US")

    def test_plaintext_or_missing_tls_is_rejected(self):
        # A 200 with no TLS evidence (captive portal / downgraded hop) must not
        # count as a measured alive node. Each of these lacks the full TLS 200.
        for text in (
            "ip=8.8.8.8\nloc=US\n",                                  # no scheme/tls
            "visit_scheme=http\ntls=TLSv1.3\nip=8.8.8.8\nloc=US\n",   # plaintext
            "visit_scheme=https\nip=8.8.8.8\nloc=US\n",              # no tls line
            "visit_scheme=https\ntls=\nip=8.8.8.8\nloc=US\n",        # empty tls
            "visit_scheme=https\ntls=off\nip=8.8.8.8\nloc=US\n",     # tls off
        ):
            with self.subTest(text=text), self.assertRaises(p.ProbeError):
                p.parse_trace(text)

    def test_invalid_trace(self):
        for text in ("", "ip=127.0.0.1\nloc=US", "ip=192.168.0.1\nloc=US", "ip=100.64.0.1\nloc=US", "visit_scheme=https\ntls=TLSv1.3\nip=8.8.8.8", "visit_scheme=https\ntls=TLSv1.3\nip=8.8.8.8\nloc=ZZ", "visit_scheme=https\ntls=TLSv1.3\nip=8.8.8.8\nloc=us", "visit_scheme=https\ntls=TLSv1.3\nip=not-ip\nloc=US", "visit_scheme=https\ntls=TLSv1.3\nip=224.0.0.1\nloc=US", "visit_scheme=https\ntls=TLSv1.3\nip=8.8.8.8\nip=1.1.1.1\nloc=US", "visit_scheme=https\ntls=TLSv1.3\nip=::1\nloc=US", "<html>failure</html>"):
            with self.subTest(text=text), self.assertRaises(p.ProbeError):
                p.parse_trace(text)

    def test_curl_is_explicit_proxy_and_reports_the_negotiation(self):
        def fake_run(command, **kwargs):
            self.assertEqual(command[:2], ["curl", "--disable"])
            self.assertIn("--fail", command)
            self.assertEqual(command[command.index("--noproxy") + 1], "")
            self.assertEqual(command[command.index("--proxy") + 1], "http://127.0.0.1:12345")
            self.assertIn("--max-time", command)
            self.assertEqual(command[-1], p.TRACE_URL)
            # Body goes to a private file, stdout carries the metadata line, so
            # the JSON trace and the protocol verdict never interleave.
            self.assertIn("--output", command)
            self.assertIn("--write-out", command)
            self.assertEqual(kwargs["stdout"], subprocess.PIPE)
            Path(command[command.index("--output") + 1]).write_text(self.GOOD, encoding="utf-8")
            return mock.Mock(returncode=0, stdout=b"2 0 0.412")
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(p.subprocess, "run", side_effect=fake_run):
            self.assertEqual(p.NativeProbe("mihomo").trace(12345, temp), ("8.8.8.8", "US", "2", 412))

    def test_a_failed_certificate_verdict_is_not_a_measurement(self):
        def fake_run(command, **kwargs):
            Path(command[command.index("--output") + 1]).write_text(self.GOOD, encoding="utf-8")
            return mock.Mock(returncode=0, stdout=b"2 20")  # X509_V_ERR_*
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(p.subprocess, "run", side_effect=fake_run):
            self.assertIsNone(p.NativeProbe("mihomo").trace(12345, temp))

    def test_http1_is_counted_but_not_rejected(self):
        probe = p.NativeProbe("mihomo")
        graph = p.Graph({"proxies": [node("h1"), node("h2", server="b.invalid")]})
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "trace", side_effect=[("1.1.1.1", "US", "1.1"), ("8.8.8.8", "US", "2")]), \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["h1", "h2"])
        self.assertEqual(len(measured), 2)
        self.assertEqual([m.http_version for m in measured], ["1.1", "2"])

    def test_a_trace_from_the_runners_own_address_is_suppressed(self):
        probe = p.NativeProbe("mihomo")
        probe.baseline_ip = "8.8.8.8"
        graph = p.Graph({"proxies": [node("node")]})
        process = mock.Mock()
        process.poll.return_value = None

        def fake_run(command, **kwargs):
            Path(command[command.index("--output") + 1]).write_text(self.GOOD, encoding="utf-8")
            return mock.Mock(returncode=0, stdout=b"2 0 0.412")

        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(p.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["node"])
        self.assertEqual(measured, [])
        self.assertEqual(probe.suppressed, 1)


class SelectionTests(unittest.TestCase):
    def test_exclusions_and_front_allowed(self):
        for name in ("probe-x", "chain-x", "rust-x", "PROBE-x", "测活-DMIT", "官方可用",
                     "gist-glados", "GIST-prologue", "gist-健康中心"):
            self.assertFalse(p.selected_source(name))
        for name in ("glados", "GlaDOS", "cf-front", "原始机场", "官方可用机场"):
            self.assertTrue(p.selected_source(name))

    def test_safe_filenames(self):
        for name in ("../../pwn", "C:\\tokens", "机场/订阅", "..", "a\nsecret"):
            filename = p.source_file(name)
            self.assertRegex(filename, r"^source-[a-f0-9]{64}\.yaml$")
            self.assertEqual(filename, p.source_file(name))
        self.assertNotEqual(p.source_file("A"), p.source_file("a"))

    def test_glados_ss_preference_other_sources_keep_every_distinct_exit(self):
        graph = p.Graph({"proxies": [node("v", "vmess"), node("s2", "ss", "b.invalid"), node("s1", "ss", "a.invalid")]})
        # Same egress for all three: exactly one survivor, SS preferred.
        measurements = [p.Measurement(n, "8.8.8.8", "US") for n in ("v", "s2", "s1")]
        chosen = p.choose_measurements("GlaDOS", graph, measurements)
        self.assertEqual(len(chosen), 1)
        self.assertEqual(graph.nodes[chosen[0].name]["type"], "ss")
        self.assertEqual(chosen, p.choose_measurements("glados", graph, measurements[::-1]))
        # Non-GlaDOS sources dedup by egress too (no per-source exception).
        self.assertEqual(len(p.choose_measurements("another", graph, measurements)), 1)
        self.assertEqual(len(p.choose_measurements("glados-pro", graph, measurements)), 1)

    def test_every_source_dedups_one_node_per_ipv4_egress(self):
        """The old contract kept duplicates for all sources but GlaDOS, which
        is what produced -2/-3/-4 names for one and the same exit address."""
        graph = p.Graph({"proxies": [node("a", "vmess"), node("b", "trojan"),
                                     node("c", "ss", "c.invalid")]})
        measurements = [p.Measurement("a", "8.8.8.8", "US"),
                        p.Measurement("b", "8.8.8.8", "US"),
                        p.Measurement("c", "8.8.8.8", "US")]
        for source in ("glados", "airport", "prologue", "健康中心", "masque"):
            with self.subTest(source=source):
                chosen = p.choose_measurements(source, graph, measurements)
                self.assertEqual(len(chosen), 1)
                self.assertEqual(chosen[0].name, "c")  # ss preferred inside a group

    def test_ipv6_and_ipv4_egress_both_used_as_dedup_key(self):
        self.assertEqual(p.egress_key("8.8.8.8"), "8.8.8.8")
        self.assertEqual(p.egress_key("2001:4860:4860::8888"), "2001:4860:4860::8888")
        graph = p.Graph({"proxies": [node("v4"), node("v6", "vmess", "v6.invalid")]})
        measurements = [p.Measurement("v4", "8.8.8.8", "US"),
                        p.Measurement("v6", "2001:4860:4860::8888", "US")]
        self.assertEqual(len(p.choose_measurements("airport", graph, measurements)), 2)

    def test_glados_without_ss_keeps_deterministic_one_per_exit(self):
        graph = p.Graph({"proxies": [node("a", "vmess"), node("b", "trojan")]})
        measurements = [p.Measurement(n, "8.8.8.8", "US") for n in ("a", "b")]
        self.assertEqual(len(p.choose_measurements("glados", graph, measurements)), 1)
        self.assertEqual(p.choose_measurements("glados", graph, measurements), p.choose_measurements("glados", graph, measurements[::-1]))

    def test_unique_non_ss_exit_survives_with_duplicate_exit_ss_preferred(self):
        graph = p.Graph({"proxies": [node("ss-shared", "ss"), node("trojan-shared", "trojan"), node("unique-anytls", "anytls")]})
        measurements = [p.Measurement("ss-shared", "8.8.8.8", "US"),
                        p.Measurement("trojan-shared", "8.8.8.8", "US"),
                        p.Measurement("unique-anytls", "1.1.1.1", "AU")]
        chosen = p.choose_measurements("glados", graph, measurements)
        self.assertEqual({item.name for item in chosen}, {"ss-shared", "unique-anytls"})
        self.assertEqual(len(p.choose_measurements("another", graph, measurements)), 2)

    def test_names_stable_without_upstream_name_or_latency(self):
        graph = p.Graph({"proxies": [node("upstream secret")]})
        first, _ = p.source_output("airport", graph, [p.Measurement("upstream secret", "8.8.8.8", "US")])
        renamed = p.Graph({"proxies": [node("new upstream name")]})
        second, _ = p.source_output("airport", renamed, [p.Measurement("new upstream name", "8.8.8.8", "US")])
        self.assertEqual(first, second)
        self.assertNotIn("upstream", first)
        renamed_name = yaml.safe_load(first)["proxies"][0]["name"]
        self.assertTrue(renamed_name.startswith("🇺🇸美国-"))
        # Offline geolocation has no ASN and no city: country-Unknown only,
        # never a fabricated "未知地址" segment.
        self.assertEqual(renamed_name, "🇺🇸美国-Unknown")

    def test_collision_suffix_is_a_stable_exit_ordinal_not_name_dependent(self):
        """Ordinal suffix follows egress-sorted order, not sibling count or name."""
        graph = p.Graph({"proxies": [node("a", "ss", "a.invalid"), node("b", "ss", "b.invalid"),
                                     node("c", "ss", "c.invalid")]})
        both = [p.Measurement("a", "8.8.8.8", "US"), p.Measurement("b", "8.8.4.4", "US")]
        allthree = both + [p.Measurement("c", "9.9.9.9", "US")]
        # All three measure the same cc with no geolocation, so they collide on
        # "🇺🇸美国-Unknown"; the egress-sorted order assigns -2/-3 deterministically.
        text_small, _ = p.source_output("airport", graph, both)
        text_large, _ = p.source_output("airport", graph, allthree)
        small = {n["server"]: n["name"] for n in yaml.safe_load(text_small)["proxies"]}
        large = {n["server"]: n["name"] for n in yaml.safe_load(text_large)["proxies"]}
        # 8.8.4.4 sorts before 8.8.8.8: base name vs -2 ordinal, in both runs.
        self.assertEqual(small["b.invalid"], large["b.invalid"])
        self.assertEqual(small["a.invalid"], large["a.invalid"])
        self.assertEqual(small["b.invalid"], "🇺🇸美国-Unknown")
        self.assertEqual(small["a.invalid"], "🇺🇸美国-Unknown-2")

    def test_collision_names_do_not_depend_on_upstream_node_name(self):
        """Renaming an upstream node must not move anybody else's name."""
        first = p.Graph({"proxies": [node("alpha", "ss", "a.invalid"),
                                     node("beta", "ss", "b.invalid")]})
        second = p.Graph({"proxies": [node("zzz", "ss", "a.invalid"),
                                      node("yyy", "ss", "b.invalid")]})
        measurements = [p.Measurement("alpha", "8.8.8.8", "US"),
                        p.Measurement("beta", "9.9.9.9", "US")]
        renamed = [p.Measurement("zzz", "8.8.8.8", "US"),
                   p.Measurement("yyy", "9.9.9.9", "US")]
        by_server = {}
        for text in (p.source_output("airport", first, measurements)[0],
                     p.source_output("airport", second, renamed)[0]):
            by_server.setdefault("run", []).append(
                {n["server"]: n["name"] for n in yaml.safe_load(text)["proxies"]})
        self.assertEqual(by_server["run"][0], by_server["run"][1])

    def test_duplicate_display_names_get_stable_ordinals(self):
        graph = p.Graph({"proxies": [node("n%d" % i, "ss", "s%d.invalid" % i) for i in range(5)]})
        measurements = [p.Measurement("n%d" % i, "10.0.0.%d" % (i + 1), "US") for i in range(5)]
        text, published = p.source_output("airport", graph, measurements)
        self.assertEqual(published, 5)
        names = [item["name"] for item in yaml.safe_load(text)["proxies"]]
        self.assertEqual(len(set(names)), 5)
        # Egress-sorted ordinals: base name, then -2/-3/-4/-5. export() orders
        # by connection identity, not by assigned name, so compare as a set.
        base = "🇺🇸美国-Unknown"
        self.assertEqual(set(names), {base} | {base + "-%d" % i for i in range(2, 6)})


class DependencyTests(unittest.TestCase):
    def test_duplicate_upstream_names_are_renamed_not_fatal(self):
        config = {"proxies": [node("same", server="a.invalid"), node("same", server="b.invalid"), node("same", server="c.invalid")]}
        deduped = p.dedupe_names(config)
        names = [item["name"] for item in deduped["proxies"]]
        self.assertEqual(len(set(names)), 3)
        self.assertEqual(names[0], "same")
        # The original config is never mutated in place.
        self.assertEqual([item["name"] for item in config["proxies"]], ["same", "same", "same"])
        graph = p.Graph(deduped)
        self.assertEqual(len(graph.nodes), 3)
        # A source with duplicated names still publishes every DISTINCT exit.
        measurements = [p.Measurement(name, "8.8.8." + str(i + 1), "US") for i, name in enumerate(names)]
        text, published = p.source_output("airport", graph, measurements)
        self.assertEqual(published, 3)
        self.assertEqual(len(yaml.safe_load(text)["proxies"]), 3)

    def test_duplicate_names_keep_the_first_for_dialer_references(self):
        config = {"proxies": [node("front", server="f.invalid"), node("exit", **{"dialer-proxy": "front"}),
                              node("front", server="f2.invalid")]}
        deduped = p.dedupe_names(config)
        graph = p.Graph(deduped)
        self.assertEqual(graph.dependency(graph.nodes["exit"]), "front")
        self.assertEqual(len(graph.nodes), 3)

    def test_named_direct_and_non_proxy_types_rejected(self):
        for proto in ("direct", "DIRECT", "reject", "dns", "pass", "unknown"):
            with self.subTest(proto=proto):
                graph = p.Graph({"proxies": [node("looks-like-a-proxy", proto=proto)]})
                with self.assertRaises(p.ProbeError):
                    graph.identity("looks-like-a-proxy")

    def test_relay_unknown_groups_not_rewritten_into_select(self):
        for proto in ("relay", "unknown", ""):
            with self.subTest(proto=proto):
                graph = p.Graph({"proxies": [node("front"), node("exit", **{"dialer-proxy": "chain"})],
                                 "proxy-groups": [{"name": "chain", "type": proto, "proxies": ["front"]}]})
                with self.assertRaises(p.ProbeError):
                    graph.export(["exit"])

    def setUp(self):
        self.front = {"proxies": [node("front-a", server="fa.invalid"), node("front-b", server="fb.invalid")], "proxy-groups": [{"name": "front-group", "type": "url-test", "url": "https://not-fetched.invalid", "proxies": ["front-b", "front-a"]}]}
        self.config = {"proxies": [node("exit", **{"dialer-proxy": "front-group"})]}

    def test_closure_retains_dialer_and_group(self):
        graph = p.Graph(self.config, self.front)
        out = graph.export(["exit"])
        self.assertEqual(len(out["proxies"]), 3)
        self.assertEqual(len(out["proxy-groups"]), 1)
        self.assertEqual(out["proxy-groups"][0]["type"], "select")
        self.assertEqual(next(n for n in out["proxies"] if n["name"] == "exit")["dialer-proxy"], "front-group")
        text, count = p.source_output("airport", graph, [p.Measurement("exit", "8.8.8.8", "US")])
        rebuilt = p.Graph(yaml.safe_load(text))
        root = next(n for n in rebuilt.nodes if not n.startswith("__front-"))
        self.assertEqual(graph.identity("exit"), rebuilt.identity(root))
        self.assertEqual(count, 1)
        self.assertEqual(len(rebuilt.nodes), 3)

    def test_missing_direct_and_cycles_fail_closed(self):
        for front in (None, {"proxies": [], "proxy-groups": [{"name": "front-group", "proxies": ["DIRECT"], "type": "select"}]}, {"proxies": [node("front-group", **{"dialer-proxy": "exit"})]}):
            with self.subTest(front=front), self.assertRaises(p.ProbeError):
                p.Graph(self.config, front).export(["exit"])
        with self.assertRaises(p.ProbeError):
            p.Graph({"proxies": [node("n", **{"dialer-proxy": "DIRECT"})]}).export(["n"])

    def test_config_loopback_fixed_listeners_no_fallback_or_geo(self):
        graph = p.Graph(self.config, self.front)
        cfg = p.kernel_config(graph, ["exit"], [2222], 3333, "secret")
        self.assertEqual(cfg["external-controller"], "127.0.0.1:3333")
        self.assertFalse(cfg["allow-lan"])
        self.assertFalse(cfg["geo-auto-update"])
        self.assertFalse(cfg["tun"]["enable"])
        self.assertEqual(cfg["rules"], ["MATCH,REJECT"])
        self.assertEqual(cfg["listeners"][0]["proxy"], "exit")
        self.assertEqual(cfg["listeners"][0]["listen"], "127.0.0.1")
        self.assertNotIn("DIRECT", p.canonical(cfg))
        self.assertNotIn("proxy-providers", cfg)
        self.assertNotIn("rule-providers", cfg)
        self.assertNotIn("url:", p.canonical(cfg))

    def test_chain_fingerprint_is_name_independent_and_chain_sensitive(self):
        a = p.Graph({"proxies": [node("root", **{"dialer-proxy": "a"}), node("a", server="front.invalid")]})
        b = p.Graph({"proxies": [node("new", **{"dialer-proxy": "b"}), node("b", server="front.invalid")]})
        direct = p.Graph({"proxies": [node("root")]})
        self.assertEqual(a.identity("root"), b.identity("new"))
        self.assertNotEqual(a.identity("root"), direct.identity("root"))

    def test_merge_dedups_connection_not_chain_namespace(self):
        a, b = candidate("one"), candidate("two")
        merged = yaml.safe_load(p.merge_sources({p.source_file(a.name): a.content, p.source_file(b.name): b.content}))
        self.assertEqual(len(merged["proxies"]), 1)
        chained = p.Graph({"proxies": [node("root", **{"dialer-proxy": "f"}), node("f", server="front.invalid")]})
        text, _ = p.source_output("chain", chained, [p.Measurement("root", "8.8.8.8", "US")])
        merged = yaml.safe_load(p.merge_sources({p.source_file(a.name): a.content, p.source_file("chain"): text}))
        self.assertEqual(len(merged["proxies"]), 3)
        self.assertTrue(any("dialer-proxy" in n for n in merged["proxies"]))


class NameFreezeTests(unittest.TestCase):
    """A published name is allocated once and then never moves."""

    def setUp(self):
        self.graph = p.Graph({"proxies": [node("a", "ss", "a.invalid"),
                                          node("b", "ss", "b.invalid"),
                                          node("c", "ss", "c.invalid")]})
        self.exits = {"a": "8.8.8.1", "b": "8.8.8.2", "c": "8.8.8.3"}

    def render(self, alive):
        measurements = [p.Measurement(name, self.exits[name], "US") for name in alive]
        text, published = p.source_output("airport", self.graph, measurements)
        return p.SourceResult("airport", 3, len(alive), published, text, measured=3)

    def names(self, files):
        return {item["server"]: item["name"]
                for item in yaml.safe_load(files[p.source_file("airport")])["proxies"]}

    def test_a_frozen_name_does_not_move_when_a_sibling_disappears(self):
        files = p.plan_updates([self.render(["a", "b", "c"])], {})
        first = self.names(files)
        self.assertEqual(len(set(first.values())), 3)
        # One node dies: the survivors' display names are recomputed from a
        # smaller sibling set, but the persisted table overrides that.
        files = p.plan_updates([self.render(["a", "c"])], files)
        second = self.names(files)
        self.assertEqual(second["a.invalid"], first["a.invalid"])
        self.assertEqual(second["c.invalid"], first["c.invalid"])

    def test_a_new_connection_takes_the_next_free_ordinal(self):
        files = p.plan_updates([self.render(["a", "b"])], {})
        first = self.names(files)
        files = p.plan_updates([self.render(["a", "b", "c"])], files)
        third = self.names(files)["c.invalid"]
        self.assertNotIn(third, first.values())
        self.assertRegex(third, r"-\d+$")

    def test_the_table_is_persisted_and_reused(self):
        files = p.plan_updates([self.render(["a", "b", "c"])], {})
        manifest = json.loads(files["manifest.json"])
        # One namespace per published file: the source artifact and the merged
        # subscription each carry the three connections.
        self.assertIn(p.source_file("airport"), manifest["names"])
        self.assertIn("merged", manifest["names"])
        self.assertEqual(sum(len(entries) for entries in manifest["names"].values()), 6)
        # A round in which every source is preserved keeps the same table.
        kept = p.plan_updates([], files)
        self.assertEqual(json.loads(kept["manifest.json"])["names"], manifest["names"])

    def test_migration_seeds_names_from_the_already_published_artifact(self):
        files = p.plan_updates([self.render(["a", "b", "c"])], {})
        first = self.names(files)
        # The upgrade lands on a round where one sibling is already gone: the
        # recomputed set would reuse "-2", but the published name must win.
        manifest = json.loads(files["manifest.json"])
        manifest.pop("names")
        legacy = dict(files, **{"manifest.json": json.dumps(manifest)})
        migrated = p.plan_updates([self.render(["a", "c"])], legacy)
        second = self.names(migrated)
        self.assertEqual(second["a.invalid"], first["a.invalid"])
        self.assertEqual(second["c.invalid"], first["c.invalid"])

    def test_merged_names_are_frozen_across_sources(self):
        def result(source, name, server):
            graph = p.Graph({"proxies": [node(name, "ss", server)]})
            text, published = p.source_output(source, graph, [p.Measurement(name, "8.8.8.1", "US")])
            return p.SourceResult(source, 1, 1, published, text, measured=1)

        # Same display name, different connection: the merge has to disambiguate
        # them, and that disambiguation must not move between rounds.
        one = result("alpha", "n1", "a.invalid")
        two = result("beta", "n1", "b.invalid")
        files = p.plan_updates([one, two], {})
        first = {item["server"]: item["name"]
                 for item in yaml.safe_load(files["mihomo-alive.yaml"])["proxies"]}
        self.assertEqual(len(set(first.values())), 2)
        files = p.plan_updates([two, one], files)
        second = {item["server"]: item["name"]
                  for item in yaml.safe_load(files["mihomo-alive.yaml"])["proxies"]}
        self.assertEqual(second, first)

    def test_two_nodes_with_the_same_connection_keep_distinct_names(self):
        # Real sources carry duplicate connections under different labels. They
        # are interchangeable, but collapsing them onto one frozen name would
        # make the artifact unparsable on the next round (duplicate name).
        graph = p.Graph({"proxies": [node("a", "ss", "same.invalid"),
                                      node("b", "ss", "same.invalid")]})
        self.assertEqual(graph.identity("a"), graph.identity("b"))
        text, published = p.source_output(
            "airport", graph,
            [p.Measurement("a", "8.8.8.1", "US"), p.Measurement("b", "8.8.8.2", "US")])
        result = p.SourceResult("airport", 2, 2, published, text, measured=2)
        files = p.plan_updates([result], {})
        names = [item["name"] for item in yaml.safe_load(files[p.source_file("airport")])["proxies"]]
        self.assertEqual(len(names), 2)
        self.assertEqual(len(set(names)), 2)
        files = p.plan_updates([result], files)
        self.assertEqual(len(yaml.safe_load(files[p.source_file("airport")])["proxies"]), 2)

    def test_free_name_never_produces_a_double_suffix(self):
        used = {"🇺🇸美国-Unknown", "🇺🇸美国-Unknown-2"}
        self.assertEqual(p._free_name("🇺🇸美国-Unknown-2", used), "🇺🇸美国-Unknown-3")
        self.assertEqual(p._free_name("🇺🇸美国-Unknown-7", {"🇺🇸美国-Unknown-7"}), "🇺🇸美国-Unknown-2")
        self.assertEqual(p._free_name("fresh", used), "fresh")


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.initial = candidate(count=4)
        self.old = p.plan_updates([self.initial], {})

    def publisher(self, transport):
        return FixturePublisher("abc123", "not-a-real-token", transport)

    def test_the_name_table_is_seeded_on_the_first_round_after_upgrade(self):
        legacy_manifest = {key: value for key, value in json.loads(self.old["manifest.json"]).items()
                           if key != "names"}
        legacy = dict(self.old, **{"manifest.json": json.dumps(legacy_manifest)})
        remote = FakeGist(legacy)
        status, _ = self.publisher(remote).publish([self.initial])
        # Nothing about the subscription changed; only the table is new, and it
        # still has to reach the Gist or it would never persist.
        self.assertEqual(status, "published")
        self.assertIn("names", json.loads(remote.files["manifest.json"]))

    def test_no_change_no_patch_even_counts_changed(self):
        remote = FakeGist(self.old)
        changed_counts = candidate(count=4)
        changed_counts.input = 999
        status, _ = self.publisher(remote).publish([changed_counts])
        self.assertEqual(status, "no_change")
        self.assertEqual(remote.patches, [])
        self.assertEqual(remote.files, self.old)

    def test_source_failure_keeps_old_without_a_revision(self):
        # A source we could not even fetch proves nothing: the artifact stays
        # and no Gist revision is created for an audit-only change.
        remote = FakeGist(self.old)
        self.assertEqual(self.publisher(remote).publish([p.SourceResult("airport", failed=True)])[0], "no_change")
        self.assertEqual(remote.files, self.old)
        self.assertEqual(remote.patches, [])

    def test_first_failing_round_keeps_the_artifact_and_records_the_grace(self):
        remote = FakeGist(self.old)
        status, files = self.publisher(remote).publish([dead()])
        self.assertEqual(status, "published")
        # The artifact itself is untouched: one bad round never empties it.
        self.assertEqual(remote.files[p.source_file("airport")], self.old[p.source_file("airport")])
        state = json.loads(remote.files["manifest.json"])["sources"][p.source_file("airport")]
        self.assertEqual(state["guard"], "zero_alive")
        self.assertEqual(state["bad_streak"], 1)
        self.assertTrue(state["preserved"])
        # Only the manifest moved; the subscription body did not.
        self.assertEqual(list(remote.patches[0]), ["manifest.json"])

    def test_first_run_all_failures_never_publishes_empty(self):
        for old in ({}, {"mihomo-alive.yaml": self.old["mihomo-alive.yaml"], "hb-full.yaml": "untouched"}):
            with self.subTest(legacy=bool(old)):
                remote = FakeGist(old)
                status, files = self.publisher(remote).publish([p.SourceResult("airport", failed=True)])
                self.assertEqual(status, "no_change")
                self.assertEqual(remote.patches, [])
                self.assertEqual(remote.files, old)
                if old:
                    self.assertEqual(files["mihomo-alive.yaml"], old["mihomo-alive.yaml"])

    def test_empty_or_mismatched_candidate_with_nonzero_alive_keeps_old(self):
        for bad in (p.SourceResult("airport", 4, 4, 4, "proxies: []\n"), p.SourceResult("airport", 4, 4, 99, candidate(count=4).content)):
            with self.subTest(published=bad.published):
                remote = FakeGist(self.old)
                self.assertEqual(self.publisher(remote).publish([bad])[0], "no_change")
                self.assertEqual(remote.files, self.old)
                self.assertEqual(remote.patches, [])

    def test_source_yaml_changes_publish_even_if_merged_unchanged(self):
        # Existing source chosen lexicographically owns identical merged roots.
        names = sorted(("source-a", "source-b"), key=p.source_file)
        first = candidate(names[0], 3)
        second = candidate(names[1], 2)
        old = p.plan_updates([first, second], {})
        remote = FakeGist(old)
        status, _ = self.publisher(remote).publish([first, candidate(names[1], 3)])
        self.assertEqual(status, "published")
        self.assertEqual(remote.files["mihomo-alive.yaml"], old["mihomo-alive.yaml"])
        self.assertNotIn("mihomo-alive.yaml", remote.patches[0])
        self.assertIn(p.source_file(names[1]), remote.patches[0])
        self.assertIn("manifest.json", remote.patches[0])

    def test_token_and_gist_id_outer_whitespace_stripped(self):
        remote = FakeGist(self.old)
        publisher = FixturePublisher("  abc123\r\n", "  test-token\r\n", remote)
        publisher.publish([self.initial])
        self.assertEqual(remote.calls[0][2]["Authorization"], "Bearer test-token")
        self.assertEqual(remote.calls[0][1], "https://api.github.com/gists/abc123")
        for token in ("\r\n", "bad\r\ntoken"):
            with self.assertRaises(p.ProbeError):
                FixturePublisher("abc123", token, remote)

    def test_412_rereads_and_replans_bounded(self):
        remote = FakeGist(self.old)
        conflicts = [True]
        calls = []
        def transport(method, url, headers=None, body=None):
            calls.append(method)
            if method == "PATCH" and conflicts:
                conflicts.pop()
                raise p.ProbeError("http_412")
            return remote(method, url, headers, body)
        self.assertEqual(self.publisher(transport).publish([candidate(count=5)])[0], "published")
        self.assertEqual(calls, ["GET", "GET", "PATCH", "GET", "GET", "PATCH"])
        def always_conflict(method, url, headers=None, body=None):
            if method == "PATCH":
                raise p.ProbeError("http_412")
            return remote(method, url, headers, body)
        with self.assertRaises(p.ProbeError):
            self.publisher(always_conflict).publish([candidate(count=6)])

    def test_managed_snapshot_change_replans_without_losing_concurrent_source(self):
        remote = FakeGist(self.old)
        reads = []
        concurrent = candidate("concurrent", 6)
        def transport(method, url, headers=None, body=None):
            if method == "GET":
                reads.append(True)
                if len(reads) == 2:
                    remote.files.update(p.plan_updates([concurrent], remote.files))
            return remote(method, url, headers, body)
        self.assertEqual(self.publisher(transport).publish([candidate(count=5)])[0], "published")
        self.assertEqual(len(reads), 4)
        self.assertEqual(remote.files[p.source_file("concurrent")], concurrent.content)
        self.assertNotIn(p.source_file("concurrent"), remote.patches[0])
        self.assertEqual(len(remote.patches), 1)

    def test_continuously_changing_managed_snapshot_aborts_bounded(self):
        remote = FakeGist(self.old)
        reads = []
        def transport(method, url, headers=None, body=None):
            if method == "GET":
                reads.append(True)
                manifest = json.loads(remote.files["manifest.json"])
                manifest["concurrent_counter"] = len(reads)
                remote.files["manifest.json"] = json.dumps(manifest)
            return remote(method, url, headers, body)
        with self.assertRaises(p.PublicationError) as got:
            self.publisher(transport).publish([candidate(count=5)])
        self.assertEqual(p.error_code(got.exception), "state_conflict")
        self.assertEqual(len(reads), 6)
        self.assertEqual(remote.patches, [])

    def test_unrelated_snapshot_change_does_not_conflict_or_get_overwritten(self):
        remote = FakeGist(dict(self.old, **{"hb-full.yaml": "old"}))
        reads = []
        def transport(method, url, headers=None, body=None):
            if method == "GET":
                reads.append(True)
                if len(reads) == 2:
                    remote.files["hb-full.yaml"] = "changed concurrently"
            return remote(method, url, headers, body)
        self.assertEqual(self.publisher(transport).publish([candidate(count=5)])[0], "published")
        self.assertEqual(len(reads), 2)
        self.assertEqual(remote.files["hb-full.yaml"], "changed concurrently")
        self.assertNotIn("hb-full.yaml", remote.patches[0])

    def test_half_previous_is_accepted(self):
        remote = FakeGist(self.old)
        self.assertEqual(self.publisher(remote).publish([candidate(count=2)])[0], "published")
        self.assertEqual(len(remote.patches), 1)

    def test_failed_source_merged_from_remote_other_source_updates(self):
        old = dict(self.old, **{"hb-full.yaml": "DO NOT TOUCH", "unrelated.txt": "unchanged"})
        remote = FakeGist(old)
        failed = p.SourceResult("airport", failed=True)
        other = candidate("other", 5)
        self.publisher(remote).publish([failed, other])
        self.assertEqual(remote.files[p.source_file("airport")], old[p.source_file("airport")])
        self.assertEqual(remote.files["hb-full.yaml"], "DO NOT TOUCH")
        self.assertEqual(remote.files["unrelated.txt"], "unchanged")
        update = remote.patches[0]
        self.assertNotIn("hb-full.yaml", update)
        self.assertNotIn(p.source_file("airport"), update)
        # Four roots overlap in connection fingerprint; the five-root union
        # includes the previous successful source plus the new contribution.
        self.assertEqual(len(yaml.safe_load(remote.files["mihomo-alive.yaml"])["proxies"]), 5)

    def test_missing_remote_sources_preserved(self):
        remote = FakeGist(self.old)
        self.publisher(remote).publish([candidate("new-source", 6)])
        self.assertEqual(remote.files[p.source_file("airport")], self.old[p.source_file("airport")])
        self.assertIn(p.source_file("airport"), json.loads(remote.files["manifest.json"])["sources"])

    def test_self_referential_gist_artifact_is_deleted_not_preserved(self):
        stale = candidate("gist-glados", 4)
        files = dict(self.old)
        files[p.source_file("gist-glados")] = stale.content
        manifest = json.loads(files["manifest.json"])
        manifest["sources"][p.source_file("gist-glados")] = {
            "name": "gist-glados", "input": 4, "alive": 4, "published": 4,
            "last_success_alive": 4, "preserved": False}
        files["manifest.json"] = json.dumps(manifest)
        remote = FakeGist(files)
        fresh = candidate(count=3)
        self.publisher(remote).publish([fresh])
        self.assertNotIn(p.source_file("gist-glados"), remote.files)
        self.assertNotIn(p.source_file("gist-glados"),
                         json.loads(remote.files["manifest.json"])["sources"])
        # The remaining real sources are written normally, not dropped.
        self.assertEqual(remote.files[p.source_file("airport")], fresh.content)

    def test_patch_failure_leaves_previous_unchanged(self):
        remote = FakeGist(self.old)
        remote.fail_patch = True
        with self.assertRaises(p.ProbeError):
            self.publisher(remote).publish([candidate(count=5)])
        self.assertEqual(remote.files, self.old)

    def test_public_gist_never_patched(self):
        remote = FakeGist(self.old, public=True)
        with self.assertRaises(p.ProbeError):
            self.publisher(remote).publish([candidate(count=5)])
        self.assertEqual(remote.patches, [])

    def test_truncated_content_fetched_authenticated_and_compared(self):
        remote = FakeGist(self.old)
        remote.truncated = set(self.old)
        self.assertEqual(self.publisher(remote).publish([self.initial])[0], "no_change")
        raw = [call for call in remote.calls if "/raw/" in call[1]]
        self.assertEqual(len(raw), len(self.old))
        self.assertTrue(all(call[2]["Authorization"] == "Bearer not-a-real-token" for call in raw))
        self.assertEqual(remote.patches, [])

    def test_raw_external_host_fails_before_patch(self):
        remote = FakeGist(self.old)
        remote.truncated = set(self.old)
        remote.raw_host = "attacker.invalid"
        with self.assertRaises(p.ProbeError):
            self.publisher(remote).publish([self.initial])
        self.assertEqual(len(remote.calls), 1)

    def test_patch_has_no_unsupported_if_match_and_manifest_is_atomic(self):
        remote = FakeGist(self.old)
        self.publisher(remote).publish([candidate(count=5)])
        patch = next(call for call in remote.calls if call[0] == "PATCH")
        self.assertNotIn("If-Match", patch[2])
        self.assertEqual([call[0] for call in remote.calls], ["GET", "GET", "PATCH"])
        self.assertIn("manifest.json", remote.patches[0])
        self.assertIn("mihomo-alive.yaml", remote.patches[0])
        self.assertNotIn("history", " ".join(remote.patches[0]))


class NativeTests(unittest.TestCase):
    def test_native_validation_discards_output_and_uses_real_t(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(p.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            self.assertTrue(p.NativeProbe("/bin/mihomo").validate(temp, {"proxies": []}))
            self.assertIn("-t", run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
            self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)

    def test_invalid_individual_node_isolated_and_two_attempts(self):
        graph = p.Graph({"proxies": [node("bad"), node("ok")]})
        probe = p.NativeProbe("mihomo")
        process = mock.Mock()
        process.poll.return_value = None
        calls = []

        def validate(directory, cfg):
            calls.append(cfg)
            return cfg["listeners"][0]["proxy"] != "bad"

        with mock.patch.object(probe, "validate", side_effect=validate), mock.patch.object(probe, "health", return_value=True) as health, mock.patch.object(probe, "trace", side_effect=[None, ("8.8.8.8", "US")]) as trace, mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["bad", "ok"])
        self.assertEqual(invalid, 1)
        self.assertEqual(unverifiable, 0)
        self.assertEqual([m.name for m in measured], ["ok"])
        self.assertEqual(trace.call_count, 2)
        self.assertEqual(health.call_count, 2)
        # Group testing: one failing batch + one call per half + the combined
        # measurement config (not one call per root).
        self.assertEqual(len(calls), 4)
        process.terminate.assert_called_once()

    def test_one_bad_root_in_a_batch_costs_log_calls_not_n(self):
        """Group testing: 1 bad root among 32 stays O(log n), not O(n)."""
        names = ["bad"] + ["ok-%d" % i for i in range(31)]
        graph = p.Graph({"proxies": [node(name) for name in names]})
        probe = p.NativeProbe("mihomo")
        process = mock.Mock()
        process.poll.return_value = None
        calls = []

        def validate(directory, cfg):
            calls.append(cfg)
            return all(lane["proxy"] != "bad" for lane in cfg["listeners"])

        with mock.patch.object(probe, "validate", side_effect=validate), mock.patch.object(probe, "health", return_value=True), mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US")), mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, names)
        self.assertEqual(invalid, 1)
        self.assertEqual([m.name for m in measured], ["ok-%d" % i for i in range(31)])
        self.assertEqual(unverifiable, 0)
        # batch + 5 failing halves + 5 passing siblings + combined config
        self.assertLess(len(calls), 16)

    def test_all_invalid_batch_starts_no_kernel(self):
        graph = p.Graph({"proxies": [node("bad1"), node("bad2")]})
        probe = p.NativeProbe("mihomo")
        with mock.patch.object(probe, "validate", return_value=False), mock.patch.object(p.subprocess, "Popen") as start:
            measured, invalid, unverifiable = probe(graph, ["bad1", "bad2"])
        self.assertEqual((measured, invalid, unverifiable), ([], 2, 0))
        start.assert_not_called()

    def test_dead_kernel_at_end_discards_measurements(self):
        graph = p.Graph({"proxies": [node()]})
        probe = p.NativeProbe("mihomo")
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe, "validate", return_value=True), mock.patch.object(probe, "health", side_effect=[True, False]), mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US")), mock.patch.object(p.subprocess, "Popen", return_value=process):
            result = p.measure_source("airport", {"proxies": [node()]}, None, probe)
        self.assertTrue(result.failed)
        self.assertIsNone(result.content)

    def test_missing_dependency_never_probed_direct(self):
        probe = p.NativeProbe("mihomo")
        graph = p.Graph({"proxies": [node(**{"dialer-proxy": "missing"})]})
        with mock.patch.object(probe, "validate") as validate, mock.patch.object(p.subprocess, "Popen") as start:
            measured, invalid, unverifiable = probe(graph, ["node"])
        self.assertEqual(measured, [])
        self.assertEqual(invalid, 1)
        self.assertEqual(unverifiable, 0)
        validate.assert_not_called()
        start.assert_not_called()

    def test_the_launched_config_carries_the_ports_that_are_probed(self):
        """Skipping the second -t must not skip writing the final config.

        Popen reads directory/config.yaml, and _assess last wrote the BATCH
        variant with different ports. Launching that while polling the new
        controller port made readiness time out (kernel_start_failure).
        """
        graph = p.Graph({"proxies": [node("a")]})
        probe = p.NativeProbe("mihomo")
        process = mock.Mock()
        process.poll.return_value = None
        writes = []

        def fake_write(path, content):
            writes.append((Path(path).name, content))

        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True) as health, \
             mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US", "2")), \
             mock.patch.object(p, "private_write", side_effect=fake_write), \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["a"])
        self.assertEqual(len(measured), 1)
        controller = str(health.call_args.args[1])
        self.assertEqual(writes[-1][0], "config.yaml")
        self.assertIn(controller, writes[-1][1])

    def test_failed_nodes_get_one_short_pass_then_one_full_pass(self):
        """Pass 1 is cheap for everyone; only failures pay the full timeout."""
        graph = p.Graph({"proxies": [node("dead"), node("live")]})
        probe = p.NativeProbe("mihomo", timeout=15)
        process = mock.Mock()
        process.poll.return_value = None
        budgets = []

        def trace(port, directory, timeout=None):
            budgets.append(timeout)
            return None

        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "trace", side_effect=trace), \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["dead", "live"])
        # Two nodes share pass 1 at the short budget (15 // 3 = 5); the two
        # failures then share pass 2 at the full budget (None -> self.timeout).
        self.assertEqual(budgets, [5, 5, None, None])
        self.assertEqual(measured, [])


class TransportTests(unittest.TestCase):
    def test_retry_503_and_oserror_but_not_401_403_412(self):
        for code, attempts in ((503, 3), (429, 3), (401, 1), (403, 1), (412, 1)):
            transport = p.Transport(sleep=lambda _: None)
            failure = p.urllib.error.HTTPError("https://fixture.invalid/SECRET", code, "SECRET", {}, None)
            with mock.patch.object(transport.opener, "open", side_effect=failure) as opened:
                with self.assertRaises(p.ProbeError) as got:
                    transport("GET", "https://fixture.invalid/SECRET")
                self.assertEqual(p.error_code(got.exception), "http_" + str(code))
                self.assertEqual(opened.call_count, attempts)
        transport = p.Transport(sleep=lambda _: None)
        with mock.patch.object(transport.opener, "open", side_effect=OSError("SECRET")) as opened:
            with self.assertRaises(p.ProbeError):
                transport("PATCH", "https://fixture.invalid/SECRET", body=b"{}")
            self.assertEqual(opened.call_count, 3)

    def test_error_categories_never_include_exception_text(self):
        for exc in (ValueError("SECRET URL"), p.ProbeError("SECRET URL"), KeyError("SECRET URL"), RuntimeError("SECRET URL")):
            self.assertNotIn("SECRET", p.error_code(exc))
            self.assertNotIn("URL", p.error_code(exc))


class RunnerTests(unittest.TestCase):
    def test_selected_sources_dedup_clashmeta_and_private_checkpoint_on_publish_failure(self):
        calls = []
        names = ["ikunkun", "pokenmen", "健康中心", "prologue", "233pio", "saki", "glados"]
        def transport(method, url, headers=None, body=None):
            calls.append(url)
            if url.startswith("https://api.github.com/"):
                raise p.ProbeError("http_403")
            if url.endswith("/api/subs"):
                return json.dumps({"data": [{"name": name} for name in names + ["not-selected"]]}).encode(), {}
            self.assertIn("?target=ClashMeta", url)
            return p.canonical({"proxies": [node()]}).encode(), {}
        def probe(graph, roots):
            return [p.Measurement(name, "8.8.8.8", "US") for name in roots], 0, 0
        failed_store = mock.Mock()
        failed_store.current.return_value = ({}, None)
        failed_store.save.side_effect = p.ProbeError("http_403")
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(
                p, "publication_backends", return_value=(failed_store, None)):
            env = {"SUBSTORE_BASE": "https://fixture.invalid/SECRET", "PROBE_OUTPUT_DIR": temp, "GIST_TOKEN": "fixture\r\n", "GIST_ID": "abc123", "PROBE_FRONT_SUB": "", "PROBE_SOURCES_JSON": json.dumps(names + ["prologue"])}
            code, summary = p.run(env, transport, probe)
            self.assertEqual(code, 2)
            self.assertEqual(summary["phase"], "publish")
            self.assertEqual(summary["error_code"], "http_403")
            self.assertEqual(summary["sources"], 7)
            self.assertEqual(summary["alive"], 7)
            self.assertEqual([item["name"] for item in summary["results"]], names)
            self.assertTrue(all(item["dedup_kept"] == 1 and item["unique_egress"] == 1 and item["countries"] == {"US": 1} for item in summary["results"]))
            self.assertEqual(len(list((Path(temp) / "candidates").glob("source-*.yaml"))), 7)
            report = json.loads((Path(temp) / "measurement.json").read_text(encoding="utf-8"))
            self.assertEqual(report["alive"], 7)
            self.assertNotIn("SECRET", json.dumps(summary))
            self.assertEqual(len(calls), 8)

    def test_source_filter_missing_or_invalid_fails_before_download(self):
        for selected in ('[]', '{}', '["missing"]', '["airport", 3]', 'invalid'):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as temp:
                transport = mock.Mock(return_value=(b'{"data":[{"name":"airport"}]}', {}))
                code, summary = p.run({"SUBSTORE_BASE": "https://fixture.invalid/private", "PROBE_OUTPUT_DIR": temp, "PROBE_SOURCES_JSON": selected}, transport, mock.Mock())
                self.assertEqual(code, 2)
                self.assertIn(summary["error_code"], {"sources_filter_invalid", "sources_filter_missing"})
                self.assertEqual(transport.call_count, 1)

    def test_all_sources_every_round_without_names_in_summary(self):
        calls = []
        names = ["first", "second", "cf-front", "probe-old", "chain-old", "rust-old", "官方可用", "测活-DMIT"]

        def transport(method, url, headers=None, body=None):
            calls.append(url)
            self.assertEqual(method, "GET")
            if url.endswith("/api/subs"):
                return json.dumps({"data": [{"name": name} for name in names]}).encode(), {}
            return p.canonical({"proxies": [node()]}).encode(), {}

        def probe(graph, roots):
            return [p.Measurement(root, "8.8.8.8", "US") for root in roots], 0, 0

        with tempfile.TemporaryDirectory() as temp:
            env = {"SUBSTORE_BASE": "https://fixture.invalid/private", "PROBE_OUTPUT_DIR": temp}
            for _ in range(2):
                code, summary = p.run(env, transport, probe)
                self.assertEqual(code, 0)
                self.assertEqual({key: summary[key] for key in ("sources", "input", "alive", "failure")}, {"sources": 3, "input": 3, "alive": 3, "failure": 0})
                self.assertEqual(summary["phase"], "complete")
                self.assertNotIn("results", summary)
            self.assertEqual(len(calls), 8)
            self.assertEqual(len(list(Path(temp).glob("source-*.yaml"))), 3)
            self.assertTrue((Path(temp) / "mihomo-alive.yaml").exists())

    def test_no_embedded_backend_no_env_no_network(self):
        transport = mock.Mock()
        code, summary = p.run({}, transport, mock.Mock())
        self.assertEqual(code, 2)
        self.assertEqual(summary["failure"], 1)
        transport.assert_not_called()

    def test_empty_authoritative_source_list_fails_without_publish(self):
        transport = mock.Mock(return_value=(b'{"data":[]}', {}))
        with tempfile.TemporaryDirectory() as temp:
            code, summary = p.run({"SUBSTORE_BASE": "https://fixture.invalid/private", "PROBE_OUTPUT_DIR": temp}, transport, mock.Mock())
            self.assertEqual(code, 2)
            self.assertEqual(summary["failure"], 1)
            self.assertEqual(transport.call_count, 1)
            self.assertFalse(list(Path(temp).iterdir()))

    def test_fetch_failure_preserves_previous_local_output(self):
        def transport(method, url, headers=None, body=None):
            if url.endswith("/api/subs"):
                return b'{"data":[{"name":"airport"}]}', {}
            raise p.ProbeError("fetch_failed")
        with tempfile.TemporaryDirectory() as temp:
            for name, content in p.plan_updates([candidate()], {}).items():
                p.private_write(Path(temp) / name, content)
            old = (Path(temp) / p.source_file("airport")).read_text()
            code, summary = p.run({"SUBSTORE_BASE": "https://fixture.invalid/private", "PROBE_OUTPUT_DIR": temp}, transport, mock.Mock())
            self.assertEqual(code, 2)
            self.assertEqual(summary["failure"], 1)
            self.assertEqual((Path(temp) / p.source_file("airport")).read_text(), old)


    def test_v6_helper_is_dispatched_from_the_fetched_configs(self):
        """The helper's job list must come from fetch, not from the results.

        That is what lets it run while the runner is still measuring instead of
        adding its whole wall time afterwards.
        """
        seen = {}
        config = {"proxies": [node("v6", server="2606:4700:4700::1111"), node("v4")]}

        def transport(method, url, headers=None, body=None):
            if url.endswith("/api/subs"):
                return b'{"data":[{"name":"airport"}]}', {}
            return p.canonical(config).encode(), {}

        class Probe:
            ipv6 = False

            def __call__(self, graph, roots):
                live = [p.Measurement(root, "8.8.8.8", "US") for root in roots if root == "v4"]
                return live, 0, len(roots) - len(live)

        def fake_request(jobs, env):
            seen["jobs"] = jobs
            return {"ok": True, "judged": 1, "promoted": 0, "error": ""}, None

        with tempfile.TemporaryDirectory() as temp, mock.patch.object(p, "request_v6", side_effect=fake_request):
            code, summary = p.run({"SUBSTORE_BASE": "https://fixture.invalid/private",
                                   "PROBE_OUTPUT_DIR": temp,
                                   "PROBE_V6_HELPER": "helper.invalid",
                                   "PROBE_V6_SSH_PORT": "22"}, transport, Probe())
        self.assertEqual(code, 0)
        self.assertEqual([job["roots"] for job in seen["jobs"]], [["v6"]])
        self.assertEqual([node["name"] for node in seen["jobs"][0]["config"]["proxies"]], ["v6"])
        self.assertTrue(summary["v6_helper"]["ok"])
        self.assertIn("helper_s", summary["timings"])
        self.assertIn("helper_wait_s", summary["timings"])


class NodeLevelPolicyTests(unittest.TestCase):
    """Node-level cleanup: a node proven dead must leave the subscription."""

    def setUp(self):
        self.old = p.plan_updates([candidate(count=4)], {})

    def publish(self, files, results):
        remote = FakeGist(files)
        status, plan = FixturePublisher("abc123", "not-a-real-token", remote).publish(results)
        return remote, status

    def state(self, remote):
        return json.loads(remote.files["manifest.json"])["sources"][p.source_file("airport")]

    def test_second_consecutive_zero_alive_round_drops_the_dead_nodes(self):
        remote, status = self.publish(self.old, [dead()])
        self.assertEqual(status, "published")
        # Round one: the artifact is kept, only the grace counter moves.
        self.assertIn(p.source_file("airport"), remote.files)
        self.assertEqual(self.state(remote)["bad_streak"], 1)
        self.assertEqual(self.state(remote)["guard"], "zero_alive")
        # Round two: every node was judged and failed, so the artifact and its
        # dead nodes are removed.
        remote, status = self.publish(remote.files, [dead()])
        self.assertEqual(status, "published")
        self.assertNotIn(p.source_file("airport"), remote.files)
        self.assertEqual(yaml.safe_load(remote.files["mihomo-alive.yaml"])["proxies"], [])
        self.assertEqual(self.state(remote)["guard"], "confirmed_dead")
        self.assertEqual(self.state(remote)["last_success_alive"], 0)
        self.assertIn(p.source_file("airport"), remote.patches[0])
        self.assertIsNone(remote.patches[0][p.source_file("airport")])

    def test_dead_source_is_kept_while_the_front_is_down(self):
        # The nodes hang off a front that is dead: their failure proves
        # nothing about the nodes themselves.
        result = dead(uses_front=True, front_alive=False)
        for _ in range(3):
            remote, status = self.publish(remote.files if "remote" in dir() else self.old, [result])
            self.assertIn(p.source_file("airport"), remote.files)
            self.assertEqual(self.state(remote)["bad_streak"], 0)
            self.assertNotIn(p.source_file("airport"), remote.patches[0] if remote.patches else {})

    def test_front_measured_alive_makes_the_death_attributable(self):
        result = dead(uses_front=True, front_alive=True)
        remote, status = self.publish(self.old, [result])
        self.assertEqual(self.state(remote)["bad_streak"], 1)

    def test_ipv6_unverifiable_nodes_are_never_scored_dead(self):
        result = dead(input_count=4)
        result.unverifiable = 4
        result.measured = 0
        remote, status = self.publish(self.old, [result])
        for _ in range(4):
            self.assertIn(p.source_file("airport"), remote.files)
            self.assertEqual(self.state(remote)["bad_streak"], 0)
            remote, status = self.publish(remote.files, [result])

    def test_degraded_source_publishes_only_the_alive_nodes_after_the_grace(self):
        remote, status = self.publish(self.old, [candidate(count=1)])
        self.assertEqual(status, "published")
        # Round one: the reduced set is held back.
        self.assertEqual(remote.files[p.source_file("airport")], self.old[p.source_file("airport")])
        self.assertEqual(self.state(remote)["bad_streak"], 1)
        # Round two: only the node that measured alive survives.
        remote, status = self.publish(remote.files, [candidate(count=1)])
        self.assertEqual(status, "published")
        self.assertEqual(len(yaml.safe_load(remote.files[p.source_file("airport")])["proxies"]), 1)
        self.assertEqual(len(yaml.safe_load(remote.files["mihomo-alive.yaml"])["proxies"]), 1)
        self.assertEqual(self.state(remote)["guard"], "degraded")

    def test_v6_bound_node_is_unverifiable_on_an_ipv4_only_host(self):
        graph = p.Graph({"proxies": [node("v6node", server="2606:4700:4700::1111"), node("v4node")]})
        probe = p.NativeProbe("mihomo", ipv6=False)
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe, "validate", return_value=True) as validate, mock.patch.object(probe, "health", return_value=True), mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US")), mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["v6node", "v4node"])
        self.assertEqual(unverifiable, 1)
        self.assertEqual(invalid, 0)
        self.assertEqual([m.name for m in measured], ["v4node"])
        # The IPv6 node is never dialled: every validated config is the IPv4 one.
        # The batch that ran during _assess is the only validation: the
        # combined config differs only in listener ports, which -t cannot see,
        # so re-validating the identical accepted set buys no evidence.
        self.assertEqual(len(validate.call_args_list), 1)  # batch only
        for call in validate.call_args_list:
            self.assertNotIn("2606:4700:4700::1111", str(call.args[1]))

    def test_v6_bound_node_is_measured_on_an_ipv6_capable_host(self):
        graph = p.Graph({"proxies": [node("v6node", server="2606:4700:4700::1111")]})
        probe = p.NativeProbe("mihomo", ipv6=True)
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe, "validate", return_value=True), mock.patch.object(probe, "health", return_value=True), mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US")), mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["v6node"])
        self.assertEqual(unverifiable, 0)
        self.assertEqual(len(measured), 1)

    def test_host_ipv6_capability_is_a_route_lookup(self):
        class DeadRoute:
            def __init__(self, family, kind):
                pass
            def connect(self, address):
                raise OSError("network unreachable")
            def close(self):
                pass
        class LiveRoute(DeadRoute):
            def connect(self, address):
                return None
        with mock.patch.object(p.socket, "socket", return_value=DeadRoute(0, 0)):
            self.assertFalse(p.host_ipv6_capable())
        with mock.patch.object(p.socket, "socket", return_value=LiveRoute(0, 0)):
            self.assertTrue(p.host_ipv6_capable())

    def test_ipv6_override_parsing(self):
        self.assertIsNone(p.ipv6_override(None))
        self.assertIsNone(p.ipv6_override(""))
        self.assertIsNone(p.ipv6_override("maybe"))
        for text in ("1", "true", "YES", " on "):
            self.assertIs(p.ipv6_override(text), True, text)
        for text in ("0", "false", "No", " off "):
            self.assertIs(p.ipv6_override(text), False, text)

    def test_measure_source_marks_front_dependent_sources(self):
        config = {"proxies": [node("root", **{"dialer-proxy": "front"})]}
        front = {"proxies": [node("front")]}
        probe = p.NativeProbe("mihomo", ipv6=True)
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe, "validate", return_value=True), mock.patch.object(probe, "health", return_value=True), mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US")), mock.patch.object(p.subprocess, "Popen", return_value=process):
            chained = p.measure_source("chained", config, front, probe)
            direct = p.measure_source("direct", {"proxies": [node("solo")]}, front, probe)
        self.assertTrue(chained.uses_front)
        self.assertFalse(direct.uses_front)

    def test_unproven_rounds_reach_the_gist_then_stop_creating_revisions(self):
        result = dead(uses_front=True, front_alive=None)
        remote, status = self.publish(self.old, [result])
        self.assertEqual(status, "published")
        self.assertIn(p.source_file("airport"), remote.files)
        self.assertEqual(self.state(remote)["unproven_rounds"], 1)
        for _ in range(p.UNPROVEN_ROUNDS_CAP + 1):
            remote, status = self.publish(remote.files, [result])
        self.assertEqual(self.state(remote)["unproven_rounds"], p.UNPROVEN_ROUNDS_CAP)
        # At the cap the counter stops changing, so a permanently unprovable
        # source no longer produces a manifest-only revision every round.
        remote, status = self.publish(remote.files, [result])
        self.assertEqual(status, "no_change")

    def test_a_round_that_dialled_nothing_never_deletes_the_source(self):
        """Batch validation can reject every root without dialling one.

        That is "unjudgeable", not "dead": a config-parse regression, a kernel
        version change or a -t timeout must never empty a healthy subscription.
        """
        result = p.SourceResult("airport", 10, 0, 0, "proxies: []\n")
        result.measured = 0
        result.invalid = 10
        files = self.old
        for round_number in range(1, 4):
            files = p.plan_updates([result], files)
            entry = json.loads(files["manifest.json"])["sources"][p.source_file("airport")]
            self.assertIn(p.source_file("airport"), files)
            self.assertEqual(entry["guard"], "not_dialled")
            self.assertEqual(entry["bad_streak"], 0)
            self.assertEqual(entry["unproven_rounds"], round_number)

    def test_unverifiable_members_are_never_deleted_by_the_ratio_gate(self):
        # Four published, this round only one v4 node answered and three nodes
        # need an IPv6 route this host does not have.
        reduced = p.SourceResult("airport", 4, 1, 1, self.old[p.source_file("airport")])
        reduced.measured = 1
        reduced.unverifiable = 3
        files = self.old
        for _ in range(3):
            files = p.plan_updates([reduced], files)
            entry = json.loads(files["manifest.json"])["sources"][p.source_file("airport")]
            self.assertEqual(files[p.source_file("airport")], self.old[p.source_file("airport")])
            self.assertEqual(entry["guard"], "unproven_hold")
            self.assertEqual(entry["bad_streak"], 0)

    def test_unmeasured_front_keeps_the_nodes_and_surfaces_the_round(self):
        # The front is not a selected source, so nobody knew whether it was up.
        # Its nodes must never be deleted, but the round must stop looking
        # identical to a healthy one.
        result = dead(uses_front=True, front_alive=None)
        files = self.old
        for round_number in range(1, 3):
            files = p.plan_updates([result], files)
            entry = json.loads(files["manifest.json"])["sources"][p.source_file("airport")]
            self.assertIn(p.source_file("airport"), files)
            self.assertEqual(entry["guard"], "front_unproven")
            self.assertEqual(entry["bad_streak"], 0)
            self.assertEqual(entry["unproven_rounds"], round_number)

    def test_an_all_corrupt_round_keeps_the_previous_merged_body(self):
        files = dict(self.old)
        files[p.source_file("airport")] = "# truncated upload\n"
        planned = p.plan_updates([], files)
        # Quarantining the only artifact must not write an empty subscription.
        self.assertEqual(planned["mihomo-alive.yaml"], files["mihomo-alive.yaml"])
        self.assertNotIn(p.source_file("airport"), planned)

    def test_a_corrupt_retained_artifact_is_quarantined_not_fatal(self):
        files = dict(self.old)
        broken = p.source_file("ghost")
        files[broken] = "proxies: null\n"  # truncated / hand-edited artifact
        remote, status = self.publish(files, [candidate(count=4)])
        self.assertEqual(status, "published")
        # The healthy source still publishes, and the unusable artifact is
        # deleted on the same PATCH instead of blocking every future round.
        self.assertIn(p.source_file("airport"), remote.files)
        self.assertNotIn(broken, remote.files)
        self.assertIsNone(remote.patches[0][broken])
        manifest = json.loads(remote.files["manifest.json"])["sources"]
        self.assertTrue(manifest[broken]["corrupt"])
        self.assertEqual(manifest[broken]["guard"], "old_content_invalid")


class V6WorkerMergeTests(unittest.TestCase):
    """A v6-capable helper settles what an IPv4-only runner cannot."""

    def result(self, alive=0, unverifiable=3, measured=0):
        r = p.SourceResult("src", 3, alive, 0, None)
        r.unverifiable = unverifiable
        r.measured = measured
        # The helper can only settle roots this round actually handed over; an
        # answer naming anything else is discarded wholesale.
        r.v6_roots = ["n1", "n2", "n3"]
        return r

    def test_promotes_answered_nodes_and_shrinks_unverifiable(self):
        result = self.result()
        payload = {"host_ipv6": True,
                   "judged": {"src": 2},
                   "results": {"src": {"n1": {"alive": True, "ip": "2a0e:97c0::1", "cc": "HK"},
                                       "n2": {"alive": True, "ip": "2a0e:97c0::2", "cc": "JP"}}}}
        merged = p.merge_v6_results([result], payload)
        self.assertEqual(merged[0].alive, 2)
        self.assertEqual(merged[0].measured, 2)
        self.assertEqual(merged[0].unverifiable, 1)      # one was never judged
        self.assertEqual(merged[0].countries, {"HK": 1, "JP": 1})

    def test_dialled_and_silent_becomes_death_evidence(self):
        result = self.result()
        payload = {"host_ipv6": True, "judged": {"src": 3}, "results": {"src": {}}}
        merged = p.merge_v6_results([result], payload)
        # Every node the helper dialled failed: no longer unverifiable, so the
        # source can finally be proven dead.
        self.assertEqual(merged[0].unverifiable, 0)
        self.assertEqual(merged[0].alive, 0)

    def test_inert_when_the_helper_has_no_ipv6(self):
        result = self.result()
        payload = {"host_ipv6": False, "judged": {"src": 3}, "results": {"src": {}}}
        merged = p.merge_v6_results([result], payload)
        self.assertEqual(merged[0].unverifiable, 3)

    def test_malformed_payload_never_changes_anything(self):
        for payload in (None, {}, {"host_ipv6": True}, {"host_ipv6": True, "judged": "x"},
                        {"host_ipv6": True, "judged": {"src": "nope"}},
                        {"host_ipv6": True, "judged": {"src": 1}, "results": {"src": {"n": {"alive": True, "ip": "not-ip", "cc": "HK"}}}},
                        {"host_ipv6": True, "judged": {"src": 1}, "results": {"src": {"n": {"alive": True, "ip": "8.8.8.8", "cc": "ZZ"}}}},
                        {"host_ipv6": True, "judged": {"src": 1}, "results": {"src": {"n": {"alive": True, "ip": "127.0.0.1", "cc": "HK"}}}}):
            with self.subTest(payload=payload):
                result = self.result()
                merged = p.merge_v6_results([result], payload)
                self.assertEqual(merged[0].alive, 0)
                self.assertEqual(merged[0].unverifiable, 3)


    def test_helper_answer_naming_a_node_it_was_not_given_is_ignored(self):
        """A poisoned or version-mismatched helper must not invent a node."""
        result = self.result()
        payload = {"host_ipv6": True, "judged": {"src": 3},
                   "results": {"src": {"EVIL": {"alive": True, "ip": "2a0e:97c0::1", "cc": "HK"}}}}
        merged = p.merge_v6_results([result], payload)
        self.assertEqual(merged[0].alive, 0)
        self.assertEqual(merged[0].unverifiable, 3)

    def test_promoted_counts_only_measurements_the_helper_added(self):
        result = self.result(alive=1, unverifiable=2)
        result.v6_roots = ["n2", "n3"]
        result.measurements = [p.Measurement("n1", "8.8.8.8", "US")]
        result.content = None
        payload = {"host_ipv6": True, "judged": {"src": 2},
                   "results": {"src": {"n2": {"alive": True, "ip": "2a0e:97c0::2", "cc": "JP"}}}}
        report = p.apply_v6([result], payload, {"src": {"proxies": []}},
                            {"ok": False, "judged": 0, "promoted": 0, "error": ""})
        self.assertEqual(report["promoted"], 1)
        self.assertLessEqual(report["promoted"], report["judged"])


class SourceSecretsTests(unittest.TestCase):
    """The reserved per-source credential extension point (docs/ADDING_SOURCES.md)."""

    def test_absent_or_empty_env_means_no_credentials(self):
        self.assertEqual(p.load_source_secrets({}), {})
        self.assertEqual(p.load_source_secrets({"SOURCE_SECRETS_JSON": "   "}), {})
        self.assertEqual(p.load_source_secrets({"SOURCE_SECRETS_JSON": '{"a": {"header": {"X": "1"}}}'}),
                         {"a": {"header": {"X": "1"}}})

    def test_invalid_shapes_fail_with_fixed_code_and_no_value_leak(self):
        cases = [
            "not json",
            "[]",
            '[{"a": 1}]',
            '{"a": "string"}',
            '{"": {"header": {"X": "1"}}}',
            '{"a": {}}',
            '{"a": {"unknown": 1}}',
            '{"a": {"header": {"X": 1}}}',
            '{"a": {"query": {"t": 1}}}',
            '{"a": {"url": "ftp://other.example/sub"}}',
            '{"a": {"url": "http://other.example/sub?token=private"}}',
            '{"a": {"url": "https://user:pass@other.example/sub"}}',
            '{"a": {"url": "not a url"}}',
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(p.ProbeError) as got:
                    p.load_source_secrets({"SOURCE_SECRETS_JSON": raw})
                self.assertEqual(p.error_code(got.exception), "source_secrets_invalid")
                self.assertNotIn("abc123", p.error_code(got.exception))

    def test_header_applies_only_to_matching_source(self):
        seen = {}

        def transport(method, url, headers=None, body=None):
            seen[url] = dict(headers or {})
            return p.canonical({"proxies": [node()]}).encode(), {}

        store = p.SubStore("https://fixture.invalid/SECRET", transport,
                           source_secrets={"机场A": {"header": {"Authorization": "Bearer abc123"}}})
        store.config("机场A")
        store.config("其他源")
        # Assert the auth header landed on the 机场A fetch and nowhere else.
        self.assertEqual(len(seen), 2)
        hits = [h for h in seen.values() if "Authorization" in h]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["Authorization"], "Bearer abc123")
        self.assertTrue(all("SECRET" not in json.dumps(h) for h in seen.values()))

    def test_query_merges_over_target_parameter(self):
        seen = {}

        def transport(method, url, headers=None, body=None):
            seen[url] = True
            return p.canonical({"proxies": [node()]}).encode(), {}

        store = p.SubStore("https://fixture.invalid/SECRET", transport,
                           source_secrets={"token源": {"query": {"token": "abc123"}}})
        store.config("token源")
        url = next(iter(seen))
        self.assertIn("target=ClashMeta", url)
        self.assertIn("token=abc123", url)

    def test_url_override_bypasses_base_for_that_source_only(self):
        seen = {}

        def transport(method, url, headers=None, body=None):
            seen[url] = True
            return p.canonical({"proxies": [node()]}).encode(), {}

        store = p.SubStore("https://fixture.invalid/SECRET", transport,
                           source_secrets={"外部源": {"url": "https://other.example/sub?target=ClashMeta"}})
        store.config("外部源")
        store.config("普通源")
        self.assertTrue(any(url.startswith("https://other.example/") for url in seen))
        self.assertTrue(any(url.startswith("https://fixture.invalid/") for url in seen))

    def test_unicode_names_are_keyed_exactly(self):
        seen = {}

        def transport(method, url, headers=None, body=None):
            seen[url] = dict(headers or {})
            return p.canonical({"proxies": [node()]}).encode(), {}

        store = p.SubStore("https://fixture.invalid/SECRET", transport,
                           source_secrets={"健康中心": {"header": {"X-Key": "abc123"}}})
        store.config("健康中心")
        store.config("健康中心 ")
        self.assertEqual(len([h for h in seen.values() if "X-Key" in h]), 1)

    def test_run_wires_source_secrets_from_env(self):
        # End-to-end: run() passes the parsed map into SubStore, so a header
        # secret set via env lands on that source's download request.
        seen = {}
        names = ["机场A"]

        def transport(method, url, headers=None, body=None):
            seen[url] = dict(headers or {})
            if url.endswith("/api/subs"):
                return json.dumps({"data": [{"name": name} for name in names]}).encode(), {}
            return p.canonical({"proxies": [node()]}).encode(), {}

        def probe(graph, roots):
            return [p.Measurement(name, "8.8.8.8", "US") for name in roots], 0, 0

        with tempfile.TemporaryDirectory() as temp:
            env = {"SUBSTORE_BASE": "https://fixture.invalid/SECRET", "PROBE_OUTPUT_DIR": temp,
                   "SOURCE_SECRETS_JSON": json.dumps({"机场A": {"header": {"Authorization": "Bearer abc123"}}})}
            code, summary = p.run(env, transport, probe)
            self.assertEqual(code, 0)
            # 机场A carries the credential; the default internal front sub
            # (cf-front) never does.
            downloads = {url: h for url, h in seen.items() if "/download/" in url}
            self.assertEqual(len(downloads), 2)
            authed = [url for url, h in downloads.items() if h.get("Authorization") == "Bearer abc123"]
            self.assertEqual(len(authed), 1)
            self.assertIn("机场A", p.urllib.parse.unquote(authed[0]))
            front = [h for url, h in downloads.items() if "cf-front" in url]
            self.assertEqual(len(front), 1)
            self.assertNotIn("Authorization", front[0])
            self.assertNotIn("abc123", json.dumps(summary))


class AuditFieldTests(unittest.TestCase):
    def test_asn_class_covers_known_and_heuristic(self):
        self.assertEqual(p.geo_naming.classify_asn(24940), "datacenter")
        self.assertEqual(p.geo_naming.classify_asn(13335), "cdn")
        self.assertEqual(p.geo_naming.classify_asn(4760), "residential")
        self.assertEqual(p.geo_naming.classify_asn(9808), "mobile")
        self.assertEqual(p.geo_naming.classify_asn(64500, "Some Cloud Hosting Ltd"), "datacenter")
        self.assertEqual(p.geo_naming.classify_asn(64500, "Korea Broadband"), "residential")
        self.assertEqual(p.geo_naming.classify_asn(64500, "Mobile Wireless"), "mobile")
        self.assertEqual(p.geo_naming.classify_asn(0, ""), "unknown")

    def test_landing_compares_only_literal_servers_without_a_dialer(self):
        graph = p.Graph({"proxies": [
            node("same", server="1.2.3.4"),
            node("transit", server="5.6.7.8"),
            node("hostname", server="edge.example"),
            node("chain", server="9.9.9.9", **{"dialer-proxy": "same"}),
        ]})
        self.assertEqual(p.landing_class(graph, "same", "1.2.3.4"), "same")
        self.assertEqual(p.landing_class(graph, "transit", "1.2.3.4"), "transit")
        self.assertEqual(p.landing_class(graph, "hostname", "1.2.3.4"), "unknown")
        self.assertEqual(p.landing_class(graph, "chain", "1.2.3.4"), "unknown")
        self.assertEqual(
            p.landing_counts(graph, [p.Measurement("same", "1.2.3.4", "US"),
                                     p.Measurement("transit", "1.2.3.4", "US")]),
            {"same": 1, "transit": 1, "unknown": 0},
        )

    def test_manifest_carries_delay_landing_and_asn_class(self):
        result = candidate(count=2)
        result.delay_median_ms, result.delay_p90_ms = 120, 200
        result.landing = {"same": 1, "transit": 1, "unknown": 0}
        result.asn_class = {"datacenter": 2}
        files = p.plan_updates([result], {})
        entry = json.loads(files["manifest.json"])["sources"][p.source_file("airport")]
        self.assertEqual((entry["delay_median_ms"], entry["delay_p90_ms"]), (120, 200))
        self.assertEqual(entry["landing"], {"same": 1, "transit": 1, "unknown": 0})
        self.assertEqual(entry["asn_class"], {"datacenter": 2})


class MeasurementDedupeTests(unittest.TestCase):
    def test_identical_connections_are_dialled_once_and_replicated(self):
        """Same resolved connection = same dial; the verdict is repeated."""
        graph = p.Graph({"proxies": [node("a", server="1.2.3.4"),
                                     node("b", server="1.2.3.4")]})
        probe = p.NativeProbe("mihomo", dedupe=True)
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US", "2")) as trace, \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["a", "b"])
        self.assertEqual(trace.call_count, 1)
        self.assertEqual(sorted(item.name for item in measured), ["a", "b"])
        self.assertEqual((invalid, unverifiable), (0, 0))
        self.assertEqual(probe.dedup_saved, 1)


class DelayPrefilterTests(unittest.TestCase):
    def _process(self):
        process = mock.Mock()
        process.poll.return_value = None
        return process

    def test_dead_node_costs_one_delay_call_and_is_not_traced(self):
        graph = p.Graph({"proxies": [node("dead", server="1.1.1.1"),
                                     node("live", server="2.2.2.2")]})
        probe = p.NativeProbe("mihomo", delay_ms=2000)
        process = self._process()

        def delay(controller, secret, name, timeout_ms=None):
            return (False, 0, False) if name == "dead" else (True, 321, False)

        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "delay_probe", side_effect=delay), \
             mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US", "2")) as trace, \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["dead", "live"])
        self.assertEqual([item.name for item in measured], ["live"])
        self.assertEqual(measured[0].delay_ms, 321)
        self.assertEqual(probe.prefiltered, 1)
        self.assertEqual(trace.call_count, 1)

    def test_controller_error_falls_back_to_curl(self):
        """An API failure must never manufacture dead nodes."""
        graph = p.Graph({"proxies": [node("a", server="1.1.1.1"),
                                     node("b", server="2.2.2.2")]})
        probe = p.NativeProbe("mihomo", delay_ms=2000)
        process = self._process()
        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "delay_probe", return_value=(False, 0, True)), \
             mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US", "2")) as trace, \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["a", "b"])
        self.assertEqual(len(measured), 2)
        self.assertEqual(probe.prefiltered, 0)
        self.assertEqual(trace.call_count, 2)
        self.assertTrue(all(item.delay_ms == 0 for item in measured))

    def test_a_slow_node_is_retried_before_being_skipped(self):
        """One short budget is stricter than curl; the retry protects the tail."""
        graph = p.Graph({"proxies": [node("slow", server="1.1.1.1")]})
        probe = p.NativeProbe("mihomo", delay_ms=3000, delay_retry_ms=8000)
        process = self._process()
        budgets = []

        def delay(controller, secret, name, timeout_ms=None):
            budgets.append(timeout_ms)
            return (timeout_ms == 8000, 4200 if timeout_ms == 8000 else 0, False)

        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "delay_probe", side_effect=delay), \
             mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US", "2")) as trace, \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["slow"])
        self.assertEqual(budgets, [3000, 8000])
        self.assertEqual(len(measured), 1)
        self.assertEqual(measured[0].delay_ms, 4200)
        self.assertEqual(probe.prefiltered, 0)
        self.assertEqual(trace.call_count, 1)

    def test_controller_errors_are_not_retried(self):
        graph = p.Graph({"proxies": [node("a", server="1.1.1.1")]})
        probe = p.NativeProbe("mihomo", delay_ms=3000, delay_retry_ms=8000)
        process = self._process()
        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "delay_probe", return_value=(False, 0, True)) as delay, \
             mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US", "2")), \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["a"])
        self.assertEqual(delay.call_count, 1)
        self.assertEqual(len(measured), 1)

    def test_curl_time_total_supplies_delay_when_the_prefilter_is_off(self):
        graph = p.Graph({"proxies": [node("a", server="1.1.1.1")]})
        probe = p.NativeProbe("mihomo")
        process = self._process()
        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US", "2", 1500)), \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            measured, invalid, unverifiable = probe(graph, ["a"])
        self.assertEqual(measured[0].delay_ms, 1500)
        self.assertEqual(probe.prefiltered, 0)


class MergedKernelTests(unittest.TestCase):
    @staticmethod
    def _job(name, root, server):
        config = {"proxies": [node(root, server=server)]}
        return p.SourceJob(name, config, p.Graph(config), [root], set(), False)

    def _process(self):
        process = mock.Mock()
        process.poll.return_value = None
        return process

    def test_two_sources_share_one_kernel_and_keep_attribution(self):
        jobs = [self._job("alpha", "a", "1.1.1.1"),
                self._job("beta", "b", "2.2.2.2")]
        probe = p.NativeProbe("mihomo")
        process = self._process()
        written = []
        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US", "2")) as trace, \
             mock.patch.object(p, "private_write", side_effect=lambda path, content: written.append(content)), \
             mock.patch.object(p.subprocess, "Popen", return_value=process) as popen:
            outcomes = probe.measure_jobs(jobs)
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(trace.call_count, 2)
        self.assertEqual(probe.merged_groups, 1)
        self.assertEqual([item.name for item in outcomes[0][0]], ["a"])
        self.assertEqual([item.name for item in outcomes[1][0]], ["b"])
        config = yaml.safe_load(written[-1])
        lanes = [listener["proxy"] for listener in config["listeners"]]
        self.assertEqual(len(lanes), 2)
        self.assertTrue(all(name.startswith(("s0-n", "s1-n")) for name in lanes))

    def test_a_bad_root_is_attributed_to_its_own_source(self):
        jobs = [self._job("alpha", "a", "1.1.1.1"),
                self._job("beta", "b", "bad.invalid")]

        def validate(directory, cfg):
            return all(proxy.get("server") != "bad.invalid" for proxy in cfg["proxies"])

        probe = p.NativeProbe("mihomo")
        process = self._process()
        with mock.patch.object(probe, "validate", side_effect=validate), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US", "2")), \
             mock.patch.object(p.subprocess, "Popen", return_value=process) as popen:
            outcomes = probe.measure_jobs(jobs)
        self.assertEqual(popen.call_count, 1)
        self.assertEqual([outcome[1] for outcome in outcomes], [0, 1])
        self.assertEqual(len(outcomes[0][0]), 1)

    def test_group_failure_falls_back_to_one_kernel_per_source(self):
        jobs = [self._job("alpha", "a", "1.1.1.1"),
                self._job("beta", "b", "2.2.2.2")]
        calls = []

        class FallbackProbe(p.NativeProbe):
            def __call__(self, graph, roots):
                calls.append(list(roots))
                return ([p.Measurement(roots[0], "8.8.8.8", "US")], 0, 0)

        probe = FallbackProbe("mihomo")
        with mock.patch.object(probe, "_measure_group", side_effect=p.ProbeError("kernel_start_failure")):
            outcomes = probe.measure_jobs(jobs)
        self.assertEqual(calls, [["a"], ["b"]])
        self.assertEqual([len(outcome[0]) for outcome in outcomes], [1, 1])
        self.assertEqual([outcome[3] for outcome in outcomes], [0, 0])

    def test_prefiltered_nodes_are_counted_per_source(self):
        jobs = [self._job("alpha", "a", "1.1.1.1"),
                self._job("beta", "b", "2.2.2.2")]
        probe = p.NativeProbe("mihomo", delay_ms=3000)
        process = mock.Mock()
        process.poll.return_value = None

        def delay(controller, secret, name, timeout_ms=None):
            return (False, 0, False) if name.startswith("s1-") else (True, 50, False)

        with mock.patch.object(probe, "validate", return_value=True), \
             mock.patch.object(probe, "health", return_value=True), \
             mock.patch.object(probe, "delay_probe", side_effect=delay), \
             mock.patch.object(probe, "trace", return_value=("8.8.8.8", "US", "2")), \
             mock.patch.object(p.subprocess, "Popen", return_value=process):
            outcomes = probe.measure_jobs(jobs)
        self.assertEqual([len(outcome[0]) for outcome in outcomes], [1, 0])
        self.assertEqual([outcome[3] for outcome in outcomes], [0, 1])


class MeasureAllTests(unittest.TestCase):
    def test_a_merged_capable_probe_measures_every_source_in_one_call(self):
        configs = {
            "alpha": {"proxies": [node("a", server="1.1.1.1")]},
            "beta": {"proxies": [node("b", server="2.2.2.2")]},
        }

        class Probe:
            ipv6 = True
            kernel_batch = 0
            merged = 0

            def measure_jobs(self, jobs, batch=0):
                self.merged = len(jobs)
                return [([p.Measurement(job.roots[0], "8.8.8.8", "US")], 0, 0) for job in jobs]

            def __call__(self, graph, roots):
                raise AssertionError("merged path must not fall back")

        probe = Probe()
        results = p.measure_all(["alpha", "beta"], configs, None, probe)
        self.assertEqual(probe.merged, 2)
        self.assertEqual([item.name for item in results], ["alpha", "beta"])
        self.assertTrue(all(item.alive == 1 for item in results))


if __name__ == "__main__":
    unittest.main()
