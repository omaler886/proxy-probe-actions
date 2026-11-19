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

    def test_curl_is_explicit_proxy_and_no_pipe(self):
        def fake_run(command, **kwargs):
            self.assertEqual(command[:2], ["curl", "--disable"])
            self.assertIn("--fail", command)
            self.assertEqual(command[command.index("--noproxy") + 1], "")
            self.assertEqual(command[command.index("--proxy") + 1], "http://127.0.0.1:12345")
            self.assertIn("--max-time", command)
            self.assertEqual(command[-1], p.TRACE_URL)
            self.assertNotEqual(kwargs["stdout"], subprocess.PIPE)
            kwargs["stdout"].write(self.GOOD.encode())
            return mock.Mock(returncode=0)
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(p.subprocess, "run", side_effect=fake_run):
            self.assertEqual(p.NativeProbe("mihomo").trace(12345, temp), ("8.8.8.8", "US"))


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


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.initial = candidate(count=4)
        self.old = p.plan_updates([self.initial], {})

    def publisher(self, transport):
        return p.GistPublisher("abc123", "not-a-real-token", transport)

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
        publisher = p.GistPublisher("  abc123\r\n", "  test-token\r\n", remote)
        publisher.publish([self.initial])
        self.assertEqual(remote.calls[0][2]["Authorization"], "Bearer test-token")
        self.assertEqual(remote.calls[0][1], "https://api.github.com/gists/abc123")
        for token in ("\r\n", "bad\r\ntoken"):
            with self.assertRaises(p.ProbeError):
                p.GistPublisher("abc123", token, remote)

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
        with self.assertRaises(p.ProbeError) as got:
            self.publisher(transport).publish([candidate(count=5)])
        self.assertEqual(p.error_code(got.exception), "gist_conflict")
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
        self.assertEqual(len(calls), 3)
        process.terminate.assert_called_once()

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
        with tempfile.TemporaryDirectory() as temp:
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
            self.assertEqual(len(calls), 9)

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
            code, summary = p.run({"SUBSTORE_BASE": "https://fixture.invalid/private", "PROBE_OUTPUT_DIR": temp, "GIST_TOKEN": "fixture", "GIST_ID": "abc123"}, transport, mock.Mock())
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


class NodeLevelPolicyTests(unittest.TestCase):
    """Node-level cleanup: a node proven dead must leave the subscription."""

    def setUp(self):
        self.old = p.plan_updates([candidate(count=4)], {})

    def publish(self, files, results):
        remote = FakeGist(files)
        status, plan = p.GistPublisher("abc123", "not-a-real-token", remote).publish(results)
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
        self.assertEqual(len(validate.call_args_list), 2)  # per-root + combined
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


class V6WorkerMergeTests(unittest.TestCase):
    """A v6-capable helper settles what an IPv4-only runner cannot."""

    def result(self, alive=0, unverifiable=3, measured=0):
        r = p.SourceResult("src", 3, alive, 0, None)
        r.unverifiable = unverifiable
        r.measured = measured
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


if __name__ == "__main__":
    unittest.main()
