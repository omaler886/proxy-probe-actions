"""Offline security boundaries, publication recovery and dial-budget regressions."""
import base64
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import actions_probe_all as probe
import publication
from probe_limits import EndpointLimiter, choose_workers, interleave_endpoints

geo_naming = probe.geo_naming


def load_tool(name):
    """Load one repository tool for an offline integration test and return it."""
    path = Path(__file__).resolve().parents[1] / "tools" / (name + ".py")
    spec = importlib.util.spec_from_file_location("security_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_node(name, server="example.invalid", **options):
    """Return a fixture SS node with recognizable connection credentials."""
    return dict(name=name, type="ss", server=server, port=443,
                password="fixture-connection-secret", **options)


class GitHubFixture:
    """Emulate separate private Contents state and a single-file delivery Gist."""

    def __init__(self):
        """Initialize an empty private repository and unlisted delivery file."""
        self.state = None
        self.is_private = True
        self.is_public_gist = False
        self.files = {"mihomo-alive.yaml": "proxies: []\n"}
        self.calls = []
        self.puts = []
        self.patches = []
        self.fail_delivery = False
        self.ambiguous_put = False
        self.use_blob = False
        self.legacy_files = {}

    def version(self):
        """Return the current Git blob SHA, or None before the first write."""
        if self.state is None:
            return None
        return hashlib.sha1(b"blob " + str(len(self.state)).encode() + b"\0" + self.state).hexdigest()

    def blob(self):
        """Return the GitHub base64 representation of the current state blob."""
        return {"type": "file", "sha": self.version(), "size": len(self.state),
                "encoding": "base64", "content": base64.b64encode(self.state).decode()}

    def __call__(self, method, url, headers=None, body=None):
        """Route a fake GitHub request; reject every unexpected external endpoint."""
        self.calls.append((method, url, headers, body))
        if url == "https://api.github.com/repos/fixture/state":
            return publication.encode_json({"private": self.is_private}), {}
        if "/git/ref/heads/main" in url:
            return b'{"ref":"refs/heads/main"}', {}
        if "/git/blobs/" in url:
            return publication.encode_json(self.blob()), {}
        if "/contents/probe/state.json" in url:
            return self.contents(method, body)
        if url == "https://api.github.com/gists/abc123":
            return self.gist(method, body)
        if url == "https://api.github.com/gists/def456":
            if method != "GET":
                raise AssertionError("the legacy Gist is read-only")
            files = {name: {"content": text} for name, text in self.legacy_files.items()}
            return publication.encode_json({"public": False, "files": files}), {}
        if url.endswith("/api/subs"):
            return b'{"data":[{"name":"fixture-source"}]}', {}
        if "/download/" in url:
            return probe.canonical({"proxies": [make_node("original-label")]}).encode(), {}
        raise AssertionError("unexpected endpoint")

    def contents(self, method, body):
        """Apply Contents API SHA checks and optionally emulate a lost PUT response."""
        if method == "GET":
            if self.state is None:
                raise probe.ProbeError("http_404")
            value = self.blob()
            if self.use_blob:
                value.update(encoding="none", content="")
            return publication.encode_json(value), {}
        if method != "PUT":
            raise AssertionError("unexpected state mutation")
        value = json.loads(body)
        if value.get("sha") != self.version():
            raise probe.ProbeError("http_409")
        self.state = base64.b64decode(value["content"])
        self.puts.append(value)
        if self.ambiguous_put:
            self.ambiguous_put = False
            # The first PUT succeeded but its response was lost; a transport
            # retry with the original SHA receives 409 from the server.
            raise probe.ProbeError("http_409")
        return b"{}", {}

    def gist(self, method, body):
        """Serve or update only the fake delivery Gist, preserving request evidence."""
        if method == "PATCH":
            if self.fail_delivery:
                raise probe.ProbeError("http_503")
            value = json.loads(body)["files"]
            self.patches.append(value)
            self.files.update({name: entry["content"] for name, entry in value.items()})
            return b"{}", {}
        files = {name: {"content": content, "truncated": False}
                 for name, content in self.files.items()}
        return publication.encode_json({"public": self.is_public_gist, "files": files}), {}


class PublicationBoundaryTests(unittest.TestCase):
    """Credential-bearing state must never be written to a delivery Gist."""

    def store(self, remote):
        """Return a private state store using the in-memory GitHub fixture."""
        return publication.PrivateStateStore("fixture/state", "state-token", remote)

    def env(self, directory):
        """Return a complete offline publication environment without real secrets."""
        return {"SUBSTORE_BASE": "https://fixture.invalid/private", "PROBE_OUTPUT_DIR": directory,
                "PROBE_FRONT_SUB": "", "PROBE_STATE_REPO": "fixture/state",
                "PROBE_STATE_TOKEN": "state-token", "GIST_ID": "abc123", "GIST_TOKEN": "gist-token"}

    def measure(self, graph, roots):
        """Return successful trace evidence without contacting a real proxy."""
        return [probe.Measurement(root, "8.8.8.8", "US") for root in roots], 0, 0

    def test_state_and_delivery_are_separate_and_authenticated(self):
        """Run the real pipeline and inspect every simulated mutation destination."""
        remote = GitHubFixture()
        with tempfile.TemporaryDirectory() as directory:
            code, summary = probe.run(self.env(directory), remote, self.measure)
        self.assertEqual(code, 0, summary)
        self.assertEqual(set(remote.patches[0]), {"mihomo-alive.yaml"})
        state = json.loads(remote.state)["files"]
        self.assertIn("manifest.json", state)
        self.assertIn(probe.source_file("fixture-source"), state)
        self.assertNotIn("fixture-source", remote.files["mihomo-alive.yaml"])
        self.assertNotIn("original-label", remote.files["mihomo-alive.yaml"])
        self.assertIn("fixture-connection-secret", remote.files["mihomo-alive.yaml"])
        self.assertNotIn("fixture-connection-secret", json.dumps(summary))
        for method, url, headers, _ in remote.calls:
            if "/repos/" in url:
                self.assertEqual(headers["Authorization"], "Bearer state-token")
                if method == "PUT":
                    self.assertEqual(headers["Content-Type"], "application/json")
            elif "/gists/" in url:
                self.assertEqual(headers["Authorization"], "Bearer gist-token")

    def test_legacy_only_configuration_fails_before_fetching_or_writing(self):
        """A missing private backend must never silently restore legacy publication."""
        remote = GitHubFixture()
        with tempfile.TemporaryDirectory() as directory:
            env = self.env(directory)
            env.pop("PROBE_STATE_REPO")
            env.pop("PROBE_STATE_TOKEN")
            code, summary = probe.run(env, remote, self.measure)
        self.assertEqual(code, 2)
        self.assertEqual(summary["error_code"], "state_config_missing")
        self.assertEqual(remote.calls, [])

    def test_public_repository_or_mixed_gist_fails_preflight(self):
        """Reject two common unsafe migration configurations without any writes."""
        for unsafe in ("public_repository", "mixed_gist", "public_gist"):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as directory:
                remote = GitHubFixture()
                if unsafe == "public_repository":
                    remote.is_private = False
                elif unsafe == "mixed_gist":
                    remote.files["manifest.json"] = "{}"
                else:
                    remote.is_public_gist = True
                code, summary = probe.run(self.env(directory), remote, self.measure)
                self.assertEqual(code, 2)
                self.assertEqual(summary["phase"], "publication_preflight")
                self.assertEqual(remote.puts, [])
                self.assertEqual(remote.patches, [])

    def test_stale_state_version_is_rejected_server_side(self):
        """An update between the final read and PUT cannot overwrite other state."""
        remote = GitHubFixture()
        store = self.store(remote)
        store.save({"manifest.json": "{}"}, None)
        _, version = store.current()
        other = self.store(remote)
        other.save({"manifest.json": '{"other":true}'}, version)
        with self.assertRaisesRegex(publication.PublicationError, "^state_conflict$"):
            store.save({"manifest.json": '{"stale":true}'}, version)

    def test_large_contents_response_uses_authenticated_blob_api(self):
        """Handle GitHub's encoding=none response without following download URLs."""
        remote = GitHubFixture()
        store = self.store(remote)
        files = {"manifest.json": "{}", "mihomo-alive.yaml": "proxies: []\n"}
        store.save(files, None)
        remote.use_blob = True
        self.assertEqual(store.current()[0], files)
        self.assertTrue(any("/git/blobs/" in call[1] for call in remote.calls))
        contents_get = next(call for call in remote.calls
                            if call[0] == "GET" and "/contents/" in call[1])
        self.assertEqual(contents_get[2]["Accept"], "application/vnd.github.object+json")

    def test_lost_put_response_does_not_advance_a_failure_twice(self):
        """A retry of one measured round must consume only one grace round."""
        remote = GitHubFixture()
        graph = probe.Graph({"proxies": [make_node("n")]})
        content, count = probe.source_output("source", graph, [probe.Measurement("n", "8.8.8.8", "US")])
        initial = probe.SourceResult("source", 1, 1, count, content, measured=1)
        probe.StatePublisher(self.store(remote)).publish([initial])
        dead = probe.SourceResult("source", 1, 0, 0, "proxies: []\n", measured=1)
        remote.ambiguous_put = True
        _, files = probe.StatePublisher(self.store(remote)).publish([dead])
        entry = json.loads(files["manifest.json"])["sources"][probe.source_file("source")]
        self.assertEqual(entry["bad_streak"], 1)
        self.assertIn(probe.source_file("source"), files)

    def test_lost_put_response_after_another_writer_does_not_advance_grace_twice(self):
        """Retain retry identity when a different source commits between PUT retries."""
        remote = GitHubFixture()
        graph = probe.Graph({"proxies": [make_node("n")]})
        content, count = probe.source_output("source", graph, [probe.Measurement("n", "8.8.8.8", "US")])
        initial = probe.SourceResult("source", 1, 1, count, content, measured=1)
        probe.StatePublisher(self.store(remote)).publish([initial])
        other_graph = probe.Graph({"proxies": [make_node("other", server="other.invalid")]})
        content, count = probe.source_output("other", other_graph, [probe.Measurement("other", "1.1.1.1", "AU")])
        other = probe.SourceResult("other", 1, 1, count, content, measured=1)
        has_interleaved = False

        def lose_response(method, url, headers=None, body=None):
            """Commit A, commit B, then lose A's response before the transport retries."""
            nonlocal has_interleaved
            response = remote(method, url, headers, body)
            if method == "PUT" and not has_interleaved:
                has_interleaved = True
                probe.StatePublisher(self.store(remote)).publish([other])
                raise probe.ProbeError("transport_failure")
            return response

        transport = probe.Transport(sleep=lambda _: None)
        transport.once = lose_response
        dead = probe.SourceResult("source", 1, 0, 0, "proxies: []\n", measured=1)
        _, files = probe.StatePublisher(self.store(transport)).publish([dead])
        state = json.loads(files["manifest.json"])["sources"][probe.source_file("source")]
        self.assertEqual(state["bad_streak"], 1)
        self.assertEqual(state["guard"], "zero_alive")
        self.assertIn(probe.source_file("source"), files)
        self.assertIn(probe.source_file("other"), files)
        self.assertEqual(len(remote.puts), 3)

    def test_delivery_failure_preserves_state_and_recovers_on_next_round(self):
        """A failed Gist PATCH cannot lose private state or falsely report success."""
        remote = GitHubFixture()
        remote.fail_delivery = True
        with tempfile.TemporaryDirectory() as directory:
            code, summary = probe.run(self.env(directory), remote, self.measure)
            self.assertEqual(code, 2)
            self.assertEqual(summary["publication"], "pending_delivery")
            self.assertIsNotNone(remote.state)
            remote.fail_delivery = False
            code, summary = probe.run(self.env(directory), remote, self.measure)
        self.assertEqual(code, 0, summary)
        self.assertEqual(len(remote.puts), 1)
        self.assertEqual(len(remote.patches), 1)

    def test_delivery_removes_source_annotations_but_keeps_required_credentials(self):
        """Sanitization must retain working chains while removing source metadata."""
        document = {"proxies": [make_node("__front-sourcehash", server="front.invalid"),
                                 make_node("node", source="source-secret", description="upstream-url",
                                           **{"dialer-proxy": "__front-sourcehash"})],
                    "manifest": {"source": "private"}}
        delivered = probe.delivery_content(probe.canonical(document))
        parsed = yaml.safe_load(delivered)
        self.assertEqual(set(parsed), {"proxies"})
        self.assertNotIn("sourcehash", delivered)
        self.assertNotIn("source-secret", delivered)
        self.assertNotIn("upstream-url", delivered)
        self.assertIn("fixture-connection-secret", delivered)
        probe.Graph(parsed).closure([node["name"] for node in parsed["proxies"]])

    def test_private_state_rejects_a_tampered_blob(self):
        """A response with a different payload and Git SHA must fail before planning."""
        remote = GitHubFixture()
        store = self.store(remote)
        store.save({"manifest.json": "{}"}, None)
        entry = remote.blob()
        entry["content"] = base64.b64encode(b'{"version":1,"files":{}}').decode()
        with self.assertRaisesRegex(publication.PublicationError, "^state_invalid$"):
            store._decode(entry, remote.version())

    def test_shared_fronts_from_separate_sources_remain_unique_in_delivery(self):
        """Removing source namespaces must not introduce duplicate kernel node names."""
        document = {"proxies": [make_node("__front-source-one", server="front.invalid"),
                                 make_node("__front-source-two", server="front.invalid"),
                                 make_node("first", server="first.invalid", **{"dialer-proxy": "__front-source-one"}),
                                 make_node("second", server="second.invalid", **{"dialer-proxy": "__front-source-two"})]}
        parsed = yaml.safe_load(probe.delivery_content(probe.canonical(document)))
        self.assertEqual(len(parsed["proxies"]), 3)
        probe.Graph(parsed).closure([node["name"] for node in parsed["proxies"]])


class HttpsAndProcessTests(unittest.TestCase):
    """Enforce encrypted fetches and isolated local child processes."""

    def test_insecure_or_malformed_urls_fail_without_transport_calls(self):
        """Reject HTTP, embedded credentials, control characters and invalid ports."""
        for url in ("http://example.invalid/private", "https://u:p@example.invalid/private",
                    "https://example.invalid/private#fragment", "https://example.invalid:bad/path",
                    "https://example.invalid/path\n"):
            with self.subTest(url=url):
                transport = mock.Mock()
                with self.assertRaises(probe.ProbeError):
                    probe.SubStore(url, transport)
                transport.assert_not_called()
        store = probe.SubStore("https://example.invalid/private", mock.Mock(),
                               {"source": {"url": "http://example.invalid/source"}})
        with self.assertRaises(probe.ProbeError):
            store.config("source")
        store.transport.assert_not_called()

    def test_transport_rejects_cross_origin_source_redirect_before_forwarding_credentials(self):
        """A source redirect cannot send its Authorization header to another host."""
        transport = probe.Transport(retries=0)
        redirect = probe.urllib.error.HTTPError("https://source.invalid/sub", 302, "redirect",
                                               {"Location": "http://other.invalid/sub"}, None)
        with mock.patch.object(transport.opener, "open", side_effect=redirect) as opener:
            with self.assertRaisesRegex(probe.ProbeError, "^upstream_redirect$"):
                transport("GET", "https://source.invalid/sub", {"Authorization": "source-token"})
        self.assertEqual(opener.call_count, 1)

    def test_missing_curl_certificate_metadata_is_not_verified(self):
        """A blank or truncated write-out cannot supply positive TLS evidence."""
        self.assertEqual(probe.NativeProbe.negotiation(b""), (False, "", 0))
        self.assertEqual(probe.NativeProbe.negotiation(b"2"), (False, "", 0))

    def test_local_children_do_not_inherit_tokens_proxy_settings_or_ssh_agents(self):
        """Validation and trace commands inherit only the existing process essentials."""
        environment = {"PATH": "fixture-path", "TEMP": "fixture-temp",
                       "GIST_TOKEN": "private-token", "PROBE_STATE_TOKEN": "private-state",
                       "SOURCE_SECRETS_JSON": "private-source", "SSH_AUTH_SOCK": "private-agent",
                       "PROBE_V6_SSH_KEY": "private-key", "HTTPS_PROXY": "private-proxy"}
        local = probe.NativeProbe("mihomo", ipv6=True)
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
                os.environ, environment, clear=True), mock.patch.object(
                probe.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=b"")) as run:
            self.assertTrue(local.validate(directory, {"proxies": []}))
            self.assertIsNone(local.trace(12345, directory))
        self.assertEqual([call.args[0][0] for call in run.call_args_list], ["mihomo", "curl"])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"], {"PATH": "fixture-path", "TEMP": "fixture-temp"})

    def test_native_ipv6_result_keeps_external_front_dependencies(self):
        """Successful runner measurements retain the exact front dependency closure."""
        config = {"proxies": [make_node("target", server="2606:4700::1111",
                                        **{"dialer-proxy": "front"})]}
        front = {"proxies": [make_node("front", server="front.invalid"), make_node("unused")]}
        local = probe.NativeProbe("mihomo", ipv6=True)
        evidence = [(("8.8.8.8", "US", "2", 20), 0)]
        with mock.patch.object(local, "validate", return_value=True), mock.patch.object(
                local, "_run_kernel", return_value=(evidence, False, set())):
            result = probe.measure_source("source", config, front, local)
        self.assertFalse(result.failed)
        self.assertEqual(result.published, 1)
        document = yaml.safe_load(result.content)
        self.assertEqual(len(document["proxies"]), 2)
        self.assertNotIn("unused", json.dumps(document))


class OfflineGeoAndConcurrencyTests(unittest.TestCase):
    """Remove online lookup latency and bound load on shared physical entries."""

    def test_main_path_never_calls_online_geo_even_when_lookup_flag_is_on(self):
        """A local ASN hit supplies the brand while all online providers are forbidden."""
        geo_naming.RESOLVER.clear()
        with mock.patch.object(geo_naming, "LOOKUP_ON", True), mock.patch.object(
                geo_naming, "_ASN_DB_PATH_WANTED", return_value=True), mock.patch.object(
                geo_naming._ASN_DB, "load"), mock.patch.object(
                geo_naming._ASN_DB, "lookup", return_value=(13335, "Cloudflare")), mock.patch.object(
                geo_naming.urllib.request, "urlopen", side_effect=AssertionError("online lookup")):
            probe._prefetch_geo([probe.Measurement("n", "1.1.1.1", "AU")])
        entry = geo_naming.RESOLVER.entry("1.1.1.1")
        self.assertEqual(entry["asn"], 13335)
        self.assertEqual(entry["org"], "Cloudflare")
        geo_naming.RESOLVER.clear()

    def test_offline_geo_accepts_fresh_cache_and_ignores_expired_cache(self):
        """Local enrichment must validate cache age and reject stale location data."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "geo.json"
            entry = dict(geo_naming._blank("US"), city="Example", org="Example", asn=64500)
            path.write_text(json.dumps({"version": 1, "updated_at": time.time(),
                                        "entries": {"8.8.8.8": entry}}), encoding="utf-8")
            self.assertEqual(geo_naming.load_geo_cache(path)["8.8.8.8"]["city"], "Example")
            path.write_text(json.dumps({"version": 1, "updated_at": 0,
                                        "entries": {"8.8.8.8": entry}}), encoding="utf-8")
            self.assertEqual(geo_naming.load_geo_cache(path), {})

    def test_enrichment_cannot_downgrade_https_or_forward_to_another_origin(self):
        """The optional cache utility must not reintroduce plaintext HTTP lookups."""
        request = geo_naming.urllib.request.Request("https://geo.invalid/query")
        handler = geo_naming.GeoRedirect()
        for url in ("http://geo.invalid/query", "https://other.invalid/query"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "redirect", {}, url)

    def test_worker_budget_scales_down_without_raising_the_configured_ceiling(self):
        """Small rounds and repeated entry hosts must use fewer workers than large rounds."""
        self.assertEqual(choose_workers(1, 64, ["entry"]), 1)
        self.assertLess(choose_workers(10, 64, list(range(10))), 64)
        self.assertEqual(choose_workers(1355, 64, list(range(1355))), 64)
        self.assertEqual(choose_workers(1355, 64, ["shared"] * 1355), 8)
        self.assertEqual(choose_workers(1355, 24, list(range(1355))), 24)
        self.assertEqual(interleave_endpoints([0, 1, 2, 3], ["a", "a", "b", "b"]), [0, 2, 1, 3])

    def test_endpoint_limiter_caps_parallel_dials_and_releases_after_exception(self):
        """Real threads must respect the cap and exceptions must return permits."""
        limiter = EndpointLimiter(["shared"], 2)
        active, peak = 0, 0
        lock = threading.Lock()

        def dial():
            """Simulate a short I/O operation and track simultaneous entry use."""
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.005)
            with lock:
                active -= 1

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(lambda _: limiter.call("shared", dial), range(32)))
        self.assertEqual(peak, 2)
        with self.assertRaises(ValueError):
            limiter.call("shared", lambda: (_ for _ in ()).throw(ValueError()))
        self.assertEqual(limiter.call("shared", lambda: "released"), "released")

    def test_first_entry_uses_front_and_ignores_port_multiplexing(self):
        """Different backend nodes behind one front must share an entry-host limit."""
        graph = probe.Graph({"proxies": [make_node("front", server="FRONT.invalid."),
                                         make_node("target", **{"dialer-proxy": "front"})]})
        self.assertEqual(graph.entry_host("target"), "front.invalid")


class MigrationAndCacheToolTests(unittest.TestCase):
    """Verify migration preserves policy state and cache tooling stays private."""

    def test_migration_is_dry_by_default_idempotent_and_never_writes_the_old_gist(self):
        """Validate, copy and re-read a baseline without changing its failure counters."""
        tool = load_tool("migrate_private_state")
        remote = GitHubFixture()
        graph = probe.Graph({"proxies": [make_node("n")]})
        text, count = probe.source_output("source", graph, [probe.Measurement("n", "8.8.8.8", "US")])
        result = probe.SourceResult("source", 1, 1, count, text, measured=1)
        remote.legacy_files = probe.plan_updates([result], {})
        env = {"LEGACY_GIST_ID": "def456", "GIST_TOKEN": "legacy-token",
               "PROBE_STATE_REPO": "fixture/state", "PROBE_STATE_TOKEN": "state-token"}
        self.assertEqual(tool.migrate(env, remote)["migration"], "validated")
        self.assertIsNone(remote.state)
        self.assertEqual(tool.migrate(env, remote, apply=True)["migration"], "copied")
        self.assertEqual(json.loads(remote.state)["files"], remote.legacy_files)
        self.assertEqual(tool.migrate(env, remote, apply=True)["migration"], "no_change")
        self.assertEqual(len(remote.puts), 1)
        self.assertEqual(remote.patches, [])

    def test_migration_refuses_to_replace_a_different_existing_state(self):
        """An incorrect destination must not overwrite an established private baseline."""
        tool = load_tool("migrate_private_state")
        remote = GitHubFixture()
        remote.legacy_files = {"manifest.json": '{"sources":{}}', "mihomo-alive.yaml": "proxies: []\n"}
        publication.PrivateStateStore("fixture/state", "state-token", remote).save(
            {"manifest.json": '{"already":"present"}'}, None)
        env = {"LEGACY_GIST_ID": "def456", "GIST_TOKEN": "legacy-token",
               "PROBE_STATE_REPO": "fixture/state", "PROBE_STATE_TOKEN": "state-token"}
        with self.assertRaisesRegex(publication.PublicationError, "^state_migration_existing$"):
            tool.migrate(env, remote, apply=True)
        self.assertEqual(len(remote.puts), 1)

    def test_enrichment_cache_is_written_as_a_private_file_without_publishing(self):
        """Mock provider work and inspect the standalone tool's cache/file permissions."""
        tool = load_tool("enrich_geo_cache")
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "exits.json", Path(directory) / "geo-cache.json"
            source.write_text('[{"ip":"8.8.8.8","cc":"US"}]', encoding="utf-8")
            with mock.patch.object(tool.geo_naming, "prefetch"), mock.patch.object(
                    tool.geo_naming, "LOOKUP_ON", False), mock.patch.object(
                    publication.PrivateStateStore, "save", side_effect=AssertionError("publication")):
                self.assertEqual(tool.enrich(source, destination), 1)
            self.assertIn("8.8.8.8", json.loads(destination.read_text())["entries"])
            if os.name != "nt":
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
