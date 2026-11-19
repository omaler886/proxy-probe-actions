#!/usr/bin/env python3
"""End-to-end policy harness for the Actions probe, runnable on any host.

Drives the real ``run()`` entry point against a stub Sub-Store transport and a
stub probe so the failure policy, the artifact deletion and the merged rebuild
are exercised without network, kernel or credentials. This is the LXC-side
acceptance test: it proves the Linux runtime takes the same decisions the unit
tests assert on Windows.

Scenarios (each starts from a clean Gist):
  1-3. baseline -> one bad round -> grace round   (node-level cleanup)
  4.   a round where every source is dead aborts before publishing
  5.   v6-bound nodes on an IPv4-only host are unverifiable, never dropped
  6.   a severely reduced source shrinks only on the second consecutive round
"""
import json
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import actions_probe_all as probe  # noqa: E402

import yaml  # noqa: E402

FAILURES = []


def check(label, got, want):
    if got != want:
        FAILURES.append("%s: got %r want %r" % (label, got, want))
        print("  FAIL %-52s got=%r want=%r" % (label, got, want))
    else:
        print("  ok   %-52s %r" % (label, got))


class Gist:
    """Minimal stand-in for the Gist API: GET snapshot, PATCH files."""

    def __init__(self, files=None):
        self.files = dict(files or {})

    def __call__(self, method, url, headers=None, body=None):
        if method == "PATCH":
            for key, entry in json.loads(body)["files"].items():
                if entry is None or entry.get("content") is None:
                    self.files.pop(key, None)
                else:
                    self.files[key] = entry["content"]
            return b"{}", {}
        if url.startswith("https://gist.githubusercontent.com/"):
            return self.files[url.rsplit("/", 1)[-1]].encode(), {}
        payload = {k: {"content": v, "truncated": False,
                       "raw_url": "https://gist.githubusercontent.com/raw/" + k}
                   for k, v in self.files.items()}
        return json.dumps({"public": False, "files": payload}).encode(), {}


def node(name, server):
    return {"name": name, "type": "ss", "server": server, "port": 443,
            "cipher": "aes-128-gcm", "password": "x"}


class Harness:
    """One source group, one Gist, N rounds."""

    def __init__(self, name, sources, probe_fn, servers=None):
        self.name = name
        self.sources = list(sources)
        self.probe_fn = probe_fn
        self.gist = Gist()
        self.servers = dict(servers or {})

    def transport(self, method, url, headers=None, body=None):
        if url.endswith("/api/subs"):
            return json.dumps({"data": [{"name": n} for n in self.sources]}).encode(), {}
        if "/download/" in url:
            quoted = url.split("/download/", 1)[1].split("?", 1)[0]
            source = urllib.parse.unquote(quoted)
            # One distinct node per source: identical servers would collapse
            # into a single merged node through the connection fingerprint.
            server = self.servers.get(source, source + ".invalid")
            return probe.canonical({"proxies": [node(source + "-node", server)]}).encode(), {}
        return self.gist(method, url, headers, body)

    def run_round(self):
        env = {"SUBSTORE_BASE": "https://fixture.invalid/private",
               "PROBE_OUTPUT_DIR": "/tmp/harness-out-%s" % self.name,
               "GIST_TOKEN": "fixture", "GIST_ID": "abc123",
               "PROBE_FRONT_SUB": ""}
        return probe.run(env, self.transport, self.probe_fn)

    def manifest(self):
        return json.loads(self.gist.files.get("manifest.json", "{}")).get("sources", {})

    def entry(self, source):
        return self.manifest().get(probe.source_file(source), {})

    def merged(self):
        text = self.gist.files.get("mihomo-alive.yaml", "proxies: []\n")
        return yaml.safe_load(text).get("proxies") or []

    def dropped(self, source):
        return probe.source_file(source) not in self.gist.files


def scenario(title):
    print("\n=== %s ===" % title)


STATE = {"alive": set()}


def probe_stateful(graph, roots):
    """Alive set is driven by STATE (names of nodes that measure alive)."""
    live = [r for r in roots if r in STATE["alive"]]
    return ([probe.Measurement(r, "8.8.8.%d" % (i + 1), "US") for i, r in enumerate(live)],
            0, 0)


def probe_none(graph, roots):
    """Every root dialled and failed."""
    return [], 0, 0


def probe_v6blind(graph, roots):
    """Every root needs IPv6 and this host cannot reach it."""
    return [], 0, len(roots)


def probe_one(graph, roots):
    """Only the first root survives: a severe reduction."""
    return ([probe.Measurement(roots[0], "9.9.9.1", "US")], len(roots) - 1, 0)


def main():
    # --- 1-3: baseline, one bad round, grace round -------------------------
    scenario("1-3 baseline -> one bad round -> grace round (node-level cleanup)")
    names = ["s-alpha", "s-beta", "s-gamma"]
    h = Harness("policy", names, probe_stateful)
    STATE["alive"] = set(n + "-node" for n in names)
    code, _ = h.run_round()
    check("round1 exit", code, 0)
    check("round1 source artifacts", len([k for k in h.gist.files if k.startswith("source-")]), 3)
    check("round1 merged nodes", len(h.merged()), 3)

    STATE["alive"] = {"s-alpha-node", "s-beta-node"}      # gamma dies
    code, _ = h.run_round()
    check("round2 exit", code, 0)
    check("round2 gamma kept", h.dropped("s-gamma"), False)
    check("round2 gamma guard", h.entry("s-gamma").get("guard"), "zero_alive")
    check("round2 gamma streak", h.entry("s-gamma").get("bad_streak"), 1)
    check("round2 merged still 3", len(h.merged()), 3)

    code, _ = h.run_round()                              # 2nd consecutive death
    check("round3 exit", code, 0)
    check("round3 gamma dropped", h.dropped("s-gamma"), True)
    check("round3 gamma guard", h.entry("s-gamma").get("guard"), "confirmed_dead")
    check("round3 gamma baseline", h.entry("s-gamma").get("last_success_alive"), 0)
    check("round3 merged nodes", len(h.merged()), 2)

    # --- 4: global failure aborts before publishing ------------------------
    scenario("4 every source dead aborts before publish")
    h2 = Harness("allfail", ["s1", "s2"], probe_none)
    seed = probe.plan_updates([probe.SourceResult("s1", 1, 1, 1,
                                                  probe.canonical({"proxies": [node("s1-node", "s1.invalid")]}),
                                                  measured=1)], {})
    h2.gist.files.update(seed)
    code, summary = h2.run_round()
    check("all-dead exit", code, 2)
    check("all-dead abort code", summary.get("error_code"), "no_successful_roots")
    check("all-dead artifacts untouched", len([k for k in h2.gist.files if k.startswith("source-")]), 1)

    # --- 5: v6-bound nodes on an IPv4-only host ----------------------------
    scenario("5 a v6 artifact survives probing from an IPv4-only host")
    h3 = Harness("v6blind", ["s-v6", "s-ok"], probe_none,
                 servers={"s-v6": "2606:4700:4700::1111"})

    def probe_mixed(graph, roots):
        live, invalid, blind = [], 0, 0
        for root in roots:
            if graph.v6_bound(root) and not HOST_IPV6[0]:
                blind += 1            # what NativeProbe does on an IPv4 host
                continue
            live.append(probe.Measurement(root, "8.8.4.4", "US"))
        return live, invalid, blind
    HOST_IPV6 = [True]

    # Seed: the v6 artifact was published while the probe ran on a host that
    # could actually reach IPv6. It must survive a round that cannot judge it.
    cfg6 = {"proxies": [node("s-v6-node", "2606:4700:4700::1111")]}
    g6 = probe.Graph(cfg6)
    text6, published6 = probe.source_output(
        "s-v6", g6, [probe.Measurement("s-v6-node", "2001:470:4892:ff69::185", "HK")])
    h3.gist.files.update(probe.plan_updates(
        [probe.SourceResult("s-v6", 1, 1, published6, text6, measured=1)], {}))
    check("v6 seed has an artifact", probe.source_file("s-v6") in h3.gist.files, True)

    h3.probe_fn = probe_mixed
    HOST_IPV6[0] = False
    for _ in range(3):
        code, summary = h3.run_round()
    check("v6 exit", code, 0)
    check("v6 artifact survives 3 blind rounds", h3.dropped("s-v6"), False)
    check("v6 streak stays 0", h3.entry("s-v6").get("bad_streak"), 0)
    check("v6 guard", h3.entry("s-v6").get("guard"), "unverifiable")
    check("v6 nodes stay in merged",
          len([n for n in h3.merged() if "2606:4700" in str(n.get("server"))]), 1)
    check("v6 healthy source kept publishing", h3.dropped("s-ok"), False)
    # The same source on an IPv6-capable host is measured again, not skipped.
    HOST_IPV6[0] = True
    code, summary = h3.run_round()
    check("v6-capable host measures it", h3.entry("s-v6").get("alive"), 1)
    check("v6-capable host guard", h3.entry("s-v6").get("guard"), "accepted")

    # --- 6: severely reduced twice ----------------------------------------
    scenario("6 severe reduction shrinks only on the second round")
    cfg = {"proxies": [node("s-big-node%d" % i, "big%d.invalid" % i) for i in range(6)]}
    graph = probe.Graph(cfg)
    text, published = probe.source_output(
        "s-big", graph,
        [probe.Measurement("s-big-node%d" % i, "9.9.9.%d" % i, "US") for i in range(6)])
    h4 = Harness("degraded", ["s-big"], probe_one)
    h4.gist.files.update(probe.plan_updates(
        [probe.SourceResult("s-big", 6, 6, published, text, measured=6)], {}))
    check("degraded seed merged", len(h4.merged()), 6)
    code, _ = h4.run_round()
    check("degraded round1 keeps 6", len(h4.merged()), 6)
    check("degraded round1 streak", h4.entry("s-big").get("bad_streak"), 1)
    code, _ = h4.run_round()
    check("degraded round2 shrinks to 1", len(h4.merged()), 1)
    check("degraded round2 guard", h4.entry("s-big").get("guard"), "degraded")

    print()
    if FAILURES:
        print("RESULT: FAIL (%d)" % len(FAILURES))
        for item in FAILURES:
            print("  - " + item)
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())