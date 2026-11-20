#!/usr/bin/env python3
"""Read-only smoke test of real IPv6 subscription nodes on the Actions runner."""
import ipaddress
import concurrent.futures
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import actions_probe_all as probe
from ipv6_transport import check_ipv6_connectivity


def sample_jobs(store, limit=12):
    """Select a protocol-diverse set of IPv6 roots from GET-only source downloads."""
    candidates, failures = {}, 0
    sources = store.sources()
    front = None
    try:
        front = store.config("cf-front")
    except Exception:
        pass  # Missing dependencies stay invalid, never rewritten as DIRECT.

    def fetch_source(name):
        """Return one source or a fixed failure indicator without logging URLs."""
        try:
            return name, store.config(name)
        except Exception:
            return name, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(sources) or 1)) as pool:
        fetched = list(pool.map(fetch_source, sources))
    for name, config in fetched:
        try:
            if config is None:
                failures += 1
                continue
            graph = probe.Graph(config, front)
            for node in config.get("proxies", []):
                root = node["name"]
                if not graph.v6_bound(root):
                    continue
                graph.closure([root])
                protocol = str(node.get("type", "unknown"))
                candidates.setdefault(protocol, []).append((name, graph, root))
        except Exception:
            failures += 1
    return select_jobs(candidates, limit), failures


def select_jobs(candidates, limit):
    """Round-robin protocol candidates into a bounded list of dependency-complete jobs."""
    selected = {}
    count = 0
    for index in range(limit):
        for protocol in sorted(candidates):
            if index >= len(candidates[protocol]) or count >= limit:
                continue
            source, graph, root = candidates[protocol][index]
            selected.setdefault(source, (graph, []))[1].append(root)
            count += 1
        if count >= limit:
            break
    jobs = []
    for source, (graph, roots) in selected.items():
        exported = graph.export(roots)
        jobs.append(probe.SourceJob(source, exported, probe.Graph(exported), roots, set(), False))
    return jobs


def verify(env):
    """Check public IPv6, then real node handshakes without publishing or logging credentials."""
    network = check_ipv6_connectivity()
    report = {"network": network, "sources_failed": 0, "tested": 0, "alive": 0,
              "invalid": 0, "unverifiable": 0, "protocols": {}, "tested_protocols": {}}
    if not network["ok"]:
        report["error"] = "runner_ipv6_unverified"
        return 2, report
    if not env.get("SUBSTORE_BASE", "").strip():
        report["error"] = "subscription_secret_missing"
        return 2, report
    store = probe.SubStore(env["SUBSTORE_BASE"], probe.Transport(),
                           source_secrets=probe.load_source_secrets(env))
    jobs, report["sources_failed"] = sample_jobs(store)
    if not jobs:
        report["error"] = "ipv6_nodes_not_found"
        return 2, report
    runner = probe.NativeProbe(env["MIHOMO_BIN"], workers=4, timeout=15, dedupe=True)
    runner.baseline_ip = probe.runner_exit_ip(probe.Transport())
    outcomes = runner.measure_jobs(jobs)
    for job, outcome in zip(jobs, outcomes):
        alive, invalid, unverifiable = outcome[:3]
        report["tested"] += len(job.roots)
        report["alive"] += len(alive)
        report["invalid"] += invalid
        report["unverifiable"] += unverifiable
        for root in job.roots:
            protocol = str(job.graph.nodes[root].get("type", "unknown"))
            report["tested_protocols"][protocol] = report["tested_protocols"].get(protocol, 0) + 1
        for item in alive:
            protocol = str(job.graph.nodes[item.name].get("type", "unknown"))
            report["protocols"][protocol] = report["protocols"].get(protocol, 0) + 1
            # The measured node's egress is allowed to be v4. This smoke proves
            # the entrance address was IPv6, not that every node has v6 egress.
            ipaddress.ip_address(item.ip)
    report["ok"] = report["alive"] > 0
    if not report["ok"]:
        report["error"] = "no_verified_ipv6_node"
    return (0 if report["ok"] else 2), report


def main():
    """Print aggregate evidence and return a nonzero status for any missing proof."""
    try:
        code, report = verify(dict(os.environ))
    except Exception as error:
        code, report = 2, {"ok": False, "error": probe.error_code(error)}
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
