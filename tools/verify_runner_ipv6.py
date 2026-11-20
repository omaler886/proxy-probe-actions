#!/usr/bin/env python3
"""Read-only smoke test of real IPv6 subscription nodes on the Actions runner."""
import ipaddress
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import actions_probe_all as probe
from ipv6_transport import check_ipv6_connectivity


def sample_jobs(store, limit=8):
    """Return bounded IPv6 node dependency closures from GET-only source downloads."""
    jobs, failures, remaining = [], 0, limit
    sources = store.sources()
    front = None
    try:
        front = store.config("cf-front")
    except Exception:
        pass  # Missing dependencies stay invalid, never rewritten as DIRECT.
    for name in sources:
        if not remaining:
            break
        try:
            config = store.config(name)
            graph = probe.Graph(config, front)
            roots = []
            for node in config.get("proxies", []):
                root = node["name"]
                if not graph.v6_bound(root):
                    continue
                graph.closure([root])
                roots.append(root)
                if len(roots) == remaining:
                    break
            if roots:
                exported = graph.export(roots)
                jobs.append(probe.SourceJob(name, exported, probe.Graph(exported), roots, set(), False))
                remaining -= len(roots)
        except Exception:
            failures += 1
    return jobs, failures


def verify(env):
    """Check public IPv6, then real node handshakes without publishing or logging credentials."""
    network = check_ipv6_connectivity()
    report = {"network": network, "sources_failed": 0, "tested": 0, "alive": 0,
              "invalid": 0, "unverifiable": 0, "protocols": {}}
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
