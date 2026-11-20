#!/usr/bin/env python3
"""Measure IPv6-bound nodes on a host that actually has IPv6.

Run on a v6-capable host (the NAT LXC pool's test machine). The driver ships a
JSON job on STDIN and gets JSON results on STDOUT, so no port, service or
credential is exposed beyond the SSH session that invoked it.

Why this exists: GitHub-hosted runners are IPv4-only, so a node whose server is
an IPv6 literal can never be dialled there. The node is not dead -- it is
unmeasurable from that host. This worker runs the SAME probe code and the SAME
trace contract on a host with a real global IPv6 route, so those nodes get a
real verdict instead of being dropped.

Job (STDIN):
  {"timeout": 15, "workers": 4, "mihomo": "/usr/local/bin/mihomo",
   "jobs": [{"source": "fe", "config": {...}, "roots": ["name", ...]}]}

Result (STDOUT):
  {"host_ipv6": true,
   "results": {"fe": {"name": {"alive": true, "ip": "...", "cc": "HK"}}},
   "judged": {"fe": 22}, "errors": []}

``judged`` counts nodes this host actually dialled (alive or dead). A node that
was dialled and failed is PROVEN DEAD; a node this host could not dial either
stays unverifiable upstream. The payload carries subscription credentials: it
is staged into a private (0600) temporary directory on this host only for the
duration of each kernel validation or dial, and deleted immediately after; it
is never written anywhere else and never printed.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import actions_probe_all as probe  # noqa: E402


def main():
    try:
        job = json.load(sys.stdin)
    except ValueError:
        print(json.dumps({"host_ipv6": False, "results": {}, "judged": {},
                          "errors": ["job_invalid"]}))
        return 2
    if not isinstance(job, dict):
        print(json.dumps({"host_ipv6": False, "results": {}, "judged": {},
                          "errors": ["job_invalid"]}))
        return 2

    capable = probe.host_ipv6_capable()
    out = {"host_ipv6": capable, "results": {}, "judged": {}, "errors": []}
    if not capable:
        # Nothing to add: the caller keeps those nodes unverifiable.
        print(json.dumps(out, ensure_ascii=False))
        return 0

    runner = probe.NativeProbe(
        job.get("mihomo") or "/usr/local/bin/mihomo",
        job.get("workers") or 4,
        job.get("timeout") or 15,
        ipv6=True,
    )
    prepared = []
    for item in job.get("jobs") or []:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source") or "")
        roots = [name for name in (item.get("roots") or []) if isinstance(name, str)]
        out["results"].setdefault(source, {})
        out["judged"].setdefault(source, 0)
        try:
            config = item.get("config") or {}
            graph = probe.Graph(probe.dedupe_names(config))
        except probe.ProbeError as exc:
            out["errors"].append("%s:%s" % (source, probe.error_code(exc)))
            continue
        except Exception as exc:  # noqa: BLE001 - never leak text, only the class
            out["errors"].append("%s:%s" % (source, type(exc).__name__))
            continue
        prepared.append(probe.SourceJob(source, config, graph, roots, set(), False))
    # One kernel for every source's v6 roots instead of one per source: the
    # fixed startup cost dominated the helper's wall time (38 starts for 314
    # nodes). measure_jobs falls back per source if the shared kernel fails.
    try:
        outcomes = runner.measure_jobs(prepared) if prepared else []
    except Exception as exc:  # noqa: BLE001
        out["errors"].extend("%s:%s" % (item.name, type(exc).__name__) for item in prepared)
        outcomes = []
    for item, outcome in zip(prepared, outcomes):
        source = item.name
        if not outcome:
            out["errors"].append("%s:probe_error" % source)
            continue
        measured, invalid, unverifiable = outcome[:3]
        for item_measured in measured:
            out["results"][source][item_measured.name] = {
                "alive": True,
                "ip": item_measured.ip,
                "cc": item_measured.cc,
                "delay_ms": item_measured.delay_ms,
            }
        # Roots the kernel refused or that stayed unverifiable were not
        # judged; everything else was dialled and simply did not come back.
        out["judged"][source] = max(0, len(item.roots) - invalid - unverifiable)
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())