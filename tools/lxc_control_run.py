#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LXC control group: naming/dedup logic only, NO SubStore write, NO Gist push.

Input : control-pkg/alive.yaml (the exact node set Actions published)
Output: /tmp/control-result.json  (naming quality metrics)

Read-only guarantees:
  * We never import/call run(), plan_updates(), GistPublisher, or SubStore.
  * Only source_output() + audit.audit() are used, both pure functions of input.
  * GIST_TOKEN / SUBSTORE_BASE are explicitly unset so even an accidental
    publish path would fail closed.
"""
import io
import json
import os
import sys
import tempfile
import importlib.util
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

# --- read-only guard: remove any credential that could enable a write --------
for key in ("GIST_TOKEN", "GITHUB_TOKEN", "SUBSTORE_BASE", "GIST_ID"):
    os.environ.pop(key, None)
assert not os.environ.get("GIST_TOKEN") and not os.environ.get("SUBSTORE_BASE")

BASE = Path("/tmp/control-pkg")
sys.path.insert(0, str(BASE))

# !!! Set env BEFORE importing any module. actions_probe_all imports its own
# geo_naming instance; patching one module object would not affect the other.
os.environ["PROBE_GEO_LOOKUP"] = "1"
os.environ["PROBE_ASN_CSV"] = str(BASE / "asn.csv.gz")

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

p = load("ap", BASE / "actions_probe_all.py")
geo = load("geo_naming", BASE / "geo_naming.py")
a = load("audit", BASE / "audit_artifacts.py")

import yaml

# Both module instances now read LOOKUP_ON=True from the environment. Point
# p's own geo_naming at the local DB too (the one actions_probe_all imported).
p_geo = sys.modules["geo_naming"]  # imported by actions_probe_all
p_geo.LOOKUP_ON = True
p_geo._ASN_DB = p_geo.AsnDb(str(BASE / "asn.csv.gz"))
p_geo._ASN_DB.load()
p_geo._ASN_DB_PATH_WANTED = lambda: True
# Also keep our direct handle in sync (used by nothing critical, but consistent).
geo = p_geo

doc = yaml.safe_load((BASE / "alive.yaml").read_text(encoding="utf-8"))

# Build one measurement per node. Use the node's server as its "egress" so all
# environments consume identical inputs; only naming/dedup differs by version.
nodes = [n for n in doc.get("proxies", [])
         if isinstance(n, dict) and isinstance(n.get("name"), str)
         and not n["name"].startswith("__front")]
servers = []
for n in nodes:
    s = str(n.get("server", ""))
    if s and (s[0].isdigit() or ":" in s):
        servers.append(s)
seen, uniq = set(), []
for s in servers:
    k = p.egress_key(s)
    if k not in seen:
        seen.add(k)
        uniq.append(s)

proxies = [{"name": "n%d" % i, "type": "ss", "server": "s%d.invalid" % i,
            "port": 443, "cipher": "aes-128-gcm", "password": "x"}
           for i in range(len(uniq))]
graph = p.Graph({"proxies": proxies})
measurements = [p.Measurement("n%d" % i, ip, "US") for i, ip in enumerate(uniq)]

geo.prefetch([(ip, "US") for ip in uniq])
text, published = p.source_output("lxc-control", graph, measurements)

# Audit through a temp local dir (no network, no Gist).
with tempfile.TemporaryDirectory() as d:
    out = Path(d)
    sf = p.source_file("lxc-control")
    (out / "manifest.json").write_text(
        json.dumps({"sources": {sf: {"name": "lxc-control"}}}), encoding="utf-8")
    (out / sf).write_text(text, encoding="utf-8")
    (out / "mihomo-alive.yaml").write_text(text, encoding="utf-8")
    artifacts = a.Artifacts("lxc", directory=d).load()
    report = a.audit(artifacts)

result = {
    "env": {
        "host": "lxc5/ct185",
        "egress": "NTT LA (<NTT_LA_EGRESS>)",
        "python": sys.version.split()[0],
        "pyyaml": yaml.__version__,
    },
    "input": {
        "published_nodes": len(nodes),
        "unique_egress": len(uniq),
    },
    "output": {
        "published": published,
        "unique_names": report["totals"]["merged_unique_names"],
    },
    "health": report.get("health", {}),
    "defects": {k: report["totals"].get(k, 0) for k in (
        "counter_suffix_merged", "generic_brand_merged", "hash_suffix_merged",
        "duplicate_connection_occurrences", "unknown_brand")},
    "sample_names": [n["name"] for n in yaml.safe_load(text)["proxies"][:10]],
    "read_only": True,
}
Path("/tmp/control-result.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8")
print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
