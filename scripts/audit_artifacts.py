#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Audit the published Gist artifacts and report naming/duplication defects.

The probe workflow publishes the same fixed files every run, so the artifacts
themselves are the evidence; no screenshot or manual inspection is involved.
This tool reads them straight from the Gist and prints (or writes) a report.

    python scripts/audit_artifacts.py                      # human report
    python scripts/audit_artifacts.py --json out.json       # machine report
    python scripts/audit_artifacts.py --gist-id <id>        # another gist

Every check maps to a defect that was visible in production:

  counters          "…-2", "…-3", …  one exit republished under an ordinal
  hash_suffix       "…-39313f52"     merger disambiguation leaking into a name
  generic_brand     "香港-Hong-Hong Kong", "中国-China-Suzhou"
  unknown_brand     brand missing entirely
  duplicate_egress  the same connection published more than once per source
  unreadable_name   empty/whitespace name, or a name longer than 80 chars

Exit code is 0 when the artifacts parse; the findings themselves are reported,
never raised, so this is safe to run on a schedule.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
RAW_HOST = "gist.githubusercontent.com"
SOURCE_FILE = re.compile(r"source-[0-9a-f]{64}\.yaml\Z")
DEFAULT_GIST = "<GIST_ID>"
DEFAULT_OWNER = "omaler886"

COUNTER = re.compile(r"-(\d{1,2})\Z")
HASH_SUFFIX = re.compile(r"-[0-9a-f]{8}\Z")
BARE_AS = re.compile(r"-AS\d+\Z")
# A bare geographic or role word used as if it were the provider brand.
GENERIC_BRAND = re.compile(
    r"-(Hong|Korea|China|Japan|Taiwan|Singapore|Asia|Pacific|Global|New|The|"
    r"Telecom|Telecommunications|Network|Networks|Broadband|Communications?|"
    r"Technology|Technologies|Digital|Internet|Cloud|Hosting|Limited|Company)"
    r"(-|\Z)")
UNKNOWN_BRAND = re.compile(r"-Unknown(-|\Z)")
FLAG = re.compile("^[\U0001F1E6-\U0001F1FF]{2}")


def fetch(url, timeout=40, retries=4):
    """GET with bounded retries for rate limits and transient errors."""
    last = None
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers={
                "User-Agent": UA,
                "Accept": "application/vnd.github+json",
            })
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code not in (403, 429, 500, 502, 503, 504) or attempt == retries:
                raise
        except (urllib.error.URLError, OSError) as exc:
            last = exc
            if attempt == retries:
                raise
        time.sleep(min(8, 2 ** attempt))
    raise last


def raw_url(owner, gist_id, name):
    """A Gist raw URL needs the owner login; /raw/<id>/<file> is a 404."""
    return "https://%s/%s/%s/raw/%s" % (RAW_HOST, owner, gist_id, name)


class Artifacts:
    """All published files for one Gist.

    Two sources, in priority order:
      * a local output directory (--dir), used inside the workflow where the
        files already exist on the runner;
      * one GitHub API read of the whole Gist, then raw fetches ONLY for files
        the API marks truncated. Fetching every raw URL separately trips
        GitHub's secondary rate limit (the old approach lost 16 of 42 files).
    """

    def __init__(self, gist_id, owner=DEFAULT_OWNER, directory=None):
        self.gist_id = gist_id
        self.owner = owner
        self.directory = Path(directory) if directory else None
        self.manifest = {}
        self.merged = {}
        self.sources = {}
        self.errors = []

    def load(self):
        if self.directory:
            return self._load_local()
        return self._load_api()

    def _accept(self, name, raw):
        if name == "manifest.json":
            self.manifest = json.loads(raw)
        elif name == "mihomo-alive.yaml":
            doc = yaml.safe_load(raw)
            if isinstance(doc, dict):
                self.merged = doc
        elif SOURCE_FILE.match(name):
            doc = yaml.safe_load(raw)
            if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
                self.sources[name] = doc

    def _load_local(self):
        try:
            self._accept("manifest.json", (self.directory / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self.errors.append("manifest.json: %s" % type(exc).__name__)
        for path in sorted(self.directory.glob("*.yaml")):
            try:
                self._accept(path.name, path.read_text(encoding="utf-8"))
            except (OSError, ValueError, yaml.YAMLError) as exc:
                self.errors.append("%s: %s" % (path.name, type(exc).__name__))
        return self

    def _load_api(self):
        url = "https://api.github.com/gists/" + self.gist_id
        try:
            document = json.loads(fetch(url))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.errors.append("gist api: %s" % type(exc).__name__)
            return self
        entries = document.get("files", {})
        raw_to_fetch = []
        for name, entry in sorted(entries.items()):
            if name not in ("manifest.json", "mihomo-alive.yaml") and not SOURCE_FILE.match(name):
                continue
            content = entry.get("content")
            if entry.get("truncated") or not isinstance(content, str):
                raw_to_fetch.append((name, entry.get("raw_url", "")))
            else:
                try:
                    self._accept(name, content)
                except (ValueError, yaml.YAMLError) as exc:
                    self.errors.append("%s: %s" % (name, type(exc).__name__))
        # Only truncated files need a second request. Validate the URL host
        # before following it, so a crafted Gist response cannot redirect us.
        for name, url in raw_to_fetch:
            parts = urllib.parse.urlsplit(url)
            if parts.scheme != "https" or parts.hostname != RAW_HOST or parts.username:
                self.errors.append("%s: gist_raw_invalid" % name)
                continue
            try:
                self._accept(name, fetch(url).decode("utf-8", "replace"))
            except (urllib.error.URLError, OSError, ValueError, yaml.YAMLError) as exc:
                self.errors.append("%s: %s" % (name, type(exc).__name__))
        return self

    def source_label(self, filename):
        return (self.manifest.get("sources", {}).get(filename, {}) or {}).get("name", filename)


def connection_key(node):
    """A connection identity that ignores the display name."""
    keys = ("type", "server", "port", "uuid", "password", "cipher",
            "servername", "sni", "network", "flow", "alterId")
    return tuple(str(node.get(key, "")) for key in keys)


def audit(artifacts):
    report = {
        "gist": artifacts.gist_id,
        "sources": len(artifacts.sources),
        "merged_proxies": len(artifacts.merged.get("proxies") or []),
        "errors": list(artifacts.errors),
        "totals": collections.Counter(),
        "findings": collections.defaultdict(list),
    }
    names_by_source = {}

    for filename, doc in sorted(artifacts.sources.items()):
        label = artifacts.source_label(filename)
        nodes = [item for item in doc["proxies"]
                 if isinstance(item, dict) and isinstance(item.get("name"), str)]
        names = [item["name"] for item in nodes]
        names_by_source[label] = names
        report["totals"]["source_nodes"] += len(nodes)

        # 1. one connection must appear once inside a source
        seen = collections.Counter(connection_key(item) for item in nodes)
        for key, count in seen.items():
            if count > 1:
                report["totals"]["duplicate_connection_occurrences"] += count - 1
                if len(report["findings"]["duplicate_egress"]) < 40:
                    server = dict(zip(("type", "server", "port"), key[:3]))
                    report["findings"]["duplicate_egress"].append(
                        {"source": label, "server": server.get("server"),
                         "count": count})

        for name in names:
            if COUNTER.search(name):
                report["totals"]["counter_suffix"] += 1
                if len(report["findings"]["counters"]) < 25:
                    report["findings"]["counters"].append({"source": label, "name": name})
            if HASH_SUFFIX.search(name):
                report["totals"]["hash_suffix"] += 1
                if len(report["findings"]["hash_suffix"]) < 25:
                    report["findings"]["hash_suffix"].append({"source": label, "name": name})
            if BARE_AS.search(name):
                report["totals"]["bare_as_brand"] += 1
            if GENERIC_BRAND.search(name):
                report["totals"]["generic_brand"] += 1
                if len(report["findings"]["generic_brand"]) < 25:
                    report["findings"]["generic_brand"].append({"source": label, "name": name})
            if UNKNOWN_BRAND.search(name):
                report["totals"]["unknown_brand"] += 1
                if len(report["findings"]["unknown_brand"]) < 15:
                    report["findings"]["unknown_brand"].append({"source": label, "name": name})
            if not name.strip() or len(name) > 80:
                report["totals"]["unreadable_name"] += 1
                if len(report["findings"]["unreadable_name"]) < 15:
                    report["findings"]["unreadable_name"].append(
                        {"source": label, "name": name[:90]})
            if not FLAG.match(name):
                report["totals"]["missing_flag"] += 1

    merged_names = [item.get("name") for item in (artifacts.merged.get("proxies") or [])
                    if isinstance(item, dict)]
    # 2. across every source: the same name must not be published twice
    counts = collections.Counter(merged_names)
    report["totals"]["merged_duplicate_names"] = sum(v - 1 for v in counts.values() if v > 1)
    for name, count in counts.items():
        if count > 1 and len(report["findings"]["merged_duplicate_names"]) < 25:
            report["findings"]["merged_duplicate_names"].append(
                {"name": name, "count": count})
    report["totals"]["merged_unique_names"] = len(counts)
    report["totals"]["counter_suffix_merged"] = sum(
        1 for name in merged_names if COUNTER.search(str(name)))
    report["totals"]["generic_brand_merged"] = sum(
        1 for name in merged_names if GENERIC_BRAND.search(str(name)))
    report["totals"]["hash_suffix_merged"] = sum(
        1 for name in merged_names if HASH_SUFFIX.search(str(name)))
    return report


def render(report):
    lines = []
    add = lines.append
    add("Gist %s" % report["gist"])
    add("  sources read      : %d" % report["sources"])
    add("  nodes in sources  : %d" % report["totals"]["source_nodes"])
    add("  merged proxies    : %d" % report["merged_proxies"])
    add("  merged unique     : %d" % report["totals"]["merged_unique_names"])
    if report["errors"]:
        add("  fetch errors      : %d" % len(report["errors"]))
        for error in report["errors"][:5]:
            add("      %s" % error)
    add("")
    add("Defects")
    for key, title in (
        ("counter_suffix", "ordinal counter suffix (-2/-3/…)"),
        ("hash_suffix", "8-hex merger suffix"),
        ("generic_brand", "generic word used as brand"),
        ("unknown_brand", "missing brand (Unknown)"),
        ("bare_as_brand", "bare AS number as brand"),
        ("unreadable_name", "empty or over-long name"),
        ("missing_flag", "no country flag prefix"),
        ("duplicate_connection_occurrences", "duplicate connection inside a source"),
        ("merged_duplicate_names", "duplicate name in merged subscription"),
    ):
        add("  %-42s %d" % (title, report["totals"].get(key, 0)))
    add("  %-42s %d" % ("ordinal suffix in merged (was 261)", report["totals"].get("counter_suffix_merged", 0)))
    add("  %-42s %d" % ("generic brand in merged (was 23)", report["totals"].get("generic_brand_merged", 0)))
    add("  %-42s %d" % ("8-hex suffix in merged (was 124)", report["totals"].get("hash_suffix_merged", 0)))
    for section, entries in report["findings"].items():
        if not entries:
            continue
        add("")
        add("%s (first %d)" % (section, len(entries)))
        for entry in entries[:12]:
            add("    %s" % json.dumps(entry, ensure_ascii=False, sort_keys=True))
    return "\n".join(lines)


def emit(text, stream=None):
    """Write UTF-8 regardless of the console code page.

    Node names carry country flags, and a Windows console defaults to GBK,
    which raises UnicodeEncodeError on every emoji. The audit must never die
    because of the terminal it happens to run in.
    """
    stream = stream or sys.stdout
    try:
        stream.write(text + "\n")
    except UnicodeEncodeError:
        buffer = getattr(stream, "buffer", None)
        if buffer is None:
            stream.write(text.encode("ascii", "replace").decode("ascii") + "\n")
        else:
            stream.flush()
            buffer.write((text + "\n").encode("utf-8", "replace"))
            buffer.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gist-id", default=DEFAULT_GIST)
    parser.add_argument("--owner", default=DEFAULT_OWNER,
                        help="Gist owner login (only used to build raw URLs)")
    parser.add_argument("--dir", dest="directory",
                        help="audit a local PROBE_OUTPUT_DIR instead of the Gist")
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--report", dest="report_path",
                        help="write the human report to this UTF-8 file")
    args = parser.parse_args(argv)

    artifacts = Artifacts(args.gist_id, args.owner, args.directory).load()
    report = audit(artifacts)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=True)
    if args.report_path:
        with open(args.report_path, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(render(report) + "\n")
    if not args.quiet:
        emit(render(report))
    return 0 if artifacts.sources else 2


if __name__ == "__main__":
    sys.exit(main())