#!/usr/bin/env python3
"""All-source Actions probe (stdlib + PyYAML); no Sub-Store writes or exit cache.

Run: SUBSTORE_BASE=... MIHOMO_BIN=/path/mihomo PROBE_OUTPUT_DIR=/private/path
     python scripts/actions_probe_all.py
Optional: GIST_TOKEN + GIST_ID (or GITHUB_GIST_ID), PROBE_CONCURRENCY=8,
PROBE_TIMEOUT=15, PROBE_FRONT_SUB=cf-front, PROBE_SOURCES_JSON='["source"]'.
When PROBE_SOURCES_JSON is unset, every selected source is tested every round.
Per-source credentials: SOURCE_SECRETS_JSON (an Actions Secret holding a JSON
map keyed by source name — see docs/ADDING_SOURCES.md). Absent or empty means
no source needs its own credential; adding a source NEVER requires touching
this file or the workflow again.
Explicitly selected source names/counts are reported; upstream names/URLs never are.
Output contains credentials: NEVER
upload this directory as an Actions artifact. Serialize workflow runs externally.
Dependency groups are frozen to deterministic select groups (same complete member
closure), preventing background health checks, fallback-to-DIRECT and latency churn.
No previous measurement is ever used as evidence that a node is alive.
"""
from __future__ import annotations

import concurrent.futures
import copy
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml

# Geolocation lives in a sibling module so the lookup providers can be tested
# in isolation (offline) and replaced without touching the probe contract.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import geo_naming  # noqa: E402

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
SOURCE_FILE = re.compile(r"source-[0-9a-f]{64}\.yaml\Z")
BUILTINS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
# Non-connection annotations must not change the stable connection identity.
ANNOTATIONS = {"name", "_probe_state", "_probe", "dialer-proxy", "dialer_proxy",
               "detour", "benchmark", "latency", "delay"}
COUNTRIES = set("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW".split())


class ProbeError(Exception):
    """Deliberately contains only a non-sensitive category."""


ERROR_CODES = set("trace_invalid github_redirect response_large upstream_redirect transport_failure redirect_limit base_invalid sources_invalid source_secrets_invalid subscription_invalid definition_invalid definition_duplicate definition_collision dependency_invalid dependency_cycle_or_direct dependency_missing kernel_validation_failure kernel_config_failure kernel_start_failure kernel_end_failure kernel_execution_failure old_content_invalid namespace_collision manifest_invalid gist_id_invalid gist_token_invalid gist_not_private gist_raw_invalid environment_missing kernel_missing curl_missing sources_empty sources_filter_invalid sources_filter_missing no_successful_roots gist_conflict http_failure request_invalid non_proxy_outbound dependency_group_unsupported".split())


def error_code(exc):
    # NEVER return arbitrary exception text: parsers/urllib can include secrets.
    if isinstance(exc, ProbeError):
        code = exc.args[0] if exc.args else ""
        return code if isinstance(code, str) and (code in ERROR_CODES or re.fullmatch(r"http_[1-5][0-9]{2}", code)) else "probe_error"
    for cls in (json.JSONDecodeError, UnicodeError, KeyError, TypeError, ValueError, OSError, yaml.YAMLError):
        if isinstance(exc, cls):
            return cls.__name__
    return "unexpected_exception"


def digest(value: str | bytes) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def source_file(name: str) -> str:
    return "source-" + digest(name) + ".yaml"


def selected_source(name: str) -> bool:
    """Upstream origins only: never our own published artifacts.

    `gist-` names are the remote subscriptions that point back at this
    publisher's fixed Gist files. Measuring them would feed the round its own
    previous output (and quietly re-measure renamed nodes), so they are
    excluded exactly like the legacy `probe-`/`chain-`/`rust-` products.
    """
    return (bool(name)
            and not name.lower().startswith(("probe-", "chain-", "rust-", "gist-"))
            and name not in {"测活-DMIT", "官方可用"})


def is_v6_literal(server) -> bool:
    """True when the address is an IPv6 literal (not a hostname)."""
    try:
        return ipaddress.ip_address(str(server)).version == 6
    except ValueError:
        return False


def host_ipv6_capable(override=None) -> bool:
    """True when this host has a usable global IPv6 route.

    A node whose server address is an IPv6 literal can only be dialled from a
    host that can reach IPv6. GitHub-hosted runners are IPv4-only, so such a
    node is unreachable FROM HERE. That is a property of the runner, not of
    the node: the node may well be alive on the user's own IPv6 network.
    Scoring it "dead" would silently delete a working node, so the probe
    reports it as unverifiable instead. The check is a route lookup (a UDP
    connect), not a probe: no packet leaves the host.

    ``override`` (env ``PROBE_IPV6=0/1``) forces the verdict, which is what the
    A/B harness uses to exercise both branches on one machine.
    """
    if override is not None:
        return bool(override)
    if not socket.has_ipv6:
        return False
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        sock.connect(("2606:4700:4700::1111", 53))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def ipv6_override(value):
    """``PROBE_IPV6`` -> True/False/None (unset = detect the host)."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return None


def env_flag(value, default=True):
    """Boolean env switch; an empty/unset value keeps ``default``."""
    if value is None:
        return default
    text = str(value).strip().lower()
    if not text:
        return default
    return text not in {"0", "false", "no", "off"}


def env_int(value, default, low=0, high=10 ** 9):
    """Bounded integer env switch; malformed input falls back to ``default``."""
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


def merge_v6_results(results, payload):
    """Apply a v6 worker's verdicts to this round's source results.

    A v6-bound node is unmeasurable from an IPv4-only host, so it is neither
    alive nor dead here. A host WITH IPv6 can settle it. Only nodes the worker
    actually dialled are settled:

      * dialled and answered -> promotes the node to alive (its own exit IP);
      * dialled and silent   -> PROVEN DEAD, so it stops being unverifiable and
                               may count toward the source's death evidence;
      * not dialled          -> stays unverifiable, unchanged.

    ``payload`` is the worker's JSON (see ``scripts/v6_worker.py``). Anything
    malformed is ignored: a broken helper must never change a publication.
    """
    if not isinstance(payload, dict) or not payload.get("host_ipv6"):
        return results
    judged = payload.get("judged") or {}
    answers = payload.get("results") or {}
    if not isinstance(judged, dict) or not isinstance(answers, dict):
        return results
    for result in results:
        try:
            count = int(judged.get(result.name) or 0)
        except (TypeError, ValueError):
            continue
        if count <= 0:
            continue
        answered = answers.get(result.name) or {}
        if not isinstance(answered, dict):
            continue
        # Only roots this round actually handed to the helper can be settled.
        # An answer about any other name is either a version mismatch or a
        # poisoned helper; promoting it would invent measurements, and the
        # rebuild would then raise KeyError on a node that is not in the graph.
        # One unknown name invalidates the whole source answer: the helper is
        # not describing this round's job, so none of its verdicts are usable.
        roots = set(result.v6_roots)
        if any(name not in roots for name in answered):
            continue
        promoted = []
        for name, verdict in answered.items():
            if not isinstance(verdict, dict) or not verdict.get("alive"):
                continue
            ip, cc = verdict.get("ip"), verdict.get("cc")
            if not isinstance(ip, str) or not isinstance(cc, str):
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not addr.is_global or cc not in COUNTRIES:
                continue
            promoted.append(Measurement(str(name), ip, cc))
        # A node is proven dead only when the helper dialled it and said nothing
        # about it. An answer we cannot parse proves nothing either way, so it
        # must leave the node unverifiable instead of silently killing it.
        silent = max(0, min(count, len(roots)) - len(answered))
        settled = len(promoted) + silent
        if not settled:
            continue
        result.measurements.extend(promoted)
        result.alive = len(result.measurements)
        result.unverifiable = max(0, result.unverifiable - settled)
        result.measured += settled
        result.unique_egress = len({egress_key(item.ip) for item in result.measurements})
        result.countries = {}
        for item in result.measurements:
            result.countries[item.cc] = result.countries.get(item.cc, 0) + 1
    return results


def canonical(value) -> str:
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=True, width=100000)


def json_text(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def parse_trace(text: str) -> tuple[str, str]:
    if len(text) > 65536:
        raise ProbeError("trace_invalid")
    fields = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in fields:
                raise ProbeError("trace_invalid")
            fields[key] = value.strip()
    try:
        addr = ipaddress.ip_address(fields.get("ip", ""))
    except ValueError:
        raise ProbeError("trace_invalid") from None
    cc = fields.get("loc", "")
    if not addr.is_global or addr.is_multicast or cc not in COUNTRIES:
        raise ProbeError("trace_invalid")
    # A 200 body alone is not evidence of a full TLS handshake: the trace URL
    # may be served over plain HTTP by a captive portal or a downgraded hop.
    # CF emits visit_scheme and tls=TLSv1.3 (or "on" on older edges); require
    # both so an intercepted/plaintext trace cannot mark a node alive.
    if fields.get("visit_scheme", "").lower() != "https":
        raise ProbeError("trace_invalid")
    tls = fields.get("tls", "").lower()
    if not (tls == "on" or tls.startswith("tlsv") or tls in {"1.2", "1.3"}):
        raise ProbeError("trace_invalid")
    return str(addr), cc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Transport:
    """Bounded responses, explicit redirect validation; injectable in offline tests."""
    def __init__(self, timeout=30, retries=2, sleep=time.sleep):
        self.timeout = timeout
        self.retries = max(0, min(3, int(retries)))
        self.sleep = sleep
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def __call__(self, method, url, headers=None, body=None):
        # Repeating the exact fixed-content PATCH is idempotent. A 412 is NEVER
        # retried here: the publisher must GET and re-plan against the new ETag.
        for attempt in range(self.retries + 1):
            try:
                return self.once(method, url, headers, body)
            except ProbeError as exc:
                code = error_code(exc)
                retryable = code == "transport_failure" or code == "http_429" or bool(re.fullmatch(r"http_5[0-9]{2}", code))
                if not retryable or attempt >= self.retries:
                    raise
                self.sleep(min(4, 2 ** attempt))

    def once(self, method, url, headers=None, body=None):
        headers = dict(headers or {})
        headers.setdefault("User-Agent", UA)
        original = urllib.parse.urlsplit(url)
        github = "Authorization" in headers and original.hostname in {"api.github.com", "gist.githubusercontent.com"}
        for _ in range(5):
            parts = urllib.parse.urlsplit(url)
            if github and (parts.scheme != "https" or parts.hostname not in {"api.github.com", "gist.githubusercontent.com"} or parts.port not in (None, 443) or parts.username):
                raise ProbeError("github_redirect")
            try:
                request = urllib.request.Request(url, data=body, headers=headers, method=method)
                with self.opener.open(request, timeout=self.timeout) as response:
                    data = response.read(32 * 1024 * 1024 + 1)
                    if len(data) > 32 * 1024 * 1024:
                        raise ProbeError("response_large")
                    return data, dict(response.headers)
            except urllib.error.HTTPError as exc:
                if exc.code in (301, 302, 303, 307, 308) and method == "GET":
                    new_url = urllib.parse.urljoin(url, exc.headers.get("Location", ""))
                    new_parts = urllib.parse.urlsplit(new_url)
                    if not github and (new_parts.scheme, new_parts.netloc) != (original.scheme, original.netloc):
                        raise ProbeError("upstream_redirect") from None
                    url = new_url
                    continue
                raise ProbeError("http_" + str(exc.code)) from None
            except (OSError, urllib.error.URLError):
                raise ProbeError("transport_failure") from None
            except ValueError:
                raise ProbeError("request_invalid") from None
        raise ProbeError("redirect_limit")


def load_source_secrets(env):
    """Parse SOURCE_SECRETS_JSON into a per-source credential map (see docs/ADDING_SOURCES.md).

    Reserved extension point for adding a subscription source that needs its own
    credential: the Actions Secret holds one JSON object keyed by source name:

        {"<source name>": {"header": {"Authorization": "..."},
                           "query": {"token": "..."},
                           "url": "https://host/override?target=ClashMeta"}}

    All three keys are optional; unknown keys and shapes fail with a fixed
    error_code so no credential fragment can reach stdout/logs. Absent or empty
    env means no source needs its own credential. Values are never logged.
    """
    raw = str(env.get("SOURCE_SECRETS_JSON", "") or "").strip()
    if not raw:
        return {}
    try:
        doc = json.loads(raw)
    except ValueError:
        raise ProbeError("source_secrets_invalid") from None
    if not isinstance(doc, dict):
        raise ProbeError("source_secrets_invalid")
    parsed = {}
    for name, spec in doc.items():
        if not isinstance(name, str) or not name or not isinstance(spec, dict):
            raise ProbeError("source_secrets_invalid")
        unknown = set(spec) - {"header", "query", "url"}
        if unknown:
            raise ProbeError("source_secrets_invalid")
        entry = {}
        headers = spec.get("header")
        if headers is not None:
            if not isinstance(headers, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
                raise ProbeError("source_secrets_invalid")
            entry["header"] = dict(headers)
        query = spec.get("query")
        if query is not None:
            if not isinstance(query, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in query.items()):
                raise ProbeError("source_secrets_invalid")
            entry["query"] = dict(query)
        url = spec.get("url")
        if url is not None:
            if not isinstance(url, str):
                raise ProbeError("source_secrets_invalid")
            parts = urllib.parse.urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname or parts.username:
                raise ProbeError("source_secrets_invalid")
            entry["url"] = url
        if not entry:
            raise ProbeError("source_secrets_invalid")
        parsed[name] = entry
    return parsed


class SubStore:
    def __init__(self, base, transport, source_secrets=None):
        parsed = urllib.parse.urlsplit(base)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.query or parsed.fragment:
            raise ProbeError("base_invalid")
        self.base, self.transport = base.rstrip("/"), transport
        # Per-source credentials are keyed by exact source name; a name without
        # an entry simply uses the plain Sub-Store URL like today.
        self.source_secrets = source_secrets or {}

    def sources(self):
        raw, _ = self.transport("GET", self.base + "/api/subs")
        obj = json.loads(raw)
        data = obj.get("data", obj) if isinstance(obj, dict) else obj
        if isinstance(data, dict):
            data = list(data.values())
        if not isinstance(data, list):
            raise ProbeError("sources_invalid")
        names = {item["name"] for item in data if isinstance(item, dict) and isinstance(item.get("name"), str) and selected_source(item["name"])}
        return sorted(names)

    def config(self, name):
        secret = self.source_secrets.get(name, {})
        url = self.base + "/download/" + urllib.parse.quote(name, safe="") + "?target=ClashMeta"
        if "url" in secret:
            # Full-URL override for a source hosted outside this Sub-Store. The
            # transport still applies its own redirect/size discipline.
            url = secret["url"]
        if "query" in secret:
            parts = urllib.parse.urlsplit(url)
            merged = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
            merged.update(secret["query"])
            url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(merged)))
        raw, _ = self.transport("GET", url, headers=secret.get("header"))
        value = yaml.safe_load(raw)
        if not isinstance(value, dict) or not isinstance(value.get("proxies"), list):
            raise ProbeError("subscription_invalid")
        return dedupe_names(value)


def dedupe_names(config):
    """Make duplicate upstream node names unique, the way the kernel needs them.

    mihomo keys proxies by name and silently drops later duplicates, so a
    subscription that lists the same name for several servers (dafeng had 40
    entries for 16 names) would lose nodes without any diagnostic. The first
    occurrence keeps the original name so a dialer reference still resolves to
    it; later occurrences get a deterministic numeric suffix. Exported names are
    replaced by the stable fingerprint names anyway.
    """
    result = copy.deepcopy(config)
    for field in ("proxies", "proxy-groups"):
        seen = {}
        for item in result.get(field) or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            if name not in seen:
                seen[name] = 1
                continue
            seen[name] += 1
            candidate = "%s#%d" % (name, seen[name])
            while candidate in seen:
                seen[name] += 1
                candidate = "%s#%d" % (name, seen[name])
            seen[candidate] = 1
            item["name"] = candidate
    return result


class Graph:
    """Resolve every dialer and group dependency; missing references fail closed."""
    def __init__(self, config, front=None):
        self.nodes, self.groups = {}, {}
        # Source definitions override identically named front definitions.
        for doc in (front or {}, config):
            for field, target in (("proxies", self.nodes), ("proxy-groups", self.groups)):
                local = set()
                for item in doc.get(field, []) or []:
                    if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                        raise ProbeError("definition_invalid")
                    name = item["name"]
                    if name in local or name in BUILTINS:
                        raise ProbeError("definition_duplicate")
                    local.add(name)
                    target[name] = copy.deepcopy(item)
        if set(self.nodes) & set(self.groups):
            raise ProbeError("definition_collision")
        self.cache = {}

    def dependency(self, node):
        refs = [node[key] for key in ("dialer-proxy", "dialer_proxy", "detour") if key in node]
        if len(refs) > 1 or (refs and not isinstance(refs[0], str)):
            raise ProbeError("dependency_invalid")
        return refs[0] if refs else None

    def identity(self, name, stack=()):
        if name in self.cache:
            return self.cache[name]
        if name in stack or name in BUILTINS:
            raise ProbeError("dependency_cycle_or_direct")
        path = stack + (name,)
        if name in self.nodes:
            item = self.nodes[name]
            # A renamed DIRECT/reject/dns outbound is not a proxy node. Otherwise
            # the runner's own trace would become false evidence of proxy health.
            if str(item.get("type", "")).lower() not in {
                "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2",
                "tuic", "wireguard", "snell", "socks5", "http", "ssh", "mieru",
                "anytls", "masque", "trusttunnel", "sudoku",
            }:
                raise ProbeError("non_proxy_outbound")
            value = {k: v for k, v in item.items() if k not in ANNOTATIONS and not k.startswith("_probe")}
            ref = self.dependency(item)
            if ref:
                value["dialer-resolved"] = self.identity(ref, path)
        elif name in self.groups:
            item = self.groups[name]
            # Only ordinary single-hop selection groups can be frozen. A relay
            # is an ordered multi-hop chain, not a selector; unsupported/unknown
            # groups must fail closed instead of changing the tested path.
            if str(item.get("type", "")).lower() not in {"select", "url-test", "fallback", "load-balance"}:
                raise ProbeError("dependency_group_unsupported")
            refs = item.get("proxies")
            if item.get("use") or not isinstance(refs, list) or not refs:
                raise ProbeError("dependency_missing")
            # A deterministic select, never a health/latency-selected chain.
            value = {"group": sorted(self.identity(ref, path) for ref in refs)}
        else:
            raise ProbeError("dependency_missing")
        fp = digest(json_text(value))
        self.cache[name] = fp
        return fp

    def closure(self, roots):
        nodes, groups = set(), set()

        def visit(name):
            self.identity(name)  # validates cycles, builtins and missing references
            if name in self.nodes:
                if name in nodes:
                    return
                nodes.add(name)
                ref = self.dependency(self.nodes[name])
                if ref:
                    visit(ref)
            else:
                if name in groups:
                    return
                groups.add(name)
                for ref in self.groups[name]["proxies"]:
                    visit(ref)
        for root in roots:
            visit(root)
        return nodes, groups

    def dial_servers(self, root):
        """Every server address the runner must dial to reach this root.

        The root's own server plus the whole dialer chain: a node whose
        FRONT is an IPv6 literal needs IPv6 just as much as a node whose own
        address is one. A malformed dialer reference stops the walk but does
        not raise: the node is already invalid and the kernel validation
        reports it, so classification must stay side-effect free.
        """
        servers, stack, seen = [], [root], set()
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            try:
                if name in self.nodes:
                    item = self.nodes[name]
                    server = item.get("server")
                    if isinstance(server, str) and server:
                        servers.append(server)
                    ref = self.dependency(item)
                    if ref:
                        stack.append(ref)
                elif name in self.groups:
                    for ref in self.groups[name].get("proxies") or []:
                        stack.append(ref)
            except ProbeError:
                continue
        return servers

    def v6_bound(self, root) -> bool:
        """True when reaching this root requires an IPv6 literal address."""
        return any(is_v6_literal(server) for server in self.dial_servers(root))

    def front_backed(self, roots, front_only) -> bool:
        """True when any root's dial chain reaches a node supplied by the front.

        Such a source cannot blame its own nodes for a dead round: the front
        may be the reason every measurement failed.
        """
        if not front_only:
            return False
        for root in roots:
            try:
                nodes, _ = self.closure([root])
            except ProbeError:
                continue
            if nodes & front_only:
                return True
        return False

    def export(self, roots, names=None):
        nodes, groups = self.closure(roots)
        names = names or {name: name for name in nodes | groups}
        proxies = []
        for name in sorted(nodes, key=lambda n: (self.identity(n), n)):
            item = {k: copy.deepcopy(v) for k, v in self.nodes[name].items() if not k.startswith("_probe") and k not in {"dialer_proxy", "detour"}}
            item["name"] = names[name]
            ref = self.dependency(self.nodes[name])
            if ref:
                item["dialer-proxy"] = names[ref]
            proxies.append(item)
        output = {"proxies": proxies}
        if groups:
            output["proxy-groups"] = [{"name": names[name], "type": "select", "proxies": [names[ref] for ref in sorted(set(self.groups[name]["proxies"]), key=lambda n: (self.identity(n), n))]} for name in sorted(groups, key=lambda n: (self.identity(n), n))]
        return output


def unused_ports(count):
    holders = []
    try:
        for _ in range(count):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            holders.append(sock)
        return [sock.getsockname()[1] for sock in holders]
    finally:
        for sock in holders:
            sock.close()


def kernel_config(graph, roots, ports, controller, secret):
    return kernel_config_document(graph.export(roots), roots, ports, controller, secret)


def kernel_config_document(document, lanes, ports, controller, secret):
    """Kernel body for already-exported proxies/groups.

    ``lanes`` holds one proxy name per listener, aligned with ``ports``. Keeping
    this separate lets a merged round concatenate several sources' exports into
    ONE kernel while each lane still remembers which source root it belongs to.
    """
    cfg = {"proxies": list(document.get("proxies") or [])}
    if document.get("proxy-groups"):
        cfg["proxy-groups"] = list(document["proxy-groups"])
    cfg.update({
        "allow-lan": False, "bind-address": "127.0.0.1", "mode": "rule",
        "ipv6": True, "log-level": "silent", "external-controller": "127.0.0.1:" + str(controller),
        "secret": secret, "external-ui": "", "geodata-mode": False, "geo-auto-update": False,
        "find-process-mode": "off", "profile": {"store-selected": False, "store-fake-ip": False},
        "dns": {"enable": False}, "tun": {"enable": False},
        "listeners": [{"name": "lane-" + str(index), "type": "http", "listen": "127.0.0.1", "port": port, "proxy": lane} for index, (lane, port) in enumerate(zip(lanes, ports))],
        "rules": ["MATCH,REJECT"],
    })
    return cfg


def private_dir(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def private_write(path, content):
    path = Path(path)
    # Random temp file in the same private directory; atomic replacement.
    fd, tmp = tempfile.mkstemp(prefix=".write-", dir=str(path.parent))
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


#: Returned by ``NativeProbe.trace`` when the response came from the runner
#: itself. It is neither a measurement nor a failure worth retrying.
DIRECT_LEAK = object()


@dataclass
class Measurement:
    name: str
    ip: str
    cc: str
    #: Negotiated protocol from curl ("2", "1.1", ...); empty when unknown
    #: (for example a v6 node settled by the helper, which does not report it).
    http_version: str = ""
    #: Round-trip milliseconds from the kernel's own delay probe. 0 means "no
    #: evidence" (prefilter disabled, or the node was settled by the v6 helper),
    #: never "0 ms".
    delay_ms: int = 0


@dataclass
class SourceResult:
    name: str
    input: int = 0
    alive: int = 0
    published: int = 0
    content: str | None = None
    failed: bool = False
    error: str = ""
    unique_egress: int = 0
    #: Alive nodes that negotiated HTTP/1.1 instead of HTTP/2. A downgraded hop
    #: is recorded for audit; it never deletes a node on its own.
    http1: int = 0
    countries: dict = field(default_factory=dict)
    #: Roots this round actually dialled. Roots with an unusable configuration
    #: are invalid; roots that need IPv6 on an IPv4-only host are unverifiable.
    measured: int = 0
    #: Roots whose configuration the kernel refused (unusable, not merely down).
    invalid: int = 0
    #: Roots this round could NOT judge because the host cannot reach IPv6.
    unverifiable: int = 0
    #: The source's nodes are dialled through the front subscription.
    uses_front: bool = False
    #: Front health this round: True alive, False dead, None not measured.
    front_alive: bool | None = None
    #: Every alive measurement, kept so a v6 worker's verdicts can be merged in
    #: and the source body rebuilt from the union.
    measurements: list = field(default_factory=list)
    #: Roots this round skipped because they need an IPv6 route the host lacks.
    v6_roots: list = field(default_factory=list)
    #: Egress latency of alive nodes, from the kernel delay probe. Audit only:
    #: latency is never part of a connection fingerprint/name.
    delay_median_ms: int = 0
    delay_p90_ms: int = 0
    #: Exit vs node ``server`` literal: {"same", "transit", "unknown"} counts.
    #: "transit" is a legitimate relay/CDN, not a defect; it is annotated only.
    landing: dict = field(default_factory=dict)
    #: Egress ASN class counts (cdn/datacenter/residential/mobile/unknown).
    asn_class: dict = field(default_factory=dict)
    #: Roots the kernel delay probe rejected before curl. Visible so a too-tight
    #: budget can be diagnosed per source instead of guessed from alive counts.
    prefiltered: int = 0


#: Upper bound on concurrent node dials. Each dial is one 1KB trace through the
#: shared kernel, so the cost is I/O and remote RTT, not CPU. 32 was far below
#: the saturation point: a 1355-node round spent 441s at 24 workers, and ~96% of
#: those node-seconds were dead nodes sitting in a timeout.
MAX_WORKERS = 256


@dataclass
class SourceJob:
    """One source prepared for measurement, independent of the kernel shape.

    Preparing (graph resolution, front attribution, v6 classification) is
    separate from measuring so several jobs can share one kernel and still be
    reported per source.
    """
    name: str
    config: dict
    graph: Graph
    roots: list
    front_only: set
    uses_front: bool
    v6_roots: list = field(default_factory=list)


class NativeProbe:
    def __init__(self, binary, workers=8, timeout=15, transport=None, ipv6=None,
                 delay_ms=0, delay_retry_ms=0, kernel_batch=0, dedupe=False):
        self.binary = binary
        self.workers = max(1, min(MAX_WORKERS, int(workers)))
        self.timeout = max(1, min(120, int(timeout)))
        #: Readiness polling must NOT reuse Transport. That opener retries a
        #: refused socket with a 1s/2s backoff, so a kernel that bound in 0.2s
        #: was observed ready only after ~1.1s -- per source, with the whole
        #: worker pool idle. A single short attempt is the right tool.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.transport = transport or Transport(timeout=2)
        #: The runner's own egress address, set by run() before measuring. A
        #: node that reports it did not carry the traffic, so it is dropped.
        self.baseline_ip = None
        #: Measurements dropped because they came out of the runner itself.
        self.suppressed = 0
        #: Roots skipped before curl because the kernel's own delay probe
        #: failed. 0 when the prefilter is disabled.
        self.prefiltered = 0
        #: Interchangeable duplicate definitions collapsed before dialling.
        self.dedup_saved = 0
        #: Number of multi-source kernels started this round.
        self.merged_groups = 0
        #: ``/proxies/<name>/delay`` budget in ms; 0 disables the prefilter.
        #: It runs BEFORE curl, so a dead node costs one short API call instead
        #: of a short trace plus a full retry. Delay is also kept as evidence.
        self.delay_ms = max(0, min(30000, int(delay_ms or 0)))
        #: One retry budget for lanes that failed the first delay probe. The
        #: slow-but-alive tail (3-8s for 1KB) must not be skipped just because
        #: a single short budget is stricter than curl's 5s+15s trace.
        self.delay_retry_ms = max(0, min(30000, int(delay_retry_ms or 0)))
        #: Sources per shared kernel; 0 = one kernel for the whole round.
        self.kernel_batch = max(0, int(kernel_batch or 0))
        #: Collapse identical connection definitions within one source.
        self.dedupe = bool(dedupe)
        # IPv6 capability is a HOST property. When the host cannot reach IPv6,
        # a node with an IPv6 literal server is unverifiable from here, never
        # dead: it may be alive on the user's own IPv6 network.
        self.ipv6 = host_ipv6_capable() if ipv6 is None else bool(ipv6)

    def validate(self, directory, cfg):
        path = Path(directory) / "config.yaml"
        private_write(path, canonical(cfg))
        try:
            run = subprocess.run([self.binary, "-t", "-d", str(directory), "-f", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            return run.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            raise ProbeError("kernel_validation_failure") from None

    def trace(self, port, directory, timeout=None):
        # A 1KB trace needs a small budget, not the full node timeout: a node
        # that cannot deliver it in a few seconds is already unusable for real
        # traffic. The caller uses the short budget first and spends the full
        # one only on the nodes that failed, so a dead node costs fast+full
        # instead of full+full.
        budget = self.timeout if timeout is None else max(1, min(self.timeout, int(timeout)))
        fd, path = tempfile.mkstemp(prefix="trace-", dir=str(directory))
        os.chmod(path, 0o600)
        os.close(fd)
        try:
            # curl writes the body itself and prints one metadata line on
            # stdout. Streaming the body to stdout (the old shape) left no room
            # for the negotiated protocol or the certificate verdict.
            run = subprocess.run([
                "curl", "--disable", "--silent", "--show-error", "--fail", "--noproxy", "",
                "--proxy", "http://127.0.0.1:" + str(port), "--max-time", str(budget),
                # curl's connect timeout only covers the loopback socket to
                # the kernel (milliseconds). The node's own dial is bounded
                # by --max-time; keep this short so a stuck controller is
                # visible instead of eating the whole budget.
                "--connect-timeout", str(min(4, budget)), "--proto", "=https",
                "--max-filesize", "65536",
                "--output", path, "--write-out", "%{http_version} %{ssl_verify_result}",
                TRACE_URL,
            ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=budget + 3)
            if run.returncode:
                return None
            ok, version = self.negotiation(run.stdout)
            if not ok:
                return None
            ip, cc = parse_trace(Path(path).read_text(encoding="utf-8"))
            if self.baseline_ip and ip == self.baseline_ip:
                # The exit is the runner itself: the request never entered the
                # node (a config bug or a silent DIRECT fallback). Not a
                # measurement, and not worth a retry either.
                self.suppressed += 1
                return DIRECT_LEAK
            return ip, cc, version
        except (OSError, UnicodeError, subprocess.TimeoutExpired, ProbeError):
            return None
        finally:
            if os.path.exists(path):
                os.unlink(path)

    @staticmethod
    def negotiation(raw):
        """Parse curl's write-out: ``(verified, http_version)``.

        ``ssl_verify_result`` is 0 for a validated chain; a non-zero value means
        curl reached the endpoint without trusting it, which is never a usable
        measurement. HTTP/1.1 is recorded, not rejected: the caller reports it
        as ``http1`` so a downgraded hop is visible instead of silent.
        """
        try:
            parts = raw.decode("utf-8", "replace").split()
        except Exception:
            return False, ""
        if len(parts) < 2:
            return True, ""
        try:
            verified = int(parts[1]) == 0
        except ValueError:
            verified = False
        return verified, parts[0]

    def health(self, process, controller, secret, once=False):
        if process.poll() is not None:
            return False
        url = "http://127.0.0.1:" + str(controller) + "/version"
        headers = {"Authorization": "Bearer " + secret}
        if once:
            # Startup readiness: one short attempt, no retry and no backoff.
            try:
                request = urllib.request.Request(url, headers=headers)
                with self.opener.open(request, timeout=0.4) as response:
                    return isinstance(json.loads(response.read()), dict) and process.poll() is None
            except Exception:
                return False
        try:
            raw, _ = self.transport("GET", url, headers)
            return isinstance(json.loads(raw), dict) and process.poll() is None
        except Exception:
            return False

    def _valid_batch(self, directory, graph, batch, secret):
        """One kernel validation over a batch's complete closures.

        Infrastructure failures (missing kernel, subprocess timeout) still
        raise; a root the graph or the kernel rejects only fails THIS batch,
        which is what the bisection in _assess needs.
        """
        try:
            ports = unused_ports(len(batch) + 1)
            cfg = kernel_config(graph, batch, ports[:-1], ports[-1], secret)
        except ProbeError as exc:
            if str(exc).startswith("kernel_"):
                raise
            return False
        return self.validate(directory, cfg)

    def _assess(self, directory, graph, batch, secret, accepted, invalid):
        """Validate a batch of roots; bisect on failure to isolate bad ones.

        Group testing: the measurement kernel runs every accepted root as one
        config anyway, so one mihomo -t covers the whole batch. A single bad
        member fails the batch, so a failing batch is split and each half is
        re-tested; k bad roots among n cost O(k log(n/k)) kernel calls instead
        of n, and the common all-healthy case is exactly one call.
        """
        if self._valid_batch(directory, graph, batch, secret):
            accepted.extend(batch)
            return
        if len(batch) == 1:
            invalid.append(batch[0])
            return
        mid = len(batch) // 2
        self._assess(directory, graph, batch[:mid], secret, accepted, invalid)
        self._assess(directory, graph, batch[mid:], secret, accepted, invalid)

    def delay_probe(self, controller, secret, name, timeout_ms=None):
        """Ask the kernel to dial one proxy and report latency.

        Returns ``(ok, delay_ms, infra)``. ``infra`` means the controller
        itself could not answer (bad secret, unknown proxy name, closed port):
        the caller must fall back to curl instead of declaring the node dead.
        A 408/504 is the kernel's own verdict that the node could not deliver
        the request in the budget, which is a real negative.
        """
        budget = max(1, min(30000, int(timeout_ms or self.delay_ms)))
        url = ("http://127.0.0.1:" + str(controller) + "/proxies/"
               + urllib.parse.quote(str(name), safe="") + "/delay?"
               + urllib.parse.urlencode({"timeout": budget, "url": TRACE_URL}))
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + secret})
        try:
            with self.opener.open(request, timeout=budget / 1000.0 + 2) as response:
                document = json.loads(response.read())
            delay = int(document.get("delay") or 0)
            return (delay > 0, delay, False)
        except urllib.error.HTTPError as exc:
            if exc.code in (408, 504):
                return (False, 0, False)
            return (False, 0, True)
        except Exception:
            return (False, 0, True)

    def _prefilter(self, lanes, controller, secret):
        """Two-stage delay pre-screen over every lane, aligned by index.

        A single short budget is measurably stricter than curl's 5s+15s trace:
        the slow tail (3-8s for 1KB) was being skipped while the old probe
        counted it alive, and the loss tracked the prefilter count almost 1:1.
        A failure is therefore retried once with ``delay_retry_ms`` before the
        lane is skipped; curl still measures every survivor by construction.

        Returns ``({index: delay_ms}, {skipped_index})``. A controller-level
        error leaves the lane OUT of ``skipped``: it is traced by curl exactly
        as before, so an API regression can never manufacture dead nodes.
        """
        if not self.delay_ms:
            return {}, set()
        delays, skipped = {}, set()
        pending = list(range(len(lanes)))
        budgets = [self.delay_ms]
        if self.delay_retry_ms > self.delay_ms:
            budgets.append(self.delay_retry_ms)
        # The controller answers these in parallel; 32 left dead nodes queuing
        # (~3s each) behind the pool. Use the round's dial concurrency as the
        # ceiling so the prefilter cannot become the new bottleneck.
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(self.workers, 128))) as pool:
            for budget in budgets:
                if not pending:
                    break
                outcomes = list(pool.map(
                    lambda index: self.delay_probe(controller, secret, lanes[index][0], budget),
                    pending,
                ))
                retry = []
                for index, (ok, delay, infra) in zip(pending, outcomes):
                    if infra:
                        continue
                    if ok:
                        delays[index] = delay
                    else:
                        retry.append(index)
                pending = retry
        skipped = set(pending)
        self.prefiltered += len(skipped)
        return delays, skipped

    def _run_kernel(self, directory, lanes, controller, secret, degrade_end=False):
        """Start one kernel over ``lanes`` and return evidence aligned with it.

        ``lanes`` is ``[(proxy_name, port)]``. Returns ``(evidence, degraded)``
        where ``evidence[i]`` is ``((ip, cc, http_version), delay_ms)``,
        ``(None, delay_ms)``, or ``(DIRECT_LEAK, delay_ms)``. ``degraded`` means
        the kernel died between the last trace and the final health check, so a
        failed lane there is NOT death evidence and the caller marks it
        unverifiable instead of deleting a node. ``degrade_end=False`` keeps the
        per-source contract: a dead kernel discards that source's round.
        """
        process = None
        try:
            process = subprocess.Popen([self.binary, "-d", str(directory), "-f", str(directory / "config.yaml")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 15
            while not self.health(process, controller, secret, once=True):
                if process.poll() is not None or time.monotonic() > deadline:
                    raise ProbeError("kernel_start_failure")
                time.sleep(0.05)
            # Delay pre-screen BEFORE curl: the kernel answers in its own
            # socket, with no fork, no temp file, and one request per node.
            delays, skipped = self._prefilter(lanes, controller, secret)
            # Two passes, not "the same attempt twice". Pass 1 gives every
            # node a short budget; nothing that needs longer than that for
            # 1KB is usable anyway. Only the failures spend the full budget
            # in pass 2, so a transient error still gets its retry while a
            # dead node stops costing 2 x the full timeout.
            fast = max(3, min(6, self.timeout // 3))
            evidence = [None] * len(lanes)
            active = [index for index in range(len(lanes)) if index not in skipped]
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
                for index, item in zip(active, pool.map(lambda index: self.trace(lanes[index][1], directory, fast), active)):
                    evidence[index] = item
                retry = [index for index in active if evidence[index] is None]
                if retry:
                    for index, item in zip(retry, pool.map(lambda index: self.trace(lanes[index][1], directory), retry)):
                        evidence[index] = item
            healthy = self.health(process, controller, secret)
            if not healthy and not degrade_end:
                raise ProbeError("kernel_end_failure")
            normalized = []
            for index in range(len(lanes)):
                item = evidence[index]
                if isinstance(item, tuple) and len(item) == 2:
                    # Tolerate the old two-field shape (tests/fakes); the
                    # production trace returns (ip, cc, http_version).
                    item = (item[0], item[1], "")
                normalized.append((item, delays.get(index, 0)))
            return normalized, not healthy, skipped
        except OSError:
            raise ProbeError("kernel_execution_failure") from None
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def _export_entries(self, entries):
        """Export entries into ONE kernel document; return (document, lanes).

        ``entries`` is ``[(job_index, job, representative_root)]``. Proxy and
        group names are namespaced by job index so two sources may carry the
        same node name without colliding; ``lanes`` stays aligned with
        ``entries`` so evidence maps back to the right source root.
        """
        by_job = {}
        for job_index, job, root in entries:
            by_job.setdefault(job_index, (job, []))[1].append(root)
        proxies, groups, lane_of = [], [], {}
        for job_index in sorted(by_job):
            job, roots = by_job[job_index]
            nodes, group_names = job.graph.closure(roots)
            names = {name: "s%d-n%s" % (job_index, job.graph.identity(name)[:16]) for name in nodes}
            names.update({name: "s%d-g%s" % (job_index, job.graph.identity(name)[:16]) for name in group_names})
            document = job.graph.export(roots, names)
            proxies.extend(document.get("proxies") or [])
            groups.extend(document.get("proxy-groups") or [])
            for root in roots:
                lane_of[(job_index, root)] = names[root]
        return ({"proxies": proxies, "proxy-groups": groups},
                [lane_of[(job_index, root)] for job_index, job, root in entries])

    def _valid_entries(self, directory, entries, secret):
        """One kernel validation over a merged subset's complete closures."""
        try:
            document, lanes = self._export_entries(entries)
            ports = unused_ports(len(lanes) + 1)
            cfg = kernel_config_document(document, lanes, ports[:-1], ports[-1], secret)
        except ProbeError as exc:
            if str(exc).startswith("kernel_"):
                raise
            return False
        return self.validate(directory, cfg)

    def _assess_entries(self, directory, entries, secret, accepted, invalid):
        """Bisect a merged batch so a bad root is attributed to its source."""
        if self._valid_entries(directory, entries, secret):
            accepted.extend(entries)
            return
        if len(entries) == 1:
            invalid.append(entries[0])
            return
        mid = len(entries) // 2
        self._assess_entries(directory, entries[:mid], secret, accepted, invalid)
        self._assess_entries(directory, entries[mid:], secret, accepted, invalid)

    def _measure_group(self, jobs):
        """Measure several sources in one kernel; return per-job outcomes.

        Outcome shape is the same ``(measurements, invalid, unverifiable)`` as
        ``__call__``. A kernel failure here falls back to one kernel per source
        in ``measure_jobs``, so the merge can never cost a whole round.
        """
        plans, unverifiable = [], [0] * len(jobs)
        for job_index, job in enumerate(jobs):
            groups = root_groups(job.graph, job.roots) if self.dedupe else [[root] for root in job.roots]
            if self.dedupe:
                self.dedup_saved += len(job.roots) - len(groups)
            runnable = []
            for group in groups:
                if not self.ipv6 and job.graph.v6_bound(group[0]):
                    unverifiable[job_index] += len(group)
                    continue
                runnable.append(group)
            plans.append(runnable)
        entries = [(job_index, job, group[0])
                   for job_index, job in enumerate(jobs) for group in plans[job_index]]
        accepted, invalid = [], []
        with tempfile.TemporaryDirectory(prefix="actions-probe-") as temp:
            directory = private_dir(temp)
            secret = secrets.token_urlsafe(24)
            self._assess_entries(directory, entries, secret, accepted, invalid)
            if accepted:
                document, lanes = self._export_entries(accepted)
                ports = unused_ports(len(lanes) + 1)
                controller = ports[-1]
                config = kernel_config_document(document, lanes, ports[:-1], controller, secret)
                private_write(Path(directory) / "config.yaml", canonical(config))
                if len(accepted) != len(entries) and not self.validate(directory, config):
                    raise ProbeError("kernel_config_failure")
                evidence, degraded, skipped = self._run_kernel(directory, list(zip(lanes, ports[:-1])), controller, secret, degrade_end=True)
            else:
                evidence, degraded, skipped = [], False, set()
        self.merged_groups += 1
        outcome = {(entry[0], entry[2]): evidence[index] for index, entry in enumerate(accepted)}
        rejected = {(accepted[index][0], accepted[index][2]) for index in skipped}
        invalid_keys = {(job_index, root) for job_index, job, root in invalid}
        results = []
        for job_index, job in enumerate(jobs):
            invalid_count = sum(len(group) for group in plans[job_index]
                                if (job_index, group[0]) in invalid_keys)
            prefiltered = sum(len(group) for group in plans[job_index]
                              if (job_index, group[0]) in rejected)
            measured = []
            for group in plans[job_index]:
                value = outcome.get((job_index, group[0]))
                if value is None:
                    continue
                item, delay = value
                if item is None or item is DIRECT_LEAK:
                    if degraded and (job_index, group[0]) in outcome:
                        unverifiable[job_index] += len(group)
                    continue
                ip, cc, version = item
                for root in group:
                    measured.append(Measurement(root, ip, cc, version, delay))
            results.append((measured, invalid_count, unverifiable[job_index], prefiltered))
        return results

    def measure_jobs(self, jobs, batch=0):
        """Measure prepared sources, merging several into one kernel.

        ``batch`` (or the instance ``kernel_batch``) bounds how many sources
        share a kernel; 0 means all of them. The first group is the whole
        round, so 38 kernel starts collapse into one.
        """
        if not jobs:
            return []
        size = self.kernel_batch or int(batch or 0)
        chunks = ([list(range(start, min(start + size, len(jobs)))) for start in range(0, len(jobs), size)]
                  if size > 0 else [list(range(len(jobs)))])
        outcomes = [None] * len(jobs)
        for chunk in chunks:
            if len(chunk) == 1:
                job = jobs[chunk[0]]
                outcomes[chunk[0]] = tuple(self(job.graph, job.roots)) + (0,)
                continue
            try:
                group = self._measure_group([jobs[index] for index in chunk])
            except Exception:
                group = None
            if group is None:
                # A shared kernel failed as a whole (start/validation). Fall
                # back to one kernel per source: attribution and the node
                # contract matter more than the saved startup time.
                for index in chunk:
                    job = jobs[index]
                    outcomes[index] = tuple(self(job.graph, job.roots)) + (0,)
            else:
                for index, value in zip(chunk, group):
                    outcomes[index] = value
        return outcomes

    def __call__(self, graph, roots):
        groups = root_groups(graph, roots) if self.dedupe else [[root] for root in roots]
        if self.dedupe:
            self.dedup_saved += len(roots) - len(groups)
        measurable, unverifiable = [], 0
        for group in groups:
            if not self.ipv6 and graph.v6_bound(group[0]):
                # Unreachable FROM THIS HOST, not proven dead. Do not spend a
                # timeout on it and do not let it count as a dead node.
                unverifiable += len(group)
                continue
            measurable.append(group)
        reps = [group[0] for group in measurable]
        accepted, invalid = [], []
        with tempfile.TemporaryDirectory(prefix="actions-probe-") as temp:
            directory = private_dir(temp)
            secret = secrets.token_urlsafe(24)
            # Unsupported protocols and unusable definitions are isolated by
            # batch bisection; an unhealthy root cannot poison its source.
            self._assess(directory, graph, reps, secret, accepted, invalid)
            if not accepted:
                invalid_set = set(invalid)
                count = sum(len(group) for group in measurable if group[0] in invalid_set)
                return [], count, unverifiable
            ports = unused_ports(len(accepted) + 1)
            controller = ports[-1]
            cfg = kernel_config(graph, accepted, ports[:-1], controller, secret)
            # Popen reads directory/config.yaml, and the last writer was
            # _assess with the BATCH config (different ports). Materialize the
            # final body unconditionally: skipping validation must not skip the
            # write, or the kernel listens on the batch ports while readiness
            # polls the new controller port.
            private_write(Path(directory) / "config.yaml", canonical(cfg))
            # _assess already validated every accepted root. The only difference
            # here is the listener port numbers, and ``-t`` does not bind them,
            # so re-validating the identical node set is a second kernel start
            # per source that buys no new evidence. Only re-check when the batch
            # had to be split (something was rejected), where the combined body
            # has genuinely never been tested.
            if len(accepted) != len(reps) and not self.validate(directory, cfg):
                raise ProbeError("kernel_config_failure")
            evidence, degraded, _skipped = self._run_kernel(directory, list(zip(accepted, ports[:-1])), controller, secret)
        index_of = {root: index for index, root in enumerate(accepted)}
        invalid_set = set(invalid)
        invalid_count = sum(len(group) for group in measurable if group[0] in invalid_set)
        measured = []
        for group in measurable:
            index = index_of.get(group[0])
            if index is None:
                continue
            item, delay = evidence[index]
            if item is None or item is DIRECT_LEAK:
                # A kernel that died at the end cannot turn its own silence
                # into death evidence; the round's positives still stand.
                if degraded:
                    unverifiable += len(group)
                continue
            ip, cc, version = item
            for root in group:
                measured.append(Measurement(root, ip, cc, version, delay))
        return measured, invalid_count, unverifiable


def egress_key(ip):
    """Dedup key for a measured exit: the IPv4 egress address.

    An IPv6-only exit still needs a stable key, so mapped IPv4 and IPv6
    literals both collapse to their canonical address text; anything that is
    not a literal address falls back to the raw string (still deduplicated).
    """
    try:
        return str(ipaddress.ip_address(str(ip)))
    except ValueError:
        return str(ip)


def root_groups(graph, roots):
    """Group interchangeable roots by connection fingerprint.

    Two nodes with the same resolved connection are the SAME dial: the
    fingerprint excludes only presentation annotations (name, delay, ...).
    Measuring one and replicating the verdict is exact, not a guess, and a
    source with 21 duplicate definitions (real data) stops paying 21 dials.
    Roots whose definition cannot be resolved stay in their own group so
    validation can reject them individually.
    """
    groups, order = {}, []
    for root in roots:
        try:
            key = graph.identity(root)
        except ProbeError:
            key = ("unresolved", root)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(root)
    return [groups[key] for key in order]


def landing_class(graph, root, exit_ip):
    """Whether the measured exit is the node's own ``server`` literal.

    * ``same``    - server is an IP literal and the exit is that address.
    * ``transit`` - server is an IP literal but the exit differs: a relay,
                     CDN front or tunnel. Legitimate, annotated, never deleted.
    * ``unknown`` - server is a hostname, the root has a dialer chain, or the
                     definition does not expose a literal server.
    """
    node = graph.nodes.get(root) if isinstance(getattr(graph, "nodes", None), dict) else None
    if not isinstance(node, dict):
        return "unknown"
    try:
        if graph.dependency(node):
            return "unknown"
    except ProbeError:
        return "unknown"
    server = node.get("server")
    if not isinstance(server, str) or not server:
        return "unknown"
    try:
        ipaddress.ip_address(server)
    except ValueError:
        return "unknown"
    return "same" if egress_key(server) == egress_key(exit_ip) else "transit"


def landing_counts(graph, measurements):
    counts = {"same": 0, "transit": 0, "unknown": 0}
    for item in measurements:
        counts[landing_class(graph, item.name, item.ip)] += 1
    return counts


def asn_class_counts(measurements):
    counts = {}
    for item in measurements:
        geo = geo_naming.RESOLVER.entry(item.ip, item.cc)
        label = geo_naming.classify_asn(geo.get("asn") or 0, geo.get("org") or "")
        counts[label] = counts.get(label, 0) + 1
    return counts


def _percentile(values, fraction):
    values = sorted(value for value in values if value > 0)
    if not values:
        return 0
    index = min(len(values) - 1, max(0, int(round(fraction * (len(values) - 1)))))
    return int(values[index])


def delay_stats(measurements):
    delays = [item.delay_ms for item in measurements if item.delay_ms > 0]
    return _percentile(delays, 0.5), _percentile(delays, 0.9)


def choose_measurements(source, graph, measurements):
    """One surviving node per IPv4 egress, for EVERY source.

    Previously only GlaDOS was collapsed by exit and every other source
    republished the same egress many times under -2/-3/-4 suffixes. Dedup is
    now universal and ordered, not protocol-based filtering:

      1. group by measured exit address;
      2. within a group prefer ``ss`` (cheapest to keep alive), then a stable
         connection fingerprint, so the winner does not move between rounds;
      3. sort the winners by fingerprint for deterministic output.
    """
    by_exit = {}
    for item in measurements:
        key = (0 if str(graph.nodes[item.name].get("type", "")).lower() == "ss" else 1,
               graph.identity(item.name), item.name)
        bucket = egress_key(item.ip)
        if bucket not in by_exit or key < by_exit[bucket][0]:
            by_exit[bucket] = (key, item)
    return [value[1] for _, value in sorted(by_exit.items())]


COUNTRY_ZH = geo_naming.COUNTRY_ZH


def _flag(cc):
    return geo_naming._flag(cc)


def _display_parts(measurement):
    """Candidate names for a measurement, most specific first."""
    return geo_naming.RESOLVER.display_parts(measurement.ip, measurement.cc)


def _display_name(measurement):
    return _display_parts(measurement)[0]


def _prefetch_geo(measurements):
    geo_naming.prefetch([(item.ip, item.cc) for item in measurements])


def _suffix(ip, width=3):
    """Stable short discriminator for an exit.

    A repeated display name must never fall back to a sequential counter: the
    old ``-2``/``-3`` numbers depended on how many siblings were alive, so the
    same node changed name between rounds. This is derived from the egress
    address only and is separated by ``@`` so it can never be confused with a
    counter.
    """
    return _stable_tag(egress_key(ip), width)


def _stable_tag(seed, width=3):
    """Base36 discriminator from any stable seed (egress IP or connection fp).

    The ``@`` separator keeps it distinct from a numeric suffix and from the
    old 8-hex merger tag, so an audit can assert zero ``-N``/``-hex`` names.
    """
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    value = int(digest(str(seed))[:12], 16)
    out = ""
    for _ in range(width):
        value, rem = divmod(value, len(alphabet))
        out = alphabet[rem] + out
    return "@" + out


def source_output(source, graph, measurements):
    selected = choose_measurements(source, graph, measurements)
    _prefetch_geo(selected)
    roots = [item.name for item in selected]
    nodes, groups = graph.closure(roots)
    namespace = digest(source)[:16]
    names = {name: "__front-" + namespace + "-" + graph.identity(name)[:20] for name in nodes}
    names.update({name: "G-" + namespace + "-" + graph.identity(name)[:20] for name in groups})
    exit_of = {item.name: item.ip for item in selected}
    candidates = {item.name: _display_parts(item) for item in selected}
    # Names must be unique inside one subscription. Walk from the most specific
    # geographic candidate to the least specific one and take the first that is
    # still free; only if every level collides do we append "-2", "-3", ...
    # Ordinals are assigned in egress-IP order (the sort key below), so a node
    # keeps its number across rounds as long as its exit siblings do not change.
    # The old bug was numbering by *surviving sibling count*, which made names
    # jump whenever a sibling died; sorting by a stable key avoids that.
    taken = set()
    for item in sorted(selected, key=lambda entry: (len(candidates[entry.name]),
                                                    candidates[entry.name][0],
                                                    egress_key(exit_of[entry.name]))):
        chosen = ""
        for candidate in candidates[item.name]:
            if candidate not in taken:
                chosen = candidate
                break
        if not chosen:
            base = candidates[item.name][-1]
            index = 2
            unique = "%s-%d" % (base, index)
            while unique in taken:
                index += 1
                unique = "%s-%d" % (base, index)
            chosen = unique
        taken.add(chosen)
        names[item.name] = chosen
    return canonical(graph.export(roots, names)), len(selected)


def runner_exit_ip(transport):
    """The runner's own egress address, or None when it cannot be determined.

    One direct request, no proxy. This is the baseline that lets the probe tell
    "the node carried the traffic" from "the request leaked out of the runner"
    (a config bug or a silent DIRECT fallback). A failure is not fatal: the
    check is skipped rather than guessed.
    """
    try:
        raw, _ = transport("GET", TRACE_URL)
        ip, cc = parse_trace(raw.decode("utf-8", "replace"))
        return ip
    except Exception:
        return None


def front_health(config, probe):
    """Whether the shared front can be dialled this round (None = not judged).

    Front nodes are copied into every dependent source's closure, so from
    inside those sources a dead front looks exactly like dead nodes. Measuring
    the front once per round is what makes the difference visible.
    """
    try:
        graph = Graph(dedupe_names(config))
        roots = [item["name"] for item in config.get("proxies") or [] if isinstance(item, dict)]
        if not roots:
            return None
        measurements, _, _ = probe(graph, roots)
        return bool(measurements)
    except Exception:
        return None


def prepare_source(name, config, front, probe):
    """Resolve one source's graph and front attribution before any dial."""
    graph = Graph(dedupe_names(config), front)
    roots = [item["name"] for item in config["proxies"]]
    # Nodes the FRONT supplies (the source's own definitions win). A root
    # that reaches one of them cannot be blamed for its own failures.
    front_only = set()
    if front:
        own = {item.get("name") for item in config.get("proxies", []) if isinstance(item, dict)}
        front_only = {item.get("name") for item in front.get("proxies", []) if isinstance(item, dict)} - own
    job = SourceJob(name, config, graph, roots, front_only,
                    graph.front_backed(roots, front_only))
    # Roots this host could not dial for lack of IPv6, handed to the helper.
    if getattr(probe, "ipv6", True) is False:
        job.v6_roots = [root for root in roots if graph.v6_bound(root)]
    return job


def finish_source(job, measurements, invalid, unverifiable, prefiltered=0):
    """Turn a job's raw outcome into a SourceResult and its published body."""
    result = SourceResult(job.name, input=len(job.config.get("proxies", [])))
    result.uses_front = job.uses_front
    result.alive = len(measurements)
    result.measurements = list(measurements)
    result.v6_roots = list(job.v6_roots)
    result.invalid = invalid
    result.unverifiable = unverifiable
    result.prefiltered = prefiltered
    result.measured = max(0, len(job.roots) - invalid - unverifiable)
    result.unique_egress = len({egress_key(item.ip) for item in measurements})
    # HTTP/1.1-only exits are kept (some clients and nodes are h1 only) but
    # counted, so a downgraded middlebox shows up in the manifest instead of
    # looking identical to a healthy h2 node.
    result.http1 = sum(1 for item in measurements
                       if item.http_version and not item.http_version.startswith("2"))
    for item in measurements:
        result.countries[item.cc] = result.countries.get(item.cc, 0) + 1
    # Geolocation answered ASN+brand for these exits; prefetching before the
    # audit fields reuses the same per-IP cache (source_output would fetch it
    # anyway). Offline (lookup disabled) degrades to "unknown", never raises.
    _prefetch_geo(measurements)
    result.asn_class = asn_class_counts(measurements)
    result.landing = landing_counts(job.graph, measurements)
    result.delay_median_ms, result.delay_p90_ms = delay_stats(measurements)
    # A missing dependency is a per-node validation failure, never stripped.
    result.content, result.published = source_output(job.name, job.graph, measurements)
    return result


def failed_source(name, config, exc):
    result = SourceResult(name, input=len(config.get("proxies", [])) if isinstance(config, dict) else 0)
    result.failed = True
    result.error = error_code(exc)
    return result


def measure_source(name, config, front, probe):
    try:
        job = prepare_source(name, config, front, probe)
        measurements, invalid, unverifiable = probe(job.graph, job.roots)
        return finish_source(job, measurements, invalid, unverifiable)
    except Exception as exc:
        return failed_source(name, config, exc)


def measure_all(sources, configs, front, probe):
    """Measure every fetched source, sharing one kernel when the probe can.

    A probe without ``measure_jobs`` (tests, alternative backends) keeps the
    one-kernel-per-source contract. The merged path is opt-in by capability:
    any group-level failure is retried per source inside the probe, and a
    per-source outcome that cannot be produced at all is marked failed so the
    gates preserve the old artifact instead of inventing death evidence.
    """
    order, jobs, failed = [], [], {}
    for name in sources:
        if name not in configs:
            continue
        order.append(name)
        try:
            jobs.append(prepare_source(name, configs[name], front, probe))
        except Exception as exc:
            failed[name] = failed_source(name, configs[name], exc)
    outcomes = None
    if len(jobs) > 1 and hasattr(probe, "measure_jobs"):
        try:
            outcomes = probe.measure_jobs(jobs, getattr(probe, "kernel_batch", 0))
        except Exception:
            outcomes = None
    results = {}
    if outcomes is not None and len(outcomes) == len(jobs):
        for job, outcome in zip(jobs, outcomes):
            if outcome is None:
                try:
                    outcome = probe(job.graph, job.roots)
                except Exception:
                    outcome = None
            if outcome is None:
                results[job.name] = failed_source(job.name, job.config,
                                                  ProbeError("kernel_execution_failure"))
                continue
            try:
                prefiltered = outcome[3] if len(outcome) > 3 else 0
                results[job.name] = finish_source(job, *outcome[:3], prefiltered=prefiltered)
            except Exception as exc:
                results[job.name] = failed_source(job.name, job.config, exc)
    else:
        for job in jobs:
            try:
                results[job.name] = finish_source(job, *probe(job.graph, job.roots))
            except Exception as exc:
                results[job.name] = failed_source(job.name, job.config, exc)
    results.update(failed)
    return [results[name] for name in order]


def merge_sources(contents, corrupt=None):
    """Dedup tested roots by resolved connection, retain independent namespaces.

    A single unparsable retained artifact (truncated upload, hand edit,
    ``proxies: null``) is skipped when ``corrupt`` is supplied, and its name is
    appended to that list. Without it the old behaviour is kept and the error
    propagates. One bad file used to abort every publication, every round.
    """
    choices = {}
    for filename, text in sorted(contents.items()):
        try:
            doc = yaml.safe_load(text)
            if not isinstance(doc, dict) or not isinstance(doc.get("proxies"), list):
                raise ProbeError("old_content_invalid")
            graph = Graph(doc)
            for node in doc["proxies"]:
                name = node["name"]
                if name.startswith("__front-"):
                    continue
                fp = graph.identity(name)
                choices.setdefault(fp, (filename, graph, name))
        except (ProbeError, yaml.YAMLError, TypeError, ValueError, KeyError, AttributeError) as exc:
            if corrupt is None:
                raise ProbeError("old_content_invalid") from exc
            corrupt.append(filename)
    merged_nodes, merged_groups = {}, {}
    for fp in sorted(choices):
        _, graph, root = choices[fp]
        doc = graph.export([root])
        rename = {}
        for key, target in (("proxies", merged_nodes), ("proxy-groups", merged_groups)):
            for item in doc.get(key, []):
                name = item["name"]
                old = target.get(name)
                if old is not None and old != item:
                    # Ordinal suffix under fp-sorted iteration: the first
                    # holder keeps the base name, later collisions get -2,
                    # -3, ... Stable as long as the source set is unchanged.
                    index = 2
                    candidate = "%s-%d" % (name, index)
                    while candidate in target or candidate in rename.values():
                        index += 1
                        candidate = "%s-%d" % (name, index)
                    rename[name] = candidate
        if rename:
            for key in ("proxies", "proxy-groups"):
                for item in doc.get(key, []):
                    item["name"] = rename.get(item["name"], item["name"])
                    if "dialer-proxy" in item:
                        item["dialer-proxy"] = rename.get(item["dialer-proxy"], item["dialer-proxy"])
                    if "proxies" in item:
                        item["proxies"] = [rename.get(value, value) for value in item["proxies"]]
        for key, target in (("proxies", merged_nodes), ("proxy-groups", merged_groups)):
            for item in doc.get(key, []):
                target[item["name"]] = item
    result = {"proxies": [merged_nodes[name] for name in sorted(merged_nodes)]}
    if merged_groups:
        result["proxy-groups"] = [merged_groups[name] for name in sorted(merged_groups)]
    return canonical(result)


#: Consecutive failing rounds a source must accumulate before its artifact is
#: replaced by the reduced measurement or dropped entirely. One bad round is
#: never enough: a transient network failure must not empty a subscription.
BAD_STREAK_LIMIT = 2

#: Upper bound on the consecutive "no node-level evidence" counter. It is
#: carried to the Gist because an unjudgeable source must be visible, but a
#: permanently unprovable one (a dead front nobody can measure) must stop
#: creating revisions of its own after a couple of days.
UNPROVEN_ROUNDS_CAP = 9


#: Connection fingerprints are sha256 hex; 16 characters is enough of a key to
#: identify a node in the persisted name table without storing 64 bytes each.
NAME_KEY_LEN = 16


def _free_name(desired, used):
    """``desired`` if free, else the smallest free ``base-N`` (2, 3, ...)."""
    if desired not in used:
        return desired
    base = re.sub(r"-\d+$", "", desired)
    index = 2
    candidate = "%s-%d" % (base, index)
    while candidate in used:
        index += 1
        candidate = "%s-%d" % (base, index)
    return candidate


def freeze_names(documents, tables):
    """Give every root a name that persists across rounds.

    The old contract derived the disambiguator from *this round's* sibling set
    and from per-round geolocation, so a node changed name whenever a sibling
    died, a lookup timed out or a new source appeared (339 of 534 published
    names were ordinals). Names are now allocated once and stored per published
    file, then reused forever. A brand-new connection takes the smallest free
    ordinal next to its display name, so the published shape stays ``-2``/
    ``-3`` instead of some opaque tag.

    ``documents`` maps scope -> YAML text and ``tables`` maps scope ->
    ``{fingerprint: name}`` (updated in place). Each published file is its own
    namespace: the same connection may legitimately carry a different name in
    its source file and in the merged subscription, and both must be stable.

    Returns ``(frozen_documents, {scope: seen_keys})``.
    """
    frozen_docs, seen = {}, {}
    for scope, text in sorted(documents.items()):
        table = tables.get(scope)
        if not isinstance(table, dict):
            table = tables[scope] = {}
        used = {value for value in table.values() if isinstance(value, str) and value}
        keys = set()
        try:
            doc = yaml.safe_load(text)
            if not isinstance(doc, dict) or not isinstance(doc.get("proxies"), list):
                frozen_docs[scope] = text
                seen[scope] = keys
                continue
            graph = Graph(doc)
        except (ProbeError, yaml.YAMLError, TypeError, ValueError):
            frozen_docs[scope] = text
            seen[scope] = keys
            continue
        roots, rename, occurrences = [], {}, {}
        # Pass 1: honour every name already frozen. The reserved names of front
        # nodes and groups are derived from their own fingerprint and are
        # already stable, so they are left alone.
        for item in doc["proxies"]:
            name = item.get("name") if isinstance(item, dict) else None
            if not isinstance(name, str) or name.startswith("__front-"):
                continue
            try:
                base = graph.identity(name)[:NAME_KEY_LEN]
            except ProbeError:
                continue
            # A source may legitimately carry two nodes with an identical
            # connection (same fingerprint, different labels). They are
            # interchangeable but must keep distinct names, so the k-th
            # occurrence gets its own key instead of collapsing onto the first.
            seen_count = occurrences.get(base, 0)
            occurrences[base] = seen_count + 1
            key = base if seen_count == 0 else "%s~%d" % (base, seen_count)
            roots.append((name, key))
            keys.add(key)
            stored = table.get(key)
            if isinstance(stored, str) and stored:
                used.add(stored)
                if stored != name:
                    rename[name] = stored
        # Pass 2: a connection seen for the first time takes its current display
        # name when free, otherwise the next ordinal. This is the only moment a
        # name is ever chosen, so later rounds cannot move it.
        for name, key in roots:
            if isinstance(table.get(key), str) and table.get(key):
                continue
            chosen = _free_name(rename.get(name, name), used)
            table[key] = chosen
            used.add(chosen)
            if chosen != name:
                rename[name] = chosen
        seen[scope] = keys
        if not rename:
            frozen_docs[scope] = text
            continue
        for field in ("proxies", "proxy-groups"):
            for item in doc.get(field) or []:
                if not isinstance(item, dict):
                    continue
                if item.get("name") in rename:
                    item["name"] = rename[item["name"]]
                if item.get("dialer-proxy") in rename:
                    item["dialer-proxy"] = rename[item["dialer-proxy"]]
                refs = item.get("proxies")
                if isinstance(refs, list):
                    item["proxies"] = [rename.get(value, value) for value in refs]
        frozen_docs[scope] = canonical(doc)
    return frozen_docs, seen


def prune_names(tables, seen):
    """Drop name entries that no longer appear in any published file.

    Bounded growth without per-round churn: entries survive while the tables
    are small and are dropped only once they outgrow the live set by 2x (or
    1000 connections). A pruned connection that returns gets a new name -- the
    only case in which that can still happen.
    """
    live = sum(len(keys) for keys in seen.values())
    total = sum(len(table) for table in tables.values() if isinstance(table, dict))
    if total <= max(1000, 2 * live):
        return tables
    pruned = {}
    for scope, table in tables.items():
        if not isinstance(table, dict):
            continue
        keep = seen.get(scope) or set()
        kept = {key: value for key, value in table.items() if key in keep}
        if kept:
            pruned[scope] = kept
    return pruned


def load_name_table(text):
    """Read the persisted ``scope -> {fingerprint: name}`` map from the manifest."""
    try:
        document = json.loads(text or "{}")
    except (ValueError, TypeError):
        return {}
    if not isinstance(document, dict):
        return {}
    raw = document.get("names")
    if not isinstance(raw, dict):
        return {}
    tables = {}
    for scope, entries in raw.items():
        if not isinstance(scope, str) or not scope or not isinstance(entries, dict):
            continue
        tables[scope] = {key: value for key, value in entries.items()
                         if isinstance(key, str) and key
                         and isinstance(value, str) and value}
    return tables


def plan_updates(results, old):
    try:
        old_manifest = json.loads(old.get("manifest.json", "{}"))
        if not isinstance(old_manifest, dict):
            raise ValueError
        previous = old_manifest.get("sources", {})
        if not isinstance(previous, dict):
            raise ValueError
    except (ValueError, TypeError):
        raise ProbeError("manifest_invalid") from None
    # The persisted name table: scope -> {fingerprint: published name}. Absent
    # in older manifests, which is the one moment names are seeded -- and they
    # are seeded from what is ALREADY published, not from this round's
    # recomputation: the migration round can coincide with a source being
    # dropped, and renumbering the survivors then would defeat the freeze.
    names = load_name_table(old.get("manifest.json", ""))
    migrating = not isinstance(old_manifest.get("names"), dict)
    name_keys = {}
    if migrating:
        published = {name: text for name, text in old.items() if SOURCE_FILE.fullmatch(name)}
        published["merged"] = old.get("mihomo-alive.yaml", "")
        _, seeded = freeze_names(published, names)
        name_keys.update(seeded)
    # Deliberately retain remote sources absent from today's authoritative selection,
    # except artifacts that were produced by measuring our own published files
    # (a `gist-` source). Those are self-referential and must not survive a fix
    # to the source filter, otherwise the feedback loop lives on in the manifest.
    effective = {key: value for key, value in old.items() if SOURCE_FILE.fullmatch(key)}
    manifest = {"version": 1, "sources": copy.deepcopy(previous)}
    dropped = set()
    for filename in list(manifest["sources"]):
        stored = manifest["sources"][filename].get("name", "")
        if isinstance(stored, str) and stored.lower().startswith("gist-"):
            manifest["sources"].pop(filename, None)
            effective.pop(filename, None)
    for result in results:
        filename = source_file(result.name)
        last = previous.get(filename, {})
        prior_alive = last.get("last_success_alive", last.get("alive", last.get("published", 0)))
        try:
            prior_alive = max(0, int(prior_alive))
        except (ValueError, TypeError):
            raise ProbeError("manifest_invalid") from None
        # An older valid file without metadata still receives a conservative gate.
        if not prior_alive and filename in effective:
            doc = yaml.safe_load(effective[filename])
            # A truncated or hand-edited artifact must not abort the round: the
            # baseline is unknown, so it falls back to 0 and the normal gate
            # applies instead of raising AttributeError on None forever.
            if isinstance(doc, dict):
                prior_alive = sum(not item.get("name", "").startswith("__front-") for item in doc.get("proxies") or [])
        try:
            streak = max(0, int(last.get("bad_streak", 0)))
        except (ValueError, TypeError):
            streak = 0
        try:
            unproven_rounds = max(0, int(last.get("unproven_rounds", 0)))
        except (ValueError, TypeError):
            unproven_rounds = 0
        # Death evidence. A node counts as dead only when THIS round dialled it
        # and the attempt failed. A source we could not fetch, a source whose
        # nodes hang off a dead front, and a node that needs IPv6 on an
        # IPv4-only host are all UNPROVEN: they must never delete a node.
        #
        # ``measured > 0`` is load-bearing. Batch validation can reject every
        # root without dialling a single one (an unsupported field, a kernel
        # version change, a ``-t`` timeout, one shared broken dependency). That
        # is "these could not be judged", not "these are dead" -- treating it
        # as death deleted healthy sources two rounds after a parse regression.
        proven_dead = (not result.failed
                       and result.measured > 0
                       and result.alive == 0
                       and result.unverifiable == 0
                       and (not result.uses_front or result.front_alive is True))
        if result.failed:
            accept, guard = False, "source_failure"
        elif result.alive > 0:
            # A smaller set may only replace the artifact when every missing
            # node was actually dialled and failed. Nodes this host cannot
            # reach (no IPv6) and a front that was never proven healthy are not
            # evidence, and publishing the reduced set would delete them --
            # exactly what the node-level contract forbids.
            unproven = result.unverifiable > 0 or (result.uses_front and result.front_alive is not True)
            if unproven and result.alive < prior_alive:
                accept, guard, streak = False, "unproven_hold", streak
            elif prior_alive and result.alive < prior_alive * 0.5:
                # Severely reduced. The surviving set is node-level truth, but
                # a single bad round must not shrink a good subscription: the
                # reduced set replaces the old one only after the second
                # consecutive reduced round.
                streak += 1
                accept = streak >= BAD_STREAK_LIMIT
                guard = "degraded" if accept else "ratio_drop"
            else:
                accept, guard, streak = True, "accepted", 0
        elif proven_dead:
            # Every node this round could judge failed. The artifact is
            # dropped so its dead nodes leave the subscription; the grace
            # period keeps one bad round from doing that.
            streak += 1
            accept = False
            guard = "confirmed_dead" if streak >= BAD_STREAK_LIMIT else "zero_alive"
        elif result.measured == 0:
            # Nothing was dialled: no root passed configuration validation, or
            # every root needs a host capability this runner lacks. Neither is
            # death evidence, so the artifact is kept and bad_streak stays put.
            accept = False
            guard = "unverifiable" if result.unverifiable else "not_dialled"
        else:
            accept = False
            if result.uses_front and result.front_alive is not True:
                # The front may be the only reason these nodes failed. Keep the
                # artifact (the node contract), but advance a separate counter:
                # a front nobody measures used to freeze bad_streak at zero
                # forever, so a genuinely dead source looked identical to an
                # unprovable one and never surfaced.
                guard = "front_unproven"
            else:
                guard = "unverifiable" if result.unverifiable else "zero_alive"
        if accept:
            try:
                candidate = yaml.safe_load(result.content)
                graph = Graph(candidate)
                roots = [item["name"] for item in candidate["proxies"]
                         if not item["name"].startswith("__front-")]
                graph.closure(roots)
                accept = bool(roots) and len(roots) == result.published and result.published <= result.alive
            except Exception:
                accept = False
            if not accept:
                guard = "candidate_invalid"
        # Consecutive rounds that produced no node-level evidence at all
        # (unmeasurable nodes, unprovable front). Kept separate from bad_streak,
        # which only counts proven failures, so a source nobody can judge
        # becomes visible without ever being deleted. A fetch failure advances
        # nothing: it is transient and must not create revision noise (it is
        # already visible as ``guard=source_failure``).
        if result.alive > 0 or proven_dead:
            unproven_rounds = 0
        elif not result.failed:
            unproven_rounds = min(UNPROVEN_ROUNDS_CAP, unproven_rounds + 1)
        if guard == "confirmed_dead" and streak >= BAD_STREAK_LIMIT:
            # Node-level cleanup: the dead nodes leave the subscription and the
            # source file is removed on the same PATCH.
            effective.pop(filename, None)
            dropped.add(filename)
            manifest["sources"][filename] = {
                "name": result.name, "input": result.input, "alive": 0,
                "published": 0, "last_success_alive": 0,
                "preserved": False, "guard": "confirmed_dead",
                "measured": result.measured, "invalid": result.invalid,
                "unverifiable": result.unverifiable, "bad_streak": streak,
                "unproven_rounds": unproven_rounds, "http1": result.http1,
                "uses_front": result.uses_front,
                "delay_median_ms": result.delay_median_ms,
                "delay_p90_ms": result.delay_p90_ms,
                "landing": result.landing, "asn_class": result.asn_class,
                "prefiltered": result.prefiltered,
            }
            continue
        if accept:
            effective[filename] = result.content
        published = result.published if accept else last.get("published", prior_alive)
        manifest["sources"][filename] = {
            "name": result.name, "input": result.input, "alive": result.alive,
            "published": published, "last_success_alive": result.alive if accept else prior_alive,
            "preserved": not accept, "guard": guard,
            "measured": result.measured, "invalid": result.invalid,
            "unverifiable": result.unverifiable, "bad_streak": streak,
            "unproven_rounds": unproven_rounds, "http1": result.http1,
            "uses_front": result.uses_front,
            "delay_median_ms": result.delay_median_ms,
            "delay_p90_ms": result.delay_p90_ms,
            "landing": result.landing, "asn_class": result.asn_class,
            "prefiltered": result.prefiltered,
        }
    # Freeze names for the sources published this round, then for the merged
    # projection (which also covers retained artifacts rendered by an older
    # version). Only a connection seen for the first time can receive a new
    # name; everything already in the table keeps it forever.
    if effective:
        # Every published file, including preserved ones: a retained artifact
        # already carries frozen names, so this is a no-op for it while its
        # connections still count as live for pruning.
        frozen, seen = freeze_names(dict(effective), names)
        effective.update(frozen)
        name_keys.update(seen)
    corrupt = []
    if effective:
        merged = merge_sources(effective, corrupt)
        for filename in corrupt:
            # Quarantine instead of aborting the round: drop the unusable
            # artifact from the plan (deleted on the same PATCH) and record the
            # reason. Retaining it would poison every future merge.
            effective.pop(filename, None)
            previous_entry = manifest["sources"].get(filename, {})
            manifest["sources"][filename] = {
                "name": previous_entry.get("name", ""), "input": 0, "alive": 0,
                "published": 0, "last_success_alive": 0, "preserved": False,
                "guard": "old_content_invalid", "corrupt": True,
                "measured": 0, "invalid": 0, "unverifiable": 0,
                "bad_streak": 0, "unproven_rounds": 0, "uses_front": False,
                "delay_median_ms": 0, "delay_p90_ms": 0,
                "landing": {}, "asn_class": {}, "prefiltered": 0,
            }
    if not effective:
        # Nothing usable remains. Every source proven dead means the merged body
        # must drop the nodes too; anything else (including a round whose only
        # artifacts were corrupt) keeps the previous body instead of writing an
        # empty subscription over it.
        merged = (canonical({"proxies": []}) if dropped
                  else old.get("mihomo-alive.yaml", canonical({"proxies": []})))
    merged_doc, merged_seen = freeze_names({"merged": merged}, names)
    merged = merged_doc["merged"]
    name_keys.update(merged_seen)
    manifest["names"] = prune_names(names, name_keys)
    for filename, content in effective.items():
        entry = manifest["sources"].setdefault(filename, {})
        entry["sha256"] = digest(content)
    manifest["sha256"] = digest(merged)
    files = dict(effective)
    files["mihomo-alive.yaml"] = merged
    files["manifest.json"] = json_text(manifest)
    return files


def manifest_state_changed(old_text, new_text) -> bool:
    """True when the manifest carries state the next round's decision needs.

    The survival baseline (``last_success_alive``) and the grace counter
    (``bad_streak``) decide whether a source is republished or dropped, so
    they must reach the Gist. ``unproven_rounds`` is carried too: without it an
    unjudgeable source is invisible (the counter would reset to 0 every round
    because it never persisted). It is capped, so a permanently unprovable
    source stops creating revisions after a couple of days. The name table also
    has to be seeded once: on the first round after the upgrade every allocated
    name equals the current one, so nothing else would change and the table
    would never persist. Audit-only fields (guard, preserved, counts) may lag:
    a failed round must not create a revision on its own.
    """
    try:
        old_doc = json.loads(old_text or "{}")
        new_doc = json.loads(new_text or "{}")
        old = old_doc.get("sources", {})
        new = new_doc.get("sources", {})
    except (ValueError, TypeError, AttributeError):
        return True
    if not isinstance(old, dict) or not isinstance(new, dict):
        return True
    if new_doc.get("names") and not old_doc.get("names"):
        return True
    for key, entry in new.items():
        previous = old.get(key)
        if not isinstance(entry, dict):
            continue
        if not isinstance(previous, dict):
            if (entry.get("last_success_alive") or entry.get("bad_streak")
                    or entry.get("unproven_rounds")):
                return True
            continue
        if entry.get("last_success_alive") != previous.get("last_success_alive"):
            return True
        if (entry.get("bad_streak") or 0) != (previous.get("bad_streak") or 0):
            return True
        if (entry.get("unproven_rounds") or 0) != (previous.get("unproven_rounds") or 0):
            return True
    for key in old:
        if key not in new:
            return True
    return False


class GistPublisher:
    def __init__(self, gist_id, token, transport):
        gist_id, token = gist_id.strip(), token.strip()
        if not token or any(ch.isspace() for ch in token):
            raise ProbeError("gist_token_invalid")
        if not re.fullmatch(r"[0-9a-fA-F]{5,64}", gist_id):
            raise ProbeError("gist_id_invalid")
        self.url = "https://api.github.com/gists/" + gist_id
        self.headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        self.transport = transport

    def current(self):
        raw, headers = self.transport("GET", self.url, self.headers)
        document = json.loads(raw)
        if document.get("public") is not False:
            raise ProbeError("gist_not_private")
        files = {}
        for name, entry in document.get("files", {}).items():
            if not SOURCE_FILE.fullmatch(name) and name not in {"mihomo-alive.yaml", "manifest.json"}:
                continue
            if entry.get("truncated") or not isinstance(entry.get("content"), str):
                url = entry.get("raw_url", "")
                parts = urllib.parse.urlsplit(url)
                if parts.scheme != "https" or parts.hostname != "gist.githubusercontent.com" or parts.port not in (None, 443) or parts.username:
                    raise ProbeError("gist_raw_invalid")
                content, _ = self.transport("GET", url, self.headers)
                files[name] = content.decode("utf-8")
            else:
                files[name] = entry["content"]
        return files, headers.get("ETag", headers.get("Etag", headers.get("etag")))

    def publish(self, results):
        for attempt in range(3):
            try:
                return self._publish_once(results)
            except ProbeError as exc:
                if error_code(exc) not in {"http_412", "gist_conflict"} or attempt == 2:
                    raise
                # Concurrent change: discard the old plan completely and read
                # current private state again before constructing another PATCH.
        raise ProbeError("gist_conflict")

    def _publish_once(self, results):
        old, _ = self.current()  # No PATCH at all if any read/parse/guard fails.
        files = plan_updates(results, old)
        # A source whose nodes were all proven dead leaves the plan; its file
        # is deleted on the same PATCH so its dead nodes cannot be pulled.
        deletions = {name for name in old if SOURCE_FILE.fullmatch(name) and name not in files}
        if not any(SOURCE_FILE.fullmatch(name) for name in files) and not deletions:
            # A completely failed first run must not create an empty subscription.
            return "no_change", files
        # Compare EVERY canonical YAML, not just the merged projection: another
        # source may already contribute all these same connection fingerprints.
        # Counts/status alone must never produce standalone manifest revisions.
        yaml_updates = {name: {"content": text} for name, text in files.items()
                        if name != "manifest.json" and digest(text) != digest(old.get(name, ""))}
        manifest_changed = digest(files["manifest.json"]) != digest(old.get("manifest.json", ""))
        state_changed = manifest_state_changed(old.get("manifest.json"), files["manifest.json"])
        if not yaml_updates and not deletions and not state_changed:
            return "no_change", files
        updates = dict(yaml_updates)
        # A file dropped from the plan (self-referential artifact cleanup, or a
        # source whose nodes were all proven dead) is deleted on the same
        # PATCH, so the stale subscription cannot be pulled.
        updates.update({name: None for name in deletions})
        if manifest_changed and (yaml_updates or deletions or state_changed):
            updates["manifest.json"] = {"content": files["manifest.json"]}
        # GitHub Gist PATCH rejects If-Match (HTTP 400): no atomic CAS exists
        # for this endpoint. Serialize our writer in Actions. Re-read managed
        # content immediately before PATCH and re-plan on a detected change;
        # this narrows, but cannot eliminate, the cross-writer race window.
        # Unrelated files are excluded from both comparison and PATCH payload.
        latest, _ = self.current()
        if latest != old:
            raise ProbeError("gist_conflict")
        headers = dict(self.headers, **{"Content-Type": "application/json"})
        self.transport("PATCH", self.url, headers, json_text({"files": updates}).encode())
        return "published", files


def read_local(directory):
    files = {}
    for path in directory.iterdir():
        if path.is_file() and (SOURCE_FILE.fullmatch(path.name) or path.name in {"mihomo-alive.yaml", "manifest.json"}):
            files[path.name] = path.read_text(encoding="utf-8")
    return files


def result_reports(results, files=None):
    entries = json.loads(files["manifest.json"]).get("sources", {}) if files else {}
    reports = []
    for item in results:
        state = entries.get(source_file(item.name), {})
        reports.append({"name": item.name, "input": item.input, "alive": item.alive,
                        "dedup_kept": item.published, "published": state.get("published", 0),
                        "failed": item.failed, "preserved": state.get("preserved", True),
                        "guard": state.get("guard", "pending"), "error_code": item.error,
                        "unique_egress": item.unique_egress, "countries": item.countries,
                        "measured": item.measured, "unverifiable": item.unverifiable,
                        "bad_streak": state.get("bad_streak", 0),
                        "http1": item.http1, "uses_front": item.uses_front,
                        "delay_median_ms": item.delay_median_ms,
                        "delay_p90_ms": item.delay_p90_ms,
                        "landing": item.landing, "asn_class": item.asn_class,
                        "prefiltered": item.prefiltered})
    return reports


def _ssh_target(env):
    """``user@host`` for the helper, defaulting the user to root.

    A runner's own account is not root, so the helper's user must be explicit
    or the key is offered to the wrong account and the auth fails.
    """
    host = str(env["PROBE_V6_HELPER"]).strip()
    if "@" in host:
        return host
    user = str(env.get("PROBE_V6_SSH_USER", "root")).strip() or "root"
    return user + "@" + host


def v6_bound_roots(config, front=None):
    """Roots whose dial chain needs an IPv6 literal. Pure graph work, no dial.

    Computed from the fetched config *before* measuring so the helper can start
    at the same time as the runner instead of waiting for it.
    """
    try:
        graph = Graph(dedupe_names(config), front)
    except ProbeError:
        return []
    roots = []
    for item in config.get("proxies") or []:
        name = item.get("name") if isinstance(item, dict) else None
        if isinstance(name, str) and name in graph.nodes and graph.v6_bound(name):
            roots.append(name)
    return roots


def request_v6(jobs, env):
    """Ship one job list to the IPv6 helper and return ``(report, answer)``.

    Runs concurrently with the runner's own measurement: nothing here depends
    on this round's results, only on the fetched configs. ``answer`` is None
    whenever any part of the exchange failed, so a broken helper can never
    change a publication on a guess.
    """
    report = {"ok": False, "judged": 0, "promoted": 0, "error": ""}
    if not jobs:
        report["ok"] = True
        return report, None
    payload = {"mihomo": env.get("PROBE_V6_MIHOMO", "/opt/probe-v6/bin/mihomo"),
               "timeout": int(env.get("PROBE_TIMEOUT", 15)),
               "workers": int(env.get("PROBE_V6_WORKERS", 4)),
               "jobs": jobs}
    command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    # Pin the algorithms. A hardened helper may offer a post-quantum KEX that
    # some clients refuse outright, which shows up as a handshake failure
    # rather than an auth problem.
    command += ["-o", "KexAlgorithms=ecdh-sha2-nistp256,curve25519-sha256",
                "-o", "HostKeyAlgorithms=ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
                "-o", "PubkeyAcceptedAlgorithms=ssh-ed25519"]
    key = env.get("PROBE_V6_SSH_KEY", "").strip()
    if key:
        # The helper is a pinned host: the key file is a secret and the host
        # key is checked against a known_hosts the runner materialises.
        command += ["-i", key, "-o", "IdentitiesOnly=yes"]
    known = env.get("PROBE_V6_SSH_KNOWN_HOSTS", "").strip()
    if known:
        command += ["-o", "UserKnownHostsFile=" + known, "-o", "StrictHostKeyChecking=yes"]
    else:
        command += ["-o", "StrictHostKeyChecking=accept-new"]
    command += ["-p", str(env["PROBE_V6_SSH_PORT"]),
               _ssh_target(env),
               "python3 /opt/probe-v6/scripts/v6_worker.py"]
    try:
        run = subprocess.run(command, input=json_text(payload).encode(),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=int(env.get("PROBE_V6_TIMEOUT", 900)))
    except (OSError, subprocess.SubprocessError):
        report["error"] = "helper_unreachable"
        return report, None
    if run.returncode != 0:
        report["error"] = "helper_failed"
        # The ssh client explains itself on stderr (refused, host key, kex).
        # Keep the first line only: it names a host or an option, never a key.
        first = run.stderr.decode("utf-8", "replace").strip().splitlines()
        if first:
            report["detail"] = first[0][:120]
        report["rc"] = run.returncode
        return report, None
    try:
        answer = json.loads(run.stdout.decode("utf-8", "replace"))
    except ValueError:
        report["error"] = "helper_answer_invalid"
        return report, None
    return report, answer


def apply_v6(results, answer, configs, report):
    """Merge the helper's verdicts into this round and rebuild affected files.

    ``promoted`` is the number of measurements the helper actually added -- not
    the alive count of every source that happened to own a v6 root, which made
    the summary claim more promotions than the number of nodes it judged.
    """
    if not isinstance(answer, dict) or not answer.get("host_ipv6"):
        report["error"] = report.get("error") or "helper_without_ipv6"
        return report
    before = sum(len(item.measurements) for item in results)
    merge_v6_results(results, answer)
    promoted = sum(len(item.measurements) for item in results) - before
    for result in results:
        if result.failed or not result.content:
            continue
        # Only a source that actually handed roots to the helper can have new
        # measurements; re-exporting every other source would repeat its
        # geolocation prefetch for nothing.
        if result.v6_roots and result.measurements:
            try:
                graph = Graph(dedupe_names(configs[result.name]))
                result.content, result.published = source_output(
                    result.name, graph, result.measurements)
            except Exception:
                # A helper answer we cannot apply must not abort the round: the
                # previous content stands and the report explains why.
                report["error"] = "rebuild_failed"
    report["ok"] = True
    report["judged"] = sum(int(v or 0) for v in (answer.get("judged") or {}).values())
    report["promoted"] = max(0, promoted)
    for message in answer.get("errors") or []:
        if isinstance(message, str):
            report.setdefault("helper_errors", []).append(message[:60])
    return report


def run(env=None, transport=None, probe=None):
    env = dict(os.environ if env is None else env)
    results, sources, output = [], [], None
    requested = bool(env.get("PROBE_SOURCES_JSON", "").strip())
    override = ipv6_override(env.get("PROBE_IPV6"))
    summary = {"sources": 0, "input": 0, "alive": 0, "failure": 0,
               "phase": "init", "error_code": "", "publication": "not_started",
               "timings": {}}
    started = time.monotonic()
    try:
        base = env.get("SUBSTORE_BASE", "").strip()
        if not base or not env.get("PROBE_OUTPUT_DIR", "").strip():
            raise ProbeError("environment_missing")
        transport = transport or Transport()
        store = SubStore(base, transport, source_secrets=load_source_secrets(env))
        output = private_dir(env["PROBE_OUTPUT_DIR"])
        if probe is None:
            binary = env.get("MIHOMO_BIN", "").strip()
            if not binary or not shutil.which(binary):
                raise ProbeError("kernel_missing")
            if not shutil.which("curl"):
                raise ProbeError("curl_missing")
            probe = NativeProbe(
                binary, env.get("PROBE_CONCURRENCY", 8), env.get("PROBE_TIMEOUT", 15),
                ipv6=override,
                # A dead node costs one 3s controller call instead of a short
                # trace plus a full retry; survivors still get a curl trace for
                # exit IP / TLS evidence, so the prefilter never replaces it.
                delay_ms=(env_int(env.get("PROBE_DELAY_TIMEOUT_MS", 3000), 3000, 0, 30000)
                          if env_flag(env.get("PROBE_DELAY_PREFILTER"), True) else 0),
                # A first-budget failure is retried once at this budget before
                # the node is skipped, so only the genuinely dead are dropped.
                delay_retry_ms=env_int(env.get("PROBE_DELAY_RETRY_MS", 15000), 15000, 0, 30000),
                kernel_batch=env_int(env.get("PROBE_KERNEL_BATCH", 0), 0, 0, 100000),
                dedupe=env_flag(env.get("PROBE_DEDUPE"), True),
            )
        summary["phase"] = "sources"
        sources = store.sources()
        if requested:
            try:
                chosen = json.loads(env["PROBE_SOURCES_JSON"])
            except (ValueError, TypeError):
                raise ProbeError("sources_filter_invalid") from None
            if not isinstance(chosen, list) or not chosen or not all(isinstance(name, str) and name and len(name) <= 128 and not any(ord(ch) < 32 for ch in name) for name in chosen):
                raise ProbeError("sources_filter_invalid")
            chosen = list(dict.fromkeys(chosen))
            if any(name not in sources for name in chosen):
                raise ProbeError("sources_filter_missing")
            sources = chosen
        summary["sources"] = len(sources)
        if not sources:
            raise ProbeError("sources_empty")
        summary["phase"] = "fetch"
        # Fetch EVERY selected source this round; no history skip. The GETs
        # are independent and I/O bound, so they share a thread pool; urllib
        # opens a fresh connection per call and Transport keeps no
        # per-request state between them. 16 is ~2x the old 8 (38 sources took
        # 11.8s in 5 waves) while still leaving the one Sub-Store host room to
        # answer instead of queueing.
        configs = {}
        mark = time.monotonic()

        def fetch_one(name):
            try:
                return name, store.config(name), ""
            except Exception as exc:
                return name, None, error_code(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(sources))) as pool:
            for name, config, failure in pool.map(fetch_one, sources):
                if failure:
                    results.append(SourceResult(name, failed=True, error=failure))
                else:
                    configs[name] = config
        front_name = env.get("PROBE_FRONT_SUB", "cf-front")
        front = configs.get(front_name)
        if front is None and front_name and selected_source(front_name) and front_name not in sources:
            try:
                front = store.config(front_name)
            except Exception:
                pass  # Individual missing dependencies fail closed in Graph.
        summary["timings"]["fetch_s"] = round(time.monotonic() - mark, 1)
        # Baseline the runner's own egress before any node is dialled: a trace
        # that comes back with this address never entered the proxy.
        if hasattr(probe, "baseline_ip"):
            probe.baseline_ip = runner_exit_ip(transport)
        # IPv6-bound nodes cannot be dialled from an IPv4-only host. The helper
        # settles exactly those, and its job list depends only on the fetched
        # configs -- never on this round's results -- so it runs CONCURRENTLY
        # with the runner instead of adding its whole wall time afterwards.
        helper_pool = helper_future = None
        helper_started = 0.0
        # Only a host that cannot reach IPv6 needs the helper, and only a
        # configured helper is worth the graph walk that finds its jobs.
        if (getattr(probe, "ipv6", True) is False
                and env.get("PROBE_V6_HELPER", "").strip()
                and env.get("PROBE_V6_SSH_PORT")):
            v6_map = {name: v6_bound_roots(configs[name], front) for name in sources if name in configs}
            helper_jobs = [{"source": name, "config": configs[name], "roots": v6_map[name]}
                           for name in sources if name in configs and v6_map[name]]
            if helper_jobs:
                helper_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                helper_started = time.monotonic()
                helper_future = helper_pool.submit(request_v6, helper_jobs, env)
        summary["phase"] = "measure"
        mark = time.monotonic()
        # One shared kernel for the whole round by default: 38 kernel starts
        # were 38 rounds of fixed startup/validation with the pool idle. The
        # probe falls back to one kernel per source if a merged group fails, so
        # a single bad config cannot lose the round.
        results.extend(measure_all(sources, configs, front, probe))
        # The front is fetched for its definitions but is usually not a source
        # of its own, so nobody measured it and ``front_alive`` stayed None --
        # which froze every front-backed source's streak at zero forever. One
        # explicit measurement (health only, never published) makes attribution
        # possible; a dead front must never delete a node. The verdict is read
        # after the helper merge, so a v6 front that the helper settled counts.
        front_measured = None
        if front is not None and not any(item.name == front_name for item in results):
            front_measured = front_health(front, probe)
        results.sort(key=lambda item: sources.index(item.name))
        summary["timings"]["measure_s"] = round(time.monotonic() - mark, 1)
        # Join the helper only after the runner's own round is done. In the
        # common case it finished during measurement, so this wait is ~0.
        if helper_future is not None:
            mark = time.monotonic()
            report, answer = helper_future.result()
            summary["timings"]["helper_wait_s"] = round(time.monotonic() - mark, 1)
            summary["v6_helper"] = report
            if answer is not None:
                apply_v6(results, answer, configs, report)
            # helper_s is the helper's own wall time, not extra wall time: it
            # overlaps measure_s by design, so the phases no longer sum to
            # total_s. helper_wait_s is what the runner actually blocked on.
            summary["timings"]["helper_s"] = round(time.monotonic() - helper_started, 1)
            helper_pool.shutdown(wait=False)
        # Geolocation runs inside source_output's prefetch (runner round and
        # helper rebuild alike); the resolver accumulates its own wall time.
        summary["timings"]["geo_s"] = round(geo_naming.PREFETCH_SECONDS, 1)
        front_result = next((item for item in results if item.name == front_name), None)
        if front_result is not None:
            front_alive = bool(not front_result.failed and front_result.alive > 0)
        else:
            front_alive = front_measured
        for item in results:
            item.front_alive = front_alive
        summary.update(input=sum(item.input for item in results), alive=sum(item.alive for item in results), failure=sum(item.failed or not item.alive for item in results))
        summary["ipv6"] = getattr(probe, "ipv6", None)
        summary["unverifiable"] = sum(item.unverifiable for item in results)
        # Traces that came back with the runner's own address: the node did not
        # carry them. Should be 0; anything else is a leak worth investigating.
        summary["direct_leak"] = getattr(probe, "suppressed", 0)
        # Work the optimisations removed: duplicate definitions collapsed
        # before dialling, dead nodes rejected by the kernel delay probe, and
        # source groups that shared one kernel. Counts only; no node names.
        summary["dedup_saved"] = getattr(probe, "dedup_saved", 0)
        summary["prefiltered"] = getattr(probe, "prefiltered", 0)
        summary["merged_kernels"] = getattr(probe, "merged_groups", 0)
        if requested:
            summary["results"] = result_reports(results)
        summary["phase"] = "checkpoint"
        # Private recovery evidence exists BEFORE any GitHub request. Candidate
        # files never overwrite last-success source artifacts before the gates.
        candidates = private_dir(output / "candidates")
        for item in results:
            if item.content is not None:
                private_write(candidates / source_file(item.name), item.content)
        private_write(output / "measurement.json", json_text(dict(summary, results=result_reports(results))))
        if not any(not item.failed and item.alive > 0 and item.published > 0 for item in results):
            raise ProbeError("no_successful_roots")
        summary["phase"] = "publish"
        mark = time.monotonic()
        if env.get("GIST_TOKEN"):
            gist_id = env.get("GIST_ID", env.get("GITHUB_GIST_ID", ""))
            status, files = GistPublisher(gist_id, env["GIST_TOKEN"], transport).publish(results)
            summary["publication"] = status
        else:
            files = plan_updates(results, read_local(output))
            summary["publication"] = "local_only"
        summary["timings"]["publish_s"] = round(time.monotonic() - mark, 1)
        if requested:
            summary["results"] = result_reports(results, files)
        summary["phase"] = "output"
        for name, content in files.items():
            private_write(output / name, content)
        summary["phase"] = "complete"
        summary["timings"]["total_s"] = round(time.monotonic() - started, 1)
        private_write(output / "measurement.json", json_text(dict(summary, results=result_reports(results, files))))
        # A partial source failure is recorded in the summary, but a successful
        # guarded publication is a successful workflow outcome. Exit nonzero only
        # when the publication path itself failed or no usable root existed.
        return 0 if summary["publication"] in {"published", "no_change", "local_only"} else 1, summary
    except Exception as exc:
        summary["failure"] = max(1, summary["failure"])
        summary["error_code"] = error_code(exc)
        if requested and results:
            summary["results"] = result_reports(results)
        if output is not None and results:
            try:
                private_write(output / "measurement.json", json_text(dict(summary, results=result_reports(results))))
            except Exception:
                pass
        return 2, summary


def main():
    code, summary = run()
    # The ONLY stdout record. Explicit filter names/counts may be included;
    # never URLs, upstream node names, raw IPs or arbitrary exception text.
    print(json.dumps(summary, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
