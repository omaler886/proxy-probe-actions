#!/usr/bin/env python3
"""All-source Actions probe (stdlib + PyYAML); no Sub-Store writes or exit cache.

Run: SUBSTORE_BASE=... MIHOMO_BIN=/path/mihomo PROBE_OUTPUT_DIR=/private/path
     python scripts/actions_probe_all.py
Optional: GIST_TOKEN + GIST_ID (or GITHUB_GIST_ID), PROBE_CONCURRENCY=8,
PROBE_TIMEOUT=15, PROBE_FRONT_SUB=cf-front, PROBE_SOURCES_JSON='["source"]'.
When PROBE_SOURCES_JSON is unset, every selected source is tested every round.
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


ERROR_CODES = set("trace_invalid github_redirect response_large upstream_redirect transport_failure redirect_limit base_invalid sources_invalid subscription_invalid definition_invalid definition_duplicate definition_collision dependency_invalid dependency_cycle_or_direct dependency_missing kernel_validation_failure kernel_config_failure kernel_start_failure kernel_end_failure kernel_execution_failure old_content_invalid namespace_collision manifest_invalid gist_id_invalid gist_token_invalid gist_not_private gist_raw_invalid environment_missing kernel_missing curl_missing sources_empty sources_filter_invalid sources_filter_missing no_successful_roots gist_conflict http_failure request_invalid non_proxy_outbound dependency_group_unsupported".split())


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


class SubStore:
    def __init__(self, base, transport):
        parsed = urllib.parse.urlsplit(base)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.query or parsed.fragment:
            raise ProbeError("base_invalid")
        self.base, self.transport = base.rstrip("/"), transport

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
        raw, _ = self.transport("GET", self.base + "/download/" + urllib.parse.quote(name, safe="") + "?target=ClashMeta")
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
    cfg = graph.export(roots)
    cfg.update({
        "allow-lan": False, "bind-address": "127.0.0.1", "mode": "rule",
        "ipv6": True, "log-level": "silent", "external-controller": "127.0.0.1:" + str(controller),
        "secret": secret, "external-ui": "", "geodata-mode": False, "geo-auto-update": False,
        "find-process-mode": "off", "profile": {"store-selected": False, "store-fake-ip": False},
        "dns": {"enable": False}, "tun": {"enable": False},
        "listeners": [{"name": "lane-" + str(index), "type": "http", "listen": "127.0.0.1", "port": port, "proxy": root} for index, (root, port) in enumerate(zip(roots, ports))],
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


@dataclass
class Measurement:
    name: str
    ip: str
    cc: str


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


class NativeProbe:
    def __init__(self, binary, workers=8, timeout=15, transport=None, ipv6=None):
        self.binary = binary
        self.workers = max(1, min(32, int(workers)))
        self.timeout = max(1, min(120, int(timeout)))
        self.transport = transport or Transport(timeout=2)
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

    def trace(self, port, directory):
        # stdout is a private regular file, not a captured named pipe (Windows).
        fd, path = tempfile.mkstemp(prefix="trace-", dir=str(directory))
        os.chmod(path, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                run = subprocess.run([
                    "curl", "--disable", "--silent", "--show-error", "--fail", "--noproxy", "",
                    "--proxy", "http://127.0.0.1:" + str(port), "--max-time", str(self.timeout),
                    "--connect-timeout", str(min(10, self.timeout)), "--proto", "=https",
                    "--max-filesize", "65536", TRACE_URL,
                ], stdout=stream, stderr=subprocess.DEVNULL, timeout=self.timeout + 3)
            if run.returncode:
                return None
            return parse_trace(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, subprocess.TimeoutExpired, ProbeError):
            return None
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def health(self, process, controller, secret):
        if process.poll() is not None:
            return False
        try:
            raw, _ = self.transport("GET", "http://127.0.0.1:" + str(controller) + "/version", {"Authorization": "Bearer " + secret})
            return isinstance(json.loads(raw), dict) and process.poll() is None
        except Exception:
            return False

    def __call__(self, graph, roots):
        accepted, invalid, unverifiable = [], 0, 0
        measurable = []
        for root in roots:
            if not self.ipv6 and graph.v6_bound(root):
                # Unreachable FROM THIS HOST, not proven dead. Do not spend a
                # timeout on it and do not let it count as a dead node.
                unverifiable += 1
                continue
            measurable.append(root)
        with tempfile.TemporaryDirectory(prefix="actions-probe-") as temp:
            directory = private_dir(temp)
            secret = secrets.token_urlsafe(24)
            # Each root's complete closure is checked independently: an unsupported
            # protocol cannot poison an otherwise healthy source.
            for root in measurable:
                try:
                    ports = unused_ports(2)
                    cfg = kernel_config(graph, [root], ports[:1], ports[1], secret)
                    if self.validate(directory, cfg):
                        accepted.append(root)
                    else:
                        invalid += 1
                except ProbeError as exc:
                    if str(exc).startswith("kernel_"):
                        raise
                    invalid += 1
            if not accepted:
                return [], invalid, unverifiable
            ports = unused_ports(len(accepted) + 1)
            controller = ports[-1]
            cfg = kernel_config(graph, accepted, ports[:-1], controller, secret)
            if not self.validate(directory, cfg):
                raise ProbeError("kernel_config_failure")
            process = None
            try:
                process = subprocess.Popen([self.binary, "-d", str(directory), "-f", str(directory / "config.yaml")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + 15
                while not self.health(process, controller, secret):
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise ProbeError("kernel_start_failure")
                    time.sleep(0.1)

                def one(pair):
                    root, port = pair
                    for _ in range(2):
                        evidence = self.trace(port, directory)
                        if evidence:
                            return Measurement(root, *evidence)
                    return None

                with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
                    measured = list(pool.map(one, zip(accepted, ports[:-1])))
                if not self.health(process, controller, secret):
                    raise ProbeError("kernel_end_failure")
                return [item for item in measured if item], invalid, unverifiable
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


def measure_source(name, config, front, probe):
    result = SourceResult(name, input=len(config.get("proxies", [])))
    try:
        graph = Graph(dedupe_names(config), front)
        roots = [item["name"] for item in config["proxies"]]
        # Nodes the FRONT supplies (the source's own definitions win). A root
        # that reaches one of them cannot be blamed for its own failures.
        front_only = set()
        if front:
            own = {item.get("name") for item in config.get("proxies", []) if isinstance(item, dict)}
            front_only = {item.get("name") for item in front.get("proxies", []) if isinstance(item, dict)} - own
        result.uses_front = graph.front_backed(roots, front_only)
        measurements, invalid, unverifiable = probe(graph, roots)
        result.alive = len(measurements)
        result.invalid = invalid
        result.unverifiable = unverifiable
        result.measured = max(0, len(roots) - invalid - unverifiable)
        result.unique_egress = len({egress_key(item.ip) for item in measurements})
        for item in measurements:
            result.countries[item.cc] = result.countries.get(item.cc, 0) + 1
        # A missing dependency is a per-node validation failure, never stripped.
        result.content, result.published = source_output(name, graph, measurements)
    except Exception as exc:
        result.failed = True
        result.error = error_code(exc)
    return result


def merge_sources(contents):
    """Dedup tested roots by resolved connection, retain independent namespaces."""
    choices = {}
    for filename, text in sorted(contents.items()):
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


def plan_updates(results, old):
    try:
        old_manifest = json.loads(old.get("manifest.json", "{}"))
        previous = old_manifest.get("sources", {})
        if not isinstance(previous, dict):
            raise ValueError
    except (ValueError, TypeError):
        raise ProbeError("manifest_invalid") from None
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
            prior_alive = sum(not item.get("name", "").startswith("__front-") for item in doc.get("proxies", []))
        try:
            streak = max(0, int(last.get("bad_streak", 0)))
        except (ValueError, TypeError):
            streak = 0
        # Death evidence. A node counts as dead only when THIS round dialled it
        # and the attempt failed. A source we could not fetch, a source whose
        # nodes hang off a dead front, and a node that needs IPv6 on an
        # IPv4-only host are all UNPROVEN: they must never delete a node.
        proven_dead = (not result.failed
                       and result.alive == 0
                       and result.unverifiable == 0
                       and (not result.uses_front or result.front_alive is True))
        if result.failed:
            accept, guard = False, "source_failure"
        elif result.alive > 0:
            if prior_alive and result.alive < prior_alive * 0.5:
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
        else:
            accept = False
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
                "uses_front": result.uses_front,
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
            "uses_front": result.uses_front,
        }
    if effective:
        merged = merge_sources(effective)
    elif dropped:
        # Every source was proven dead this round: the merged body must drop
        # the nodes too, otherwise the dead nodes survive in the subscription.
        merged = canonical({"proxies": []})
    else:
        # Nothing published yet and nothing dropped: keep whatever the previous
        # round produced rather than writing an empty subscription.
        merged = old.get("mihomo-alive.yaml", canonical({"proxies": []}))
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
    they must reach the Gist. Audit-only fields (guard, preserved, counts)
    may lag: a failed round must not create a revision on its own.
    """
    try:
        old = json.loads(old_text or "{}").get("sources", {})
        new = json.loads(new_text or "{}").get("sources", {})
    except (ValueError, TypeError, AttributeError):
        return True
    if not isinstance(old, dict) or not isinstance(new, dict):
        return True
    for key, entry in new.items():
        previous = old.get(key)
        if not isinstance(entry, dict):
            continue
        if not isinstance(previous, dict):
            if entry.get("last_success_alive") or entry.get("bad_streak"):
                return True
            continue
        if entry.get("last_success_alive") != previous.get("last_success_alive"):
            return True
        if (entry.get("bad_streak") or 0) != (previous.get("bad_streak") or 0):
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
                        "uses_front": item.uses_front})
    return reports


def run(env=None, transport=None, probe=None):
    env = dict(os.environ if env is None else env)
    results, sources, output = [], [], None
    requested = bool(env.get("PROBE_SOURCES_JSON", "").strip())
    override = ipv6_override(env.get("PROBE_IPV6"))
    summary = {"sources": 0, "input": 0, "alive": 0, "failure": 0,
               "phase": "init", "error_code": "", "publication": "not_started"}
    try:
        base = env.get("SUBSTORE_BASE", "").strip()
        if not base or not env.get("PROBE_OUTPUT_DIR", "").strip():
            raise ProbeError("environment_missing")
        transport = transport or Transport()
        store = SubStore(base, transport)
        output = private_dir(env["PROBE_OUTPUT_DIR"])
        if probe is None:
            binary = env.get("MIHOMO_BIN", "").strip()
            if not binary or not shutil.which(binary):
                raise ProbeError("kernel_missing")
            if not shutil.which("curl"):
                raise ProbeError("curl_missing")
            probe = NativeProbe(binary, env.get("PROBE_CONCURRENCY", 8), env.get("PROBE_TIMEOUT", 15), ipv6=override)
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
        # Fetch EVERY selected source this round; no history skip.
        configs = {}
        for name in sources:
            try:
                configs[name] = store.config(name)
            except Exception as exc:
                results.append(SourceResult(name, failed=True, error=error_code(exc)))
        front_name = env.get("PROBE_FRONT_SUB", "cf-front")
        front = configs.get(front_name)
        if front is None and front_name and selected_source(front_name) and front_name not in sources:
            try:
                front = store.config(front_name)
            except Exception:
                pass  # Individual missing dependencies fail closed in Graph.
        summary["phase"] = "measure"
        for name in sources:
            if name in configs:
                results.append(measure_source(name, configs[name], front, probe))
        results.sort(key=lambda item: sources.index(item.name))
        # Front health decides whether a front-dependent source may be judged
        # dead: with a dead front, its nodes failed for someone else's reason.
        front_result = next((item for item in results if item.name == front_name), None)
        front_alive = None
        if front_result is not None:
            front_alive = bool(not front_result.failed and front_result.alive > 0)
        for item in results:
            item.front_alive = front_alive
        summary.update(input=sum(item.input for item in results), alive=sum(item.alive for item in results), failure=sum(item.failed or not item.alive for item in results))
        summary["ipv6"] = getattr(probe, "ipv6", None)
        summary["unverifiable"] = sum(item.unverifiable for item in results)
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
        if env.get("GIST_TOKEN"):
            gist_id = env.get("GIST_ID", env.get("GITHUB_GIST_ID", ""))
            status, files = GistPublisher(gist_id, env["GIST_TOKEN"], transport).publish(results)
            summary["publication"] = status
        else:
            files = plan_updates(results, read_local(output))
            summary["publication"] = "local_only"
        if requested:
            summary["results"] = result_reports(results, files)
        summary["phase"] = "output"
        for name, content in files.items():
            private_write(output / name, content)
        summary["phase"] = "complete"
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
