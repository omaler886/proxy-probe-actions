#!/usr/bin/env python3
"""Verify public IPv6 on the measuring runner without a remote helper."""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys


TCP_TARGETS = (
    ("one.one.one.one", "2606:4700:4700::1111", "/cdn-cgi/trace", "trace"),
    ("dns.google", "2001:4860:4860::8888", "/resolve?name=example.com&type=AAAA", "dns"),
)
UDP_TARGETS = ("2606:4700:4700::1111", "2001:4860:4860::8888")
CHECK_TIMEOUT = 6


def process_environment():
    """Return curl's process essentials without ambient proxies or API credentials."""
    allowed = {"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"}
    return {key: value for key, value in os.environ.items() if key in allowed}


def has_ipv6_route():
    """Return whether the OS selects an IPv6 route; this alone proves no connectivity."""
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as connection:
            connection.connect((UDP_TARGETS[0], 53))
        return True
    except OSError:
        return False


def check_tcp_target(target):
    """Verify one pinned public IPv6 HTTPS endpoint; return only a boolean verdict."""
    hostname, address, path, response_type = target
    command = ["curl", "--disable", "--silent", "--fail", "--ipv6", "--noproxy", "*",
               "--proto", "=https", "--connect-timeout", "3", "--max-time", str(CHECK_TIMEOUT),
               "--max-filesize", "65536", "--resolve", hostname + ":443:[" + address + "]",
               "--write-out", "\n%{remote_ip} %{ssl_verify_result} %{http_code}",
               "https://" + hostname + path]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=CHECK_TIMEOUT + 2, env=process_environment())
        if result.returncode:
            return False
        body, metadata = result.stdout.decode("utf-8").rsplit("\n", 1)
        remote, verified, status = metadata.split()
        if (ipaddress.ip_address(remote) != ipaddress.ip_address(address)
                or verified != "0" or status != "200"):
            return False
        if response_type == "dns":
            document = json.loads(body)
            return document.get("Status") == 0 and bool(document.get("Answer"))
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        observed = ipaddress.ip_address(fields.get("ip", ""))
        return (observed.version == 6 and observed.is_global
                and fields.get("visit_scheme") == "https"
                and fields.get("tls", "").lower().startswith("tls"))
    except (OSError, ValueError, UnicodeError, AttributeError, subprocess.SubprocessError):
        return False


def check_udp_target(address):
    """Send a real IPv6 UDP DNS query; return whether its valid answer comes back."""
    transaction = secrets.randbelow(65536)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    packet = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as connection:
            connection.settimeout(CHECK_TIMEOUT)
            connection.connect((address, 53))
            connection.send(packet)
            answer = connection.recv(4096)
        if len(answer) < 12:
            return False
        observed, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", answer[:12])
        return (observed == transaction and bool(flags & 0x8000)
                and flags & 0x000F == 0 and questions == 1 and answers > 0)
    except (OSError, ValueError, struct.error):
        return False


def check_ipv6_connectivity():
    """Return real HTTPS/UDP capability counts; never expose measured addresses or secrets."""
    report = {"ok": False, "tcp_ok": False, "udp_ok": False,
              "tcp_passed": 0, "tcp_total": len(TCP_TARGETS),
              "udp_passed": 0, "udp_total": len(UDP_TARGETS)}
    if not has_ipv6_route():
        report["error"] = "no_ipv6_route"
        return report
    # Independent public destinations distinguish a local route from a usable
    # tunnel. DNS/UDP is a separate capability; TCP success cannot prove QUIC.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        tcp = [pool.submit(check_tcp_target, target) for target in TCP_TARGETS]
        udp = [pool.submit(check_udp_target, address) for address in UDP_TARGETS]
        report["tcp_passed"] = sum(bool(result.result()) for result in tcp)
        report["udp_passed"] = sum(bool(result.result()) for result in udp)
    report["tcp_ok"] = report["tcp_passed"] == len(TCP_TARGETS)
    report["udp_ok"] = report["udp_passed"] > 0
    report["ok"] = report["tcp_ok"]
    if not report["ok"]:
        report["error"] = "ipv6_https_unverified"
    return report


def write_report(path, report):
    """Atomically store an aggregate-only local report with owner-only permissions."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + "." + secrets.token_hex(8))
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            temporary.chmod(0o600)
            stream.write(json.dumps(report, sort_keys=True) + "\n")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    """Check runner IPv6 and optionally write an aggregate report; exit 1 if unverified."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", help="Local aggregate report destination")
    arguments = parser.parse_args()
    report = check_ipv6_connectivity()
    if arguments.report:
        write_report(arguments.report, report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
