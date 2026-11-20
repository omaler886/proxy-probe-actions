"""Offline checks for verified IPv6 connectivity and local-only node smoke."""
import io
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ipv6_transport as network


class Ipv6ConnectivityTests(unittest.TestCase):
    """Distinguish a selected IPv6 route from verified TCP and UDP connectivity."""

    def test_route_selection_alone_does_not_enable_ipv6(self):
        """A blackholed default route must return an unverified transport verdict."""
        with mock.patch.object(network, "has_ipv6_route", return_value=True), mock.patch.object(
                network, "check_tcp_target", return_value=False), mock.patch.object(
                network, "check_udp_target", return_value=False):
            report = network.check_ipv6_connectivity()
        self.assertFalse(report["ok"])
        self.assertEqual(report["tcp_passed"], 0)

    def test_two_independent_https_targets_are_required_and_udp_is_separate(self):
        """TCP capability must not invent UDP capability or trust a single target."""
        with mock.patch.object(network, "has_ipv6_route", return_value=True), mock.patch.object(
                network, "check_tcp_target", return_value=True), mock.patch.object(
                network, "check_udp_target", return_value=False):
            report = network.check_ipv6_connectivity()
        self.assertTrue(report["ok"])
        self.assertFalse(report["udp_ok"])
        with mock.patch.object(network, "has_ipv6_route", return_value=True), mock.patch.object(
                network, "check_tcp_target", side_effect=[True, False]), mock.patch.object(
                network, "check_udp_target", return_value=True):
            report = network.check_ipv6_connectivity()
        self.assertFalse(report["ok"])
        self.assertTrue(report["udp_ok"])

    def test_missing_route_avoids_network_requests(self):
        """An IPv4-only host should fail fast without spending HTTPS/UDP timeouts."""
        with mock.patch.object(network, "has_ipv6_route", return_value=False), mock.patch.object(
                network, "check_tcp_target") as tcp, mock.patch.object(network, "check_udp_target") as udp:
            report = network.check_ipv6_connectivity()
        self.assertEqual(report["error"], "no_ipv6_route")
        tcp.assert_not_called()
        udp.assert_not_called()

    def test_https_check_forces_ipv6_literal_and_validated_tls_without_tokens(self):
        """Inspect the external request and require its remote v6 address and TLS result."""
        body = ("ip=2606:4700::1234\nvisit_scheme=https\ntls=TLSv1.3\n"
                "\n2606:4700:4700::1111 0 200").encode()
        with mock.patch.dict(os.environ, {"SUBSTORE_BASE": "sensitive", "HTTPS_PROXY": "private"}), mock.patch.object(
                network.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=body)) as run:
            self.assertTrue(network.check_tcp_target(network.TCP_TARGETS[0]))
        command = run.call_args.args[0]
        self.assertIn("--ipv6", command)
        self.assertIn("one.one.one.one:443:[2606:4700:4700::1111]", command)
        self.assertNotIn("--insecure", command)
        self.assertNotIn("HTTPS_PROXY", run.call_args.kwargs["env"])
        self.assertNotIn("SUBSTORE_BASE", run.call_args.kwargs["env"])

    def test_https_check_rejects_ipv4_and_failed_certificate_or_wrong_body(self):
        """A fallback, invalid certificate or unrelated 200 response is not IPv6 proof."""
        for metadata in (b"8.8.8.8 0 200", b"2606:4700:4700::1111 20 200",
                         b"2606:4700:4700::1111 0 200"):
            with self.subTest(metadata=metadata), mock.patch.object(
                    network.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=b"unrelated\n" + metadata)):
                self.assertFalse(network.check_tcp_target(network.TCP_TARGETS[0]))

    def test_google_response_validates_dns_answer(self):
        """A successful independent DNS HTTPS response supplies the second proof."""
        response = b'{"Status":0,"Answer":[{"data":"2606:2800:220:1:248:1893:25c8:1946"}]}\n2001:4860:4860::8888 0 200'
        with mock.patch.object(network.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=response)):
            self.assertTrue(network.check_tcp_target(network.TCP_TARGETS[1]))

    def test_udp_check_matches_transaction_and_successful_response(self):
        """A UDP socket opening without a correlated DNS answer is insufficient."""
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.return_value = struct.pack("!HHHHHH", 1234, 0x8180, 1, 1, 0, 0)
        with mock.patch.object(network.secrets, "randbelow", return_value=1234), mock.patch.object(
                network.socket, "socket", return_value=connection):
            self.assertTrue(network.check_udp_target(network.UDP_TARGETS[0]))
            connection.recv.return_value = struct.pack("!HHHHHH", 9999, 0x8180, 1, 1, 0, 0)
            self.assertFalse(network.check_udp_target(network.UDP_TARGETS[0]))
            connection.recv.side_effect = socket.timeout()
            self.assertFalse(network.check_udp_target(network.UDP_TARGETS[0]))

    def test_private_aggregate_report_contains_no_observed_ip(self):
        """The persisted capability artifact only exposes counts and fixed categories."""
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "network.json"
            network.write_report(destination, {"ok": True, "tcp_passed": 2, "udp_passed": 1})
            self.assertEqual(json.loads(destination.read_text())["tcp_passed"], 2)
            if os.name != "nt":
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_cli_fails_when_transport_is_unverified(self):
        """A smoke workflow must not turn a failed capability check into success."""
        with mock.patch.object(sys, "argv", ["ipv6_transport.py"]), mock.patch.object(
                network, "check_ipv6_connectivity", return_value={"ok": False}), mock.patch(
                "sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(network.main(), 1)
        self.assertEqual(json.loads(output.getvalue()), {"ok": False})


if __name__ == "__main__":
    unittest.main()
