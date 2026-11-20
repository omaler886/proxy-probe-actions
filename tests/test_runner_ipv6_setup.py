"""Offline Bash regressions for WARP rollback and the production measurement gate."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
SETUP_HARNESS = r'''
warp_connected=0
trace_mode=original

# Purpose: expose CLI discovery without executing a client. Args: any. Return: failure.
warp-cli() { return 90; }

# Purpose: emulate routing effects only. Args: sudo command. Return: fixture exit status.
sudo() {
  case "$*" in
    'warp-cli --accept-tos connect')
      if [[ -f "$RUNNER_TEMP/probe-ipv6/routing-unverified" ]]; then
        printf 'connect:marked\n' >> "$TEST_EVENTS"
      else
        printf 'connect:unmarked\n' >> "$TEST_EVENTS"
      fi
      warp_connected=1
      trace_mode="$TEST_ROUTE"
      if [[ "$TEST_ROUTE" == late_change ]]; then trace_mode=original; fi
      if [[ "$TEST_ABORT" == connect ]]; then return 23; fi ;;
    'warp-cli --accept-tos disconnect')
      if [[ "$warp_connected" == 1 ]]; then
        printf 'disconnect:attempted\n' >> "$TEST_EVENTS"
        if [[ "$TEST_DISCONNECT" == fail ]]; then return 42; fi
        trace_mode="$TEST_DISCONNECT"
        warp_connected=0
      fi ;;
    'warp-cli --accept-tos tunnel protocol set WireGuard')
      if [[ "$TEST_ROUTE" == late_change ]]; then return 43; fi ;;
    'warp-cli --accept-tos status' | 'warp-cli --accept-tos registration new' | \
    'warp-cli --accept-tos mode tunnel_only' | \
    'warp-cli --accept-tos tunnel ip add-range 0.0.0.0/0' | \
    'warp-cli --accept-tos tunnel protocol set MASQUE' | \
    'apt-get update -qq' | 'DEBIAN_FRONTEND=noninteractive apt-get install -y '* | \
    'systemctl start warp-svc') ;;
    *) printf 'unexpected_sudo\n' >> "$TEST_EVENTS"; return 90 ;;
  esac
  return 0
}

# Purpose: provide fixed trace responses without HTTP. Args: curl flags. Return: fixture status.
curl() {
  case "$*" in
    *https://www.cloudflare.com/cdn-cgi/trace)
      printf 'trace:%s\n' "$trace_mode" >> "$TEST_EVENTS"
      case "$trace_mode" in
        original) printf 'ip=192.0.2.10\nwarp=off\n' ;;
        changed) printf 'ip=192.0.2.20\nwarp=on\n' ;;
        different_ip) printf 'ip=192.0.2.20\nwarp=off\n' ;;
        warp_on) printf 'ip=192.0.2.10\nwarp=on\n' ;;
        unreadable) return 22 ;;
        *) return 90 ;;
      esac ;;
    *https://pkg.cloudflareclient.com/*) ;;
    *) printf 'unexpected_curl\n' >> "$TEST_EVENTS"; return 90 ;;
  esac
}

# Purpose: stub connectivity checks; retain the stdin parser. Args: Python args. Return: verdict.
python3() {
  if [[ "$1" == '-c' ]]; then command "$TEST_PYTHON" "$@"; return $?; fi
  if [[ "$1" != */scripts/ipv6_transport.py ]]; then return 90; fi
  if [[ "$TEST_ROUTE" == late_change && "$warp_connected" == 1 ]]; then
    trace_mode=changed
  fi
  if [[ "$TEST_IPV6" == native ]]; then return 0; fi
  if [[ "$TEST_IPV6" == warp && "$warp_connected" == 1 ]]; then return 0; fi
  return 1
}

# Purpose: consume the fixture checksum without a package. Args: any. Return: success.
sha256sum() { cat >/dev/null; }

# Purpose: remove delays or inject an early error. Args: interval. Return: fixture status.
sleep() { if [[ "$TEST_ABORT" == sleep ]]; then return 23; fi; return 0; }

source "$1"
'''
MEASUREMENT_HARNESS = r'''
# Purpose: record entry into measurement without running it. Args: script. Return: fixture status.
python() {
  if [[ "$*" != 'scripts/actions_probe_all.py' ]]; then return 90; fi
  printf 'measurement:called\n' >> "$TEST_EVENTS"
}
'''


@unittest.skipUnless(os.name == "posix" and BASH, "requires POSIX Bash; use WSL on Windows")
class RunnerIpv6SetupTests(unittest.TestCase):
    """Run the unchanged setup and workflow body with all external effects stubbed."""

    @classmethod
    def setUpClass(cls):
        """Read the production measurement shell body for every gate assertion."""
        workflow = yaml.safe_load((ROOT / ".github/workflows/probe-all.yml").read_text(encoding="utf-8"))
        cls.measurement_body = next(
            step["run"] for step in workflow["jobs"]["probe"]["steps"]
            if step.get("name") == "Measure, commit private state and deliver merged subscription")

    def run_scenario(self, *, disconnect="original", ipv6="never", route="changed", abort="none"):
        """Run one fixture and its actual measurement gate; return captured evidence."""
        with tempfile.TemporaryDirectory(prefix="runner-ipv6-test-") as directory:
            events = Path(directory) / "events.log"
            environment = {
                "PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C",
                "GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "RUNNER_TEMP": directory,
                "GITHUB_ENV": str(Path(directory) / "github.env"),
                "TEST_EVENTS": str(events), "TEST_PYTHON": sys.executable,
                "TEST_DISCONNECT": disconnect, "TEST_IPV6": ipv6,
                "TEST_ROUTE": route, "TEST_ABORT": abort,
                "SUBSTORE_BASE": "https://fixture.invalid/private", "PROBE_DRY_RUN": "true",
            }
            setup = subprocess.run(
                [BASH, "--noprofile", "--norc", "-s", "--", str(ROOT / "scripts/setup_runner_ipv6.sh")],
                input=SETUP_HARNESS, text=True, capture_output=True, env=environment, timeout=10)
            marker = (Path(directory) / "probe-ipv6/routing-unverified").is_file()
            measurement = subprocess.run(
                [BASH, "--noprofile", "--norc", "-s"],
                input=MEASUREMENT_HARNESS + self.measurement_body,
                text=True, capture_output=True, env=environment, timeout=5)
            evidence = events.read_text(encoding="utf-8").splitlines() if events.exists() else []
            self.assertNotIn("connect:unmarked", evidence)
            self.assertFalse(any(event.startswith("unexpected_") for event in evidence), evidence)
            return {"setup": setup, "marker": marker, "measurement": measurement, "events": evidence}

    def assert_measurement_gate(self, evidence, *, blocked):
        """Assert the workflow's exit status and whether its measurement command ran."""
        self.assertEqual(evidence["marker"], blocked)
        self.assertEqual(evidence["measurement"].returncode != 0, blocked,
                         evidence["measurement"].stderr)
        self.assertEqual("measurement:called" in evidence["events"], not blocked)

    def test_failed_disconnect_keeps_marker_and_blocks_measurement(self):
        """An IPv4 route change with failed rollback must never reach measurement."""
        evidence = self.run_scenario(disconnect="fail")
        self.assertEqual(evidence["setup"].returncode, 1, evidence["setup"].stderr)
        self.assertIn("runner_ipv6_error=ipv4_path_changed", evidence["setup"].stdout)
        self.assertIn("runner_ipv6_error=ipv4_restoration_unverified", evidence["setup"].stdout)
        self.assertEqual(evidence["events"].count("disconnect:attempted"), 3)
        self.assert_measurement_gate(evidence, blocked=True)

    def test_exact_restoration_allows_ipv4_fallback(self):
        """A failed IPv6 setup may continue only after the original IPv4 trace returns."""
        evidence = self.run_scenario()
        self.assertEqual(evidence["setup"].returncode, 1, evidence["setup"].stderr)
        self.assertIn("disconnect:attempted", evidence["events"])
        self.assertEqual(evidence["events"][-2:], ["trace:original", "measurement:called"])
        self.assert_measurement_gate(evidence, blocked=False)

    def test_ipv4_change_after_first_check_blocks_measurement(self):
        """A failed final protocol must retain its guard after an earlier safe IPv4 check."""
        evidence = self.run_scenario(route="late_change", disconnect="fail")
        self.assertEqual(evidence["setup"].returncode, 1, evidence["setup"].stderr)
        self.assertIn("runner_ipv6_protocol_unavailable=WireGuard", evidence["setup"].stdout)
        self.assertIn("runner_ipv6_error=ipv4_path_changed", evidence["setup"].stdout)
        self.assertIn("trace:changed", evidence["events"])
        self.assert_measurement_gate(evidence, blocked=True)

    def test_early_error_restores_ipv4_and_preserves_exit_status(self):
        """The EXIT trap must restore routing even before normal failure cleanup runs."""
        evidence = self.run_scenario(abort="sleep")
        self.assertEqual(evidence["setup"].returncode, 23, evidence["setup"].stderr)
        self.assertEqual(evidence["events"].count("disconnect:attempted"), 1)
        self.assert_measurement_gate(evidence, blocked=False)

    def test_early_error_with_failed_rollback_blocks_measurement(self):
        """An early failure cannot bypass the marker when its EXIT cleanup also fails."""
        evidence = self.run_scenario(abort="sleep", disconnect="fail")
        self.assertEqual(evidence["setup"].returncode, 23, evidence["setup"].stderr)
        self.assertEqual(evidence["events"].count("disconnect:attempted"), 1)
        self.assert_measurement_gate(evidence, blocked=True)

    def test_connect_error_after_route_change_is_guarded(self):
        """A failing connect command can leave routes installed and must stay blocked."""
        evidence = self.run_scenario(abort="connect", disconnect="fail")
        self.assertEqual(evidence["setup"].returncode, 1, evidence["setup"].stderr)
        self.assertIn("connect:marked", evidence["events"])
        self.assert_measurement_gate(evidence, blocked=True)

    def test_restoration_requires_matching_ip_and_warp_flag(self):
        """Different egress, remaining WARP, and an unreadable trace all fail closed."""
        for restored in ("different_ip", "warp_on", "unreadable"):
            with self.subTest(restored=restored):
                evidence = self.run_scenario(disconnect=restored)
                self.assertEqual(evidence["setup"].returncode, 1)
                self.assertIn("runner_ipv6_error=ipv4_restoration_unverified", evidence["setup"].stdout)
                self.assert_measurement_gate(evidence, blocked=True)

    def test_native_ipv6_needs_no_warp_connection(self):
        """Native success must leave measurement available without any WARP connection."""
        evidence = self.run_scenario(ipv6="native")
        self.assertEqual(evidence["setup"].returncode, 0, evidence["setup"].stderr)
        self.assertIn("runner_ipv6_transport=native", evidence["setup"].stdout)
        self.assertNotIn("connect:marked", evidence["events"])
        self.assert_measurement_gate(evidence, blocked=False)

    def test_verified_warp_keeps_original_ipv4_and_allows_measurement(self):
        """Successful WARP IPv6 may continue after proving unchanged IPv4 routing."""
        evidence = self.run_scenario(ipv6="warp", route="original")
        self.assertEqual(evidence["setup"].returncode, 0, evidence["setup"].stderr)
        self.assertIn("runner_ipv6_transport=warp_WireGuard", evidence["setup"].stdout)
        self.assertIn("connect:marked", evidence["events"])
        self.assert_measurement_gate(evidence, blocked=False)


if __name__ == "__main__":
    unittest.main()
