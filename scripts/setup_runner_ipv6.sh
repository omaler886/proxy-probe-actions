#!/usr/bin/env bash
# Prepare IPv6 on an ephemeral Actions runner; preserve its original IPv4 path.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || "${RUNNER_OS:-}" != "Linux" ]]; then
  echo 'runner_ipv6_error=ephemeral_actions_runner_required'
  exit 2
fi

task_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
state_dir="${RUNNER_TEMP:?}/probe-ipv6"
mkdir -p "$state_dir"
chmod 700 "$state_dir"
umask 077

# Purpose: identify route changes without emitting addresses. Args: none.
# Return: the original public IPv4 and WARP flag, or a nonzero status.
read_ipv4_baseline() {
  curl --disable --noproxy '*' -4 --fail --silent --proto '=https' \
    --connect-timeout 5 --max-time 15 https://www.cloudflare.com/cdn-cgi/trace |
    python3 -c 'import sys; fields=dict(line.strip().split("=",1) for line in sys.stdin if "=" in line); print(fields["ip"] + " " + fields.get("warp","unknown"))'
}

# Purpose: run the official CLI without exposing registration data in logs.
# Args: warp-cli arguments. Return: the CLI exit status.
run_warp_cli() {
  sudo warp-cli --accept-tos "$@" >> "$state_dir/cli.log" 2>&1
}

# Purpose: restore the direct runner path after a failed setup. Args: none.
# Return: success regardless of whether a WARP registration exists.
disconnect_warp() {
  run_warp_cli disconnect || true
}

# Purpose: disconnect WARP after an unexpected setup failure. Args: none.
# Return: preserve the original failing exit status.
cleanup_failed_setup() {
  local status=$?
  if (( status != 0 )) && command -v warp-cli >/dev/null 2>&1; then
    disconnect_warp
    if [[ -n "${baseline_v4:-}" ]]; then
      touch "$state_dir/routing-unverified"
      local restored
      restored="$(read_ipv4_baseline)" || restored='unverified'
      if [[ "$restored" == "$baseline_v4" ]]; then
        rm -f -- "$state_dir/routing-unverified"
      else
        echo 'runner_ipv6_error=ipv4_restoration_unverified'
      fi
    fi
  fi
  return "$status"
}
trap cleanup_failed_setup EXIT

# Purpose: verify the live v6 path and the unchanged v4 path. Args: baseline string.
# Return: success only when both routing assertions hold.
verify_paths() {
  local before="$1"
  local after
  after="$(read_ipv4_baseline)" || return 1
  if [[ "$before" != "$after" ]]; then
    echo 'runner_ipv6_error=ipv4_path_changed'
    return 1
  fi
  rm -f -- "$state_dir/routing-unverified"
  python3 "$task_root/scripts/ipv6_transport.py" --report "$state_dir/network.json"
}

if python3 "$task_root/scripts/ipv6_transport.py" --report "$state_dir/network.json"; then
  echo 'runner_ipv6_transport=native'
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo 'PROBE_IPV6_TRANSPORT=native' >> "$GITHUB_ENV"
  fi
  exit 0
fi

baseline_v4="$(read_ipv4_baseline)"
if [[ "$baseline_v4" != *' off' ]]; then
  echo 'runner_ipv6_error=original_ipv4_path_unverified'
  exit 1
fi

# Official package is pinned by version and SHA-256; never execute a third-party
# bootstrap script. Installation occurs only on the disposable Actions runner.
warp_version='2026.8.2115.0'
warp_package="$state_dir/cloudflare-warp.deb"
curl --disable --fail --silent --show-error --location --proto '=https' \
  --proto-redir '=https' --retry 2 --connect-timeout 10 --max-time 180 \
  "https://pkg.cloudflareclient.com/pool/noble/main/c/cloudflare-warp/cloudflare-warp_${warp_version}_amd64.deb" \
  --output "$warp_package"
echo "0209107860c3c6851a9ab8fd03690121a3dea3199b084f8197620072c671cd68  $warp_package" | sha256sum --check --status
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$warp_package" > "$state_dir/install.log" 2>&1
sudo systemctl start warp-svc

for attempt in {1..15}; do
  if run_warp_cli status; then
    break
  fi
  sleep 1
done
run_warp_cli registration new
run_warp_cli mode tunnel_only
# Request the IPv4 exclusion on the new registration. Runtime assertions below
# must prove the effective split-tunnel mode leaves the IPv4 egress untouched.
run_warp_cli tunnel ip add-range 0.0.0.0/0

for protocol in WireGuard MASQUE; do
  disconnect_warp
  if ! run_warp_cli tunnel protocol set "$protocol"; then
    echo "runner_ipv6_protocol_unavailable=$protocol"
    continue
  fi
  touch "$state_dir/routing-unverified"
  if ! run_warp_cli connect; then
    continue
  fi
  for attempt in {1..6}; do
    sleep 3
    if verify_paths "$baseline_v4"; then
      echo "runner_ipv6_transport=warp_$protocol"
      if [[ -n "${GITHUB_ENV:-}" ]]; then
        echo "PROBE_IPV6_TRANSPORT=warp_$protocol" >> "$GITHUB_ENV"
      fi
      exit 0
    fi
  done
done

disconnect_warp
echo 'runner_ipv6_error=warp_ipv6_unverified'
exit 1
