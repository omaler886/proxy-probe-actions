# IPv6 on the measurement runner

IPv6 measurement runs locally on the same GitHub Actions Ubuntu 24.04 runner.
There is no SSH helper, remote worker or transfer of subscription configurations
to another probe host. `V6_HELPER_*` secrets and the retired `v6_worker.py` are
not used. Existing private-state and delivery-Gist authentication is unchanged.

## Transport establishment

`bash scripts/setup_runner_ipv6.sh` first verifies two independent public IPv6
HTTPS destinations. It pins their literal IPv6 addresses through curl's
`--resolve`, requires validated TLS and checks their expected response bodies.
A selected default route alone is insufficient. UDP is checked separately with
correlated DNS requests to public IPv6 resolvers.

When native IPv6 is absent, the script downloads the official Ubuntu Noble
Cloudflare WARP package version `2026.8.2115.0`, checks its SHA-256, and installs
it on the disposable Actions runner. It refuses to perform installation outside
an Actions Linux environment. This is an explicit transport dependency, not a
third-party bootstrap script.

The fresh WARP registration uses `tunnel_only`, leaving DNS management alone.
The IPv4 default destination range is added to the split-tunnel exclusion list
before connection. The script verifies that the runner's IPv4 Cloudflare trace
still returns its original egress and `warp=off`. It tries WireGuard followed by
MASQUE, and accepts neither unless actual IPv6 HTTPS connectivity is verified.
An IPv4 path change fails validation. Registration/CLI details are retained only
in the private temporary runner directory and never uploaded.

The setup receives no subscription or publication secrets. Its routing changes
apply only to the ephemeral job; the workflow disconnects WARP in an `always()`
cleanup step and the setup also disconnects on errors. The production probe can
continue with IPv4 if setup fails and the original IPv4 route is verified. If
restoration cannot be verified, a local marker prevents measurement/publication
from treating a changed observer route as node-death evidence.

## Measurement and failure attribution

`NativeProbe` obtains a fresh `ipv6_transport` snapshot before measuring. Roots
requiring IPv6 remain unjudgeable without the verified transport; UDP-based
adapters additionally require the separate UDP capability. During a batch a
background heartbeat retains any observed TCP/UDP interruption, even if a later
sample recovers. Failed nodes using the interrupted transport remain unjudged;
successful traces are retained. A post-measurement check also protects failures
if the tunnel is still down at the end. This is sampled observer evidence, not
a proof that every packet between samples was delivered. Existing source
grace policy and successful traces are retained.

`PROBE_IPV6=0/1` remains an explicit local testing override; production workflows
do not set it. Setting it to 1 does not establish a tunnel and bypasses automatic
capability checks, so do not use it to force production success.

The test URL reached *through* a proxy can choose an IPv4 egress. A successful
IPv6 entry trace therefore proves an IPv6 connection to the proxy entrance and
an authenticated proxy handshake, not a guarantee of IPv6 egress or all UDP
applications. UDP DNS capability alone does not prove QUIC to every destination.

## Read-only smoke workflow

`Action runtime verification` installs the pinned kernel, establishes transport
and reads subscription sources with GET only. It samples up to twelve IPv6 roots
and probes their actual protocol configurations, including dependency closures.
At least one successful IPv6-entry node is required. Only aggregate counts and
protocol names are logged. The job receives no Gist or private-state write
credentials and never publishes results or advances production failure counters.

For a full pipeline rehearsal, dispatch `All subscription probes` with `dry_run`
enabled. It omits all publication tokens and uses only local temporary output;
the standard measurement code and real source discovery still execute.

Official references:

- [Cloudflare Linux CLI](https://developers.cloudflare.com/warp-client/get-started/linux/)
- [Official Noble packages](https://pkg.cloudflareclient.com/)
- [Split tunnel routing](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/route-traffic/split-tunnels/)

The CLI grammar is verified against the pinned binary. Effective `/0` exclusion
and public IPv6 transport are runtime assertions, not inferred from the CLI help.

## Verified Actions evidence (2026-11-20)

- [Initial native/WARP and real-node smoke](https://github.com/omaler886/proxy-probe-actions/actions/runs/44713953533): native IPv6 had no route; WARP WireGuard established IPv6 with HTTPS 2/2 and UDP 2/2 passing, while the IPv4 baseline was unchanged. Seven of eight IPv6-entry VLESS nodes returned a verified trace.
- [Protocol-diverse smoke](https://github.com/omaler886/proxy-probe-actions/actions/runs/44716125187): the same transport checks passed; twelve nodes were sampled (six VLESS and six MASQUE), with five VLESS traces successful and no MASQUE traces successful. Kernel validation rejected none. This proves the local tunnel and real VLESS entry measurement; it does **not** establish that the tested MASQUE nodes are healthy or that every UDP-based proxy works through WARP.
- [Full pipeline dry run](https://github.com/omaler886/proxy-probe-actions/actions/runs/44716304339): 38 sources, 2,162 input nodes, 1,421 successful traces, zero unverifiable nodes and zero direct-leak detections. Measurement took 93.4 seconds; the probe's total was 109.1 seconds. HTTPS and UDP IPv6 checks passed before and after measurement. Publication was `local_only`; production state was untouched. These counts are one observer's round, not a guarantee of global node availability.

These jobs receive no publication tokens and update no production failure state.
