# All-source proxy probes on GitHub Actions

Public execution repository. This tree is world-readable by design: subscription data and API tokens must never appear here — every credential lives in Actions secrets, and Git history is treated as public.

Policy state now requires a **separate private GitHub repository**. The delivery
Gist must contain **only `mihomo-alive.yaml`**. Existing installations need the
[security migration](docs/SECURITY_MIGRATION.md) before using this workflow.
A working proxy subscription still contains node credentials: its delivery URL
must be shared only with trusted recipients.

## Pipeline

1. Read original subscriptions from Sub-Store over **HTTPS** (`GET` only). HTTP, embedded URL credentials, fragments and cross-origin redirects are rejected. Exclude generated `probe-*`, `chain-*`, `rust-*`, `gist-*`, `测活-DMIT`, and `官方可用` sources to avoid feedback loops.
2. Use native mihomo on the GitHub-hosted Ubuntu runner. Validate each node with its full dialer dependency closure; never strip a required dialer into a direct connection.
3. Request `https://www.cloudflare.com/cdn-cgi/trace` through a node-specific loopback HTTP listener, with certificate validation and no direct fallback. Only a successful trace with a global `ip` and valid `loc` counts as alive. Every node gets a short first pass; only failures spend the full timeout in a second pass. IPv6 nodes run on the **same runner**, using verified native IPv6 or a local WARP tunnel. No SSH helper or remote node configuration transfer is used.
4. Rename from country/ASN brand and an optional local geo cache. Measurement never queries online geolocation providers. Timing is not embedded in names.
5. Within each source, group successful nodes by actual trace exit IP. Prefer Shadowsocks (`ss`), then a stable connection fingerprint. Every distinct exit is retained regardless of protocol. This selection favors a stable representative, not necessarily the lowest-latency protocol.
6. Commit source YAMLs, the merged YAML and `manifest.json` together as one JSON bundle in a **private** GitHub repository. Contents API blob SHA checks prevent stale state from overwriting a concurrent update. Retry IDs prevent an ambiguous write response from consuming two grace rounds.
7. Deliver **only** the merged connection YAML into a separate unlisted Gist. Strip source annotations and dependency source namespaces; retain connection credentials and references. A Gist containing any additional file is rejected before measurement. Gist delivery remains a single-writer operation; it is not transactional with the private state commit.

## Failure policy (node-level, with a grace round)

A source is **not** frozen as a whole when it fails. Each round records how many
of its nodes were actually dialled (`measured`), how many were unusable
configuration (`invalid`) and how many could not be judged because the host
cannot reach IPv6 (`unverifiable`). A node counts as dead **only** when this
round dialled it and the attempt failed.

| Round result | Artifact |
|---|---|
| any alive, at least half of the previous count | replaced with this round's alive set |
| any alive, fewer than half (severely reduced) | kept this round; replaced by the alive set on the **2nd consecutive** reduced round |
| any alive, but some nodes could not be judged (`unverifiable`, or the front was not proven alive) | **held** (`unproven_hold`): a shrink is published only when every missing node was dialled and failed |
| every dialled node failed | kept this round; **dropped** on the **2nd consecutive** round, so its dead nodes leave the merged subscription |
| source could not be fetched | kept (nothing was proven) |
| **no node could be dialled** (every root rejected by kernel validation) | kept (`not_dialled`); `unproven_rounds` advances, `bad_streak` does not |
| nodes hang off a dead or unmeasured front (`uses_front`) | kept (`front_unproven`); the front is measured once per round so this is attributable |
| nodes need IPv6 the host cannot reach | kept (unverifiable, never scored dead) |
| a retained artifact is unparsable (`proxies: null`, truncated) | quarantined and deleted on the same PATCH instead of blocking the round |

`bad_streak` in the private `manifest.json` is the consecutive-round counter that drives the
grace and counts **proven** failures only. `unproven_rounds` counts consecutive
rounds that produced no node-level evidence at all (unfetchable source,
unmeasurable nodes, unprovable front); it never deletes an artifact and exists
so an unjudgeable source is visible instead of silently frozen. Only the
survival baseline and those counters force a manifest-only revision;
audit-only fields are allowed to lag so a failed round does not create revision
noise.

A held source keeps its previous body until the missing nodes can be judged
again. That is deliberately conservative: a source with an unmeasurable member
will not shrink while the runner cannot judge it, because the
alternative is deleting a node for a limitation of the observer.


## Naming

A published name is `<flag><country>-<brand>-<city>` plus, only when two
connections would otherwise share it, an ordinal `-2`/`-3`. The ordinal is
chosen **once**: the resulting name is stored in `manifest.json` under `names`,
keyed by connection fingerprint, with one namespace per published file (the
merged subscription and each `source-*.yaml`). Later rounds reuse it verbatim,
so a node keeps its name when a sibling dies, when a geolocation lookup is
temporarily unavailable, or when another source is added.

The table is bounded: entries are dropped only once it outgrows the live set by
2x (or 1000 connections). Connections that are no longer published lose their
reservation and would receive a new name if they returned.

`manifest.json` also carries `http1` per source: alive nodes that negotiated
HTTP/1.1 instead of HTTP/2. It is an audit signal for a downgraded hop, never a
deletion rule.

Three audit fields are recorded per source and never affect selection:
`delay_median_ms`/`delay_p90_ms` (end-to-end round trip from curl's
`%{time_total}`, or from the optional kernel `/delay` prefilter when enabled;
0 = no evidence), `landing` (`same`/`transit`/`unknown`, comparing the measured
exit with the node's `server` literal — a relay or CDN front is legitimate, so
it is annotated only), and `asn_class` (`cdn`/`datacenter`/`residential`/
`mobile`/`unknown`, from the egress ASN).

The `/delay` prefilter is **opt-in** (`PROBE_DELAY_PREFILTER=1`). Measured on
the real workload, a safe configuration (a failed 3s probe retried at curl's
full 15s budget) cost more wall time than it saved once kernels were merged:
121.4s vs 81.7s of measurement, with no additional alive nodes.

Measurement itself is de-duplicated twice: identical connection definitions
inside one source share a single dial (the verdict is replicated to every
duplicate label), and independent sources share one kernel instead of one
kernel per source. A shared kernel that fails falls back to one kernel per
source automatically.

`PROBE_CONCURRENCY` is a ceiling (64 by default). The adaptive pool uses fewer
workers for small rounds and never raises that ceiling automatically. At most
`PROBE_PER_ENDPOINT_CONCURRENCY` dials (8 by default) share a first-entry host,
including nodes behind the same dialer front and ports on the same host. Groups
are interleaved to reduce queue blocking. This is a **configured entry-host**
limit: different hostnames or unknown shared exits cannot be reliably grouped
before measurement. `dial_workers` and `per_entry_limit` report budgets, not
observed throughput or proof that these settings are optimal.

The optional `/delay` prefilter obeys the same entry-host limit. A local ASN
download failure degrades new names instead of aborting measurement. Existing
names remain frozen. Optional city enrichment can be generated separately:

```sh
python tools/enrich_geo_cache.py --input /private/exits.json --output /private/geo.json
PROBE_GEO_CACHE=/private/geo.json python scripts/actions_probe_all.py
```

The input is a JSON list of `{"ip":"8.8.8.8","cc":"US"}` exit observations.
Only the explicit enrichment command contacts online providers; the cache
contains exit addresses, is written with mode 0600, expires after 30 days, and
must not be committed or uploaded as a public artifact. Without it, new names
use trace country and the local ASN database without inventing city data.

Before measuring, the probe records the runner's own egress address with one
direct trace. A node that reports that address never carried the request (a
configuration bug or a silent DIRECT fallback); such a trace is counted in
`direct_leak` and never counts as a measured alive node.


## Trigger / cadence

Actions → **All subscription probes** → Run workflow. The optional `sources_json` input accepts a JSON list (for example `["ikunkun","pokenmen","健康中心","prologue","233pio","saki","glados"]`); duplicates are removed. An empty input keeps the full-source schedule. Scheduled every six hours at minute 23 (UTC), with one run at a time. GitHub scheduled execution is best effort and may be delayed.

Enable `dry_run` for a read-only full measurement: publishing tokens are omitted,
no Gist/private state requests are made, and results stay in private temporary
runner files. Production failure counters are not advanced by a dry run.

**IPv6 is a measured host capability, not a node property.** The workflow first
checks two independent public IPv6 HTTPS endpoints with verified certificates
and literal IPv6 routing. If native connectivity is absent, it installs the
pinned official Cloudflare WARP client on the ephemeral runner. IPv4 is excluded
from the tunnel and its public egress must remain unchanged. WireGuard is tried
first, with MASQUE as a fallback. WARP is disconnected during job cleanup.

UDP capability is checked separately using real IPv6 DNS datagrams. Without it,
IPv6 UDP adapters (including Hysteria2/TUIC/WireGuard) remain `unverifiable`.
The same checks run after measurement: if the transport degrades, failed IPv6
attempts remain unjudged while successful node traces are retained. The summary
reports aggregate evidence in `ipv6_transport`. A route lookup or `warp=on`
alone never enables node death evidence. See [runner IPv6 setup](docs/RUNNER_IPV6.md).

Runner location/reachability is different from HK/CN/LXC; a location-restricted
node may still fail from this observer. Testing an IPv6 **entry** does not imply
the measured node has an IPv6 **exit**. Its Cloudflare trace can legitimately
return an IPv4 egress.

## Secrets

- `SUBSTORE_BASE`: complete Sub-Store backend base URL, stored only as an Actions Secret.
- `GIST_TOKEN`: dedicated token with Gist access, stored only as an Actions Secret.
- `GIST_ID`: the target Gist id, stored only as an Actions Secret. Treat it as sensitive — it is the only thing standing between the subscription and the world.
- `PROBE_STATE_REPO`: `owner/repository` of a dedicated **private** state repository, with an existing `main` branch.
- `PROBE_STATE_TOKEN`: a separate token scoped to Contents read/write for that private repository only. Metadata read is also needed to verify visibility. Do not reuse the Gist token.

Optional Actions variables: `PROBE_STATE_BRANCH` (default `main`),
`PROBE_STATE_PATH` (default `probe/state.json`), `PROBE_CONCURRENCY` (default 64)
and `PROBE_PER_ENDPOINT_CONCURRENCY` (default 8). A `GIST_TOKEN`/`GIST_ID`
configuration without a private state backend fails closed; there is no legacy
multi-file Gist publishing fallback. Omitting both publication backends permits
local-only runs into the private output directory.

Gist `public: false` means **unlisted**, not access-controlled/private: holders of the raw URL can read the credentials in a subscription. The source code repository itself is public, so the Gist id must never be rendered into step summaries, logs, or committed files. Do not distribute raw URLs publicly.

IPv6 requires no helper host, SSH key or extra subscription secrets. Legacy
`V6_HELPER_*` secrets are unused. Native/WARP network setup receives no publishing
or subscription credentials. Only the local measurement step reads subscriptions.

## Adding a subscription source

Sources are discovered live from Sub-Store (`GET /api/subs`): a new Sub-Store sub is picked up by the next round with **no code or workflow change** — avoid the reserved `probe-`/`chain-`/`rust-` name prefixes (and `测活-DMIT`, `官方可用`).

A source that needs its own credential (auth header, token query parameter, or a URL hosted outside this Sub-Store) uses the reserved `SOURCE_SECRETS_JSON` Actions Secret: one JSON map keyed by exact source name, applied per source at fetch time. Adding the Nth source means updating that Secret's value only — never this repo. Full guide (bilingual): [docs/ADDING_SOURCES.md](docs/ADDING_SOURCES.md).

## Outputs

- Delivery Gist: `mihomo-alive.yaml`, the only shared file.
- Private repository state bundle: the merged baseline, `source-<sha256(source-name)>.yaml` per source, and `manifest.json` containing names/counts/digests/preservation flags.
- Private temporary output: working copies, candidate files and measurement diagnostics. These are not delivery files.

No subscription/config files are uploaded as Actions artifacts or caches. Temporary runner storage is destroyed at job teardown. Logs contain aggregate counts only.

Partial source failures do not make a guarded publication fail. A private-state
or Gist write failure does fail the run. If Gist delivery fails after the state
commit, `state_publication` records that commit and `publication` stays
`pending_delivery`; the next successful round retries delivery. A failed run is
not evidence that nodes are globally dead. Previous good sources stay in the
merged subscription until replaced by a successful candidate or deliberately removed.

## Local tests

```sh
python -m pip install PyYAML==6.0.3
python -m unittest discover -s tests -v
```

## Old executors

Only retire confirmed probe measurement/writer services after the first full-source run is reviewed. Keep Sub-Store, its upstream source subscriptions, its backup timer, unrelated proxy services, and infrastructure health monitoring intact. Never delete local subscriptions just because `source: local`: many local subscriptions are original hand-authored node lists.
