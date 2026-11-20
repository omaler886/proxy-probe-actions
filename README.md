# All-source proxy probes on GitHub Actions

Public execution repository. This tree is world-readable by design: subscription data and API tokens must never appear here — every credential lives in Actions secrets, and Git history is treated as public.

## Pipeline

1. Read original subscriptions from Sub-Store (`GET` only). Exclude generated `probe-*`, `chain-*`, `rust-*`, `测活-DMIT`, and `官方可用` sources to avoid feedback loops.
2. Use native mihomo on the GitHub-hosted Ubuntu runner. Validate each node with its full dialer dependency closure; never strip a required dialer into a direct connection.
3. Request `https://www.cloudflare.com/cdn-cgi/trace` through a node-specific loopback HTTP listener, with certificate validation and no direct fallback. Only a successful trace with a global `ip` and valid `loc` counts as alive. Every node gets a short first pass (a 1KB trace that needs longer is unusable); only failures spend the full timeout in a second pass, so a dead node costs fast+full instead of full+full. IPv6-bound nodes are settled by the helper host in parallel with the runner's own round.
4. Rename from source/country/protocol/exit hash/connection fingerprint. Timing is not embedded in names.
5. For **GlaDOS only**, group successful nodes by actual trace exit IP. For a duplicate-exit group prefer Shadowsocks (`ss`); if the group has no SS, keep one deterministic member. A unique exit is retained regardless of protocol (including AnyTLS/Trojan). This is NOT a global SS-only filter. Other sources keep their protocols and are not collapsed by exit.
6. PATCH fixed files in the existing secret Gist. Retain unrelated Gist files. Same YAML content produces no new revision. GitHub Gist PATCH rejects `If-Match` (HTTP 400); instead serialize this workflow and recheck the managed-file snapshot before writing. This is not server-side atomic compare-and-swap: never add a second writer for these managed filenames.

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

`bad_streak` in `manifest.json` is the consecutive-round counter that drives the
grace and counts **proven** failures only. `unproven_rounds` counts consecutive
rounds that produced no node-level evidence at all (unfetchable source,
unmeasurable nodes, unprovable front); it never deletes an artifact and exists
so an unjudgeable source is visible instead of silently frozen. Only the
survival baseline and those counters force a manifest-only revision;
audit-only fields are allowed to lag so a failed round does not create revision
noise.

A held source keeps its previous body until the missing nodes can be judged
again. That is deliberately conservative: a source with an unmeasurable member
will not shrink while the host (or the helper) cannot judge it, because the
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

Before measuring, the probe records the runner's own egress address with one
direct trace. A node that reports that address never carried the request (a
configuration bug or a silent DIRECT fallback); such a trace is counted in
`direct_leak` and never counts as a measured alive node.


## Trigger / cadence

Actions → **All subscription probes** → Run workflow. The optional `sources_json` input accepts a JSON list (for example `["ikunkun","pokenmen","健康中心","prologue","233pio","saki","glados"]`); duplicates are removed. An empty input keeps the full-source schedule. Scheduled every six hours at minute 23 (UTC), with one run at a time. GitHub scheduled execution is best effort and may be delayed.

**IPv6 is a host capability, not a node property.** GitHub-hosted runners have
no global IPv6 route, so a node whose server address (or whose front's address)
is an IPv6 literal cannot be dialled there. Such a node is reported as
`unverifiable`, never as dead, and the round summary records the host verdict in
`ipv6`. A v6-bound node is only measured when the probe runs on an IPv6-capable
host. Runner location/reachability is also different from HK/CN/LXC; a
location-restricted node may fail from GitHub even when reachable elsewhere.

## Secrets

- `SUBSTORE_BASE`: complete Sub-Store backend base URL, stored only as an Actions Secret.
- `GIST_TOKEN`: dedicated token with Gist access, stored only as an Actions Secret.
- `GIST_ID`: the target Gist id, stored only as an Actions Secret. Treat it as sensitive — it is the only thing standing between the subscription and the world.

Gist `public: false` means **unlisted**, not access-controlled/private: holders of the raw URL can read the credentials in a subscription. The source code repository itself is public, so the Gist id must never be rendered into step summaries, logs, or committed files. Do not distribute raw URLs publicly.

## Adding a subscription source

Sources are discovered live from Sub-Store (`GET /api/subs`): a new Sub-Store sub is picked up by the next round with **no code or workflow change** — avoid the reserved `probe-`/`chain-`/`rust-` name prefixes (and `测活-DMIT`, `官方可用`).

A source that needs its own credential (auth header, token query parameter, or a URL hosted outside this Sub-Store) uses the reserved `SOURCE_SECRETS_JSON` Actions Secret: one JSON map keyed by exact source name, applied per source at fetch time. Adding the Nth source means updating that Secret's value only — never this repo. Full guide (bilingual): [docs/ADDING_SOURCES.md](docs/ADDING_SOURCES.md).

## Outputs

- `mihomo-alive.yaml`: fixed merged subscription (no per-run names).
- `source-<sha256(source-name)>.yaml`: one stable file per source.
- `manifest.json`: source names and counts, digest, and previous-result preservation flags.

No subscription/config files are uploaded as Actions artifacts or caches. Temporary runner storage is destroyed at job teardown. Logs contain aggregate counts only.

A run can publish healthy sources and still finish nonzero if other sources failed; consult the count summary and manifest preservation flags. Failed is not evidence that those nodes are globally dead. Previous good sources stay in the merged subscription until replaced by a successful candidate or deliberately removed.

## Local tests

```sh
python -m pip install PyYAML==6.0.3
python -m unittest discover -s tests -v
```

## Old executors

Only retire confirmed probe measurement/writer services after the first full-source run is reviewed. Keep Sub-Store, its upstream source subscriptions, its backup timer, unrelated proxy services, and infrastructure health monitoring intact. Never delete local subscriptions just because `source: local`: many local subscriptions are original hand-authored node lists.
