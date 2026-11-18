# All-source proxy probes on GitHub Actions

Private execution repository. Subscription data and API tokens never belong in Git.

## Pipeline

1. Read original subscriptions from Sub-Store (`GET` only). Exclude generated `probe-*`, `chain-*`, `rust-*`, `测活-DMIT`, and `官方可用` sources to avoid feedback loops.
2. Use native mihomo on the GitHub-hosted Ubuntu runner. Validate each node with its full dialer dependency closure; never strip a required dialer into a direct connection.
3. Request `https://www.cloudflare.com/cdn-cgi/trace` through a node-specific loopback HTTP listener, with certificate validation and no direct fallback. Only a successful trace with a global `ip` and valid `loc` counts as alive.
4. Rename from source/country/protocol/exit hash/connection fingerprint. Timing is not embedded in names.
5. For **GlaDOS only**, group successful nodes by actual trace exit IP; prefer Shadowsocks (`ss`), then a stable connection fingerprint. Where there is no live SS, keep one deterministic non-SS node. Other sources are not collapsed by exit.
6. PATCH fixed files in the existing secret Gist. Preserve failed/empty/severely reduced sources from the previous successful publication. Retain unrelated Gist files. Same YAML content produces no new revision.

## Trigger / cadence

Actions → **All subscription probes** → Run workflow. Scheduled every six hours at minute 23 (UTC), with one run at a time. GitHub scheduled execution is best effort and may be delayed. Runner location/reachability is different from HK/CN/LXC; an IPv6-only or location-restricted node may fail from GitHub even when reachable elsewhere.

## Secrets

- `SUBSTORE_BASE`: complete Sub-Store backend base URL, stored only as an Actions Secret.
- `GIST_TOKEN`: dedicated token with Gist access, stored only as an Actions Secret.
- `GIST_ID` is set as a non-sensitive workflow value.

Gist `public: false` means **unlisted**, not access-controlled/private: holders of the raw URL can read the credentials in a subscription. The source code repository itself is private. Do not distribute raw URLs publicly.

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
