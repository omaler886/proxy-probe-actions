# Private state and isolated delivery

The code supports the new storage layout; changing local files does not migrate
an existing deployment, create repositories, rotate credentials or change VPS
accounts. Complete the following configuration before enabling the new workflow.

## What changes

| Data | Destination | Reader authorization |
| --- | --- | --- |
| Original Sub-Store sources | Existing Sub-Store, GET over HTTPS | Existing source credentials |
| Per-source YAML, manifest and merged policy baseline | One JSON bundle in a dedicated private GitHub repository | Repository Contents read token |
| Sanitized merged connection YAML | A separate unlisted Gist with one file | Possession of its URL |
| IPv6 node configurations | Temporary 0700/0600 files on the same runner | Local measurement process only |

A usable subscription contains passwords/UUIDs and is itself sensitive.
Sanitizing removes source annotations and internal source namespaces; it does
not remove credentials needed by the client. Do not label this file safe for
public distribution. For access control on the merged subscription too, use
private-state-only mode (omit both Gist secrets) and an authenticated delivery
service of your choice. This repository does not deploy a public HTTP service.

## Create the storage boundary

1. Create a dedicated **private** repository with an initialized `main` branch.
   Keep it private for its entire lifetime: Git history contains past node
   credentials. Never place this state in the public execution repository.
2. Add `PROBE_STATE_REPO` and `PROBE_STATE_TOKEN` to the execution repository's
   Actions Secrets. Use a fine-grained token restricted to this private repo,
   with Contents read/write and Metadata read. Keep `GIST_TOKEN` separate.
3. Create a new **unlisted** Gist containing exactly `mihomo-alive.yaml` with
   `proxies: []` as its initial content. Set `GIST_ID` to this new locator only
   after the old baseline has been migrated. Extra files, including a README,
   are rejected with `delivery_gist_mixed`.
4. IPv6 setup now runs directly on the Actions runner using native connectivity
   or WARP, as described in [RUNNER_IPV6.md](RUNNER_IPV6.md). No helper host or
   SSH credentials are needed. A failed IPv6 setup preserves unjudgeable nodes.
5. Ensure `SUBSTORE_BASE` and every source override URL use HTTPS and trusted
   certificates. HTTP, URL userinfo and URL fragments are now rejected.

## Copy the existing baseline

Keep the old locator in `LEGACY_GIST_ID` for this command; the new delivery
locator belongs in `GIST_ID`. Provide all values via your secret manager or
private environment, never command-line arguments or committed files.

```sh
python tools/migrate_private_state.py
python tools/migrate_private_state.py --apply
```

The first command only validates. The second copies managed legacy files once
into an empty private state file and reads them back to verify the copy. It
preserves frozen names, failure counters and the previous merged baseline.
It refuses to replace a different existing private state. Both commands read
the old Gist without changing or deleting it and print counts/fixed errors only.

The old Gist remains exposed to holders of its URL, including its revision
history. Moving state or removing files from the latest revision does not
invalidate credentials already downloaded. Handle retirement of old URLs and
rotation of any exposed node credentials separately; this migration command
performs neither action.

## Update consumers and verify

Existing `gist-<source>` Sub-Store subscriptions keep pointing at the old source
files until their URLs are changed. **They do not become authenticated private
sources automatically.** Clients that only need the merged result can switch to
the new merged URL. A per-source consumer needs an authenticated adapter that
reads the private state bundle and returns its selected YAML, or a locally
managed file. A private repository token must not be embedded in a shared raw
URL. No changes to Sub-Store collections or existing subscriptions are made by
this repository.

Run the workflow manually after configuration. Verify
`publication_preflight_ok=true`, `phase=complete`, the count summary and one-file
delivery Gist. Inspect private state via authenticated GitHub access. Aggregate
logs omit repository locators, raw IPs and node/source details unless a source
filter was explicitly requested.

State writes use a blob SHA on the Contents API PUT. The complete policy bundle
is one file, so counters and source removals change together. Each process uses
a round ID, and the last 512 committed round IDs are retained. This prevents an
ambiguous successful PUT from advancing grace twice even when another writer
commits before the retry. Retry identity expires after 512 newer commits; keep
the serialized workflow as the supported writer. Delivery occurs afterwards; it is not a transaction with the state
commit. Gist writes still require a single serialized workflow writer.

## Concurrency and performance evidence

Defaults: global ceiling 64 on the runner and 8 simultaneous
dials per first-entry host. Small rounds use a smaller pool. Entry hosts behind
`dialer-proxy` share a limit even when the final nodes have different servers;
different ports on the same host also share it. DNS aliases and shared egresses
cannot all be inferred before a trace, so the cap is not a global per-exit-IP
rate limit.

Online geolocation is removed from the measurement path. Local ASN lookup and
an optional private cache supply names; the cache enrichment tool is separate.
The ASN download has a bounded step timeout and may fail without failing the
measurement. New names can lose the city segment without a cache, while stored
names stay frozen.

The offline tests verify concurrency limits, exception recovery and publication
boundaries. They do not benchmark live node throughput. Before raising a ceiling,
compare the same authorized source set at 24/48/64 workers over multiple rounds
on the same host; use `measure_s`, setup time, alive counts and error counts.
Keep timeout, entry cap, source set and kernel version constant. Use local-only
output directories for these experiments and omit all publication credentials;
never compare runs that write the production policy counters. There is no
automatic concurrency increase based on an unverified performance assumption.

## API references

The implementation uses GitHub REST API version `2022-11-28`:
[Contents API](https://docs.github.com/en/rest/repos/contents?apiVersion=2022-11-28#get-repository-content),
[Contents updates](https://docs.github.com/en/rest/repos/contents?apiVersion=2022-11-28#create-or-update-file-contents),
and [Git blob reads](https://docs.github.com/en/rest/git/blobs?apiVersion=2022-11-28#get-a-blob).
Contents reads explicitly request `application/vnd.github.object+json`; when
GitHub omits inline content for a larger file, the immutable blob SHA is fetched
with authentication and verified against the decoded bytes. The state bundle
has a 16 MiB decoded size limit. GitHub documents the reader boundary of
[secret Gists](https://docs.github.com/en/get-started/writing-on-github/editing-and-sharing-content-with-gists/creating-gists#about-gists)
as URL possession, rather than private authentication.
