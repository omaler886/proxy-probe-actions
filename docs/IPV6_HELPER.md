# Dedicated IPv6 helper

The helper needs working IPv6, Python 3 with the pinned PyYAML dependency, curl,
and the same pinned mihomo binary as the runner. This document is a deployment
recipe; editing the repository does not change any remote account or service.

## Account and files

After verifying the intended host's identity, an administrator can create a
dedicated account with no sudo access. Use a dedicated VM/container whose
filesystem contains no unrelated subscription credentials or production data.

```sh
useradd --create-home --shell /bin/sh probe-v6
install -d -o root -g root -m 0755 /opt/probe-v6/scripts /opt/probe-v6/bin
```

Copy `actions_probe_all.py`, `geo_naming.py`, `publication.py`, `probe_limits.py`
and `v6_worker.py` into `/opt/probe-v6/scripts`, owned by root and readable but
not writable by `probe-v6`. Install the pinned, checksum-verified mihomo binary
at `/opt/probe-v6/bin/mihomo`, owned by root, executable by the helper account.
Install PyYAML in its system Python environment. Jobs cannot override this
binary path. Update the worker files together whenever the protocol changes.

Create `/home/probe-v6/.ssh` with mode 0700 and an `authorized_keys` file with
mode 0600. For the dedicated Actions public key, use these authorized-key options
before the public key text supplied by your secret manager:

```
restrict,command="/usr/bin/python3 /opt/probe-v6/scripts/v6_worker.py"
```

Those options and the actual public key must form one authorized_keys line.
`restrict` disables forwarding, PTY and user rc features. The fixed command
prevents this key from requesting an arbitrary shell. Keep the account without
sudo privileges. A locked password is compatible with key authentication when
the host's SSH/PAM policy permits it; check that policy before changing it.

The account needs outbound network access to proxy entries and the HTTPS trace
endpoint. Restrict access to unrelated private services using the VM/container's
network policy if that environment contains sensitive internal networks.
Using a non-root Unix account alone is not a network isolation boundary.

## Actions secrets

Set `V6_HELPER_HOST`, `V6_HELPER_PORT`, `V6_HELPER_USER=probe-v6`,
`V6_HELPER_KEY` and `V6_HELPER_KNOWN_HOSTS`. Obtain the host key through an
independently verified administration channel. A runtime `ssh-keyscan` alone
does not establish the server's identity. For a non-default port, known_hosts
uses `[host]:port`.

The driver ignores ambient SSH configuration, disables agent forwarding and
uses only the dedicated key and pinned known_hosts. It rejects root and missing
host pinning. The worker also refuses to run as root before consuming its input.

Only requested IPv6 roots and their dependency closures are sent over SSH stdin;
unrelated proxies, provider URLs and top-level configuration are omitted. The
worker validates and probes them with temporary 0700 directories and 0600 files,
then removes those temporary files. The fixed worker has no Gist or state token.
Runner children do not inherit Actions secrets in their process environments.
This reduces credential exposure; trusted host administrators can still inspect
the configurations while they are in use.

Verify as the dedicated account with a harmless empty job before enabling
production probes. SSH failure and an unavailable helper leave nodes
unverifiable rather than declaring them dead. The optional helper has no
publisher and cannot directly change private policy state or the delivery Gist.
