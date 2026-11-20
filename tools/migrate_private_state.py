#!/usr/bin/env python3
"""Copy legacy policy state into private storage; never mutate the old Gist."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import actions_probe_all as probe
from publication import PrivateStateStore, PublicationError


def migrate(env, transport, apply=False):
    """Validate legacy state and optionally copy it once into an empty private store."""
    legacy = probe.LegacyGistReader(env.get("LEGACY_GIST_ID", ""), env.get("GIST_TOKEN", ""), transport)
    files, _ = legacy.current()
    if "manifest.json" not in files or "mihomo-alive.yaml" not in files:
        raise PublicationError("state_migration_invalid")
    # Reuse the policy parser/merger to validate the baseline before copying it.
    probe.plan_updates([], files)
    destination = PrivateStateStore(
        env.get("PROBE_STATE_REPO", ""), env.get("PROBE_STATE_TOKEN", ""), transport,
        branch=env.get("PROBE_STATE_BRANCH", "main"),
        path=env.get("PROBE_STATE_PATH", "probe/state.json"))
    existing, version = destination.current()
    if existing and existing != files:
        raise PublicationError("state_migration_existing")
    if existing == files:
        return {"migration": "no_change", "files": len(files)}
    if apply:
        destination.save(files, version)
        copied, _ = destination.current()
        if copied != files:
            raise PublicationError("state_migration_verification_failed")
    return {"migration": "copied" if apply else "validated", "files": len(files)}


def main():
    """Read credentials only from environment and print non-sensitive migration status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Copy into an empty private state file")
    arguments = parser.parse_args()
    try:
        result = migrate(dict(os.environ), probe.Transport(), arguments.apply)
        print(json.dumps(result))
        return 0
    except Exception as error:
        print(json.dumps({"migration": "failed", "error_code": probe.error_code(error)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
