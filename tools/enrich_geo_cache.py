#!/usr/bin/env python3
"""Optional offline-from-measurement geo enrichment; never publishes subscriptions."""
import argparse
import ipaddress
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import actions_probe_all as probe
import geo_naming


def enrich(input_path, output_path):
    """Enrich a JSON list of {ip, cc} exits and save a private cache; return a count."""
    source = Path(input_path)
    if source.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("input too large")
    document = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("expected exit list")
    items = {}
    for item in document:
        if not isinstance(item, dict):
            raise ValueError("expected exit object")
        address = ipaddress.ip_address(item.get("ip", ""))
        if not address.is_global or item.get("cc") not in probe.COUNTRIES:
            raise ValueError("invalid exit")
        items[str(address)] = item["cc"]
    # This standalone command is the only workflow that enables online geo.
    # It does not read publishing credentials and never runs inside probe.run.
    geo_naming.LOOKUP_ON = True
    geo_naming.RESOLVER.clear()
    geo_naming.prefetch(list(items.items()))
    cache = {"version": 1, "updated_at": time.time(),
             "entries": {ip: geo_naming.RESOLVER.entry(ip, cc) for ip, cc in items.items()}}
    destination = Path(output_path).absolute()
    # Set permissions on the output itself; do not chmod an arbitrary user directory.
    destination.parent.mkdir(parents=True, exist_ok=True)
    probe.private_write(destination, probe.json_text(cache))
    return len(items)


def main():
    """Read explicit local paths and print counts/errors without exit addresses."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Private JSON list of measured exits")
    parser.add_argument("--output", required=True, help="Private output geo cache path")
    arguments = parser.parse_args()
    try:
        print(json.dumps({"cached": enrich(arguments.input, arguments.output)}))
        return 0
    except Exception as error:
        print(json.dumps({"cache": "failed", "error_code": type(error).__name__}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
