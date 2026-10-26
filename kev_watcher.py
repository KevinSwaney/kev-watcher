#!/usr/bin/env python3
"""
kev-watcher: diff the CISA Known Exploited Vulnerabilities catalog.

Fetches the public CISA KEV JSON feed, compares CVE IDs to a local seen
file, prints only new entries, then updates the seen file.

Usage:
    python kev_watcher.py
    python kev_watcher.py --seen seen.json

No API key. Nothing is sent anywhere except the public feed request.
"""

import argparse
import json
import sys
import urllib.request

DEFAULT_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_seen(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return set(data)
        return set(data.get("cve_ids", []))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def main():
    parser = argparse.ArgumentParser(description="Diff the CISA KEV catalog.")
    parser.add_argument("--feed", default=DEFAULT_FEED)
    parser.add_argument("--seen", default="seen.json")
    args = parser.parse_args()

    try:
        with urllib.request.urlopen(args.feed, timeout=30) as response:
            catalog = json.load(response)
    except Exception as exc:
        print(f"Could not fetch the KEV feed: {exc}", file=sys.stderr)
        sys.exit(1)

    vulns = catalog.get("vulnerabilities", [])
    seen = load_seen(args.seen)
    new = [v for v in vulns if v.get("cveID") not in seen]

    # Save state first, so a truncated pipe does not lose the diff.
    with open(args.seen, "w", encoding="utf-8") as f:
        json.dump({"cve_ids": sorted(v.get("cveID") for v in vulns if v.get("cveID"))}, f, indent=2)

    print(f"KEV catalog: {catalog.get('catalogVersion')} (released {catalog.get('dateReleased')})")
    print(f"New entries: {len(new)}")
    for v in new:
        product = v.get("product", "unknown product")
        vendor = v.get("vendorProject", "")
        due = v.get("dueDate", "")
        print(f"- {v.get('cveID')} | {vendor} {product} | due {due}")
    print(f"Seen file updated: {args.seen} ({len(vulns)} entries)")


if __name__ == "__main__":
    main()
