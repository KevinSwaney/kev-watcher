# kev-watcher

Diff the CISA Known Exploited Vulnerabilities (KEV) catalog and list what is new since the last run.

KEV is the public list of vulnerabilities CISA says are known to be exploited in the wild. This tool fetches the public JSON feed, compares it to a local seen file, and prints only the new entries, with the federal remediation due date for each.

No API key needed. No data is sent anywhere except the public CISA feed request.

## Usage

```bash
python kev_watcher.py
python kev_watcher.py --seen seen.json
python kev_watcher.py --feed https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

On the first run, everything in the catalog is "new" and the seen file is created. On later runs, only entries added since then are printed. That is the point: a daily run gives you the daily diff.

## Example output

```
KEV catalog: 2026.10.23 (released 2026-10-23)
New entries: 1
- CVE-2026-110447 | Collabora Online / Nextcloud | due 2026-10-26
```

## What to do with a new entry

1. Check if the product is in your environment, including bundled and hosted versions.
2. Patch by the due date, or take the product offline if you cannot patch in time.
3. Hunt for exploitation indicators, not just the patch status. A patched system is not proof it was never compromised.

## Notes

- Requires Python 3.6+. No dependencies.
- A clean diff does not mean nothing changed elsewhere. This watches KEV only.

## Author

Kevin Swaney — Principal Cybersecurity Engineer. More at [kevintswaney.com](https://kevintswaney.com).
