# WatchTower - SOC Dashboard

[Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
[Flask](https://img.shields.io/badge/Flask-3.1+-black.svg)
[SQLite](https://img.shields.io/badge/SQLite-3-blue.svg)
[Status](https://img.shields.io/badge/Status-Complete-brightgreen.svg)

A Flask + SQLite SOC dashboard that imports JSON reports from all 9 SOC tools into one database, then shows them in one view with search, stats, and CSV export.

It is the final layer of the SOC portfolio. The other tools detect, WatchTower triages.

> **One-line summary for GitHub:** `WatchTower | Flask + SQLite SOC dashboard that imports all 9 tools into one view. Search alerts, view stats, and export to CSV.`

---

## Why WatchTower

A SOC analyst does not want to open 4 different JSON files to see what happened. They want one dashboard.

WatchTower solves that:
- Import `alerts.json` from LogSentinel Pro, `web_report.json` from WebHawk, `hash_report.json` from HashHound, `packet_report.json` from PacketLens
- Store them all in one SQLite table with the same schema: `tool, check, severity, message, source_file, created_at`
- Search across all tools at once, e.g. search `HIGH` to see every HIGH finding
- See stats at a glance: total, HIGH, MEDIUM, LOW, INFO
- Export the filtered view to CSV for evidence or reporting

This is the same workflow used in real SOCs: collect, normalize, triage, export [1][2].

---

## What It Does

| Feature | What It Does | Why It Matters |
| :--- | :--- | :--- |
| **Import** | Reads JSON reports from 4 tools into SQLite | Normalizes different tools into one format |
| **Dashboard** | Shows all alerts in one HTML table, newest first | One view, no need to open 4 files |
| **Search** | Searches `tool`, `check`, `severity`, `message` with SQL `LIKE` | Find `brute force`, `HIGH`, `WebHawk` in one box |
| **Stats** | Counts total, HIGH, MEDIUM, LOW, INFO | See severity distribution at a glance |
| **Export** | Exports filtered alerts to CSV | Evidence for tickets, reports, or further analysis |

---

## MITRE ATT&CK Mapping

WatchTower itself does not detect, it aggregates detections from the other tools. Those detections map to [3]:

| Source Tool | MITRE Technique | Example Finding |
| :--- | :--- | :--- |
| LogSentinel Pro | **T1110 - Brute Force** | Success after brute force, CRITICAL |
| WebHawk | **T1595 - Active Scanning**, **T1190 - Exploit Public-Facing Application** | Missing security headers, SQLi reflection |
| HashHound | **T1110.001 - Password Guessing**, **T1552 - Unsecured Credentials** | Weak password, pwned hash |
| PacketLens | **T1071 - Application Layer Protocol**, **T1071.004 - DNS** | Beaconing, DNS queries |

WatchTower makes that mapping visible in one place. You can search for `Beaconing` and see PacketLens findings, or search for `HIGH` and see all HIGH across tools.
