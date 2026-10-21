# ZScaler Log Analyzer

A single-file Windows GUI (HTA) for triaging **Zscaler Internet Access (ZIA) web logs exactly as the admin portal exports them** (Analytics > Web Insights > Logs > Export CSV). Point it at a folder of exports and it answers the questions an investigator asks of a secure web gateway:

- **Who went where?** Per user: requests, blocks, security events, distinct hosts, raw-IP destinations, the egress / bypass channels used. Per host: users, outcome, category, cloud app, first seen relative to day 1, URL paths.
- **What was malicious?** Every request with a threat name / category, ATP / malware / DLP / sandbox / SSL policy, malicious category or bad certificate, each citing its source line.
- **What is checking in on a timer?** Beacon timing per user->host pair (median interval, jitter, share of regular intervals), plus implant-style URL paths (`/cmd/`, `/getcmd`, `?h=<host>&u=<user>`) on raw IPs / uncategorised hosts.
- **How could data leave or controls be bypassed?** Remote-access tools, tunnels / anonymisers, paste sites / temp file hosts / webhooks, file sharing, webmail, generative AI, DNS over HTTPS, raw IP, uncategorised / newly registered, cryptocurrency, adware.
- **When?** Stacked hourly / daily charts (requests by outcome, security events, egress, bypass, blocked risky channels, active users, unscannable files, IOC hits), a user x time heatmap and an hour-of-week heatmap on the users' business clock with each user's off-hours share.

Part of the DFIR toolkit family (Artifact Finder, the EZ-tool wrappers, Hayabusa, Hawk, UAC, vSphere, Data Domain and FortiGate analysers). Works fully offline - it never reaches the network.

## How it works

The `.hta` is the launcher and the viewer. A PowerShell engine is embedded in it; on **Process** it is written next to the output and run. The engine's C# core (Add-Type) streams every record once - about **10 seconds for a 1,000,000-row / 400 MB export** - and writes:

| Output | What it is |
|---|---|
| `<name>-ZScaler-<stamp>.json` | Every table as a preview of up to 6000 rows with true totals (priority rows kept first), hourly counters and hour-of-week bins - what the viewer loads |
| `<stamp>_<table>.csv` | Every table in full (Open full CSV). Event lists (security events, unscannable files, large uploads, IOC hits) stream to disk while reading, so nothing is dropped |
| `runinfo.json` | Family provenance entry (app, name, input, files, triage summary) |

Output goes to `_Processed\<name>\ZScaler-Log-Analyzer\` next to the app. The input is only read. Flag rules and findings live in the viewer, so they change without reprocessing.

## Export notes

- **Row limit.** A ZIA CSV export stops at a row cap (1,000,000 in the sample). A file holding exactly a round limit raises a CRITICAL finding - export the period in slices (per day / per user group) and process the folder together.
- **Columns** are mapped by header name. Validated against the sample's 26-column Web Insights export (No., Event Time, User, URL, Policy Action, Cloud Application Class, Cloud Application, URL Class, URL Super Category, URL Category, Threat Category, Threat Name, Location, Department, Blocked Policy Type, Certificate Chain Validity, Server Certificate Self Signed, DLP MD5, DLP Identifier, ALPN Protocol, Unscannable Type, Forwarding Rule, Forwarding Method, Application Segment, Gateway IP, Gateway Name). Client / Server IP, Request / Response Size, File Name / Type, MD5, User Agent, Referer and Device Hostname are mapped **provisionally** (documented portal names, not yet seen in a real export); they enable the byte-based checks when present. Unmapped columns are listed on Sources > Files.
- **Time.** Event Time is written in the exporting admin's portal timezone as an abbreviation (`PDT`). It is converted to UTC per record (daylight-saving changes inside an export are handled). Ambiguous abbreviations (IST, CST, BST, AST, GST) are flagged; an unknown or missing zone stops the run until **Source timezone override** (`+HH:MM`) is set. Time_Source keeps the original text on every event row; SourceFile + SourceLine cite the record (`file#row=N`, header counted).

## Quick start

1. Run `ZScaler-Log-Analyzer.hta`, pick the folder of CSV exports (or one CSV). The line under the input shows who exported it, when, and the Event Time zone.
2. Check **Target name** (guessed from a `Cases\<case-id>` path or the exporting admin's tenant), then **Process -> analyze**.
3. Start on **Overview** - findings are leads, most severe first; click one to open the rows behind it. Check the **Coverage** card before concluding anything is absent.
4. On **Activity over time**, set the **business clock** to the users' timezone (it defaults to the export's timezone, which is the admin's, not necessarily the users'). The choice is remembered.
5. Narrow with **Pivot** (user / host / IP / CIDR / URL text across every tab), **User**, **Department**, **Allowed / Blocked only**, **Off-hours only**, **Hide common infrastructure**, severity and date window.

## Command line

```
mshta "ZScaler-Log-Analyzer.hta" "<input>" ["<outDir>"] [/auto] [/from:yyyy-MM-dd] [/to:yyyy-MM-dd] [/tz:+HH:MM] [/selftest]
```

`<input>` is a CSV folder or file (processed with `/auto`), a run `.json`, or an output folder (reloads its newest run). `/selftest` (with a `.json`, or with `/auto`) renders every tab, writes the result to `ZScaler-Log-Analyzer.boot.log` next to the app and closes - used for regression checks.

## Building and testing

`ZScaler-Log-Analyzer.src.hta` + `ZScaler-Engine.ps1` -> `build-hta.ps1` -> `ZScaler-Log-Analyzer.hta` (guards: pure ASCII, no closing script tag in the engine, one placeholder).

`test\run-tests.ps1` (Windows PowerShell 5.1) runs 62 regression checks on synthetic fixtures: beacon first-burst handling, C2 paths found on every record regardless of order or length, the timezone / override policy on every parse path (incl. `-00:30` and negative overrides as the HTA passes them), truncated and outcome-less records, complete user -> host membership, and the viewer's identity matching, three-state outcome rules and filters, reload reconciliation, legacy-run handling and overlapping / same-named multi-file input. `/selftest` additionally checks reload behaviour natively under mshta (`test\viewer-tests.js`, needs node.js). Run it after every change.

## Changes

- **0.1.4** - fixes from the fourth review, multi-file input: overlapping inputs (a folder and its subfolder, a folder and one of its files, a repeated path, or aliases of one path - `..`, case, 8.3 short names) read the same file more than once and inflated every count - each file is now canonicalised and read once, and the run reports how many duplicates were ignored; same-named files under separately selected roots got identical `SourceFile#row=N` citations - every SourceFile id is now the path relative to the common root of the whole file set, so it is unique in the run and identical however the same files were selected. The command line now accepts several `|`-separated inputs like the Input box. Regression suite: 62 checks.
- **0.1.3** - fixes from the third review, all state carried across a reload: the row-detail panel and Copy row survived loading another run (Copy row re-resolved an old row index against the new table) - the selection is now bound to the table object it came from and cleared on every load and table change; a selected user or department absent from the new run stayed active but invisible (blank dropdown, zero rows) - rebuilt filters are now reconciled with the run (absent = cleared and reported in the status line, case-only difference = the run's spelling); Allowed only / Blocked only still treated a `(none)` action as blocked - they now use the three-state classifier, so unknown outcomes are in neither. Sorts are also reset on load (column positions can differ between runs). Regression suite: 53 checks; `/selftest`: 38.
- **0.1.2** - fixes from the second review: the user -> host membership cache survived loading another run (same selected user could show the previous run's hosts as "exact") - every per-run cache is now reset on load, and `/selftest` checks it natively; allowed / blocked / unknown are now three distinct outcomes in every flag and finding (a threat or remote-access request with no Policy Action is `...-OUTCOME-UNKNOWN`, ranked like allowed, never "blocked"); runs saved by v0.1.0 (no C2 counters) are classified from their sample paths again, with a HIGH finding that C2 detection for that run is incomplete and should be re-processed. `/selftest` now also logs every finding. Regression suite: 44 checks.
- **0.1.1** - fixes from the 21 Oct 2026 code review: beacon timing kept dropping the first check-in (pairs with exactly 8 bursts vanished; 20 became 19); C2 paths were only tested on the six display samples per host - now every record's full path is tested and counted (`C2PathHits`, `C2WeakHits`, `C2Paths` with citations); zone-free values reaching the fallback parser were silently taken as UTC and bypassed the override; `-00:30` lost its sign; records shorter than the header were aggregated and a missing action counted as Allowed - now excluded as `Incomplete` (lines cited) and empty actions are an unknown outcome; the user filter matched identity prefixes - now exact, and Destinations uses the new complete **User -> host** table instead of the top-four TopUsers summary. Also: negative timezone overrides failed to reach the engine (`-File` read `-07:00` as a parameter name).

## Limits

- ZIA logs only traffic forwarded to it: off-tunnel traffic, bypassed destinations and non-web protocols are absent.
- NSS feed / syslog formats and ZIA firewall / DNS logs are not read in this version (web-log CSV only).
- Beacon timing uses the one-second resolution of Event Time; requests within 2 s count as one check-in.

## License

MIT (c) 2026 Ben Morris
