# Log Sentinel
![CI](https://github.com/cachuchablanco/log-sentinel/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

A small, recruiter-readable **mini-SIEM**: parse authentication, web, and firewall logs into a common event model, run **YAML detection rules**, and emit SOC-style **JSON alerts** plus a markdown **incident report**.

Built as a portfolio piece for junior cybersecurity / SOC analyst roles. It demonstrates log parsing, ATT&CK-mapped detections, and ticket-quality reporting — not a production SIEM replacement.

## Why it exists

Junior SOC work is mostly: read logs → recognize a pattern → write a clear alert → open a ticket with evidence and next steps. This repo packages that loop in a few hundred lines of Python you can run locally in under a minute.


## If you ask me on a call

I would not start with the architecture diagram. I would start with the planted case: `203.0.113.50` hits the web logs with attack strings, then brute-forces `alice` on SSH, then gets in. WEB-001 and AUTH-001 are the same actor. That is the ticket.

What I would say next:

- YAML rules plus Python detectors, so a threshold change is not a code change
- IPs are documentation-range only. This is not a scanner. It reads logs you already have
- The markdown report is the point. Junior SOC is writing, not collecting tools
- This is not Splunk. If they ask why I did not just use Elastic, the answer is: I wanted something I can walk line by line

If they open `detectors.py`, I can talk brute-force vs password spray (AUTH-001 vs AUTH-004), impossible travel, and why after-hours admin is medium not high. Spray is one IP, many usernames, few tries each. Brute force is the opposite.


## Architecture

```
samples/*.log  →  parsers  →  Event[]  →  YAML rules + detectors  →  Alert[]
                                                              ↘ alerts.json
                                                              ↘ incident_report.md
```

- **Parsers** (`src/log_sentinel/parsers.py`) normalize sshd, nginx combined, and a simple firewall format into `Event`.
- **Rules** (`rules/detections.yaml`) name a detector, severity, MITRE mapping, and thresholds.
- **Detectors** (`src/log_sentinel/detectors.py`) are pure functions over events. Geo is a synthetic IP→city table (`geo.py`) using documentation-range addresses only.
- **CLI** (`log-sentinel analyze`) writes `out/alerts.json` and `out/incident_report.md`.

No database, no agents, no live scanners. Detection of already-collected logs only.

## Detection rules

| Rule ID | Name | What it catches | MITRE |
|---|---|---|---|
| AUTH-001 | brute_force | Many SSH failures then a success for the same user/IP | T1110 Brute Force |
| AUTH-002 | impossible_travel | Two successes for one user from distant geos at impossible speed | T1078 Valid Accounts |
| AUTH-003 | after_hours_admin | Successful login by `admin`/`root` outside 08:00–18:00 UTC | T1078.003 Valid Accounts — Local |
| AUTH-004 | password_spray | One IP, many usernames, few SSH failures each | T1110.003 Password Spraying |
| NET-001 | port_sweep | Many distinct destinations (or ports) from one source in a short window | T1046 Network Service Discovery |
| WEB-001 | web_attack | SQLi / XSS / path-traversal *strings in access logs* | T1190 Exploit Public-Facing Application |

WEB-001 inspects query strings that already appear in nginx logs (e.g. `' OR 1=1`). It is not an exploit tool and does not send traffic.

## Quick start

Requires Python 3.11+.

```bash
cd log-sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
log-sentinel analyze samples/
```

Artifacts land in `out/`:

- `alerts.json` — structured alerts (severity, rule id, MITRE, evidence, recommended next steps)
- `incident_report.md` — ticket-style write-up for the highest-signal planted case

### Expected CLI output (abridged)

```text
Log Sentinel — analyzing samples
  parsed  188 events  (auth=92, firewall=53, web=43)

Detections
  HIGH  WEB-001   web_attack              203.0.113.50
        Web attack patterns from 203.0.113.50 (path_traversal, sqli, xss)
  HIGH  AUTH-001  brute_force             alice @ 203.0.113.50
        SSH brute-force against alice from 203.0.113.50
  HIGH  AUTH-002  impossible_travel       bob @ 203.0.113.80
        Impossible travel for bob: New York → Tokyo
  HIGH  AUTH-004  password_spray          203.0.113.91
        SSH password spray from 203.0.113.91
  MED   AUTH-003  after_hours_admin       admin @ 198.51.100.200
        After-hours admin login: admin from 198.51.100.200
  MED   NET-001   port_sweep              198.51.100.77
        Horizontal scan from 198.51.100.77 (20 hosts)

Wrote 6 alerts → out/alerts.json
Wrote incident report → out/incident_report.md
  primary case: SSH brute-force against alice from 203.0.113.50
```

(Exact event counts may shift slightly if samples are edited; all six rule IDs must appear.)

## Case walkthrough — `203.0.113.50` vs `alice`

Planted campaign on 2026-08-26 UTC (see `samples/README.md`):

1. **11:28–11:30** — nginx records SQLi, XSS, and `../../etc/passwd` probes from `203.0.113.50` (synthetic geo: Moscow). WEB-001 fires.
2. **11:40–11:43** — twelve SSH password failures for `alice`, then an acceptance from the same IP. AUTH-001 fires.
3. Firewall shows earlier denies on port 22 and a late allow matching the success.

The generated incident report treats this as the primary ticket: timeline of that IP across sources, impact language, related detections (web + auth), and concrete response steps (reset account, block IP, hunt sibling hosts, verify MFA).

Other planted cases in the same day: `bob` New York→Tokyo (AUTH-002), horizontal SSH sweep from `198.51.100.77` (NET-001), `admin` login at 03:14 UTC from Frankfurt (AUTH-003). Benign employee traffic and below-threshold internet noise are mixed in so the corpus is not toy-clean.

## Project layout

```text
log-sentinel/
├── rules/detections.yaml      # config-driven thresholds + MITRE
├── samples/                   # synthetic auth / nginx / firewall logs
├── src/log_sentinel/          # parsers, detectors, CLI, report writer
├── tests/                     # pytest: parsers + each rule + CLI
├── pyproject.toml
└── README.md
```

## What I'd add next

- Streaming ingest (file tail or syslog) instead of batch files
- Correlation IDs that bind multi-rule campaigns into one case automatically
- Sigma rule import for a subset of community detections
- Optional Slack/email sink for alerts
- Richer geo (still offline) and ASN enrichment for the evidence block

## License

MIT. Sample data is fictional; IPs are RFC 5737 / RFC 1918 only.
