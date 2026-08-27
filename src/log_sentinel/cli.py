"""Command-line interface: `log-sentinel analyze samples/`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from log_sentinel import __version__
from log_sentinel.engine import DEFAULT_RULES, load_rules, run_detections
from log_sentinel.ingest import ingest
from log_sentinel.report import write_alerts_json, write_incident_report

SEVERITY_PAD = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-sentinel",
        description="Parse logs, run YAML detection rules, write JSON alerts and an incident report.",
    )
    parser.add_argument("--version", action="version", version=f"log-sentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Ingest a log file or directory and emit detections.")
    analyze.add_argument("path", type=Path, help="Log file or directory (e.g. samples/)")
    analyze.add_argument(
        "--rules",
        type=Path,
        default=None,
        help=f"YAML rules file (default: {DEFAULT_RULES})",
    )
    analyze.add_argument(
        "--out",
        type=Path,
        default=Path("out"),
        help="Output directory for alerts.json and incident_report.md (default: out/)",
    )
    return parser


def _print_summary(
    path: Path,
    event_count: int,
    counts: dict[str, int],
    alerts: list,
    out_dir: Path,
    primary_title: str | None,
) -> None:
    print(f"Log Sentinel — analyzing {path}")
    parts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
    print(f"  parsed  {event_count} events  ({parts})")
    print()
    if not alerts:
        print("Detections")
        print("  (none)")
        print()
        print(f"Wrote 0 alerts → {out_dir / 'alerts.json'}")
        print(f"Wrote incident report → {out_dir / 'incident_report.md'}")
        return
    print("Detections")
    for alert in alerts:
        sev = SEVERITY_PAD.get(alert.severity, alert.severity.upper()[:4]).ljust(4)
        who = alert.src_ip or "-"
        if alert.user:
            who = f"{alert.user} @ {who}"
        print(f"  {sev}  {alert.rule_id:<8}  {alert.rule_name:<22}  {who}")
        print(f"        {alert.title}")
    print()
    print(f"Wrote {len(alerts)} alerts → {out_dir / 'alerts.json'}")
    print(f"Wrote incident report → {out_dir / 'incident_report.md'}")
    if primary_title:
        print(f"  primary case: {primary_title}")


def cmd_analyze(args: argparse.Namespace) -> int:
    target: Path = args.path
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2
    rules_path = args.rules
    config = load_rules(rules_path)
    events, counts = ingest(target)
    alerts = run_detections(events, config)
    out_dir: Path = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    write_alerts_json(alerts, out_dir / "alerts.json")
    primary = write_incident_report(alerts, events, out_dir / "incident_report.md", str(target))
    _print_summary(target, len(events), counts, alerts, out_dir, primary.title if primary else None)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
