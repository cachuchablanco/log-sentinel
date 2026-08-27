"""Write JSON alerts and a markdown incident report for the primary planted case."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from log_sentinel.geo import lookup
from log_sentinel.models import Alert, Event

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def write_alerts_json(alerts: list[Alert], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert_count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# When several alerts share an IP, prefer the one that implies access success.
_PRIMARY_RULE_BONUS = {
    "AUTH-001": 0,  # brute force with success — best ticket lead
    "AUTH-002": 1,
    "WEB-001": 2,
    "AUTH-003": 3,
    "NET-001": 4,
}


def _pick_primary(alerts: list[Alert]) -> Alert | None:
    """Prefer a high-severity alert that correlates with others from the same IP."""
    if not alerts:
        return None
    by_ip: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        if a.src_ip:
            by_ip[a.src_ip].append(a)
    scored: list[tuple[tuple[int, int, int, str], Alert]] = []
    for a in alerts:
        cluster = len(by_ip.get(a.src_ip or "", []))
        rule_bonus = _PRIMARY_RULE_BONUS.get(a.rule_id, 9)
        scored.append(
            (
                (
                    SEVERITY_RANK.get(a.severity, 9),
                    -cluster,
                    rule_bonus,
                    a.rule_id,
                ),
                a,
            )
        )
    scored.sort(key=lambda item: item[0])
    return scored[0][1]


def write_incident_report(
    alerts: list[Alert],
    events: list[Event],
    path: Path,
    source_label: str,
) -> Alert | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    primary = _pick_primary(alerts)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append("# Incident Report — Log Sentinel")
    lines.append("")
    lines.append(f"- Generated: {now}")
    lines.append(f"- Source: `{source_label}`")
    lines.append(f"- Alerts in this run: **{len(alerts)}**")
    lines.append("")

    if primary is None:
        lines.append("No detections fired. No incident ticket opened.")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return None

    related = [
        a
        for a in alerts
        if a is not primary and a.src_ip and a.src_ip == primary.src_ip
    ]

    ticket = f"INC-{primary.first_seen.strftime('%Y%m%d')}-{primary.rule_id}"
    geo = lookup(primary.src_ip) if primary.src_ip else None

    lines.append(f"## Ticket {ticket}")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Title | {primary.title} |")
    lines.append(f"| Severity | **{primary.severity.upper()}** |")
    lines.append(f"| Rule | `{primary.rule_id}` / {primary.rule_name} |")
    lines.append(
        f"| MITRE ATT&CK | {primary.mitre_technique_id} {primary.mitre_technique} "
        f"({primary.mitre_tactic}) |"
    )
    lines.append(f"| Actor IP | `{primary.src_ip or 'n/a'}` |")
    if geo:
        lines.append(f"| Synthetic geo | {geo.label()} |")
    lines.append(f"| User | `{primary.user or 'n/a'}` |")
    lines.append(f"| First seen | {primary.first_seen.isoformat()} |")
    lines.append(f"| Last seen | {primary.last_seen.isoformat()} |")
    lines.append("| Status | Open — needs analyst review |")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(primary.description)
    lines.append("")
    if related:
        lines.append(
            f"The same source IP appears in **{len(related)}** additional alert(s) "
            "in this window, suggesting a multi-stage campaign rather than an isolated event."
        )
        lines.append("")

    lines.append("## Timeline")
    lines.append("")
    lines.append("| Time (UTC) | Source | What happened |")
    lines.append("|---|---|---|")
    timeline: list[tuple[datetime, str, str]] = []
    for ev in events:
        if primary.src_ip and ev.src_ip == primary.src_ip:
            parts = [ev.action]
            if ev.user:
                parts.append(f"user={ev.user}")
            if ev.path:
                parts.append(f"{ev.method or 'GET'} {ev.path}")
            if ev.dst_ip:
                parts.append(f"→ {ev.dst_ip}:{ev.dst_port}")
            what = " ".join(parts)
            timeline.append((ev.timestamp, ev.source_type, what))
    # Always include primary evidence times even if src_ip didn't match (e.g. user-centric)
    if not timeline:
        for raw in primary.evidence:
            if raw.startswith("..."):
                continue
            timeline.append((primary.first_seen, primary.rule_name, raw[:120]))
    for ts, src, what in sorted(timeline, key=lambda r: r[0])[:40]:
        lines.append(f"| {ts.strftime('%Y-%m-%d %H:%M:%S')} | {src} | `{what}` |")
    if len(timeline) > 40:
        lines.append(f"| … | … | {len(timeline) - 40} additional events omitted |")
    lines.append("")

    lines.append("## Impact")
    lines.append("")
    if primary.rule_name == "brute_force" or primary.extra.get("success_count"):
        lines.append(
            "A privileged or named account authenticated from an untrusted source after "
            "repeated failures. Treat the account and the destination host as compromised "
            "until proven otherwise. Potential impact: foothold on the jump host, credential "
            "reuse against other internal services, and data access from that host's trust zone."
        )
    elif primary.rule_name == "impossible_travel":
        lines.append(
            "The account was used from two distant locations faster than travel allows. "
            "At least one of the sessions is not the legitimate user. Potential impact: "
            "account takeover, session hijack, and undetected persistence if the second "
            "login was not the employee."
        )
    else:
        lines.append(
            "Observed activity is consistent with reconnaissance or initial access. "
            "Until contained, the source may continue probing or reuse any foothold already gained."
        )
    lines.append("")

    lines.append("## Related detections")
    lines.append("")
    if related:
        lines.append("| Severity | Rule | Title |")
        lines.append("|---|---|---|")
        for a in related:
            lines.append(f"| {a.severity} | `{a.rule_id}` | {a.title} |")
    else:
        lines.append("No other alerts share this source IP in the current run.")
    lines.append("")

    lines.append("## Other alerts this run")
    lines.append("")
    others = [a for a in alerts if a is not primary and a not in related]
    if others:
        lines.append("| Severity | Rule | Title |")
        lines.append("|---|---|---|")
        for a in others:
            lines.append(f"| {a.severity} | `{a.rule_id}` | {a.title} |")
    else:
        lines.append("None — remaining alerts (if any) are clustered with the primary source.")
    lines.append("")

    lines.append("## Recommended response")
    lines.append("")
    for i, step in enumerate(primary.recommended_next_steps, 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    lines.append("## Evidence excerpts")
    lines.append("")
    lines.append("```")
    for row in primary.evidence:
        lines.append(row)
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("This report is generated from synthetic sample logs. IPs are RFC 5737 documentation ranges.")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return primary
