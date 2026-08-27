"""Detection functions. Each takes events + a rule config dict and returns alerts.

These are detections of *already observed* log patterns (brute-force successes,
geo-inconsistent logins, scans, web-attack strings in access logs). They are not
exploit tools and do not generate attack traffic.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable
from urllib.parse import unquote_plus

from log_sentinel.geo import haversine_km, lookup
from log_sentinel.models import Alert, Event

Detector = Callable[[list[Event], dict[str, Any]], list[Alert]]

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _mitre(rule: dict[str, Any]) -> tuple[str, str, str]:
    m = rule.get("mitre") or {}
    return (
        str(m.get("tactic", "Unknown")),
        str(m.get("technique_id", "T0000")),
        str(m.get("technique", "Unspecified")),
    )


def _alert(
    rule: dict[str, Any],
    *,
    title: str,
    description: str,
    events: list[Event],
    src_ip: str | None,
    user: str | None,
    steps: list[str],
    extra: dict[str, Any] | None = None,
    evidence_limit: int = 12,
) -> Alert:
    tactic, tid, technique = _mitre(rule)
    ordered = sorted(events, key=lambda e: e.timestamp)
    evidence = [e.raw for e in ordered[:evidence_limit]]
    if len(ordered) > evidence_limit:
        evidence.append(f"... {len(ordered) - evidence_limit} additional matching events omitted")
    return Alert(
        rule_id=str(rule["id"]),
        rule_name=str(rule.get("name", rule.get("detector", "unknown"))),
        severity=str(rule.get("severity", "medium")).lower(),
        mitre_tactic=tactic,
        mitre_technique_id=tid,
        mitre_technique=technique,
        title=title,
        description=description,
        src_ip=src_ip,
        user=user,
        first_seen=ordered[0].timestamp,
        last_seen=ordered[-1].timestamp,
        evidence=evidence,
        recommended_next_steps=steps,
        extra=extra or {},
    )


def detect_brute_force(events: list[Event], rule: dict[str, Any]) -> list[Alert]:
    """Many auth failures for the same (src_ip, user), optionally followed by success."""
    params = rule.get("params") or {}
    threshold = int(params.get("fail_threshold", 8))
    window = timedelta(minutes=int(params.get("window_minutes", 10)))
    require_success = bool(params.get("require_success", True))

    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for ev in events:
        if ev.source_type != "auth" or ev.user is None:
            continue
        if ev.action not in {"login_fail", "invalid_user", "login_success"}:
            continue
        grouped[(ev.src_ip, ev.user)].append(ev)

    alerts: list[Alert] = []
    for (src_ip, user), group in grouped.items():
        group.sort(key=lambda e: e.timestamp)
        fails = [e for e in group if e.is_auth_failure]
        successes = [e for e in group if e.is_auth_success]
        if len(fails) < threshold:
            continue

        fired = False
        for i, start in enumerate(fails):
            window_fails = [e for e in fails[i:] if e.timestamp - start.timestamp <= window]
            if len(window_fails) < threshold:
                continue
            window_end = window_fails[-1].timestamp
            matching_success = [
                s
                for s in successes
                if start.timestamp <= s.timestamp <= window_end + window
            ]
            if require_success and not matching_success:
                continue
            related = window_fails + matching_success
            related.sort(key=lambda e: e.timestamp)
            outcome = (
                "followed by a successful login"
                if matching_success
                else "with no observed success in-window"
            )
            alerts.append(
                _alert(
                    rule,
                    title=f"SSH brute-force against {user} from {src_ip}",
                    description=(
                        f"{len(window_fails)} failed SSH attempts for user '{user}' from "
                        f"{src_ip} within {int(window.total_seconds() // 60)} minutes, {outcome}."
                    ),
                    events=related,
                    src_ip=src_ip,
                    user=user,
                    steps=[
                        "Lock or reset the targeted account and invalidate existing sessions.",
                        "Block the source IP at the edge firewall / WAF and hunt for other hosts it touched.",
                        "Review sudo, file, and outbound traffic from the destination host after the success.",
                        "Confirm MFA is enforced for this account; if not, treat credentials as compromised.",
                    ],
                    extra={
                        "fail_count": len(window_fails),
                        "success_count": len(matching_success),
                    },
                )
            )
            fired = True
            break
        if fired:
            continue
    return alerts


def detect_impossible_travel(events: list[Event], rule: dict[str, Any]) -> list[Alert]:
    """Two successful logins for one user from geos that imply impossible speed."""
    params = rule.get("params") or {}
    max_kmh = float(params.get("max_speed_kmh", 800))
    min_km = float(params.get("min_distance_km", 500))

    by_user: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        if ev.is_auth_success and ev.user:
            by_user[ev.user].append(ev)

    alerts: list[Alert] = []
    for user, logins in by_user.items():
        logins.sort(key=lambda e: e.timestamp)
        for a, b in zip(logins, logins[1:]):
            geo_a, geo_b = lookup(a.src_ip), lookup(b.src_ip)
            # Office/RFC1918 hops are not geographic travel.
            if geo_a.internal or geo_b.internal:
                continue
            if geo_a.city == geo_b.city and geo_a.country == geo_b.country:
                continue
            hours = (b.timestamp - a.timestamp).total_seconds() / 3600.0
            if hours <= 0:
                continue
            distance = haversine_km(geo_a.lat, geo_a.lon, geo_b.lat, geo_b.lon)
            if distance < min_km:
                continue
            speed = distance / hours
            if speed <= max_kmh:
                continue
            alerts.append(
                _alert(
                    rule,
                    title=f"Impossible travel for {user}: {geo_a.city} → {geo_b.city}",
                    description=(
                        f"User '{user}' had successful SSH logins from {a.src_ip} "
                        f"({geo_a.label()}) then {b.src_ip} ({geo_b.label()}) "
                        f"{int((b.timestamp - a.timestamp).total_seconds() // 60)} minutes later "
                        f"(~{distance:.0f} km, implied {speed:.0f} km/h)."
                    ),
                    events=[a, b],
                    src_ip=b.src_ip,
                    user=user,
                    steps=[
                        "Contact the user out-of-band; do not use the possibly-compromised session.",
                        "Revoke both sessions and rotate credentials / SSH keys.",
                        "Check which login is the anomaly (new ASN, new device, after-hours).",
                        "Hunt for follow-on activity from both source IPs across auth, VPN, and web logs.",
                    ],
                    extra={
                        "from": geo_a.label(),
                        "to": geo_b.label(),
                        "distance_km": round(distance, 1),
                        "implied_kmh": round(speed, 1),
                    },
                )
            )
    return alerts


def detect_port_sweep(events: list[Event], rule: dict[str, Any]) -> list[Alert]:
    """Horizontal scan (many hosts, few ports) or vertical scan (many ports, one host)."""
    params = rule.get("params") or {}
    window = timedelta(minutes=int(params.get("window_minutes", 5)))
    min_hosts = int(params.get("min_unique_hosts", 12))
    min_ports = int(params.get("min_unique_ports", 12))

    fw_events = [e for e in events if e.source_type == "firewall"]
    by_src: dict[str, list[Event]] = defaultdict(list)
    for ev in fw_events:
        by_src[ev.src_ip].append(ev)

    alerts: list[Alert] = []
    for src_ip, group in by_src.items():
        group.sort(key=lambda e: e.timestamp)
        # sliding window by index
        left = 0
        best_hosts: list[Event] = []
        best_ports: list[Event] = []
        for right, ev in enumerate(group):
            while group[right].timestamp - group[left].timestamp > window:
                left += 1
            window_slice = group[left : right + 1]
            hosts = {e.dst_ip for e in window_slice if e.dst_ip}
            ports = {e.dst_port for e in window_slice if e.dst_port is not None}
            if len(hosts) >= min_hosts and len(window_slice) >= len(best_hosts):
                best_hosts = list(window_slice)
            if len(ports) >= min_ports and len(window_slice) >= len(best_ports):
                best_ports = list(window_slice)

        geo = lookup(src_ip)
        if best_hosts:
            hosts = sorted({e.dst_ip for e in best_hosts if e.dst_ip})
            ports = sorted({e.dst_port for e in best_hosts if e.dst_port is not None})
            denies = sum(1 for e in best_hosts if e.action == "deny")
            alerts.append(
                _alert(
                    rule,
                    title=f"Horizontal scan from {src_ip} ({len(hosts)} hosts)",
                    description=(
                        f"Source {src_ip} ({geo.label()}) contacted {len(hosts)} distinct destinations "
                        f"on port(s) {ports[:8]} within {int(window.total_seconds() // 60)} minutes "
                        f"({denies} denied)."
                    ),
                    events=best_hosts,
                    src_ip=src_ip,
                    user=None,
                    steps=[
                        "Confirm the source is not an approved scanner / vuln-mgmt box.",
                        "Block the source at the perimeter if unauthorised.",
                        "Identify any allow hits — those hosts may need host-level review.",
                        "Correlate with auth logs for the same source immediately after the sweep.",
                    ],
                    extra={
                        "scan_type": "horizontal",
                        "unique_hosts": len(hosts),
                        "unique_ports": ports,
                        "deny_count": denies,
                    },
                )
            )
        if best_ports and best_ports is not best_hosts:
            # avoid double-alerting identical windows as both types when possible
            hosts = sorted({e.dst_ip for e in best_ports if e.dst_ip})
            ports = sorted({e.dst_port for e in best_ports if e.dst_port is not None})
            if len(ports) >= min_ports:
                alerts.append(
                    _alert(
                        rule,
                        title=f"Vertical port sweep from {src_ip} ({len(ports)} ports)",
                        description=(
                            f"Source {src_ip} ({geo.label()}) probed {len(ports)} distinct destination "
                            f"ports on {len(hosts)} host(s) within "
                            f"{int(window.total_seconds() // 60)} minutes."
                        ),
                        events=best_ports,
                        src_ip=src_ip,
                        user=None,
                        steps=[
                            "Confirm the source is not an approved scanner.",
                            "Block the source if unauthorised and review any allow hits.",
                            "Check whether the probed ports belong to internet-facing services.",
                        ],
                        extra={
                            "scan_type": "vertical",
                            "unique_hosts": len(hosts),
                            "unique_ports": ports,
                        },
                    )
                )
    return alerts


_DEFAULT_WEB_PATTERNS: list[tuple[str, str]] = [
    ("sqli", r"(?i)(\bunion\b.+\bselect\b|'(\s*)or(\s*)\d+=\d+|or\s+1\s*=\s*1|--\s|/\*|\bwaitfor\b\s+\bdelay\b)"),
    ("xss", r"(?i)(<script[\s>]|javascript:|onerror\s*=|onload\s*=|<img[\s>].*onerror)"),
    ("path_traversal", r"(?i)(\.\./|\.\.\\|/etc/passwd)"),
]


def detect_web_attack(events: list[Event], rule: dict[str, Any]) -> list[Alert]:
    """Flag HTTP requests whose path/query matches SQLi, XSS, or traversal strings.

    This inspects already-collected access logs. It does not send payloads.
    """
    params = rule.get("params") or {}
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for item in params.get("patterns") or []:
        compiled.append((str(item["id"]), re.compile(item["regex"])))
    if not compiled:
        compiled = [(name, re.compile(rx)) for name, rx in _DEFAULT_WEB_PATTERNS]

    hits: dict[str, list[tuple[Event, list[str]]]] = defaultdict(list)
    for ev in events:
        if ev.source_type != "web" or not ev.path:
            continue
        decoded = unquote_plus(ev.path)
        kinds = [name for name, rx in compiled if rx.search(decoded) or rx.search(ev.path)]
        if kinds:
            hits[ev.src_ip].append((ev, kinds))

    alerts: list[Alert] = []
    for src_ip, rows in hits.items():
        kinds = sorted({k for _, ks in rows for k in ks})
        matched_events = [e for e, _ in rows]
        geo = lookup(src_ip)
        alerts.append(
            _alert(
                rule,
                title=f"Web attack patterns from {src_ip} ({', '.join(kinds)})",
                description=(
                    f"{len(rows)} HTTP request(s) from {src_ip} ({geo.label()}) contained "
                    f"query/path strings matching {', '.join(kinds)} signatures "
                    f"(SQLi/XSS/traversal-like). This is attacker traffic observed in logs, "
                    f"not an exploit against a live target."
                ),
                events=matched_events,
                src_ip=src_ip,
                user=None,
                steps=[
                    "Confirm the requests were blocked or returned an error; if 200s, inspect app logs.",
                    "Block or rate-limit the source at the WAF / reverse proxy.",
                    "Search access logs for the same payload family from other IPs.",
                    "If any request authenticated, treat that session as untrusted.",
                ],
                extra={
                    "pattern_ids": kinds,
                    "hit_count": len(rows),
                    "status_codes": sorted({e.status_code for e in matched_events if e.status_code}),
                },
            )
        )
    return alerts


def detect_after_hours_admin(events: list[Event], rule: dict[str, Any]) -> list[Alert]:
    """Successful login by an admin-class account outside business hours."""
    params = rule.get("params") or {}
    admins = {u.lower() for u in params.get("admin_users", ["admin", "root"])}
    start_hour = int(params.get("start_hour", 8))
    end_hour = int(params.get("end_hour", 18))

    alerts: list[Alert] = []
    for ev in events:
        if not ev.is_auth_success or not ev.user:
            continue
        if ev.user.lower() not in admins:
            continue
        hour = ev.timestamp.hour
        in_hours = start_hour <= hour < end_hour
        if in_hours:
            continue
        geo = lookup(ev.src_ip)
        alerts.append(
            _alert(
                rule,
                title=f"After-hours admin login: {ev.user} from {ev.src_ip}",
                description=(
                    f"Privileged account '{ev.user}' authenticated at "
                    f"{ev.timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')} from {ev.src_ip} "
                    f"({geo.label()}). Business hours are {start_hour:02d}:00–{end_hour:02d}:00 UTC."
                ),
                events=[ev],
                src_ip=ev.src_ip,
                user=ev.user,
                steps=[
                    "Verify with the account owner (out-of-band) that the login was expected.",
                    "If unconfirmed, disable the account and terminate the session.",
                    "Review commands / sudo on the destination host after this timestamp.",
                    "Check whether this source IP appears in other log sources the same night.",
                ],
                extra={"hour_utc": hour, "geo": geo.label()},
            )
        )
    return alerts



def detect_password_spray(events: list[Event], rule: dict[str, Any]) -> list[Alert]:
    """One source IP, many usernames, few failures each. Not brute force (one user, many tries)."""
    params = rule.get("params") or {}
    min_users = int(params.get("min_users", 8))
    max_fails_per_user = int(params.get("max_fails_per_user", 3))
    window = timedelta(minutes=int(params.get("window_minutes", 15)))

    fails = [e for e in events if e.is_auth_failure and e.user]
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for ev in fails:
        by_ip[ev.src_ip].append(ev)

    alerts: list[Alert] = []
    seen_ips: set[str] = set()
    for src_ip, group in by_ip.items():
        group.sort(key=lambda e: e.timestamp)
        for i, start in enumerate(group):
            window_events = [e for e in group[i:] if e.timestamp - start.timestamp <= window]
            counts: dict[str, int] = defaultdict(int)
            for e in window_events:
                counts[e.user] += 1
            spray_users = [u for u, c in counts.items() if c <= max_fails_per_user]
            if len(spray_users) < min_users:
                continue
            if src_ip in seen_ips:
                break
            seen_ips.add(src_ip)
            related = [e for e in window_events if e.user in spray_users]
            related.sort(key=lambda e: e.timestamp)
            user_list = ", ".join(sorted(spray_users)[:12])
            more = "" if len(spray_users) <= 12 else f" (+{len(spray_users) - 12} more)"
            alerts.append(
                _alert(
                    rule,
                    title=f"SSH password spray from {src_ip}",
                    description=(
                        f"{len(spray_users)} distinct usernames failed SSH from {src_ip} "
                        f"within {int(window.total_seconds() // 60)} minutes, "
                        f"at most {max_fails_per_user} failures per user ({user_list}{more}). "
                        "That is a spray, not a brute-force against one account."
                    ),
                    events=related,
                    src_ip=src_ip,
                    user=None,
                    steps=[
                        "Do not treat this as a single locked-out user. Many accounts were probed.",
                        "Block or rate-limit the source IP on the jump host / VPN.",
                        "Search for any success from this IP after the spray.",
                        "Check whether the same usernames failed from other IPs (credential stuffing follow-on).",
                    ],
                    extra={
                        "user_count": len(spray_users),
                        "users": sorted(spray_users),
                        "max_fails_per_user": max(counts[u] for u in spray_users),
                    },
                )
            )
            break
    return alerts


REGISTRY: dict[str, Detector] = {
    "brute_force": detect_brute_force,
    "password_spray": detect_password_spray,
    "impossible_travel": detect_impossible_travel,
    "port_sweep": detect_port_sweep,
    "web_attack": detect_web_attack,
    "after_hours_admin": detect_after_hours_admin,
}


def available_detectors() -> Iterable[str]:
    return REGISTRY.keys()
