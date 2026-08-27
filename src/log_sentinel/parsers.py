"""Parsers for auth (sshd), web (nginx combined), and firewall logs."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from log_sentinel.models import Event

# 2026-08-26T09:12:01Z jump sshd[1022]: ...
_TS = r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"

_AUTH_ACCEPTED = re.compile(
    rf"^{_TS} (?P<host>\S+) sshd\[\d+\]: Accepted (?:password|publickey) "
    rf"for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_AUTH_FAILED = re.compile(
    rf"^{_TS} (?P<host>\S+) sshd\[\d+\]: Failed password for "
    rf"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_AUTH_INVALID = re.compile(
    rf"^{_TS} (?P<host>\S+) sshd\[\d+\]: Invalid user (?P<user>\S+) "
    rf"from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)
_AUTH_DISCONNECT = re.compile(
    rf"^{_TS} (?P<host>\S+) sshd\[\d+\]: Disconnected from user (?P<user>\S+) "
    rf"(?P<ip>\S+) port (?P<port>\d+)"
)
_AUTH_SESSION = re.compile(
    rf"^{_TS} (?P<host>\S+) sshd\[\d+\]: pam_unix\(sshd:session\): "
    rf"session (?P<sess>opened|closed) for user (?P<user>\S+)"
)

# nginx combined: ip - user [26/Aug/2026:09:15:22 +0000] "GET /path HTTP/1.1" 200 4312 "ref" "ua"
_NGINX = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>\S+)" '
    r'(?P<status>\d+) (?P<bytes>\d+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

_NGINX_TS = "%d/%b/%Y:%H:%M:%S %z"

# firewall: 2026-08-26T11:05:00Z deny tcp 198.51.100.77 44112 10.0.1.10 22 0 outside_in
_FW = re.compile(
    rf"^{_TS} (?P<action>allow|deny) (?P<proto>\S+) "
    rf"(?P<src_ip>\S+) (?P<src_port>\d+) (?P<dst_ip>\S+) (?P<dst_port>\d+) "
    rf"(?P<bytes>\d+) (?P<rule>\S+)"
)


def parse_ts(value: str) -> datetime:
    """Parse ISO-8601 timestamps, treating naive values as UTC."""
    cleaned = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_auth_line(line: str) -> Event | None:
    raw = line.rstrip("\n")
    if not raw or raw.startswith("#"):
        return None

    m = _AUTH_ACCEPTED.match(raw)
    if m:
        return Event(
            timestamp=parse_ts(m["ts"]),
            source_type="auth",
            src_ip=m["ip"],
            action="login_success",
            raw=raw,
            user=m["user"],
            src_port=int(m["port"]),
            dst_port=22,
            protocol="ssh",
            host=m["host"],
            extra={"auth_method": "password_or_key"},
        )

    m = _AUTH_FAILED.match(raw)
    if m:
        return Event(
            timestamp=parse_ts(m["ts"]),
            source_type="auth",
            src_ip=m["ip"],
            action="login_fail",
            raw=raw,
            user=m["user"],
            src_port=int(m["port"]),
            dst_port=22,
            protocol="ssh",
            host=m["host"],
        )

    m = _AUTH_INVALID.match(raw)
    if m:
        port = int(m["port"]) if m["port"] else None
        return Event(
            timestamp=parse_ts(m["ts"]),
            source_type="auth",
            src_ip=m["ip"],
            action="invalid_user",
            raw=raw,
            user=m["user"],
            src_port=port,
            dst_port=22,
            protocol="ssh",
            host=m["host"],
        )

    m = _AUTH_DISCONNECT.match(raw)
    if m:
        return Event(
            timestamp=parse_ts(m["ts"]),
            source_type="auth",
            src_ip=m["ip"],
            action="disconnect",
            raw=raw,
            user=m["user"],
            src_port=int(m["port"]),
            dst_port=22,
            protocol="ssh",
            host=m["host"],
        )

    m = _AUTH_SESSION.match(raw)
    if m:
        return Event(
            timestamp=parse_ts(m["ts"]),
            source_type="auth",
            src_ip="0.0.0.0",
            action=f"session_{m['sess']}",
            raw=raw,
            user=m["user"],
            host=m["host"],
        )

    return None


def parse_nginx_line(line: str) -> Event | None:
    raw = line.rstrip("\n")
    if not raw or raw.startswith("#"):
        return None
    m = _NGINX.match(raw)
    if not m:
        return None
    ts = datetime.strptime(m["ts"], _NGINX_TS).astimezone(timezone.utc)
    user = m["user"] if m["user"] != "-" else None
    try:
        status = int(m["status"])
    except ValueError:
        status = None
    return Event(
        timestamp=ts,
        source_type="web",
        src_ip=m["ip"],
        action="http_request",
        raw=raw,
        user=user,
        method=m["method"],
        path=m["path"],
        status_code=status,
        user_agent=m["ua"],
        protocol=m["proto"],
        extra={"bytes": int(m["bytes"]), "referer": m["ref"]},
    )


def parse_firewall_line(line: str) -> Event | None:
    raw = line.rstrip("\n")
    if not raw or raw.startswith("#"):
        return None
    m = _FW.match(raw)
    if not m:
        return None
    return Event(
        timestamp=parse_ts(m["ts"]),
        source_type="firewall",
        src_ip=m["src_ip"],
        action=m["action"],
        raw=raw,
        dst_ip=m["dst_ip"],
        src_port=int(m["src_port"]),
        dst_port=int(m["dst_port"]),
        protocol=m["proto"],
        extra={"bytes": int(m["bytes"]), "rule": m["rule"]},
    )


_PARSER_BY_NAME = {
    "auth": parse_auth_line,
    "web": parse_nginx_line,
    "nginx": parse_nginx_line,
    "firewall": parse_firewall_line,
    "fw": parse_firewall_line,
}


def guess_parser(path: Path) -> str | None:
    name = path.name.lower()
    if "auth" in name or "sshd" in name or "secure" in name:
        return "auth"
    if "nginx" in name or "access" in name or "web" in name:
        return "web"
    if "fw" in name or "firewall" in name or "iptables" in name:
        return "firewall"
    return None


def parse_file(path: Path, source_type: str | None = None) -> list[Event]:
    kind = source_type or guess_parser(path)
    if kind is None:
        raise ValueError(f"cannot guess log type for {path}; pass source_type")
    parser = _PARSER_BY_NAME.get(kind)
    if parser is None:
        raise ValueError(f"unknown log type {kind!r} for {path}")
    events: list[Event] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        ev = parser(line)
        if ev is not None:
            events.append(ev)
    return events
