from __future__ import annotations

from datetime import timezone

from log_sentinel.parsers import parse_auth_line, parse_firewall_line, parse_nginx_line, parse_file
from pathlib import Path


def test_parse_auth_success():
    line = "2026-08-26T09:12:01Z jump sshd[1022]: Accepted password for alice from 10.0.2.5 port 49811 ssh2"
    ev = parse_auth_line(line)
    assert ev is not None
    assert ev.is_auth_success
    assert ev.user == "alice"
    assert ev.src_ip == "10.0.2.5"
    assert ev.src_port == 49811
    assert ev.dst_port == 22
    assert ev.timestamp.tzinfo is not None
    assert ev.timestamp.tzinfo == timezone.utc or ev.timestamp.utcoffset().total_seconds() == 0


def test_parse_auth_fail_and_invalid_user():
    fail = parse_auth_line(
        "2026-08-26T11:40:02Z jump sshd[5510]: Failed password for alice from 203.0.113.50 port 60001 ssh2"
    )
    assert fail is not None and fail.is_auth_failure and fail.user == "alice"

    invalid = parse_auth_line(
        "2026-08-26T00:07:16Z jump sshd[881]: Invalid user test from 192.0.2.88 port 44190"
    )
    assert invalid is not None and invalid.action == "invalid_user" and invalid.user == "test"


def test_parse_auth_skips_comments_and_garbage():
    assert parse_auth_line("# comment") is None
    assert parse_auth_line("not a syslog line") is None
    assert parse_auth_line("") is None


def test_parse_nginx_combined():
    line = (
        '203.0.113.50 - - [26/Aug/2026:11:28:22 +0000] '
        '"GET /search?q=%27+OR+1%3D1-- HTTP/1.1" 200 891 "-" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'
    )
    ev = parse_nginx_line(line)
    assert ev is not None
    assert ev.source_type == "web"
    assert ev.src_ip == "203.0.113.50"
    assert ev.method == "GET"
    assert ev.path.startswith("/search?")
    assert ev.status_code == 200
    assert ev.user is None


def test_parse_nginx_with_user():
    line = (
        '10.0.2.5 - alice [26/Aug/2026:09:15:22 +0000] '
        '"GET /dashboard HTTP/1.1" 200 4312 "-" "Mozilla/5.0"'
    )
    ev = parse_nginx_line(line)
    assert ev is not None and ev.user == "alice"


def test_parse_firewall_deny():
    line = "2026-08-26T11:02:11Z deny tcp 198.51.100.77 44001 10.0.1.1 22 0 scan-drop"
    ev = parse_firewall_line(line)
    assert ev is not None
    assert ev.source_type == "firewall"
    assert ev.action == "deny"
    assert ev.src_ip == "198.51.100.77"
    assert ev.dst_ip == "10.0.1.1"
    assert ev.dst_port == 22
    assert ev.extra["rule"] == "scan-drop"


def test_parse_file_auth_samples(samples_dir: Path):
    events = parse_file(samples_dir / "auth.log")
    assert len(events) >= 40
    assert any(e.is_auth_success and e.user == "alice" for e in events)
    assert any(e.is_auth_failure and e.src_ip == "203.0.113.50" for e in events)
