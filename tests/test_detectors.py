from __future__ import annotations

from datetime import timedelta

from log_sentinel.detectors import (
    detect_after_hours_admin,
    detect_brute_force,
    detect_password_spray,
    detect_impossible_travel,
    detect_port_sweep,
    detect_web_attack,
)
from log_sentinel.engine import load_rules, run_detections
from log_sentinel.ingest import ingest
from tests.conftest import ev, ts


def _rule(config: dict, rule_id: str) -> dict:
    for rule in config["rules"]:
        if rule["id"] == rule_id:
            return rule
    raise KeyError(rule_id)


def test_brute_force_requires_threshold_and_success(rules_path):
    rule = _rule(load_rules(rules_path), "AUTH-001")
    src, user = "203.0.113.50", "alice"
    fails = [
        ev(
            timestamp=ts(11, 40, i),
            source_type="auth",
            src_ip=src,
            action="login_fail",
            user=user,
        )
        for i in range(12)
    ]
    success = ev(
        timestamp=ts(11, 43, 19),
        source_type="auth",
        src_ip=src,
        action="login_success",
        user=user,
    )
    alerts = detect_brute_force(fails + [success], rule)
    assert len(alerts) == 1
    assert alerts[0].user == "alice"
    assert alerts[0].extra["fail_count"] >= 8
    assert alerts[0].extra["success_count"] >= 1
    assert alerts[0].mitre_technique_id == "T1110"


def test_brute_force_does_not_fire_on_few_fails(rules_path):
    rule = _rule(load_rules(rules_path), "AUTH-001")
    events = [
        ev(
            timestamp=ts(1, 22, i),
            source_type="auth",
            src_ip="203.0.113.14",
            action="login_fail",
            user="root",
        )
        for i in range(3)
    ]
    assert detect_brute_force(events, rule) == []


def test_impossible_travel_nyc_to_tokyo(rules_path):
    rule = _rule(load_rules(rules_path), "AUTH-002")
    events = [
        ev(
            timestamp=ts(14, 2, 11),
            source_type="auth",
            src_ip="198.51.100.10",
            action="login_success",
            user="bob",
        ),
        ev(
            timestamp=ts(14, 24, 44),
            source_type="auth",
            src_ip="203.0.113.80",
            action="login_success",
            user="bob",
        ),
    ]
    alerts = detect_impossible_travel(events, rule)
    assert len(alerts) == 1
    assert alerts[0].user == "bob"
    assert alerts[0].extra["implied_kmh"] > 800
    assert "Tokyo" in alerts[0].title


def test_impossible_travel_ignores_internal_to_internal(rules_path):
    rule = _rule(load_rules(rules_path), "AUTH-002")
    events = [
        ev(
            timestamp=ts(9, 0, 0),
            source_type="auth",
            src_ip="10.0.2.5",
            action="login_success",
            user="alice",
        ),
        ev(
            timestamp=ts(9, 5, 0),
            source_type="auth",
            src_ip="10.0.2.8",
            action="login_success",
            user="alice",
        ),
    ]
    assert detect_impossible_travel(events, rule) == []


def test_port_sweep_horizontal(rules_path):
    rule = _rule(load_rules(rules_path), "NET-001")
    events = [
        ev(
            timestamp=ts(11, 2, i),
            source_type="firewall",
            src_ip="198.51.100.77",
            action="deny",
            dst_ip=f"10.0.1.{i + 1}",
            dst_port=22,
        )
        for i in range(16)
    ]
    alerts = detect_port_sweep(events, rule)
    assert len(alerts) >= 1
    assert any(a.extra.get("scan_type") == "horizontal" for a in alerts)
    assert alerts[0].src_ip == "198.51.100.77"
    assert alerts[0].mitre_technique_id == "T1046"


def test_web_attack_sqli_xss_and_traversal(rules_path):
    rule = _rule(load_rules(rules_path), "WEB-001")
    events = [
        ev(
            timestamp=ts(11, 28, 22),
            source_type="web",
            src_ip="203.0.113.50",
            action="http_request",
            path="/search?q=' OR 1=1--",
        ),
        ev(
            timestamp=ts(11, 29, 18),
            source_type="web",
            src_ip="203.0.113.50",
            action="http_request",
            path="/comment?text=<script>alert(1)</script>",
        ),
        ev(
            timestamp=ts(11, 30, 8),
            source_type="web",
            src_ip="203.0.113.50",
            action="http_request",
            path="/download?file=../../etc/passwd",
        ),
        ev(
            timestamp=ts(11, 30, 21),
            source_type="web",
            src_ip="203.0.113.50",
            action="http_request",
            path="/search?q=quarterly+report",
        ),
    ]
    alerts = detect_web_attack(events, rule)
    assert len(alerts) == 1
    kinds = set(alerts[0].extra["pattern_ids"])
    assert {"sqli", "xss", "path_traversal"} <= kinds
    assert alerts[0].extra["hit_count"] == 3


def test_web_attack_ignores_benign_search(rules_path):
    rule = _rule(load_rules(rules_path), "WEB-001")
    events = [
        ev(
            timestamp=ts(10, 2, 18),
            source_type="web",
            src_ip="10.0.2.5",
            action="http_request",
            path="/search?q=vpn+reset",
        )
    ]
    assert detect_web_attack(events, rule) == []


def test_after_hours_admin_fires_at_0314_not_0802(rules_path):
    rule = _rule(load_rules(rules_path), "AUTH-003")
    night = ev(
        timestamp=ts(3, 14, 2),
        source_type="auth",
        src_ip="198.51.100.200",
        action="login_success",
        user="admin",
    )
    morning = ev(
        timestamp=ts(8, 2, 41),
        source_type="auth",
        src_ip="10.0.0.8",
        action="login_success",
        user="admin",
    )
    employee = ev(
        timestamp=ts(3, 14, 2),
        source_type="auth",
        src_ip="10.0.2.5",
        action="login_success",
        user="alice",
    )
    alerts = detect_after_hours_admin([night, morning, employee], rule)
    assert len(alerts) == 1
    assert alerts[0].user == "admin"
    assert alerts[0].src_ip == "198.51.100.200"


def test_samples_fire_every_planted_rule(samples_dir, rules_path):
    events, counts = ingest(samples_dir)
    assert counts["auth"] > 0 and counts["web"] > 0 and counts["firewall"] > 0
    alerts = run_detections(events, load_rules(rules_path))
    ids = {a.rule_id for a in alerts}
    assert ids >= {"AUTH-001", "AUTH-002", "AUTH-003", "NET-001", "WEB-001"}

    brute = next(a for a in alerts if a.rule_id == "AUTH-001")
    assert brute.src_ip == "203.0.113.50" and brute.user == "alice"

    travel = next(a for a in alerts if a.rule_id == "AUTH-002")
    assert travel.user == "bob"

    sweep = next(a for a in alerts if a.rule_id == "NET-001")
    assert sweep.src_ip == "198.51.100.77"

    web = next(a for a in alerts if a.rule_id == "WEB-001")
    assert web.src_ip == "203.0.113.50"

    after = next(a for a in alerts if a.rule_id == "AUTH-003")
    assert after.user == "admin" and after.src_ip == "198.51.100.200"


def test_password_spray_many_users_few_fails(rules_path):
    rule = _rule(load_rules(rules_path), "AUTH-004")
    src = "203.0.113.91"
    users = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "mysql", "ftp", "guest", "pi"]
    events = [
        ev(
            timestamp=ts(19, 2, i * 3),
            source_type="auth",
            src_ip=src,
            action="login_fail",
            user=user,
        )
        for i, user in enumerate(users)
    ]
    alerts = detect_password_spray(events, rule)
    assert len(alerts) == 1
    assert alerts[0].src_ip == src
    assert alerts[0].extra["user_count"] >= 8
    assert alerts[0].mitre_technique_id == "T1110.003"
    assert "alice" not in alerts[0].extra["users"]


def test_password_spray_does_not_fire_on_brute_force(rules_path):
    rule = _rule(load_rules(rules_path), "AUTH-004")
    events = [
        ev(
            timestamp=ts(11, 40, i),
            source_type="auth",
            src_ip="203.0.113.50",
            action="login_fail",
            user="alice",
        )
        for i in range(12)
    ]
    assert detect_password_spray(events, rule) == []
