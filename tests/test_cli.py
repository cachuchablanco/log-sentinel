from __future__ import annotations

import json
from pathlib import Path

from log_sentinel.cli import main


def test_analyze_writes_alerts_and_report(samples_dir: Path, tmp_path: Path, capsys):
    out = tmp_path / "out"
    rc = main(["analyze", str(samples_dir), "--out", str(out)])
    assert rc == 0
    printed = capsys.readouterr().out
    assert "AUTH-001" in printed
    assert "WEB-001" in printed
    assert "NET-001" in printed
    assert "AUTH-002" in printed
    assert "AUTH-003" in printed

    alerts_path = out / "alerts.json"
    report_path = out / "incident_report.md"
    assert alerts_path.is_file()
    assert report_path.is_file()

    payload = json.loads(alerts_path.read_text(encoding="utf-8"))
    assert payload["alert_count"] >= 5
    rule_ids = {a["rule_id"] for a in payload["alerts"]}
    assert {"AUTH-001", "AUTH-002", "AUTH-003", "NET-001", "WEB-001"} <= rule_ids
    for alert in payload["alerts"]:
        assert "mitre_technique_id" in alert
        assert alert["evidence"]
        assert alert["recommended_next_steps"]

    report = report_path.read_text(encoding="utf-8")
    assert report.startswith("# Incident Report")
    assert "Timeline" in report
    assert "Recommended response" in report
    assert "203.0.113.50" in report or "alice" in report.lower()


def test_analyze_missing_path_exits_2(tmp_path: Path):
    rc = main(["analyze", str(tmp_path / "nope")])
    assert rc == 2
