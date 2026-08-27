"""Load YAML rules and run enabled detectors."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from log_sentinel.detectors import REGISTRY
from log_sentinel.models import Alert, Event

DEFAULT_RULES = Path(__file__).resolve().parents[2] / "rules" / "detections.yaml"


def load_rules(path: Path | None = None) -> dict[str, Any]:
    rules_path = path or DEFAULT_RULES
    if not rules_path.is_file():
        raise FileNotFoundError(f"rules file not found: {rules_path}")
    data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "rules" not in data:
        raise ValueError(f"{rules_path} must contain a top-level 'rules' list")
    return data


def run_detections(events: list[Event], config: dict[str, Any]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in config.get("rules") or []:
        if not rule.get("enabled", True):
            continue
        detector_name = rule.get("detector")
        fn = REGISTRY.get(detector_name)
        if fn is None:
            raise KeyError(
                f"unknown detector {detector_name!r} for rule {rule.get('id')}; "
                f"known: {sorted(REGISTRY)}"
            )
        alerts.extend(fn(events, rule))
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    alerts.sort(key=lambda a: (severity_rank.get(a.severity, 9), a.first_seen, a.rule_id))
    return alerts
