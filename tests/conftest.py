from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from log_sentinel.models import Event

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
RULES = ROOT / "rules" / "detections.yaml"


def ts(hour: int, minute: int = 0, second: int = 0) -> datetime:
    return datetime(2026, 8, 26, hour, minute, second, tzinfo=timezone.utc)


def ev(
    *,
    timestamp: datetime,
    source_type: str,
    src_ip: str,
    action: str,
    user: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    path: str | None = None,
    method: str | None = "GET",
    raw: str | None = None,
) -> Event:
    return Event(
        timestamp=timestamp,
        source_type=source_type,
        src_ip=src_ip,
        action=action,
        raw=raw or f"{timestamp.isoformat()} {action} {src_ip} {user or ''} {path or ''}".strip(),
        user=user,
        dst_ip=dst_ip,
        dst_port=dst_port,
        path=path,
        method=method if source_type == "web" else None,
    )


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES


@pytest.fixture
def rules_path() -> Path:
    return RULES
