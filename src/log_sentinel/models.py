"""Shared event and alert models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    """Normalized log event produced by a parser."""

    timestamp: datetime
    source_type: str  # auth | web | firewall
    src_ip: str
    action: str
    raw: str
    dst_ip: str | None = None
    user: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    host: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_auth_failure(self) -> bool:
        return self.source_type == "auth" and self.action in {"login_fail", "invalid_user"}

    @property
    def is_auth_success(self) -> bool:
        return self.source_type == "auth" and self.action == "login_success"


@dataclass
class Alert:
    """Structured detection output suitable for a SOC ticket."""

    rule_id: str
    rule_name: str
    severity: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique: str
    title: str
    description: str
    src_ip: str | None
    user: str | None
    first_seen: datetime
    last_seen: datetime
    evidence: list[str]
    recommended_next_steps: list[str]
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["first_seen"] = self.first_seen.isoformat()
        payload["last_seen"] = self.last_seen.isoformat()
        return payload
