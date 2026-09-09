from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Source(StrEnum):
    SURICATA = "suricata"
    ZEEK = "zeek"
    WAZUH = "wazuh"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class AlertStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class NormalizedAlert(BaseModel):
    source: Source
    source_event_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    title: str
    source_ip: str | None = None
    destination_ip: str | None = None
    device: str | None = None
    rule_id: str | None = None
    mitre: list[str] = Field(default_factory=list)
    raw: dict[str, Any]

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)


class TriageResult(BaseModel):
    severity: Severity
    explanation: str = Field(min_length=1, max_length=1200)
    recommended_action: str = Field(min_length=1, max_length=600)
    reasoning: str | None = Field(default=None, max_length=2400)


class AlertDetail(BaseModel):
    id: int
    source: Source
    timestamp: datetime
    title: str
    source_ip: str | None
    destination_ip: str | None
    device: str | None
    rule_id: str | None
    mitre: list[str]
    raw: dict[str, Any]
    status: AlertStatus
    duplicate_count: int
    triage: TriageResult | None
