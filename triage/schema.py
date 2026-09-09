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


# Rank order used whenever two severities must be compared. UNKNOWN sits above LOW
# because a triage the model could not validate still needs a human look, but below
# MEDIUM because it asserts nothing about the actual risk.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.UNKNOWN: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def coerce_severity(value: Any) -> Severity:
    """Any unrecognised value is treated as UNKNOWN rather than raising."""
    try:
        return Severity(value)
    except ValueError:
        return Severity.UNKNOWN


def max_severity(first: Any, second: Any) -> Severity:
    """Return the more severe of two values by SEVERITY_RANK."""
    left, right = coerce_severity(first), coerce_severity(second)
    return left if SEVERITY_RANK[left] >= SEVERITY_RANK[right] else right


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
    # Severity the sensor itself reported, derived deterministically in the readers.
    # It is the floor the model is not allowed to undercut. LOW is the safe default:
    # it never raises risk on its own, it only stops a downgrade when a sensor spoke.
    sensor_severity: Severity = Severity.LOW
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


class TriagePublic(BaseModel):
    """Triage fields an owner may see. Deliberately has no `reasoning`."""
    severity: Severity
    explanation: str
    recommended_action: str


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
    sensor_severity: Severity = Severity.UNKNOWN
    triage: TriageResult | None


class AlertDetailOwner(BaseModel):
    """Owner-facing shape of an alert.

    README places technical evidence at analyst level and above, so the raw sensor
    record, the detection rule id and the analyst reasoning are absent from this
    model entirely. `from_detail` filters through the model itself, so adding a
    field to AlertDetail can never leak it here by accident.
    """
    id: int
    source: Source
    timestamp: datetime
    title: str
    source_ip: str | None
    destination_ip: str | None
    device: str | None
    mitre: list[str]
    status: AlertStatus
    duplicate_count: int
    sensor_severity: Severity = Severity.UNKNOWN
    triage: TriagePublic | None

    @classmethod
    def from_detail(cls, detail: AlertDetail) -> "AlertDetailOwner":
        # Pydantic ignores unknown keys by default, so `raw`, `rule_id` and
        # `triage.reasoning` are dropped by validation rather than by hand.
        return cls.model_validate(detail.model_dump())
