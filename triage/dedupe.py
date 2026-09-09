from __future__ import annotations

import hashlib

from .schema import NormalizedAlert


def fingerprint(alert: NormalizedAlert) -> str:
    """Stable identity for repeat detector hits, intentionally excluding timestamp."""
    values = [alert.source, alert.rule_id or alert.title, alert.source_ip or "", alert.destination_ip or "", alert.device or ""]
    return hashlib.sha256("|".join(values).encode()).hexdigest()
