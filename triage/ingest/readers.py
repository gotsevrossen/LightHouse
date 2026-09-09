from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from ..schema import NormalizedAlert, Source


def parse_record(source: Source, raw: dict[str, Any]) -> NormalizedAlert:
    """Convert native JSON records into the one shape used downstream."""
    if source is Source.SURICATA:
        alert = raw.get("alert")
        if not isinstance(alert, dict):
            raise ValueError("Suricata record has no alert object")
        mitre = [entry.get("technique_id") for entry in alert.get("metadata", {}).get("mitre", []) if entry.get("technique_id")]
        return NormalizedAlert(source=source, source_event_id=str(raw.get("flow_id", "")) or None,
            timestamp=raw["timestamp"], title=alert.get("signature", "Unnamed Suricata alert"), source_ip=raw.get("src_ip"),
            destination_ip=raw.get("dest_ip"), rule_id=str(alert.get("signature_id", "")) or None, mitre=mitre, raw=raw)
    if source is Source.ZEEK:
        if not raw.get("ts"):
            raise ValueError("Zeek record has no ts")
        note = raw.get("note") or raw.get("service") or raw.get("_path")
        return NormalizedAlert(source=source, source_event_id=raw.get("uid"), timestamp=raw["ts"],
            title=f"Zeek {note or 'network activity'}", source_ip=raw.get("id.orig_h"), destination_ip=raw.get("id.resp_h"),
            device=raw.get("id.orig_h"), raw=raw)
    if source is Source.WAZUH:
        rule = raw.get("rule")
        if not isinstance(rule, dict) or not raw.get("timestamp"):
            raise ValueError("Wazuh record requires timestamp and rule")
        mitre = [item.get("id") for item in rule.get("mitre", {}).get("technique", []) if item.get("id")]
        return NormalizedAlert(source=source, source_event_id=str(raw.get("id", "")) or None, timestamp=raw["timestamp"],
            title=rule.get("description", "Unnamed Wazuh alert"), source_ip=raw.get("data", {}).get("srcip"),
            device=raw.get("agent", {}).get("name"), rule_id=str(rule.get("id", "")) or None, mitre=mitre, raw=raw)
    raise ValueError(f"Unsupported source: {source}")


async def tail_json_lines(path: Path, source: Source) -> AsyncIterator[NormalizedAlert]:
    """Tail a JSON-lines file. Caller owns retry/restart policy for rotated files."""
    with path.open(encoding="utf-8") as handle:
        handle.seek(0, 2)
        while True:
            line = handle.readline()
            if not line:
                await asyncio.sleep(0.5)
                continue
            try:
                yield parse_record(source, json.loads(line))
            except (ValueError, json.JSONDecodeError):
                continue
