import json
from pathlib import Path

import pytest

from triage.ingest import parse_record
from triage.schema import Source


@pytest.mark.parametrize("source", [Source.SURICATA, Source.ZEEK, Source.WAZUH])
def test_fixture_parses(source):
    raw = json.loads((Path("samples") / f"{source}.jsonl").read_text().splitlines()[0])
    alert = parse_record(source, raw)
    assert alert.source == source
    assert alert.title
    assert alert.raw == raw

def test_bad_suricata_rejected():
    with pytest.raises(ValueError): parse_record(Source.SURICATA, {"timestamp": "2026-01-01T00:00:00+00:00"})
