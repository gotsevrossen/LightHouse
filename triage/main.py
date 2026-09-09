from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .db import Database
from .ingest import parse_record
from .llm import FixtureTriageModel, OllamaTriageModel
from .schema import Source
from .service import TriageService

async def replay(mock: bool) -> None:
    service = TriageService(Database(), FixtureTriageModel() if mock else OllamaTriageModel())
    service.db.initialize()
    for path in Path("samples").glob("*.jsonl"):
        source = Source(path.stem)
        for line in path.read_text(encoding="utf-8").splitlines():
            alert_id, duplicate = await service.process(parse_record(source, json.loads(line)))
            print(f"{'suppressed duplicate' if duplicate else 'triaged'}: {path.name} -> {alert_id}")

def cli() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    replay_parser = sub.add_parser("replay"); replay_parser.add_argument("--mock", action="store_true")
    args = parser.parse_args()
    if args.command == "replay": asyncio.run(replay(args.mock))

if __name__ == "__main__": cli()
