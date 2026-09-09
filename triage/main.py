from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from .db import Database, default_db_path
from .ingest import parse_record, tail_json_lines
from .llm import FixtureTriageModel, OllamaTriageModel, TriageModel
from .schema import Source
from .service import TriageService

# The live log file for each sensor, as documented in the README.
SOURCE_ENV_VARS: dict[Source, str] = {
    Source.SURICATA: "LIGHTHOUSE_SURICATA_PATH",
    Source.ZEEK: "LIGHTHOUSE_ZEEK_PATH",
    Source.WAZUH: "LIGHTHOUSE_WAZUH_PATH",
}


def build_model(mock: bool) -> TriageModel:
    if mock:
        return FixtureTriageModel()
    return OllamaTriageModel(os.getenv("LIGHTHOUSE_MODEL", "qwen3:8b"),
                             os.getenv("LIGHTHOUSE_OLLAMA_URL", "http://localhost:11434"))


def build_service(mock: bool) -> TriageService:
    service = TriageService(Database(default_db_path()), build_model(mock))
    service.db.initialize()
    return service


def configured_sources() -> dict[Source, Path]:
    """Sensors with a path set. Anything unset is simply not ingested."""
    configured: dict[Source, Path] = {}
    for source, variable in SOURCE_ENV_VARS.items():
        value = (os.getenv(variable) or "").strip()
        if value:
            configured[source] = Path(value)
    return configured


async def replay(mock: bool) -> None:
    service = build_service(mock)
    for path in Path("samples").glob("*.jsonl"):
        source = Source(path.stem)
        for line in path.read_text(encoding="utf-8").splitlines():
            alert_id, duplicate = await service.process(parse_record(source, json.loads(line)))
            print(f"{'suppressed duplicate' if duplicate else 'triaged'}: {path.name} -> {alert_id}")


async def _tail_source(service: TriageService, source: Source, path: Path) -> None:
    print(f"tailing {source}: {path}", flush=True)
    try:
        async for alert in tail_json_lines(path, source):
            try:
                alert_id, duplicate = await service.process(alert)
            except Exception as error:  # one bad record must not stop the sensor
                print(f"error: {source} record could not be triaged: {error}", file=sys.stderr, flush=True)
                continue
            print(f"{'suppressed duplicate' if duplicate else 'triaged'}: {source} -> {alert_id}", flush=True)
    except asyncio.CancelledError:
        raise
    except OSError as error:
        print(f"error: stopped tailing {path}: {error}", file=sys.stderr, flush=True)


async def tail(mock: bool) -> None:
    """Follow every configured sensor log at once and triage each new record."""
    configured = configured_sources()
    if not configured:
        raise SystemExit("No sensor log paths configured. Set at least one of: " + ", ".join(SOURCE_ENV_VARS.values()))
    unreadable = []
    for source, path in configured.items():
        if not path.is_file():
            unreadable.append(f"{SOURCE_ENV_VARS[source]}={path} (not a readable file)")
        else:
            try:
                with path.open(encoding="utf-8"):
                    pass
            except OSError as error:
                unreadable.append(f"{SOURCE_ENV_VARS[source]}={path} ({error.strerror or error})")
    if unreadable:
        raise SystemExit("Cannot read configured sensor log: " + "; ".join(unreadable))

    service = build_service(mock)
    tasks = [asyncio.create_task(_tail_source(service, source, path), name=str(source))
             for source, path in configured.items()]
    try:
        await asyncio.gather(*tasks)
    finally:
        # Reached on Ctrl+C as well: stop every tail before the loop closes.
        for task in tasks:
            task.cancel()
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            # Already shutting down; the cancellations above are what matter.
            pass


def cli() -> None:
    parser = argparse.ArgumentParser(prog="python -m triage.main")
    sub = parser.add_subparsers(dest="command", required=True)
    replay_parser = sub.add_parser("replay", help="triage the bundled sample files")
    replay_parser.add_argument("--mock", action="store_true", help="use the fixture model instead of Ollama")
    tail_parser = sub.add_parser("tail", help="follow the configured live sensor logs")
    tail_parser.add_argument("--mock", action="store_true", help="use the fixture model instead of Ollama")
    args = parser.parse_args()
    try:
        if args.command == "replay":
            asyncio.run(replay(args.mock))
        elif args.command == "tail":
            asyncio.run(tail(args.mock))
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)


if __name__ == "__main__": cli()
