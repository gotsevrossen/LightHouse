# GUARD — Local AI Security Copilot

GUARD turns local Suricata, Zeek, and Wazuh records into validated, plain-English security guidance. It is designed for a Linux appliance: monitoring data and AI inference stay on the customer network.

## Quick start (Linux VM)

1. Install Python 3.11+, Node 20+, and Ollama; pull `qwen3:8b`.
2. Create a virtual environment and install the backend:
   `python -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'`
3. Seed the demo database without calling a model:
   `python -m triage.main replay --mock`
4. Run the API: `uvicorn triage.api:app --reload`
5. In another terminal: `cd dashboard && npm install && npm run dev`

The seeded administrator is `admin` / `change-me-now`. Change it before exposing the dashboard on a network.

## Live ingestion

Configure JSON-line paths with `GUARD_SURICATA_PATH`, `GUARD_ZEEK_PATH`, and `GUARD_WAZUH_PATH`, then run `python -m triage.main tail`. Zeek must be configured to emit JSON (`LogAscii::use_json=T`).

## Roles

- **Owner**: plain-language alerts, trends, and personal preferences.
- **Analyst**: Owner access plus technical evidence and health views.
- **Admin**: Analyst access plus users and appliance settings.

See `docs/implementation-log.md`, `docs/missing-information.md`, and `docs/backend-completion-requirements.md` for current implementation status, deployment inputs, and the backend handoff checklist.
