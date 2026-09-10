# LightHouse — Local AI Security Copilot

LightHouse turns local Suricata, Zeek, and Wazuh records into validated, plain-English security guidance. It is designed for a Linux appliance: monitoring data and AI inference stay on the customer network.

## What you need on the appliance

- A Linux VM (Ubuntu 24.04 LTS is a practical default) with Python 3.11+.
- Ollama running on `http://localhost:11434` with `qwen3:8b` pulled.
- nginx or Caddy on the appliance to terminate TLS. LightHouse itself speaks plain HTTP on loopback only.
- Node 20+ **on the machine that builds the dashboard**. The appliance does not need Node at runtime — it serves a directory of static files.

## Deploying (production)

### 1. Install the backend

```
python -m venv .venv && . .venv/bin/activate
pip install -e .
```

Use `pip install -e '.[dev]'` if you also want to run the test suite.

### 2. Build the dashboard

```
cd dashboard
npm ci
npm run build
```

The built dashboard uses the LightHouse UI frame as its initial interface. Its
sidebar navigation, collapse control, recent chats, alert actions, filters, trends,
settings, administration, sign out, and local chat prompts are connected to the
React application and API.

`npm run build` writes static assets to `dashboard/dist`. Nothing from `dashboard/` other than `dist/` needs to reach the appliance: build here, then copy the directory across (`rsync -a dashboard/dist/ appliance:/opt/lighthouse/dashboard/dist/`) and point `LIGHTHOUSE_STATIC_DIR` at it. Build output is deliberately not committed — `dashboard/dist/` and `node_modules/` are in `.gitignore`. Building on the appliance itself also works, but then it needs Node 20+ and a full `node_modules` tree.

**Lockfile — do this once, before the first deployment.** This repository does not ship `dashboard/package-lock.json` yet, and `npm ci` refuses to run without one. On a trusted workstation (not the customer appliance) run `npm install` once, review the resulting `dashboard/package-lock.json`, and commit it. From then on every build uses `npm ci`, which installs exactly the reviewed tree and nothing newer. Every dependency in `package.json` is pinned to an exact version, but only a committed lockfile pins the transitive dependencies — and npm runs install scripts as the deploying user on a host that can read the session-token database.

### 3. Seed the demo database (optional)

```
python -m triage.main replay --mock
```

This fills the database from `samples/` without calling a model. Skip it on a real deployment.

### 4. Run the API on loopback

```
uvicorn triage.api:app --host 127.0.0.1 --port 8000
```

No `--reload` — it is a development file-watcher, it doubles the process count, and it re-executes application code on any file change.

When `LIGHTHOUSE_STATIC_DIR` (default `dashboard/dist`) exists, the API mounts it at `/` and serves the built dashboard itself. The dashboard and the API are then the same origin, so no CORS configuration and no second listener are needed. If that directory is missing, the API still serves `/api/...` and the dashboard routes simply 404 — that is the symptom of a skipped `npm run build`.

### 5. Terminate TLS in front of it

Publish only 443 on the LAN and proxy to `127.0.0.1:8000`. Session tokens are bearer tokens that stay valid for eight hours; without TLS both the login POST and every subsequent request carry them across the customer network in cleartext.

nginx:

```
server {
    listen 443 ssl;
    server_name lighthouse.lan;
    ssl_certificate     /etc/ssl/lighthouse/fullchain.pem;
    ssl_certificate_key /etc/ssl/lighthouse/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Caddy needs one line: `lighthouse.lan { reverse_proxy 127.0.0.1:8000 }`.

Never expose uvicorn directly, and never run the Vite dev server on the customer network — `--host 0.0.0.0` on a dev server publishes unminified sources, source maps, and an unauthenticated module endpoint.

### 6. Run it under systemd

`/etc/systemd/system/lighthouse.service`:

```
[Unit]
Description=LightHouse local security copilot
After=network-online.target

[Service]
User=lighthouse
Group=lighthouse
WorkingDirectory=/opt/lighthouse
Environment=LIGHTHOUSE_DB_PATH=/var/lib/lighthouse/lighthouse.db
Environment=LIGHTHOUSE_STATIC_DIR=/opt/lighthouse/dashboard/dist
Environment=LIGHTHOUSE_MODEL=qwen3:8b
ExecStart=/opt/lighthouse/.venv/bin/uvicorn triage.api:app --host 127.0.0.1 --port 8000
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/lighthouse

[Install]
WantedBy=multi-user.target
```

Keep the database directory readable only by the service account: it holds password hashes, live session tokens, and raw alert payloads.

## First sign-in

On first start LightHouse generates a random administrator password and prints it **once** to stdout. Under systemd it lands in the journal:

```
sudo journalctl -u lighthouse --no-pager | grep -i password
```

Capture it, sign in as `admin`, and the dashboard immediately forces a change-password screen — nothing else renders until the temporary password is replaced. The new password must be at least 12 characters. There is no default credential to forget to change; if the generated one is lost before it is changed, the admin account has to be re-provisioned against the database at `LIGHTHOUSE_DB_PATH`.

That screen is the only password-change UI today; it posts to `POST /api/auth/password` (current password, new password), which any signed-in user may call. Signing out revokes the session token on the server, so a copied token stops working immediately rather than at the end of its eight-hour life.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `LIGHTHOUSE_DB_PATH` | `lighthouse.db` | SQLite database (WAL mode, so `.db-wal` and `.db-shm` sit beside it). Put it on a path only the service account can read. |
| `LIGHTHOUSE_STATIC_DIR` | `dashboard/dist` | Built dashboard. Mounted at `/` when the directory exists; ignored when it does not. |
| `LIGHTHOUSE_CORS_ORIGINS` | empty | Comma-separated extra browser origins. Leave empty in production: the same-origin deployment above needs none. |
| `LIGHTHOUSE_DEV` | unset | Development conveniences, including the Vite dev-server origin. Never set it on an appliance. |
| `LIGHTHOUSE_MODEL` | `qwen3:8b` | Local Ollama model used for triage. |
| `LIGHTHOUSE_SURICATA_PATH` | unset | Suricata `eve.json` to tail. |
| `LIGHTHOUSE_ZEEK_PATH` | unset | Zeek JSON log to tail. |
| `LIGHTHOUSE_WAZUH_PATH` | unset | Wazuh alert JSON export to tail. |

## Live ingestion

Set `LIGHTHOUSE_SURICATA_PATH`, `LIGHTHOUSE_ZEEK_PATH`, and `LIGHTHOUSE_WAZUH_PATH` to the JSON-line log paths, then run `python -m triage.main tail`. Zeek must be configured to emit JSON (`LogAscii::use_json=T`). The service account needs read access to each file and to its directory, so that log rotation does not silently stop ingestion.

## Local development

On a workstation only, never on the appliance:

```
LIGHTHOUSE_DEV=1 uvicorn triage.api:app --reload --host 127.0.0.1 --port 8000
cd dashboard && npm ci && npm run dev
```

Vite serves the dashboard on `http://localhost:5173` and proxies `/api` to `127.0.0.1:8000`. Both listeners stay on loopback; reach them over an SSH tunnel rather than by binding to `0.0.0.0`.

## Roles

- **Owner**: plain-language alerts, trends, and personal preferences.
- **Analyst**: Owner access plus technical evidence and health views.
- **Admin**: Analyst access plus users and appliance settings.

See `docs/implementation-log.md`, `docs/missing-information.md`, and `docs/backend-completion-requirements.md` for current implementation status, deployment inputs, and the backend handoff checklist.
