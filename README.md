# LightHouse — Local AI Security Copilot

LightHouse turns local Suricata, Zeek, and Wazuh records into validated, plain-English security guidance. Everything — the monitoring data and the AI inference — stays on your own machine. Nothing is sent to a remote service.

It ships as a normal Linux desktop application: install it, find it in your applications menu, double-click it, see a window.

---

## Installing (Ubuntu 22.04 LTS or 24.04 LTS)

Download `lighthouse_0.1.0_amd64.deb`, then either double-click it in Files, or run:

```
sudo apt install ./lighthouse_0.1.0_amd64.deb
```

That single step installs the application, installs and configures the sensors it reads (Suricata, Zeek, the Wazuh manager) and the local AI model runner (Ollama), detects your actual local network, creates the background monitoring service, and adds LightHouse to your applications menu. It takes a while the first time, mostly downloading the AI model.

Then open **LightHouse** from your applications menu. On the very first launch it shows you a one-time administrator password; write it down, sign in with it, and LightHouse immediately asks you to choose your own.

That is the whole install. There is no terminal step, no config file to edit, and no password to go hunting for in a log.

### What gets installed

| Component | Purpose |
| --- | --- |
| Suricata | Network intrusion detection, configured for your real local subnet |
| Zeek | Network traffic analysis, set to emit JSON |
| Wazuh manager | Host security monitoring. The CVE feed and the OpenSearch indexer are switched off — they are a multi-gigabyte download that duplicates what LightHouse already shows you |
| Ollama | Runs the AI model locally. Model size is chosen from your hardware (GPU, RAM) |
| `lighthouse.service` | The background monitoring service, started at boot |

### Monitoring runs whether the window is open or not

The window is a **viewer**, not the product. Closing it does not stop protection — `lighthouse.service` keeps reading your sensors and triaging alerts from boot onwards, and the window simply shows you what it found.

```
systemctl status lighthouse     # is monitoring running?
journalctl -u lighthouse -f     # what is it doing?
```

**Known limitation.** Unlike a dedicated always-on appliance, this runs on a computer you also use for other things. When it is asleep, shut down, or off the network, it is not monitoring. The "continuous" in continuous monitoring is bounded by how often the machine is actually on. If you need genuinely uninterrupted coverage, see the appliance deployment at the end of this document.

### Uninstalling

```
sudo apt remove lighthouse    # removes the app, keeps your alert history
sudo apt purge  lighthouse    # removes the alert history and credentials too
```

Neither removes Suricata, Zeek, Wazuh, or Ollama — they are ordinary packages and may be in use by something else. Remove them explicitly if you want them gone.

---

## Building the package

On **Ubuntu 22.04**, not 24.04: the bundled binary links against the build machine's glibc, and a 22.04 build runs on 24.04 while the reverse does not.

```
sudo apt install python3-pip nodejs npm dpkg-dev
pip install -e '.[desktop,dev]'
./packaging/build-deb.sh
```

This builds the dashboard with `npm ci`, bundles the backend with PyInstaller, and assembles `build/lighthouse_0.1.0_amd64.deb`.

`npm ci` and not `npm install`: it installs exactly the reviewed `dashboard/package-lock.json` tree and nothing newer. That lockfile is committed, and it matters here more than it does in most projects — npm runs dependency install scripts as the building user, and this build output is embedded in a package that installs with root privileges on somebody else's computer. Review lockfile changes as you would review code.

### Running from source

You do not need to build a package to work on it:

```
pip install -e '.[desktop,dev]'
cd dashboard && npm ci && npm run build && cd ..
python -m triage.desktop
```

The desktop entry point checks whether a LightHouse service is already answering on `127.0.0.1:8000`. If one is, it opens a window onto it; if not, it starts the API itself in a background thread. It never enables `--reload` or `LIGHTHOUSE_DEV` — the desktop build behaves like production always.

For frontend work, the Vite dev server with hot reload is faster:

```
LIGHTHOUSE_DEV=1 uvicorn triage.api:app --reload --host 127.0.0.1 --port 8000
cd dashboard && npm run dev
```

Vite serves the dashboard on `http://localhost:5173` and proxies `/api` to `127.0.0.1:8000`. Both stay on loopback. `LIGHTHOUSE_DEV` publishes the schema and the route table, so it is a workstation-only setting.

Run the tests with `python -m pytest`.

---

## Architecture

The desktop build is a single process doing two jobs:

- **The API** — FastAPI on `127.0.0.1:8000`, serving both `/api/...` and the built dashboard from the same origin.
- **Ingestion** — the sensor log tails, running as a background `asyncio` task inside the API's lifespan.

Folding ingestion into the API process means one service to install and one to supervise, rather than two that can fail independently on a machine with nobody watching. The cost is that they now share a process, so the ingestion task is deliberately isolated: it catches everything below `CancelledError` and logs it. A parsing bug in a sensor record leaves you with a degraded install; letting it escape would leave you with an application you cannot even log in to.

The appliance deployment keeps the original two-process split — see below.

**Loopback only.** The API is never exposed on the LAN, there is no TLS termination, and there is no reverse proxy. There is nothing to expose: it listens on `127.0.0.1` and the window connects to it locally. LAN access is what the appliance deployment is for.

### Configuration

Set in `/etc/lighthouse/lighthouse.env` by the installer. You will not normally edit these.

| Variable | Default | Purpose |
| --- | --- | --- |
| `LIGHTHOUSE_DESKTOP` | unset | Selects desktop behavior: per-user data directory, in-process ingestion, first-run password handoff. Implied by a bundled build. |
| `LIGHTHOUSE_DB_PATH` | `~/.local/share/lighthouse/lighthouse.db` (desktop), `lighthouse.db` (appliance) | SQLite database, WAL mode. Holds password hashes and live session tokens; the directory is created `0700`. |
| `LIGHTHOUSE_FIRST_RUN_DIR` | the data directory | Where the one-time admin password is handed from the service to the window. The package points this at `/var/lib/lighthouse/handoff` (`0750`, group `lighthouse`), because service and window run as different accounts. |
| `LIGHTHOUSE_STATIC_DIR` | `dashboard/dist` under the bundle or working directory | Built dashboard, mounted at `/` when present. |
| `LIGHTHOUSE_MODEL` | chosen by hardware at install | Local Ollama model used for triage. |
| `LIGHTHOUSE_PORT` | `8000` | Loopback port for the API. |
| `LIGHTHOUSE_SURICATA_PATH` | `/var/log/suricata/eve.json` | Suricata `eve.json` to tail. |
| `LIGHTHOUSE_ZEEK_PATH` | `/opt/zeek/logs/current/conn.log` | Zeek JSON log to tail. |
| `LIGHTHOUSE_WAZUH_PATH` | `/var/ossec/logs/alerts/alerts.json` | Wazuh alert JSON to tail. |
| `LIGHTHOUSE_CORS_ORIGINS` | empty | Extra browser origins. Leave empty: same-origin needs none. |
| `LIGHTHOUSE_DEV` | unset | Development conveniences. Never set outside a workstation. |

### Roles

- **Owner**: plain-language alerts, trends, and personal preferences.
- **Analyst**: Owner access plus technical evidence and health views.
- **Admin**: Analyst access plus user management and settings.

Role filtering happens on the server. The dashboard hiding a tab is presentation, not access control.

### First sign-in, in detail

On first start LightHouse generates a random administrator password and does two things with it: prints it once to stdout (which lands in the systemd journal), and — in desktop mode only — writes it to a one-time file that the window reads, displays, and deletes. It is stored only as a bcrypt hash.

Signing in with it forces a password change before anything else renders; every request except login, logout, and the password change itself is refused until it is replaced. The new password must be at least 12 characters. There is no default credential. If the generated one is lost before it is changed, the admin account has to be re-provisioned against the database.

If the window never showed you a password, it is still in the journal:

```
sudo journalctl -u lighthouse --no-pager | grep -A3 "administrator account"
```

---

## Alternative: hardware appliance deployment

**This is not the default deployment, and most readers should stop here.** It describes running LightHouse as a dedicated always-on box on a customer network, reachable from other machines over the LAN — the original deployment model, kept because it is real working knowledge and because it solves the always-on limitation the desktop app has.

It is a fundamentally different security posture: the desktop app is loopback-only and has no network attack surface, while this one is exposed on the LAN and therefore *requires* TLS in front of it. Do not mix the two sets of instructions.

### What you need on the appliance

- A Linux machine or VM (Ubuntu 24.04 LTS is a practical default) with Python 3.11+.
- Ollama on `http://localhost:11434` with `qwen3:8b` pulled.
- nginx or Caddy on the appliance to terminate TLS. LightHouse itself speaks plain HTTP on loopback only.
- Node 20+ **on the machine that builds the dashboard**. The appliance needs no Node at runtime — it serves static files.

### 1. Install the backend

```
python -m venv .venv && . .venv/bin/activate
pip install -e .
```

Use `pip install -e '.[dev]'` to also run the test suite.

### 2. Build the dashboard

```
cd dashboard
npm ci
npm run build
```

`npm run build` writes to `dashboard/dist`. Nothing from `dashboard/` other than `dist/` needs to reach the appliance: build on a workstation, copy the directory across (`rsync -a dashboard/dist/ appliance:/opt/lighthouse/dashboard/dist/`), and point `LIGHTHOUSE_STATIC_DIR` at it. Build output is deliberately not committed.

### 3. Seed the demo database (optional)

```
python -m triage.main replay --mock
```

Fills the database from `samples/` without calling a model. Skip on a real deployment.

### 4. Run the API on loopback

```
uvicorn triage.api:app --host 127.0.0.1 --port 8000
```

No `--reload`: it is a development file-watcher, it doubles the process count, and it re-executes application code on any file change.

`LIGHTHOUSE_DESKTOP` is left unset here, so the API does **not** start ingestion — that stays a separate process on the appliance (step 7).

### 5. Terminate TLS in front of it

Publish only 443 on the LAN and proxy to `127.0.0.1:8000`. Session tokens are bearer tokens valid for eight hours; without TLS both the login POST and every later request carry them across the customer network in cleartext.

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

### 7. Live ingestion, as a second unit

Set `LIGHTHOUSE_SURICATA_PATH`, `LIGHTHOUSE_ZEEK_PATH`, and `LIGHTHOUSE_WAZUH_PATH` to the JSON-line log paths, then run:

```
python -m triage.main tail
```

Zeek must be configured to emit JSON (`LogAscii::use_json=T`). The service account needs read access to each file *and its directory*, so log rotation does not silently stop ingestion.

### First sign-in on the appliance

The generated admin password reaches the journal, not a window:

```
sudo journalctl -u lighthouse --no-pager | grep -i password
```

---

See `docs/implementation-log.md`, `docs/missing-information.md`, and `docs/backend-completion-requirements.md` for implementation status, deployment inputs, and the backend handoff checklist.
