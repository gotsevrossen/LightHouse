# Native Windows deployment

Build from an x64 Windows development checkout (Node/npm and uv required):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File packaging/windows/build.ps1
```

The build installs Inno Setup with winget if needed, builds the existing React
app, bundles an isolated Python 3.13 runtime and locked backend dependencies,
and produces `dist/LightHouse-Setup.exe`. Target machines do not need Python,
Node, Git, uv, WSL, Docker, Zeek, or Wazuh. Internet access is required during
installation for the sensor packages, rules, Ollama, and model download.
Windows 10 22H2 or newer, x64, is required.

Double-click the EXE and approve Windows elevation. The free Npcap installer
has its own interactive wizard. Enable WinPcap compatibility mode. All other
dependency setup runs unattended. The setup then installs Suricata's official
MSI, Sysmon with the SwiftOnSecurity starting configuration, Ollama, and
`phi4-mini`. It enables Security logon success/failure auditing.

**The free Npcap edition cannot install silently.** This is a missing feature,
not a switch that LightHouse can enable. See the [Npcap vendor guide](https://npcap.com/guide/npcap-users-guide.html).
For a completely unattended install, preinstall Npcap or supply an OEM installer
path in `C:\ProgramData\LightHouse\config\windows.json` under
`NpcapOemInstaller`. Then run, from an elevated terminal:

```powershell
.\dist\LightHouse-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="C:\Temp\LightHouse-setup.log"
```

Absent Npcap/OEM, silent setup fails explicitly and does not open a hidden driver
wizard. On an incomplete install, correct the reported cause and rerun the EXE.
The application payload may already be installed, but that is not a running stack.

## Files, credentials, and services

- Application and dashboard: `C:\Program Files\LightHouse`.
- Database: `C:\ProgramData\LightHouse\lighthouse.db`.
- Operator configuration: `C:\ProgramData\LightHouse\config\windows.json`.
- Sysmon rules: `C:\ProgramData\LightHouse\config\sysmon.xml`.
- Suricata configuration/rules/EVE: `config\suricata.yaml`, `rules`, and `suricata\eve.json` below the data directory.
- Event Log checkpoints: `C:\ProgramData\LightHouse\state`.
- Model storage: `C:\ProgramData\LightHouse\models`.
- Installer transcript: `C:\ProgramData\LightHouse\logs\install.log`.
- Last setup result: `C:\Program Files\LightHouse\setup\last-result.txt`.
- Initial `admin` password: `C:\ProgramData\LightHouse\logs\LightHouse-API.stdout.log` (including rotated copies).

Read the credential log using an elevated editor/terminal. The existing generated
password banner and mandatory first-login password change are unchanged. Data,
configuration, model storage and logs have an Administrators/SYSTEM-only ACL.
API startup initializes the database before ingestion starts, so the credential
banner is in the API log. Repair preserves accounts and does not reset passwords.

NSSM registers these automatic LocalSystem services, with restart-on-failure and
rotating stdout/stderr logs under the data directory:

| Service | Command / responsibility |
| --- | --- |
| LightHouse-API | `python -m uvicorn triage.api:app --host 127.0.0.1 --port 8000` |
| LightHouse-Ingestion | `python -m triage.main tail` |
| LightHouse-Suricata | Native Suricata packet capture and EVE output |
| LightHouse-Ollama | `ollama serve`, using port 11435 and shared model storage |

Ollama uses a dedicated loopback port so its service does not compete with a
user's tray application on 11434. The API/dashboard is at http://127.0.0.1:8000.
NSSM's service environment supplies all application settings; no user PATH or
shell activation is required. No inbound firewall rule is added.

## Network configuration and repair

First setup selects the IPv4 default-route adapter and its subnet. Review
`HomeNet` and `CaptureInterface` before relying on coverage, particularly on
machines with multiple adapters or a VPN. A host's adapter only sees traffic
available to that host/interface; full LAN monitoring requires an appropriate
mirror/TAP arrangement.

Example `windows.json` (use your real adapter GUID and subnet):

```json
{
  "HomeNet": "192.168.1.0/24",
  "CaptureInterface": "\\Device\\NPF_{YOUR-ADAPTER-GUID}",
  "SuricataDir": "C:\\Suricata",
  "Model": "phi4-mini",
  "ApiPort": 8000,
  "OllamaPort": 11435,
  "NpcapOemInstaller": ""
}
```

Rerun setup after changing the JSON. It stops only the LightHouse services before
updating files, preserves the database/config/checkpoints/models, updates service
settings in place, reapplies the existing Sysmon XML, regenerates Suricata YAML
from the vendor file and JSON, validates it with `suricata -T`, and starts services
in dependency order. ET Open's currently published Suricata 7.0.3 rule archive is
used with Suricata 8; setup validates the resulting rules/configuration. Download
SHA256 values are recorded in the transcript. Successful downloads are cached;
remove a particular cache file as administrator to refresh that dependency.

Uninstall removes the four LightHouse service registrations and application
payload. It preserves data and the separately installed Npcap/Suricata/Sysmon/
Ollama dependencies; it does not change auditing back or remove shared drivers.
Installation is repairable, but does not offer transactional rollback of vendor
installers. Honor a dependency's reported reboot requirement.

## Ingestion configuration

| Environment variable | Windows default |
| --- | --- |
| LIGHTHOUSE_SURICATA_PATH | `C:\Suricata\log\eve.json`; installer overrides to ProgramData |
| LIGHTHOUSE_SYSMON_CHANNEL | `Microsoft-Windows-Sysmon/Operational` |
| LIGHTHOUSE_SECURITY_CHANNEL | `Security` |
| LIGHTHOUSE_EVENT_STATE_DIR | `C:\ProgramData\LightHouse\state` |
| LIGHTHOUSE_MODEL | `phi4-mini` |
| LIGHTHOUSE_OLLAMA_URL | `http://localhost:11434`; installer overrides to port 11435 |

Set a channel/path to an empty string to disable that input. Windows ignores
`LIGHTHOUSE_WAZUH_PATH` and `LIGHTHOUSE_ZEEK_PATH`. Linux keeps its existing file
sources, environment variables, commands and model default.

Sysmon/Security events use the existing Wazuh-compatible host-alert shape and
therefore retain `source=wazuh` in the existing dashboard/API. Native provider,
channel, Event ID, record ID and event data are retained in `raw.data.win`; no
Wazuh process runs. All Sysmon events are accepted. Security events include
4624, 4625, 4648, 4672, 4720, 4726, 4732 and 1102. Routine activity has a low
sensor floor; failed logon and account changes are medium; audit clearing and
Sysmon process tampering are high. The model can raise these floors as before.

First Event Log startup follows new events. Later starts resume saved record
positions, advancing only after successful processing. Log clear/rollover is
detected using both record ID and timestamp and replays retained records.
Normal downstream deduplication still applies. Failures are logged and retried.
Suricata accepts alert, flow, http, tls, dns and smb records. Its Windows reader
waits for file creation, handles partial lines, and reopens on rotation/truncate.
As with the original file tailer, it starts at EOF and has no persistent file
offset across service downtime. The event channels have independent readers.

## Validation status (2026-09-18)

- Backend suite: **62 passed**, including 11 new Windows ingestion tests.
- React production build: passed; no UI or chat changes.
- Embedded Python: backend, bcrypt, uvicorn and pywin32 import smoke test passed.
- Bundled API/dashboard: health and HTML checks passed on two consecutive starts;
  the existing administrator password hash was preserved on restart.
- Native pywin32: successfully read the developer machine's Application channel.
- Suricata: official MSI downloaded/extracted; generated configuration and ET Open
  rule assembly verified against its vendor YAML. Live `suricata -T`/capture has
  not been validated because Npcap is not installed.
- Inno Setup: compiled to an actual EXE. An initial EXE was run on the development
  machine and installed the application payload, then reported incomplete
  dependency setup. No LightHouse services were created. Its dependency log is
  admin-protected; a later UAC request to inspect it was cancelled. The final
  build additionally returns a failing exit code and records dependency failure
  text in the Inno log and `last-result.txt`.
- **Full dependency installation, model pull, service startup, reboot survival,
  and end-to-end repair/reinstall have not been validated.**
- **No clean-machine or VM validation was performed.** All checks above used this
  Windows development machine. Do not interpret compilation as a successful
  clean-machine installation.
