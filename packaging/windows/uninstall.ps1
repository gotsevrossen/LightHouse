param([Parameter(Mandatory=$true)][string]$AppDir, [switch]$StopOnly)
$ErrorActionPreference = 'Stop'
try {
    # LightHouse-Ollama exists only on installs from releases before llama.cpp.
    foreach ($name in @('LightHouse-Ingestion', 'LightHouse-API', 'LightHouse-Suricata', 'LightHouse-Ollama')) {
        $service = Get-Service $name -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne 'Stopped') { Stop-Service $name -Force; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)) }
            if (!$StopOnly) {
                & "$AppDir\tools\nssm.exe" remove $name confirm
                if ($LASTEXITCODE -ne 0) { throw "Failed to remove $name" }
            }
        }
    }
    # Preserve the database, logs, models, sensor software and operator config.
    exit 0
} catch { Write-Error $_; exit 1 }
