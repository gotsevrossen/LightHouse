param([Parameter(Mandatory=$true)][string]$AppDir, [switch]$Unattended,
      [string]$DataDir = "$env:ProgramData\LightHouse")
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$resultPath = "$AppDir\setup\last-result.txt"
function Set-Result([string]$Text) { [IO.File]::WriteAllText($resultPath, $Text) }
# Replace the previous run's outcome before anything can fail.
Set-Result 'Installation started.'
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the LightHouse installer as administrator.' }
    . "$PSScriptRoot\security.ps1"
    Protect-DataDirectory $DataDir
    $dependencyHashes = Get-Content "$PSScriptRoot\dependency-hashes.json" -Raw | ConvertFrom-Json
    New-Item -ItemType Directory -Force "$DataDir\logs", "$DataDir\cache", "$DataDir\config", "$DataDir\state", "$DataDir\models", "$DataDir\rules", "$DataDir\suricata", "$AppDir\tools" | Out-Null
} catch {
    # The data tree is not trusted yet, so the reason goes only to the result file.
    Write-Host "INSTALLATION FAILED: $_"
    Set-Result "Installation incomplete: $_"
    exit 1
}
Start-Transcript -Path "$DataDir\logs\install.log" -Append | Out-Null
function Complete([string]$Result, [int]$Code) {
    Set-Result $Result
    try { Restore-DataOwnership $DataDir } catch { Write-Host "Could not restore data directory ownership: $_" }
    Stop-Transcript | Out-Null
    exit $Code
}
function Run([string]$File, [string]$Arguments) {
    Write-Host "Running $File"
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -eq 3010) { Write-Host 'Dependency requests a reboot; reboot after setup.' }
    elseif ($process.ExitCode -ne 0) { throw "$File failed with exit code $($process.ExitCode)" }
}
function Assert-Dependency([string]$Path, [string]$Name) {
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    Write-Host "$Name SHA256 $hash"
    if ($Name -eq 'OllamaSetup.exe') {
        Assert-Publisher $Path @('Ollama', 'Ollama Inc.', 'Ollama, Inc.')
    } elseif ($Name -eq 'Sysmon.zip') {
        Assert-SysmonArchive $Path "$DataDir\cache\sysmon-verify"
    } elseif ($Name -match '\.(exe|msi|zip)$') {
        Assert-FileHash $Path $dependencyHashes.$Name $hash
    }
}
function Fetch([string]$Url, [string]$Name) {
    $target = Join-Path "$DataDir\cache" $Name
    if (Test-Path -LiteralPath $target) {
        try { Assert-Dependency $target $Name; return $target }
        catch { Write-Host "Cached $Name failed verification ($_); downloading again."; Remove-Item -LiteralPath $target -Force }
    }
    # Keep the extension: Authenticode and archive checks inspect it.
    $partial = Join-Path "$DataDir\cache" "partial-$Name"
    Write-Host "Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $partial -UseBasicParsing
    # Only verified files enter the cache, so a bad download is retried next run.
    try { Assert-Dependency $partial $Name }
    catch { Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue; throw }
    Move-Item -LiteralPath $partial -Destination $target -Force
    return $target
}
function Nssm([string[]]$Arguments) {
    & "$AppDir\tools\nssm.exe" @Arguments
    if ($LASTEXITCODE -ne 0) { throw "NSSM failed: $Arguments ($LASTEXITCODE)" }
}
function Register([string]$Name, [string]$Exe, [string]$Arguments, [string[]]$Environment) {
    if (!(Get-Service $Name -ErrorAction SilentlyContinue)) { Nssm @('install', $Name, $Exe) }
    Nssm @('set', $Name, 'Application', $Exe)
    Nssm @('set', $Name, 'AppParameters', $Arguments)
    Nssm @('set', $Name, 'AppDirectory', $AppDir)
    Nssm @('set', $Name, 'Start', 'SERVICE_AUTO_START')
    Nssm @('set', $Name, 'AppExit', 'Default', 'Restart')
    Nssm @('set', $Name, 'AppRestartDelay', '5000')
    Nssm @('set', $Name, 'AppStdout', "$DataDir\logs\$Name.stdout.log")
    Nssm @('set', $Name, 'AppStderr', "$DataDir\logs\$Name.stderr.log")
    Nssm @('set', $Name, 'AppRotateFiles', '1')
    Nssm @('set', $Name, 'AppRotateOnline', '1')
    Nssm @('set', $Name, 'AppRotateBytes', '10485760')
    Nssm (@('set', $Name, 'AppEnvironmentExtra') + $Environment)
}
function Wait-Http([string]$Url) {
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        try { return Invoke-RestMethod $Url -TimeoutSec 2 } catch { Start-Sleep -Seconds 2 }
    }
    throw "Service did not become ready: $Url. See $DataDir\logs."
}
try {
    $configPath = "$DataDir\config\windows.json"
    if (!(Test-Path $configPath)) {
        $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
            Sort-Object @{Expression={$_.RouteMetric + $_.InterfaceMetric}} | Select-Object -First 1
        if (!$route) { throw 'No IPv4 default route. Configure windows.json with HomeNet and CaptureInterface.' }
        $adapter = Get-NetAdapter | Where-Object ifIndex -eq $route.InterfaceIndex | Select-Object -First 1
        if (!$adapter) { throw 'Default route adapter is unavailable. Configure CaptureInterface manually.' }
        $address = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 |
            Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -First 1
        [ordered]@{HomeNet="$($address.IPAddress)/$($address.PrefixLength)";
            CaptureInterface="\Device\NPF_$(([guid]$adapter.InterfaceGuid).ToString('B'))";
            SuricataDir='C:\Suricata'; Model='phi4-mini'; ApiPort=8000;
            OllamaPort=11435; NpcapOemInstaller=''} | ConvertTo-Json | Set-Content $configPath -Encoding utf8
    }
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    foreach ($port in @($config.ApiPort, $config.OllamaPort)) {
        if ([int]$port -lt 1024 -or [int]$port -gt 65535) { throw 'Ports must be in 1024..65535.' }
    }
    if ($config.ApiPort -eq $config.OllamaPort) { throw 'API and Ollama ports must differ.' }
    if (!(Get-Service npcap -ErrorAction SilentlyContinue)) {
        if ($config.NpcapOemInstaller) {
            $oem = "$DataDir\cache\npcap-oem.exe"
            Copy-Item -LiteralPath $config.NpcapOemInstaller -Destination $oem -Force
            Assert-Publisher $oem @('Nmap Software LLC', 'Insecure.Com LLC')
            Run $oem '/S /winpcap_mode=yes'
        } elseif ($Unattended) {
            throw 'Free Npcap cannot install silently. Install it first or set NpcapOemInstaller in config\windows.json to an OEM installer path, then rerun.'
        } else {
            $npcap = Fetch 'https://npcap.com/dist/npcap-1.89.exe' 'npcap-1.89.exe'
            # Free Npcap requires its visible wizard. /S is OEM-only.
            $process = Start-Process $npcap -ArgumentList '/winpcap_mode=yes' -Wait -PassThru -WindowStyle Normal
            if ($process.ExitCode -notin @(0, 3010)) { throw 'Npcap installation was cancelled or failed.' }
        }
        if (!(Get-Service npcap -ErrorAction SilentlyContinue)) { throw 'Npcap driver was not installed.' }
    }
    $suricataMsi = Fetch 'https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.7-1-64bit.msi' 'Suricata-8.0.7-1-64bit.msi'
    $repair = if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{42AB4288-8940-4B7D-97E2-75901A1D188F}') { 'REINSTALL=ALL REINSTALLMODE=vomus' } else { '' }
    Run 'msiexec.exe' "/i `"$suricataMsi`" /qn /norestart $repair INSTALLDIR=`"$($config.SuricataDir)`" /L*v `"$DataDir\logs\suricata-msi.log`""
    $suricataExe = Get-ChildItem $config.SuricataDir -Filter suricata.exe -Recurse | Select-Object -First 1
    if (!$suricataExe) { throw "Suricata not found in $($config.SuricataDir)" }
    $sysmonZip = Fetch 'https://download.sysinternals.com/files/Sysmon.zip' 'Sysmon.zip'
    Expand-Archive $sysmonZip "$AppDir\tools\sysmon" -Force
    if (!(Test-Path "$DataDir\config\sysmon.xml")) {
        $rules = Fetch 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' 'swift-sysmon.xml'
        Copy-Item $rules "$DataDir\config\sysmon.xml"
    }
    $sysmonSwitch = if (Get-Service Sysmon64,Sysmon -ErrorAction SilentlyContinue) { '-c' } else { '-i' }
    Run "$AppDir\tools\sysmon\Sysmon64.exe" "-accepteula $sysmonSwitch `"$DataDir\config\sysmon.xml`""
    Run 'auditpol.exe' '/set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'
    # Fail before the long model download if the service could not read the channels.
    $python = "$AppDir\runtime\python.exe"
    & $python -m triage.ingest.health --preflight
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read required Event Log channels.' }
    $ollamaInstaller = Fetch 'https://ollama.com/download/OllamaSetup.exe' 'OllamaSetup.exe'
    Run $ollamaInstaller "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /NOICONS /DIR=`"$AppDir\tools\ollama`""
    $ollama = "$AppDir\tools\ollama\ollama.exe"
    if (!(Test-Path $ollama)) { throw 'Ollama executable missing after install.' }
    # Always restore the wrapper from the verified archive, also on repair.
    $nssmZip = Fetch 'https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip' 'nssm-2.24-101-g897c7ad.zip'
    Expand-Archive $nssmZip "$DataDir\cache\nssm" -Force
    Copy-Item "$DataDir\cache\nssm\nssm-2.24-101-g897c7ad\win64\nssm.exe" "$AppDir\tools\nssm.exe" -Force
    $ollamaEnvironment = @("OLLAMA_HOST=127.0.0.1:$($config.OllamaPort)", "OLLAMA_MODELS=$DataDir\models")
    Register 'LightHouse-Ollama' $ollama 'serve' $ollamaEnvironment
    Start-Service LightHouse-Ollama
    Wait-Http "http://127.0.0.1:$($config.OllamaPort)/api/tags" | Out-Null
    $env:OLLAMA_HOST = "127.0.0.1:$($config.OllamaPort)"
    $env:OLLAMA_MODELS = "$DataDir\models"
    & $ollama pull $config.Model
    if ($LASTEXITCODE -ne 0) { throw 'Ollama model pull failed.' }
    $rules = Fetch 'https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz' 'emerging.rules.tar.gz'
    $vendorYaml = Get-ChildItem $config.SuricataDir -Filter suricata.yaml -Recurse | Select-Object -First 1
    if (!$vendorYaml) { throw 'Suricata vendor YAML missing.' }
    & $python "$AppDir\setup\configure_suricata.py" $vendorYaml.FullName "$DataDir\config\suricata.yaml" $configPath $DataDir $rules
    if ($LASTEXITCODE -ne 0) { throw 'Invalid Suricata configuration.' }
    Run $suricataExe.FullName "-T -c `"$DataDir\config\suricata.yaml`" -l `"$DataDir\suricata`""
    Register 'LightHouse-Suricata' $suricataExe.FullName "-c `"$DataDir\config\suricata.yaml`" -i `"$($config.CaptureInterface)`" -l `"$DataDir\suricata`"" @("PATH=$env:PATH;$env:WINDIR\System32\Npcap")
    Nssm @('set', 'LightHouse-Suricata', 'DependOnService', 'npcap')
    Start-Service LightHouse-Suricata
    $environment = @('PYTHONUNBUFFERED=1', 'LIGHTHOUSE_DESKTOP=0', "LIGHTHOUSE_DB_PATH=$DataDir\lighthouse.db",
        "LIGHTHOUSE_STATIC_DIR=$AppDir\dashboard\dist", "LIGHTHOUSE_SURICATA_PATH=$DataDir\suricata\eve.json",
        'LIGHTHOUSE_SYSMON_CHANNEL=Microsoft-Windows-Sysmon/Operational', 'LIGHTHOUSE_SECURITY_CHANNEL=Security',
        "LIGHTHOUSE_EVENT_STATE_DIR=$DataDir\state", "LIGHTHOUSE_MODEL=$($config.Model)",
        "LIGHTHOUSE_OLLAMA_URL=http://127.0.0.1:$($config.OllamaPort)")
    Register 'LightHouse-API' $python "-m uvicorn triage.api:app --host 127.0.0.1 --port $($config.ApiPort)" $environment
    Start-Service LightHouse-API
    # API seeds first, placing the existing credential banner in API stdout.
    Wait-Http "http://127.0.0.1:$($config.ApiPort)/api/health" | Out-Null
    Register 'LightHouse-Ingestion' $python '-m triage.main tail' $environment
    Nssm @('set', 'LightHouse-Ingestion', 'DependOnService', 'LightHouse-API', 'LightHouse-Ollama', 'LightHouse-Suricata', 'EventLog')
    $ingestionStarted = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    Start-Service LightHouse-Ingestion
    Start-Sleep -Seconds 5
    foreach ($name in @('LightHouse-API', 'LightHouse-Ingestion', 'LightHouse-Suricata', 'LightHouse-Ollama')) {
        if ((Get-Service $name).Status -ne 'Running') { throw "$name is not running; see service logs." }
    }
    if (!(Test-Path "$DataDir\suricata\eve.json")) { throw 'Suricata has not created eve.json; check capture interface and service stderr.' }
    $healthy = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & $python -m triage.ingest.health --state-dir "$DataDir\state" --since $ingestionStarted
        if ($LASTEXITCODE -eq 0) { $healthy = $true; break }
        Start-Sleep -Seconds 2
    }
    if (!$healthy) { throw 'Event ingestion did not report fresh healthy channels. See ingestion stderr.' }
    Write-Host "LightHouse ready: http://127.0.0.1:$($config.ApiPort)"
    Write-Host "Initial admin credential: $DataDir\logs\LightHouse-API.stdout.log"
    Write-Host "Configuration: $configPath. Review HOME_NET and capture adapter for this network."
    Complete 'Installation completed.' 0
} catch {
    Write-Host "INSTALLATION FAILED: $_"
    Complete "Installation incomplete: $_" 1
}
