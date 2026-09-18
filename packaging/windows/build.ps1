param([string]$PythonVersion = '3.13.7')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = (Resolve-Path "$PSScriptRoot\..\..").Path
$build = Join-Path $repo 'build\windows'
$stage = Join-Path $build ('payload-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force "$stage\runtime", "$stage\dashboard\dist", "$build\downloads" | Out-Null
function Check-Exit { if ($LASTEXITCODE -ne 0) { throw "Command failed: $LASTEXITCODE" } }
Push-Location $repo
try {
    & npm.cmd ci --prefix dashboard; Check-Exit
    & npm.cmd run build --prefix dashboard; Check-Exit
    Copy-Item dashboard\dist\* "$stage\dashboard\dist" -Recurse -Force
    $zip = "$build\downloads\python-$PythonVersion-embed-amd64.zip"
    if (!(Test-Path $zip)) { Invoke-WebRequest "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip" -OutFile $zip -UseBasicParsing }
    Expand-Archive $zip "$stage\runtime" -Force
    $pth = Get-ChildItem "$stage\runtime\python*._pth" | Select-Object -First 1
    # Enable site processing so pywin32's DLL/bootstrap .pth is loaded.
    @("python$($PythonVersion.Split('.')[0])$($PythonVersion.Split('.')[1]).zip", '.', 'Lib\site-packages', 'import site') | Set-Content $pth.FullName -Encoding ascii
    & uv export --frozen --no-dev --no-emit-project --no-hashes --format requirements-txt --output-file "$build\requirements.txt" | Out-Null; Check-Exit
    & uv pip install --python 3.13 --target "$stage\runtime\Lib\site-packages" -r "$build\requirements.txt"; Check-Exit
    & uv pip install --python 3.13 --target "$stage\runtime\Lib\site-packages" --no-deps .; Check-Exit
    & "$stage\runtime\python.exe" -c 'import triage.main, win32evtlog, uvicorn, yaml, bcrypt'; Check-Exit
    $compiler = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (!$compiler) {
        & winget install --id JRSoftware.InnoSetup --exact --source winget --silent --scope user --accept-source-agreements --accept-package-agreements; Check-Exit
        $compiler = "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    }
    & $compiler /Qp "/DPayloadDir=$stage" "$PSScriptRoot\lighthouse.iss"; Check-Exit
    Get-FileHash "$repo\dist\LightHouse-Setup.exe" -Algorithm SHA256
} finally { Pop-Location }
