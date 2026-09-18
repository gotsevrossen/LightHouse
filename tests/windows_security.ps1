$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\packaging\windows\security.ps1"
function Assert($Condition, $Message) { if (!$Condition) { throw $Message } }
function Rejects([scriptblock]$Action, [string]$Reason) {
    # Match the reason so a different check failing cannot mask a missing one.
    $rejected = $false
    try { & $Action } catch {
        Assert ("$_" -like "*$Reason*") "Expected rejection '$Reason', got: $_"
        $rejected = $true
    }
    Assert $rejected "Unsafe input was accepted (expected '$Reason')"
}
foreach ($directory in @($true, $false)) {
    $acl = New-PrivateAcl $directory
    Assert $acl.AreAccessRulesProtected 'DACL must be protected'
    Assert ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544') 'Unexpected owner'
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert ($rules.Count -eq 2) 'DACL must contain exactly two grants'
    foreach ($rule in $rules) {
        Assert ($rule.IdentityReference.Value -in @('S-1-5-18','S-1-5-32-544')) 'Untrusted grant'
        Assert ($rule.FileSystemRights -eq 'FullControl') 'Wrong access rights'
    }
}
# Exercise trust policy using actual Windows ACL objects, without elevation.
$script:FixtureAcl = New-PrivateAcl $true
function Get-Acl { param($LiteralPath) return $script:FixtureAcl }
$item = [pscustomobject]@{FullName='fixture'; Attributes=[IO.FileAttributes]::Directory}
Assert-TrustedItem $item
$read = New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]'S-1-1-0','ReadAndExecute','Allow')
$script:FixtureAcl.AddAccessRule($read)
Assert-TrustedItem $item
$write = New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]'S-1-1-0','Write','Allow')
$script:FixtureAcl.AddAccessRule($write)
Rejects { Assert-TrustedItem $item } 'Untrusted write permission'
# Generic rights on inherit-only ACEs have no FileSystemRights name.
foreach ($generic in @('GW', 'GA')) {
    $script:FixtureAcl = New-PrivateAcl $true
    $script:FixtureAcl.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;$generic;;;BU)")
    Rejects { Assert-TrustedItem $item } 'Untrusted write permission'
}
$script:FixtureAcl = New-PrivateAcl $true
$script:FixtureAcl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-1-0')
Rejects { Assert-TrustedItem $item } 'Untrusted owner'
# The account running setup is a trusted owner only with an unfiltered admin token.
Assert ((Test-UnfilteredAdminToken) -is [bool]) 'Token elevation type must be readable'
$script:FixtureAcl = New-PrivateAcl $true
$script:FixtureAcl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
function Test-UnfilteredAdminToken { return $true }
Assert-TrustedItem $item
# An elevated UAC admin's own account may also run reduced-rights programs.
function Test-UnfilteredAdminToken { return $false }
Rejects { Assert-TrustedItem $item } 'Untrusted owner'
Remove-Item Function:\Test-UnfilteredAdminToken
. "$PSScriptRoot\..\packaging\windows\security.ps1"
$script:FixtureAcl = New-PrivateAcl $true
$item.Attributes = [IO.FileAttributes]::ReparsePoint
Rejects { Assert-TrustedItem $item } 'Reparse points are not permitted'
Remove-Item Function:\Get-Acl
$tempFile = Join-Path ([IO.Path]::GetTempPath()) ('lighthouse-security-test-' + [guid]::NewGuid().ToString('N'))
try {
    [IO.File]::WriteAllText($tempFile, 'trusted payload')
    $expected = (Get-FileHash $tempFile -Algorithm SHA256).Hash
    Assert-FileHash $tempFile $expected
    Assert-FileHash $tempFile $expected $expected
    [IO.File]::WriteAllText($tempFile, 'modified payload')
    Rejects { Assert-FileHash $tempFile $expected } 'SHA256 mismatch'
    Rejects { Assert-FileHash $tempFile '' } 'Missing trusted SHA256'
    Rejects { Assert-Publisher $tempFile @('Microsoft Corporation') } 'Invalid Authenticode signature'
    # A Sysmon archive must carry a signed Sysmon64.exe; staging is always removed.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archiveSource = "$tempFile-src"
    New-Item -ItemType Directory $archiveSource | Out-Null
    [IO.File]::WriteAllText("$archiveSource\Sysmon64.exe", 'unsigned')
    [IO.Compression.ZipFile]::CreateFromDirectory($archiveSource, "$tempFile.zip")
    Rejects { Assert-SysmonArchive "$tempFile.zip" "$tempFile-staging" } 'Invalid Authenticode signature'
    Assert (!(Test-Path "$tempFile-staging")) 'Sysmon staging directory was left behind'
    [IO.File]::WriteAllText("$tempFile.zip", '<html>captive portal</html>')
    Rejects { Assert-SysmonArchive "$tempFile.zip" "$tempFile-staging" } 'Central Directory'
} finally {
    Remove-Item -LiteralPath $tempFile, "$tempFile.zip", "$tempFile-src" -Recurse -Force -ErrorAction SilentlyContinue
}
# Verify both trust-chain status and the expected signing identity are required.
$cert = New-Object PSObject
$cert | Add-Member ScriptMethod GetNameInfo { param($Type,$Issuer) return 'Expected Publisher' }
$script:Signature = [pscustomobject]@{Status='Valid'; SignerCertificate=$cert}
function Get-AuthenticodeSignature { param($LiteralPath) return $script:Signature }
Assert-Publisher 'fixture.exe' @('Expected Publisher')
Rejects { Assert-Publisher 'fixture.exe' @('Another Publisher') } 'Unexpected signing publisher'
$script:Signature.Status = 'HashMismatch'
Rejects { Assert-Publisher 'fixture.exe' @('Expected Publisher') } 'Invalid Authenticode signature'
Write-Output 'Windows installer security regression checks passed'
