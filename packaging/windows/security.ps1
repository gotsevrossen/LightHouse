# Shared, side-effect-free definitions used by setup and regression tests.
function New-PrivateAcl([bool]$Directory) {
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $inheritance = if ($Directory) { 'ContainerInherit,ObjectInherit' } else { 'None' }
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            [Security.Principal.SecurityIdentifier]$sid, 'FullControl', $inheritance, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    return $acl
}
function Test-UnfilteredAdminToken {
    # True for an administrator without a split UAC token (built-in Administrator,
    # UAC off). Such an account never runs anything with reduced rights.
    if (!('LightHouse.Token' -as [type])) {
        Add-Type -Namespace LightHouse -Name Token -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool GetTokenInformation(IntPtr token, int infoClass, out int info, int length, out int returned);
'@
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return $false }
        $elevationType = 0; $returned = 0
        # TokenElevationType (18): 1 = default (no split token), 2 = full, 3 = limited.
        if (![LightHouse.Token]::GetTokenInformation($identity.Token, 18, [ref]$elevationType, 4, [ref]$returned)) {
            throw 'Unable to read the setup token elevation type.'
        }
        return $elevationType -eq 1
    } finally { $identity.Dispose() }
}
function Get-TrustedSids {
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    # An unfiltered admin token makes the account itself, not Administrators, the
    # owner of what it creates, including earlier installs. Trusting it adds no
    # risk because that account has no reduced-rights programs to plant files.
    # Elevated UAC admins already create Administrators-owned files.
    if (Test-UnfilteredAdminToken) { $trusted += [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
    return $trusted
}
function Assert-TrustedItem($Item) {
    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse points are not permitted: $($Item.FullName)" }
    $acl = Get-Acl -LiteralPath $Item.FullName
    $trusted = Get-TrustedSids
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw "Untrusted owner on $($Item.FullName). Move the existing directory aside and reinstall; do not reuse untrusted configuration or cached files."
    }
    # Inherit-only ACEs often carry generic rights (GENERIC_WRITE 0x40000000,
    # GENERIC_ALL 0x10000000), which have no FileSystemRights name.
    $writeMask = [int][Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership' -bor 0x50000000
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and ($rule.FileSystemRights -band $writeMask)) {
            throw "Untrusted write permission on $($Item.FullName). Refusing to consume potentially modified installation data."
        }
    }
}
function Set-PrivateTree([string]$Path, [bool]$Verify) {
    $queue = New-Object 'Collections.Generic.Queue[IO.FileSystemInfo]'
    $queue.Enqueue((Get-Item -LiteralPath $Path -Force))
    while ($queue.Count) {
        $item = $queue.Dequeue()
        if ($Verify) { Assert-TrustedItem $item }
        elseif ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse points are not permitted: $($item.FullName)" }
        try {
            # Replace the entire DACL, including explicit grants, and the owner.
            Set-Acl -LiteralPath $item.FullName -AclObject (New-PrivateAcl $item.PSIsContainer)
            $children = if ($item.PSIsContainer) { @(Get-ChildItem -LiteralPath $item.FullName -Force) } else { @() }
        } catch {
            # Running services may rotate logs or drop SQLite journals meanwhile.
            if ($Verify -or (Test-Path -LiteralPath $item.FullName)) { throw }
            continue
        }
        foreach ($child in $children) { $queue.Enqueue($child) }
    }
}
function Protect-DataDirectory([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    # Reject junctions in the path before creating or following any children.
    $ancestor = [IO.DirectoryInfo]$full
    while ($null -ne $ancestor) {
        if ($ancestor.Exists -and ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Reparse point in data path: $($ancestor.FullName)" }
        $ancestor = $ancestor.Parent
    }
    if (!(Test-Path -LiteralPath $full)) {
        [IO.Directory]::CreateDirectory($full, (New-PrivateAcl $true)) | Out-Null
    }
    Set-PrivateTree $full $true
}
function Restore-DataOwnership([string]$Path) {
    # Only administrators and SYSTEM can write below a protected tree, so what
    # this run created is trusted; hand it to Administrators so a later repair
    # by any administrator accepts it.
    Set-PrivateTree ([IO.Path]::GetFullPath($Path)) $false
}
function Assert-FileHash([string]$Path, [string]$Expected, [string]$Actual) {
    if ($Expected -notmatch '^[0-9a-fA-F]{64}$') { throw "Missing trusted SHA256 for $Path" }
    if (!$Actual) { $Actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
    if ($Actual -ne $Expected) { throw "SHA256 mismatch: $Path. Dependency will not be executed." }
}
function Assert-Publisher([string]$Path, [string[]]$Publishers) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate) { throw "Invalid Authenticode signature: $Path" }
    $publisher = $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if ($publisher -notin $Publishers) { throw "Unexpected signing publisher '$publisher': $Path" }
}
function Assert-SysmonArchive([string]$Path, [string]$Staging) {
    # Sysinternals serves only the latest release at a fixed URL, so a pinned
    # hash would break on every release. Pin the signer and product instead.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Staging) { Remove-Item -LiteralPath $Staging -Recurse -Force }
    try {
        [IO.Compression.ZipFile]::ExtractToDirectory($Path, $Staging)
        $sysmon = Join-Path $Staging 'Sysmon64.exe'
        Assert-Publisher $sysmon @('Microsoft Windows Publisher', 'Microsoft Corporation')
        $product = (Get-Item -LiteralPath $sysmon).VersionInfo.ProductName
        if ($product -ne 'Sysinternals Sysmon') { throw "Unexpected Sysmon product '$product': $Path" }
    } finally {
        Remove-Item -LiteralPath $Staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}
