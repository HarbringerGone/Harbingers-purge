<#
.SYNOPSIS
    Harbinger's Purge - CyberPatriot Windows 11 / Windows Server 2022 user hardening.

.DESCRIPTION
    1. Attempts to download/install wsd.crt FIRST (before all other hardening stages).
    2. Downloads/installs the latest HardeningKitty release and runs HailMary against the machine finding list.
    3. Reads the CyberPatriot README for THIS image.
    3. Compares local users to the README's Authorized Administrators and Authorized Users.
    4. Disables enabled local accounts that are not authorized; Guest, WDAGUtilityAccount, DefaultAccount, and defaultuser0 are explicitly disabled when present.
    5. Applies the exact password and account-lockout policies requested.
    6. Applies the requested per-user password flags.
    7. Assesses ONLY the password text supplied in the README for the built-in Administrator account.
       If that README password is weak, Administrator gets User may change password = ON and
       User must change password at next logon = ON. The current password is never read or tested.
    8. Verifies the resulting account states and administrator-group membership.
    10. Produces a report showing PASS / WARN / ERROR / MANUAL REVIEW items.

    HardeningKitty: Deterministically selects an OS/version-matched *_machine.csv finding list; user.csv is never selected.
    Windows 11 25H2 uses the exact 0x6d69636b machine list when present. Windows Server 2022 selects
    the highest available matching 21H2 or 22H2 machine baseline. If an exact OS/version match cannot be
    established, HailMary is refused rather than guessing.

    Supported operating systems:
      - Windows 11
      - Windows Server 2022

.AUTHOR
    Channveer Singh

.TITLE
    Harbinger's Purge

.VERSION
    1.9 - Deterministic OS/version-based HardeningKitty machine list selection for Windows 11 and Windows Server 2022.
#>

[CmdletBinding()]
param(
    [string]$ReadmeUri,
    [string]$CertificateUri,
    [switch]$DryRun,
    [switch]$KeepBackupFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------
# Configuration
# -----------------------------
# Set this once if you have a permanent direct download URL for wsd.crt.
# You can also pass -CertificateUri at runtime.
$DefaultWsdCertificateUri = ''
# HardeningKitty settings. Machine lists only. The actual list is selected at runtime.
$HardeningKittyReleaseApi = 'https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest'
$HardeningKittyRoot = Join-Path $TempRoot 'HardeningKitty'
$HardeningKittyLogPath = Join-Path $ProgramDataRoot 'HardeningKitty-HailMary.log'

$Policy = [ordered]@{
    PasswordHistorySize                    = 24
    MaximumPasswordAge                    = 30
    MinimumPasswordAge                     = 7
    MinimumPasswordLength                 = 14
    PasswordComplexity                     = 1
    ClearTextPassword                      = 0
    RelaxMinimumPasswordLengthLimits       = 1
    LockoutDuration                       = 30
    LockoutBadCount                        = 5
    ResetLockoutCount                     = 15
}

$AlwaysDisableAccounts = @(
    'Guest',
    'WDAGUtilityAccount',
    'DefaultAccount',
    'defaultuser0'
)

# ADSI/WinNT UF_* flags used for local account state.
$UF_ACCOUNTDISABLE        = 0x00000002
$UF_PASSWD_NOTREQD        = 0x00000020
$UF_PASSWD_CANT_CHANGE    = 0x00000040
$UF_DONT_EXPIRE_PASSWD    = 0x00010000
$UF_PASSWORD_EXPIRED      = 0x00800000

# Fast native Windows account API used to avoid the much slower ADSI round-trips.
# NetUserGetInfo/NetUserSetInfo are supported on Windows 11 and Windows Server 2022.
if (-not ('HarbingersNetApi' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class HarbingersNetApi
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_1
    {
        public IntPtr name;
        public IntPtr password;
        public uint password_age;
        public uint priv;
        public IntPtr home_dir;
        public IntPtr comment;
        public uint flags;
        public IntPtr script_path;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct USER_INFO_1008
    {
        public uint flags;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetInfo(
        string servername, string username, int level, out IntPtr bufptr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserSetInfo(
        string servername, string username, int level, IntPtr buf, out int parm_err);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr Buffer);

    public static int GetFlags(string server, string user, out uint flags)
    {
        flags = 0;
        IntPtr p = IntPtr.Zero;
        try
        {
            int rc = NetUserGetInfo(server, user, 1, out p);
            if (rc != 0) return rc;
            var info = Marshal.PtrToStructure<USER_INFO_1>(p);
            flags = info.flags;
            return 0;
        }
        finally
        {
            if (p != IntPtr.Zero) NetApiBufferFree(p);
        }
    }

    public static int SetFlags(string server, string user, uint flags, out int parmError)
    {
        parmError = 0;
        IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(USER_INFO_1008)));
        try
        {
            var info = new USER_INFO_1008 { flags = flags };
            Marshal.StructureToPtr(info, p, false);
            return NetUserSetInfo(server, user, 1008, p, out parmError);
        }
        finally
        {
            Marshal.FreeHGlobal(p);
        }
    }
}
"@
}

$ProgramDataRoot = Join-Path $env:ProgramData 'HarbingersPurge'
$BackupRoot      = Join-Path $ProgramDataRoot 'Backups'
$TempRoot        = Join-Path $env:TEMP 'HarbingersPurge'
$Desktop         = [Environment]::GetFolderPath('Desktop')
$ReportPath      = Join-Path $Desktop 'Harbingers-Purge-Report.txt'
$TranscriptPath  = Join-Path $ProgramDataRoot 'Harbingers-Purge-Transcript.txt'

$null = New-Item -ItemType Directory -Path $ProgramDataRoot -Force
$null = New-Item -ItemType Directory -Path $BackupRoot -Force
$null = New-Item -ItemType Directory -Path $TempRoot -Force

$script:Log = New-Object System.Collections.Generic.List[string]
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Warnings = New-Object System.Collections.Generic.List[string]
$script:Changes = New-Object System.Collections.Generic.List[string]
$script:AccountResults = New-Object System.Collections.Generic.List[object]
$script:AccountActionResults = New-Object System.Collections.Generic.List[object]
$script:PhaseResults = New-Object System.Collections.Generic.List[object]
$script:CurrentPhase = $null

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','CHANGE','WARN','ERROR')][string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $script:Log.Add($line)
    if ($Level -eq 'ERROR') { $script:Failures.Add($Message) }
    elseif ($Level -eq 'WARN') { $script:Warnings.Add($Message) }
    elseif ($Level -eq 'CHANGE') { $script:Changes.Add($Message) }
    Write-Host $line
}

function Start-Phase {
    param([Parameter(Mandatory)][string]$Name)
    $phase = [pscustomobject]@{
        Name      = $Name
        Status    = 'RUNNING'
        Started   = Get-Date
        Completed = $null
        Detail    = ''
    }
    $script:PhaseResults.Add($phase)
    $script:CurrentPhase = $phase
    Write-Log "--- PHASE: $Name ---"
}

function Complete-Phase {
    param(
        [ValidateSet('PASS','WARN','ERROR','SKIPPED')][string]$Status,
        [string]$Detail = ''
    )
    if ($null -eq $script:CurrentPhase) { return }
    $script:CurrentPhase.Status = $Status
    $script:CurrentPhase.Completed = Get-Date
    $script:CurrentPhase.Detail = $Detail
    $level = switch ($Status) {
        'PASS' { 'INFO' }
        'WARN' { 'WARN' }
        'ERROR' { 'ERROR' }
        default { 'INFO' }
    }
    if ($Detail) { Write-Log "PHASE RESULT: $($script:CurrentPhase.Name) = $Status - $Detail" $level }
}

function Write-FinalSummary {
    param([switch]$DryRun)

    $accountPass = @($script:AccountResults | Where-Object { $_.Status -eq 'PASS' }).Count
    $accountReview = @($script:AccountResults | Where-Object { $_.Status -ne 'PASS' }).Count
    $changes = $script:Changes.Count
    $warnings = $script:Warnings.Count
    $errors = $script:Failures.Count

    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host "HARBINGER'S PURGE - FINAL SUMMARY" -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ("Run mode: {0}" -f ($(if ($DryRun) { 'DRY RUN' } else { 'LIVE' })))
    Write-Host ("Changes made/planned: $changes")
    Write-Host ("Warnings/manual review: $warnings") -ForegroundColor $(if ($warnings) { 'Yellow' } else { 'Green' })
    Write-Host ("Errors/failures: $errors") -ForegroundColor $(if ($errors) { 'Red' } else { 'Green' })
    Write-Host ("Account reconciliation: $accountPass PASS / $accountReview NEED REVIEW")

    Write-Host ''
    Write-Host 'WHAT HAPPENED:' -ForegroundColor Green
    if ($script:Changes.Count -eq 0) {
        Write-Host '  No changes were recorded.'
    } else {
        foreach ($m in $script:Changes) { Write-Host "  [CHANGE] $m" }
    }

    Write-Host ''
    Write-Host 'WHAT WENT WRONG / NEEDS REVIEW:' -ForegroundColor Yellow
    if (($warnings + $errors) -eq 0) {
        Write-Host '  Nothing was reported as a warning or error.' -ForegroundColor Green
    } else {
        foreach ($m in $script:Warnings) { Write-Host "  [WARN]  $m" -ForegroundColor Yellow }
        foreach ($m in $script:Failures) { Write-Host "  [ERROR] $m" -ForegroundColor Red }
    }

    Write-Host ''
    Write-Host 'ACCOUNT ACTIONS:' -ForegroundColor Cyan
    if ($script:AccountActionResults.Count -eq 0) {
        Write-Host '  No account actions were recorded.'
    } else {
        foreach ($a in $script:AccountActionResults) {
            $color = if ($a.Result -eq 'SUCCESS' -or $a.Result -eq 'ALREADY CORRECT') { 'Green' } elseif ($a.Result -eq 'FAILED') { 'Red' } else { 'Yellow' }
            Write-Host ("  {0} | {1} | {2}" -f $a.Account, $a.Action, $a.Result) -ForegroundColor $color
            if ($a.Detail) { Write-Host "      $($a.Detail)" }
        }
    }

    Write-Host ''
    Write-Host 'PHASE RESULTS:' -ForegroundColor Cyan
    foreach ($phase in $script:PhaseResults) {
        $color = switch ($phase.Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Gray' } }
        $detail = if ($phase.Detail) { " - $($phase.Detail)" } else { '' }
        Write-Host ("  {0}: {1}{2}" -f $phase.Name, $phase.Status, $detail) -ForegroundColor $color
    }

    Write-Host ''
    if ($script:PhaseResults | Where-Object { $_.Name -eq 'HardeningKitty HailMary' }) {
        $hkPhase = $script:PhaseResults | Where-Object { $_.Name -eq 'HardeningKitty HailMary' } | Select-Object -Last 1
        Write-Host ("HardeningKitty HailMary: {0}" -f $hkPhase.Status) -ForegroundColor (if ($hkPhase.Status -eq 'PASS') { 'Green' } else { 'Yellow' })
    }
    Write-Host "Full report: $ReportPath" -ForegroundColor Cyan
    Write-Host "Full transcript: $TranscriptPath" -ForegroundColor Cyan
}

function Require-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Harbinger's Purge must be run from an elevated PowerShell window (Run as administrator)."
    }
}

function Get-OsInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $caption = [string]$os.Caption
    $build = [int]$os.BuildNumber

    $kind = if ($caption -match 'Windows 11') {
        'Windows 11'
    }
    elseif ($caption -match 'Windows Server 2022' -or $build -eq 20348) {
        'Windows Server 2022'
    }
    else {
        $null
    }

    [pscustomobject]@{
        Caption = $caption
        Build   = $build
        Kind    = $kind
    }
}

function Get-ReadmeResponse {
    param([Parameter(Mandatory)][string]$Source)

    if (Test-Path -LiteralPath $Source -PathType Leaf) {
        Write-Log "Reading local README: $Source"
        return [pscustomobject]@{
            Source = (Resolve-Path -LiteralPath $Source).Path
            Html   = Get-Content -LiteralPath $Source -Raw
            Links  = @()
        }
    }

    if (-not [Uri]::IsWellFormedUriString($Source, [UriKind]::Absolute)) {
        throw "README source is not a valid file path or URL: $Source"
    }

    Write-Log "Downloading README: $Source"
    $response = Invoke-WebRequest -Uri $Source -UseBasicParsing -MaximumRedirection 5
    [pscustomobject]@{
        Source = $Source
        Html   = [string]$response.Content
        Links  = @($response.Links)
    }
}

function Convert-HtmlToText {
    param([Parameter(Mandatory)][string]$Html)

    $text = $Html
    $text = $text -replace '(?is)<script.*?</script>', "`n"
    $text = $text -replace '(?is)<style.*?</style>', "`n"
    $text = $text -replace '(?i)<br\s*/?>', "`n"
    $text = $text -replace '(?is)</(p|div|li|h1|h2|h3|h4|h5|h6|tr|td|th)>', "`n"
    $text = $text -replace '(?is)<[^>]+>', ' '
    $text = [System.Net.WebUtility]::HtmlDecode($text)
    $text = $text -replace "\u00A0", ' '
    $text = $text -replace '[\t ]+', ' '
    $text = $text -replace ' *\r?\n *', "`n"
    return $text.Trim()
}

function Get-CleanLines {
    param([Parameter(Mandatory)][string]$Text)
    return @(
        ($Text -split "`r?`n") |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' }
    )
}

function Parse-AuthorizedUsers {
    param([Parameter(Mandatory)][string]$Text)

    $lines = Get-CleanLines -Text $Text
    $adminHeader = -1
    $userHeader = -1
    $guidelineHeader = $lines.Count

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^Authorized Administrators:\s*$') { $adminHeader = $i }
        if ($lines[$i] -match '^Authorized Users:\s*$') { $userHeader = $i }
        if ($lines[$i] -match '^(Competition Guidelines|Answer Key|Reminders)') {
            if ($i -lt $guidelineHeader) { $guidelineHeader = $i }
        }
    }

    if ($adminHeader -lt 0 -or $userHeader -lt 0 -or $userHeader -le $adminHeader) {
        throw 'Could not locate both "Authorized Administrators:" and "Authorized Users:" sections in the README.'
    }

    $admins = New-Object System.Collections.Generic.List[string]
    $users  = New-Object System.Collections.Generic.List[string]
    $adminCredentials = @{}
    $currentAdmin = $null

    $userRegex = '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$'

    for ($i = $adminHeader + 1; $i -lt $userHeader; $i++) {
        $line = $lines[$i] -replace '^[-*•]\s*', ''
        $line = $line -replace '\s+\(you\)\s*$', ''

        if ($line -match '^password\s*:\s*(.*)$' -and $currentAdmin) {
            $adminCredentials[$currentAdmin] = $Matches[1]
            continue
        }

        if ($line -match $userRegex -and $line -notmatch '^(password|Authorized|Administrators|Users)$') {
            $currentAdmin = $line
            $admins.Add($line)
        }
    }

    $userEnd = $guidelineHeader
    if ($userEnd -le $userHeader) { $userEnd = $lines.Count }
    for ($i = $userHeader + 1; $i -lt $userEnd; $i++) {
        $line = $lines[$i] -replace '^[-*•]\s*', ''
        if ($line -match $userRegex -and $line -notmatch '^(password|Authorized|Administrators|Users)$') {
            $users.Add($line)
        }
    }

    $all = @($admins + $users | Sort-Object -Unique)
    if ($all.Count -eq 0) {
        throw 'README parsing produced zero authorized users. No account changes were made.'
    }

    [pscustomobject]@{
        Administrators = @($admins | Sort-Object -Unique)
        Users          = @($users  | Sort-Object -Unique)
        AllAuthorized  = $all
        AdminPasswords = $adminCredentials
    }
}

function Get-CurrentUsername { return [Environment]::UserName }

function Get-AutologonUser {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    try {
        $wl = Get-ItemProperty -Path $path -ErrorAction Stop
        if ([string]$wl.AutoAdminLogon -eq '1' -and -not [string]::IsNullOrWhiteSpace([string]$wl.DefaultUserName)) {
            return [string]$wl.DefaultUserName
        }
    } catch {
        Write-Log "Could not read Winlogon auto-logon settings: $($_.Exception.Message)" 'WARN'
    }
    return $null
}

function Assert-CurrentUserAuthorized {
    param(
        [Parameter(Mandatory)][string[]]$Authorized,
        [Parameter(Mandatory)][string]$CurrentUser
    )

    if (-not ($Authorized | Where-Object { $_ -ieq $CurrentUser })) {
        throw "Safety stop: the currently logged-in account '$CurrentUser' is not listed in the README's authorized users/admins. No account changes were made."
    }
}

function Backup-SecurityPolicy {
    if ($DryRun) {
        Write-Log 'DRY RUN: would export the current security policy before changes.'
        return $null
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path = Join-Path $BackupRoot "secpol-$stamp.inf"
    & "$env:SystemRoot\System32\secedit.exe" /export /cfg $path /areas SECURITYPOLICY | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path)) {
        throw "secedit.exe could not export the current security policy (exit code $LASTEXITCODE)."
    }
    Write-Log "Backed up current security policy to $path"
    return $path
}

function Set-SeceditValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    $content = Get-Content -LiteralPath $Path -Raw
    $sectionPattern = '(?ms)^\[' + [regex]::Escape($Section) + '\].*?(?=^\[|\z)'
    $match = [regex]::Match($content, $sectionPattern)

    if (-not $match.Success) {
        $content += "`r`n[$Section]`r`n$Name = $Value`r`n"
    }
    else {
        $sectionText = $match.Value
        $linePattern = '(?m)^\s*' + [regex]::Escape($Name) + '\s*=.*$'
        if ([regex]::IsMatch($sectionText, $linePattern)) {
            $sectionText = [regex]::Replace($sectionText, $linePattern, "$Name = $Value")
        }
        else {
            $sectionText = $sectionText.TrimEnd("`r", "`n") + "`r`n$Name = $Value`r`n"
        }
        $content = $content.Substring(0, $match.Index) + $sectionText + $content.Substring($match.Index + $match.Length)
    }

    Set-Content -LiteralPath $Path -Value $content -Encoding Unicode
}

function Apply-ExactPolicies {
    param([string]$BackupPath)

    if ($DryRun) {
        Write-Log 'DRY RUN: would apply the exact password policy and account-lockout policy targets.'
        return
    }

    if (-not $BackupPath) { throw 'A security-policy backup is required before applying policy changes.' }

    $cfg = Join-Path $TempRoot 'HarbingersPurge-SecPolicy.inf'
    Copy-Item -LiteralPath $BackupPath -Destination $cfg -Force

    foreach ($entry in $Policy.GetEnumerator()) {
        if ($entry.Key -eq 'RelaxMinimumPasswordLengthLimits') { continue }
        Set-SeceditValue -Path $cfg -Section 'System Access' -Name $entry.Key -Value ([string]$entry.Value)
    }

    Write-Log 'Applying exact password and account-lockout values.' 'CHANGE'
    & "$env:SystemRoot\System32\secedit.exe" /configure /db (Join-Path $TempRoot 'HarbingersPurge.sdb') /cfg $cfg /areas SECURITYPOLICY /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "secedit.exe could not apply the security policy (exit code $LASTEXITCODE)."
    }

    # Set RelaxMinimumPasswordLengthLimits through the .NET registry API instead of
    # the PowerShell registry provider. On some Windows builds the provider can
    # throw a misleading 'Cannot delete a subkey tree because the subkey does not exist'
    # error when touching the SAM key.
    $samSubKey = 'SYSTEM\CurrentControlSet\Control\SAM'
    $regBase = $null
    $samKey = $null
    try {
        $regBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Default
        )
        $samKey = $regBase.OpenSubKey($samSubKey, $true)
        if ($null -eq $samKey) {
            throw "Could not open HKLM:\$samSubKey for writing."
        }
        $samKey.SetValue(
            'RelaxMinimumPasswordLengthLimits',
            1,
            [Microsoft.Win32.RegistryValueKind]::DWord
        )
    }
    finally {
        if ($null -ne $samKey) { $samKey.Dispose() }
        if ($null -ne $regBase) { $regBase.Dispose() }
    }

    Write-Log 'Password policy and account lockout policy applied.' 'CHANGE'
}

function Get-NetUserFlagsFast {
    param([Parameter(Mandatory)][string]$Name)
    [uint32]$flags = 0
    $rc = [HarbingersNetApi]::GetFlags($env:COMPUTERNAME, $Name, [ref]$flags)
    if ($rc -ne 0) {
        throw "NetUserGetInfo failed for '$Name' with Win32 error $rc."
    }
    return [int64]$flags
}

function Set-NetUserFlagsFast {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int64]$Flags
    )
    [int]$parmError = 0
    $rc = [HarbingersNetApi]::SetFlags($env:COMPUTERNAME, $Name, [uint32]$Flags, [ref]$parmError)
    if ($rc -ne 0) {
        throw "NetUserSetInfo failed for '$Name' with Win32 error $rc (parameter $parmError)."
    }
}

function Get-UserFlagState {
    param([Parameter(Mandatory)][string]$Name)
    $flags = Get-NetUserFlagsFast -Name $Name
    [pscustomobject]@{
        Name                    = $Name
        PasswordNeverExpires    = (($flags -band $UF_DONT_EXPIRE_PASSWD) -ne 0)
        PasswordRequired        = (($flags -band $UF_PASSWD_NOTREQD) -eq 0)
        UserMayChangePassword   = (($flags -band $UF_PASSWD_CANT_CHANGE) -eq 0)
        MustChangeAtNextLogon   = (($flags -band $UF_PASSWORD_EXPIRED) -ne 0)
        Disabled                = (($flags -band $UF_ACCOUNTDISABLE) -ne 0)
        Flags                   = $flags
    }
}

function Set-BaselineUserPasswordState {
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$TemporarilyRemoveFromAdministrators,
        [switch]$CurrentMustChange
    )

    $flags = Get-NetUserFlagsFast -Name $Name
    $target = $flags
    $target = $target -band (-bnot $UF_DONT_EXPIRE_PASSWD) # Password never expires = OFF
    $target = $target -band (-bnot $UF_PASSWD_NOTREQD)     # Password required = ON
    $target = $target -bor  $UF_PASSWD_CANT_CHANGE        # User may change = OFF

    # Clearing an already-expired password is not possible without changing the password.
    # Only clear the expiration flag when the password is not already expired.
    if (-not $CurrentMustChange) {
        $target = $target -band (-bnot $UF_PASSWORD_EXPIRED)
    }

    $changedFlags = ($target -ne $flags)

    if ($DryRun) {
        Write-Log "DRY RUN: would set '$Name': PasswordNeverExpires=OFF; PasswordRequired=ON; UserMayChangePassword=OFF; MustChangeAtNextLogon=OFF (unless already expired)."
        return
    }

    if (-not $changedFlags) {
        Write-Log "'$Name': password flags already match target (skipped native write)." 'INFO'
        return
    }

    $removedFromAdmins = $false
    try {
        if ($TemporarilyRemoveFromAdministrators -and (($flags -band $UF_PASSWD_CANT_CHANGE) -eq 0)) {
            Remove-LocalGroupMember -Group 'Administrators' -Member "$env:COMPUTERNAME\$Name" -ErrorAction Stop
            $removedFromAdmins = $true
            Write-Log "Temporarily removed authorized administrator '$Name' from Administrators only because UserMayChangePassword needed to change." 'INFO'
        }

        Set-NetUserFlagsFast -Name $Name -Flags $target
    }
    catch {
        $originalError = $_.Exception.Message
        if ($removedFromAdmins) {
            try {
                Add-LocalGroupMember -Group 'Administrators' -Member "$env:COMPUTERNAME\$Name" -ErrorAction Stop
                Write-Log "Restored administrator '$Name' after a failed password-flag change." 'INFO'
            }
            catch {
                Write-Log "Could not restore '$Name' to Administrators after the password-flag failure: $($_.Exception.Message)" 'ERROR'
            }
        }
        throw $originalError
    }

    if ($removedFromAdmins) {
        try {
            Add-LocalGroupMember -Group 'Administrators' -Member "$env:COMPUTERNAME\$Name" -ErrorAction Stop
            Write-Log "Restored authorized administrator '$Name' to the Administrators group." 'INFO'
        }
        catch {
            throw "Password flags were applied to '$Name', but restoring Administrators membership failed: $($_.Exception.Message)"
        }
    }

    if ($CurrentMustChange) {
        Write-Log "'$Name': PasswordNeverExpires=OFF; PasswordRequired=ON; UserMayChangePassword=OFF. MustChangeAtNextLogon remains ON because the existing password is already expired and Windows does not allow clearing that state without changing the password." 'WARN'
    }
    else {
        Write-Log "'$Name': PasswordNeverExpires=OFF; PasswordRequired=ON; UserMayChangePassword=OFF; MustChangeAtNextLogon=OFF." 'CHANGE'
    }
}

function Set-AdministratorWeakPasswordState {
    param([Parameter(Mandatory)][string]$Name)

    $flags = Get-NetUserFlagsFast -Name $Name
    $flags = $flags -band (-bnot $UF_DONT_EXPIRE_PASSWD)
    $flags = $flags -band (-bnot $UF_PASSWD_NOTREQD)
    $flags = $flags -band (-bnot $UF_PASSWD_CANT_CHANGE)     # User may change = ON
    $flags = $flags -bor $UF_PASSWORD_EXPIRED                # Must change at next logon = ON

    if ($DryRun) {
        Write-Log "DRY RUN: would set 'Administrator': UserMayChangePassword=ON; MustChangeAtNextLogon=ON because the README password is weak."
        return
    }

    Set-NetUserFlagsFast -Name $Name -Flags $flags
    Write-Log "'Administrator': UserMayChangePassword=ON; MustChangeAtNextLogon=ON because the README password is weak." 'CHANGE'
}

function Get-LocalAdministratorsMemberNames {
    try {
        $localUsersBySid = @{}
        foreach ($u in @(Get-LocalUser)) {
            $localUsersBySid[[string]$u.SID.Value] = [string]$u.Name
        }

        $names = New-Object System.Collections.Generic.List[string]
        foreach ($member in @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)) {
            $sid = $null
            try { $sid = [string]$member.SID.Value } catch { continue }
            if ($localUsersBySid.ContainsKey($sid)) {
                $names.Add($localUsersBySid[$sid])
            }
        }
        return @($names | Sort-Object -Unique)
    }
    catch {
        throw "Could not enumerate local user members of the Administrators group: $($_.Exception.Message)"
    }
}

function Disable-SpecificLocalAccount {
    param([Parameter(Mandatory)][string]$Name)

    if ($DryRun) {
        Write-Log "DRY RUN: would disable local account '$Name'." 'CHANGE'
        $script:AccountActionResults.Add([pscustomobject]@{Account=$Name; Action='Disable account'; Result='WOULD CHANGE'; Detail='Dry run'})
        return
    }

    try {
        Disable-LocalUser -Name $Name -ErrorAction Stop
    }
    catch {
        $output = & "$env:SystemRoot\System32\net.exe" user $Name /active:no 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Could not disable '$Name' with Disable-LocalUser or net user: $($output -join ' ')"
        }
    }

    Write-Log "Disabled local account '$Name'." 'CHANGE'
    $script:AccountActionResults.Add([pscustomobject]@{Account=$Name; Action='Disable account'; Result='SUCCESS'; Detail='Account is disabled'})
}

function Test-PasswordMeetsPolicy {
    param(
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$Username
    )

    $reasons = New-Object System.Collections.Generic.List[string]

    if ($Password.Length -lt [int]$Policy.MinimumPasswordLength) {
        $reasons.Add("shorter than $($Policy.MinimumPasswordLength) characters")
    }

    $categories = 0
    if ($Password -match '[A-Z]') { $categories++ }
    if ($Password -match '[a-z]') { $categories++ }
    if ($Password -match '[0-9]') { $categories++ }
    if ($Password -match '[^A-Za-z0-9]') { $categories++ }
    if ($categories -lt 3) {
        $reasons.Add('does not meet the Windows complexity requirement (3 of 4 character categories)')
    }

    $userParts = $Username -split '[._-]'
    foreach ($part in $userParts) {
        if ($part.Length -ge 3 -and $Password.IndexOf($part, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $reasons.Add('contains part of the account name')
            break
        }
    }

    [pscustomobject]@{
        IsWeak  = ($reasons.Count -gt 0)
        Reasons = @($reasons)
    }
}

function Test-LocalUserIsAdministrator {
    param(
        [Parameter(Mandatory)][string]$Name,
        [System.Collections.Generic.HashSet[string]]$AdminSids
    )
    try {
        if ($null -eq $AdminSids) {
            $AdminSids = Get-AdministratorsSidSet
        }
        $user = Get-LocalUser -Name $Name -ErrorAction Stop
        return $AdminSids.Contains($user.SID.Value)
    }
    catch {
        Write-Log "Could not determine whether '$Name' is in Administrators: $($_.Exception.Message)" 'WARN'
        return $false
    }
}

function Remove-UnapprovedAdministratorsAndDisableUnlisted {
    param(
        [Parameter(Mandatory)][object]$ParsedUsers,
        [Parameter(Mandatory)][string]$CurrentUser
    )

    $authorizedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ParsedUsers.AllAuthorized) { [void]$authorizedSet.Add($name) }

    $authorizedAdminSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ParsedUsers.Administrators) { [void]$authorizedAdminSet.Add($name) }

    # Remove unapproved LOCAL USER accounts from Administrators first.
    $localAdmins = @()
    try {
        $localAdmins = @(Get-LocalAdministratorsMemberNames)
    }
    catch {
        Write-Log $_.Exception.Message 'ERROR'
    }

    foreach ($name in $localAdmins) {
        if ($authorizedAdminSet.Contains($name)) { continue }
        if ($name -ieq $CurrentUser) {
            throw "Safety stop: current logged-in account '$CurrentUser' is not an authorized administrator."
        }

        # The built-in Administrator stays in the built-in group but will be disabled below.
        if ($name -ieq 'Administrator') { continue }

        if ($DryRun) {
            Write-Log "DRY RUN: would remove unauthorized administrator '$name' from the local Administrators group." 'CHANGE'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name; Action='Remove from Administrators'; Result='WOULD CHANGE'; Detail='Unauthorized administrator'})
            continue
        }

        try {
            Remove-LocalGroupMember -Group 'Administrators' -Member "$env:COMPUTERNAME\$name" -ErrorAction Stop
            Write-Log "Removed unauthorized administrator '$name' from the local Administrators group." 'CHANGE'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name; Action='Remove from Administrators'; Result='SUCCESS'; Detail='No longer a member of local Administrators'})
        }
        catch {
            Write-Log "Could not remove unauthorized administrator '$name' from Administrators: $($_.Exception.Message)" 'ERROR'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name; Action='Remove from Administrators'; Result='FAILED'; Detail=$_.Exception.Message})
        }
    }

    # Explicitly disable Guest and Windows-managed local accounts.
    foreach ($name in $AlwaysDisableAccounts) {
        $local = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $local) {
            Write-Log "Requested account '$name' does not exist on this VM." 'INFO'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name; Action='Disable account'; Result='NOT PRESENT'; Detail='Account does not exist'})
            continue
        }

        if (-not $local.Enabled) {
            Write-Log "Requested account '$name' is already disabled."
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name; Action='Disable account'; Result='ALREADY CORRECT'; Detail='Account already disabled'})
            continue
        }

        try { Disable-SpecificLocalAccount -Name $name }
        catch {
            Write-Log "Could not disable required account '$name': $($_.Exception.Message)" 'ERROR'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name; Action='Disable account'; Result='FAILED'; Detail=$_.Exception.Message})
        }
    }

    # Disable the built-in Administrator whenever the README does not authorize it.
    $builtinAdmin = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
    if ($null -ne $builtinAdmin -and -not $authorizedAdminSet.Contains('Administrator')) {
        if ($builtinAdmin.Enabled) {
            try { Disable-SpecificLocalAccount -Name 'Administrator' }
            catch {
                Write-Log "Could not disable built-in 'Administrator': $($_.Exception.Message)" 'ERROR'
                $script:AccountActionResults.Add([pscustomobject]@{Account='Administrator'; Action='Disable account'; Result='FAILED'; Detail=$_.Exception.Message})
            }
        }
        else {
            Write-Log "Built-in 'Administrator' is already disabled."
            $script:AccountActionResults.Add([pscustomobject]@{Account='Administrator'; Action='Disable account'; Result='ALREADY CORRECT'; Detail='Account already disabled'})
        }
    }

    # Disable every remaining enabled local account not listed anywhere in the README.
    foreach ($u in @(Get-LocalUser | Sort-Object Name)) {
        if ($authorizedSet.Contains($u.Name)) { continue }
        if ($AlwaysDisableAccounts -contains $u.Name) { continue }
        if ($u.Name -ieq 'Administrator') { continue }
        if ($u.Name -ieq $CurrentUser) {
            throw "Safety stop: current logged-in account '$CurrentUser' is not authorized by the README."
        }
        if (-not $u.Enabled) { continue }

        try { Disable-SpecificLocalAccount -Name $u.Name }
        catch {
            Write-Log "Could not disable unauthorized account '$($u.Name)': $($_.Exception.Message)" 'ERROR'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$u.Name; Action='Disable account'; Result='FAILED'; Detail=$_.Exception.Message})
        }
    }
}

function Get-AdministratorsSidSet {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    try {
        $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
    }
    catch {
        throw "Could not enumerate the local Administrators group: $($_.Exception.Message)"
    }

    foreach ($member in $members) {
        try { [void]$set.Add($member.SID.Value) } catch {}
    }
    return $set
}

function Get-AccountReconciliation {
    param([Parameter(Mandatory)][object]$ParsedUsers)

    $localUsers = @(Get-LocalUser | Sort-Object Name)
    $localByName = @{}
    foreach ($u in $localUsers) { $localByName[$u.Name.ToLowerInvariant()] = $u }
    $adminSids = Get-AdministratorsSidSet

    $authorizedAdminSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ParsedUsers.Administrators) { [void]$authorizedAdminSet.Add($name) }
    $authorizedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ParsedUsers.AllAuthorized) { [void]$authorizedSet.Add($name) }

    foreach ($name in $ParsedUsers.AllAuthorized) {
        $key = $name.ToLowerInvariant()
        if (-not $localByName.ContainsKey($key)) {
            $script:AccountResults.Add([pscustomobject]@{
                Account = $name; Authorized = 'YES'; Exists = 'NO'; Enabled = '-'; Administrator = if ($authorizedAdminSet.Contains($name)) {'YES'} else {'NO'}; Status = 'MISSING'
            })
            continue
        }

        $u = $localByName[$key]
        $isAdmin = $false
        try { $isAdmin = $adminSids.Contains($u.SID.Value) } catch {}
        $status = if (-not $u.Enabled) { 'DISABLED' } elseif ($authorizedAdminSet.Contains($name) -and -not $isAdmin) { 'ADMIN GROUP MISMATCH' } else { 'PASS' }

        $script:AccountResults.Add([pscustomobject]@{
            Account = $name; Authorized = 'YES'; Exists = 'YES'; Enabled = if ($u.Enabled) {'YES'} else {'NO'}; Administrator = if ($isAdmin) {'YES'} else {'NO'}; Status = $status
        })
    }

    foreach ($u in $localUsers) {
        if (-not $authorizedSet.Contains($u.Name)) {
            $isAdmin = $false
            try { $isAdmin = $adminSids.Contains($u.SID.Value) } catch {}
            $script:AccountResults.Add([pscustomobject]@{
                Account = $u.Name; Authorized = 'NO'; Exists = 'YES'; Enabled = if ($u.Enabled) {'YES'} else {'NO'}; Administrator = if ($isAdmin) {'YES'} else {'NO'}; Status = if ($u.Enabled) {'UNAUTHORIZED ENABLED'} else {'UNAUTHORIZED DISABLED'}
            })
        }
    }
}

function Apply-UserPasswordStates {
    param(
        [Parameter(Mandatory)][object]$ParsedUsers,
        [string]$AutologonUser,
        [Parameter(Mandatory)][object[]]$LocalUsers,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$AdminSids
    )

    $authorizedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ParsedUsers.AllAuthorized) { [void]$authorizedSet.Add($name) }

    # Only process authorized, enabled accounts. Use the already-fetched account list
    # and one cached Administrators SID set instead of re-enumerating them for each user.
    foreach ($u in $LocalUsers) {
        if (-not $authorizedSet.Contains($u.Name)) { continue }
        if (-not $u.Enabled) {
            Write-Log "Authorized account '$($u.Name)' is disabled; password flags were left unchanged." 'WARN'
            continue
        }

        if ($AutologonUser -and $AutologonUser -ieq $u.Name) {
            Write-Log "'$($u.Name)' is the auto-logon account; per-user password flags were intentionally left unchanged." 'WARN'
            continue
        }

        try {
            $state = Get-UserFlagState -Name $u.Name
            $isAuthorizedAdmin = [bool]($ParsedUsers.Administrators | Where-Object { $_ -ieq $u.Name })
            $isLocalAdmin = $false
            if ($isAuthorizedAdmin) { $isLocalAdmin = $AdminSids.Contains($u.SID.Value) }

            $baselineAlreadyCorrect = (
                -not $state.PasswordNeverExpires -and
                $state.PasswordRequired -and
                -not $state.UserMayChangePassword -and
                -not $state.MustChangeAtNextLogon
            )

            if ($baselineAlreadyCorrect) {
                Write-Log "'$($u.Name)': baseline password flags already correct; skipped." 'INFO'
                $script:AccountActionResults.Add([pscustomobject]@{Account=$u.Name; Action='Set password flags'; Result='ALREADY CORRECT'; Detail='Skipped native account write'})
            }
            else {
                Set-BaselineUserPasswordState -Name $u.Name -TemporarilyRemoveFromAdministrators:$isLocalAdmin -CurrentMustChange:$state.MustChangeAtNextLogon
                $script:AccountActionResults.Add([pscustomobject]@{Account=$u.Name; Action='Set password flags'; Result='SUCCESS'; Detail='Baseline flags applied; existing password-expired state is reported separately when applicable'})
            }
        }
        catch {
            Write-Log "Could not set password flags for '$($u.Name)': $($_.Exception.Message). Continuing to next account." 'ERROR'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$u.Name; Action='Set password flags'; Result='FAILED'; Detail=$_.Exception.Message})
            continue
        }
    }

    # ONLY assess the password text provided in the README for the built-in Administrator.
    if ($ParsedUsers.AdminPasswords.ContainsKey('Administrator')) {
        $builtinAdmin = $LocalUsers | Where-Object { $_.Name -ieq 'Administrator' } | Select-Object -First 1
        if ($null -ne $builtinAdmin) {
            $candidate = [string]$ParsedUsers.AdminPasswords['Administrator']
            $check = Test-PasswordMeetsPolicy -Password $candidate -Username 'Administrator'
            if ($check.IsWeak) {
                try {
                    Set-AdministratorWeakPasswordState -Name 'Administrator'
                    $script:AccountActionResults.Add([pscustomobject]@{Account='Administrator'; Action='Apply README weak-password response'; Result='SUCCESS'; Detail='User may change ON; must change at next logon ON'})
                }
                catch {
                    Write-Log "Could not apply weak-README password response for Administrator: $($_.Exception.Message)" 'ERROR'
                    $script:AccountActionResults.Add([pscustomobject]@{Account='Administrator'; Action='Apply README weak-password response'; Result='FAILED'; Detail=$_.Exception.Message})
                }
                Write-Log "README Administrator password assessed as weak: $($check.Reasons -join '; '). The current VM password was NOT read or tested."
            }
            else {
                Write-Log 'README Administrator password assessed as meeting the configured policy; default user-change flags remain OFF.'
            }
        }
    }
    elseif ($LocalUsers | Where-Object { $_.Name -ieq 'Administrator' }) {
        Write-Log 'README did not provide an Administrator password; no README-password assessment was possible.' 'WARN'
    }
}

function Verify-Policies {
    if ($DryRun) {
        Write-Log 'DRY RUN: skipping post-change policy verification because no policy changes were made.'
        return
    }

    $verify = Join-Path $TempRoot 'HarbingersPurge-Verify.inf'
    & "$env:SystemRoot\System32\secedit.exe" /export /cfg $verify /areas SECURITYPOLICY | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not export the post-change security policy for verification.'
    }
    $text = Get-Content -LiteralPath $verify -Raw
    foreach ($entry in $Policy.GetEnumerator()) {
        if ($entry.Key -eq 'RelaxMinimumPasswordLengthLimits') { continue }
        $pattern = '(?m)^\s*' + [regex]::Escape($entry.Key) + '\s*=\s*(\d+)\s*$'
        $m = [regex]::Match($text, $pattern)
        if (-not $m.Success) {
            Write-Log "Verification could not locate $($entry.Key) in the exported security policy." 'WARN'
            continue
        }
        $actual = [int]$m.Groups[1].Value
        if ($actual -ne [int]$entry.Value) {
            Write-Log "Verification mismatch: $($entry.Key) expected $($entry.Value), found $actual." 'ERROR'
        }
        else {
            Write-Log "Verified $($entry.Key) = $actual."
        }
    }

    $relax = $null
    $regBase = $null
    $samKey = $null
    try {
        $regBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Default
        )
        $samKey = $regBase.OpenSubKey('SYSTEM\CurrentControlSet\Control\SAM', $false)
        if ($null -eq $samKey) {
            throw 'Could not open HKLM:\SYSTEM\CurrentControlSet\Control\SAM for verification.'
        }
        $relax = $samKey.GetValue('RelaxMinimumPasswordLengthLimits', $null)
    }
    finally {
        if ($null -ne $samKey) { $samKey.Dispose() }
        if ($null -ne $regBase) { $regBase.Dispose() }
    }

    if ($null -eq $relax -or [int]$relax -ne 1) {
        Write-Log "Verification mismatch: RelaxMinimumPasswordLengthLimits expected 1, found $relax." 'ERROR'
    }
    else {
        Write-Log 'Verified RelaxMinimumPasswordLengthLimits = 1.'
    }
}

function Verify-UserStates {
    param(
        [Parameter(Mandatory)][object]$ParsedUsers,
        [string]$AutologonUser,
        [Parameter(Mandatory)][object[]]$LocalUsers,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$AdminSids
    )

    $localByName = @{}
    foreach ($u in $LocalUsers) { $localByName[$u.Name.ToLowerInvariant()] = $u }

    foreach ($name in $ParsedUsers.AllAuthorized) {
        $key = $name.ToLowerInvariant()
        if (-not $localByName.ContainsKey($key)) {
            Write-Log "Verification: authorized account '$name' is MISSING." 'WARN'
            continue
        }

        $u = $localByName[$key]
        if (-not $u.Enabled) {
            Write-Log "Verification: authorized account '$name' is DISABLED." 'WARN'
            continue
        }

        try {
            if ($AutologonUser -and $AutologonUser -ieq $name) {
                Write-Log "Verification: auto-logon account '$name' was intentionally left unchanged." 'WARN'
                continue
            }

            $state = Get-UserFlagState -Name $name
            $expectedMayChange = $false
            $expectedMustChange = $false

            if ($name -ieq 'Administrator' -and $ParsedUsers.AdminPasswords.ContainsKey('Administrator')) {
                $check = Test-PasswordMeetsPolicy -Password ([string]$ParsedUsers.AdminPasswords['Administrator']) -Username 'Administrator'
                if ($check.IsWeak) {
                    $expectedMayChange = $true
                    $expectedMustChange = $true
                }
            }

            if ($state.PasswordNeverExpires) { Write-Log "Verification mismatch for '$name': PasswordNeverExpires should be OFF." 'ERROR' }
            if (-not $state.PasswordRequired) { Write-Log "Verification mismatch for '$name': PasswordRequired should be ON." 'ERROR' }
            if ($state.UserMayChangePassword -ne $expectedMayChange) { Write-Log "Verification mismatch for '$name': UserMayChangePassword expected $expectedMayChange, found $($state.UserMayChangePassword)." 'ERROR' }

            if ($state.MustChangeAtNextLogon -ne $expectedMustChange) {
                if (-not $expectedMustChange -and $state.MustChangeAtNextLogon) {
                    Write-Log "Verification notice for '$name': MustChangeAtNextLogon is ON because the existing password is already expired; Windows does not allow clearing that state without changing the password." 'WARN'
                }
                else {
                    Write-Log "Verification mismatch for '$name': MustChangeAtNextLogon expected $expectedMustChange, found $($state.MustChangeAtNextLogon)." 'ERROR'
                }
            }

            $mustChangeAcceptable = ($state.MustChangeAtNextLogon -eq $expectedMustChange) -or (-not $expectedMustChange -and $state.MustChangeAtNextLogon)
            if (-not $state.PasswordNeverExpires -and $state.PasswordRequired -and $state.UserMayChangePassword -eq $expectedMayChange -and $mustChangeAcceptable) {
                Write-Log "Verified user state for '$name'."
            }
        }
        catch {
            Write-Log "Could not verify password flags for '$name': $($_.Exception.Message)" 'ERROR'
        }
    }

    foreach ($name in $ParsedUsers.Administrators) {
        if (-not $localByName.ContainsKey($name.ToLowerInvariant())) { continue }
        $u = $localByName[$name.ToLowerInvariant()]
        try {
            $isAdmin = $AdminSids.Contains($u.SID.Value)
            if (-not $isAdmin) {
                Write-Log "Verification mismatch: authorized administrator '$name' is not in the local Administrators group." 'ERROR'
            }
            else {
                Write-Log "Verified administrator group membership for '$name'."
            }
        }
        catch {
            Write-Log "Could not verify Administrators membership for '$name': $($_.Exception.Message)" 'ERROR'
        }
    }
}

function Select-HardeningKittyMachineFindingList {
    param([Parameter(Mandatory)][string]$ListsPath)

    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $osCaption = [string]$osInfo.Caption
    $osVersion = [string]$osInfo.Version
    $osBuild = [int64]$osInfo.BuildNumber

    $displayVersion = ''
    try {
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $displayVersion = [string]$cv.DisplayVersion
    }
    catch {}

    # Use the OS build as a fallback when DisplayVersion is unavailable.
    if ([string]::IsNullOrWhiteSpace($displayVersion)) {
        if ($osCaption -match 'Windows Server 2022') {
            # Server 2022 uses build 20348 for both 21H2 and 22H2, so an exact
            # branch cannot be inferred from the build alone. Stop rather than guess.
            $displayVersion = ''
        }
        elseif ($osCaption -match 'Windows 11') {
            switch ($osBuild) {
                { $_ -ge 26200 } { $displayVersion = '25H2'; break }
                { $_ -ge 26100 } { $displayVersion = '24H2'; break }
                { $_ -ge 22631 } { $displayVersion = '23H2'; break }
                { $_ -ge 22621 } { $displayVersion = '22H2'; break }
                { $_ -ge 22000 } { $displayVersion = '21H2'; break }
            }
        }
    }

    if ($osCaption -match 'Windows 11') {
        $family = 'Windows 11'
    }
    elseif ($osCaption -match 'Windows Server 2022') {
        $family = 'Windows Server 2022'
    }
    else {
        throw "Unsupported Windows OS for automatic HardeningKitty list selection: $osCaption (version $osVersion, build $osBuild)."
    }

    $machineLists = @(Get-ChildItem -LiteralPath $ListsPath -Filter '*.csv' -File -ErrorAction Stop |
        Where-Object { $_.Name -match '(?i)_machine\.csv$' })

    if ($machineLists.Count -eq 0) {
        throw "No *_machine.csv finding lists were found in '$ListsPath'. user.csv will never be selected."
    }

    function Get-BaselineVersionParts {
        param([Parameter(Mandatory)][string]$Name)
        $m = [regex]::Match($Name, '(?i)_(\d+\.\d+(?:\.\d+)*)_machine\.csv$')
        if (-not $m.Success) { return @(0,0,0) }
        $parts = $m.Groups[1].Value.Split('.') | ForEach-Object { [int]$_ }
        while ($parts.Count -lt 3) { $parts += 0 }
        return @($parts[0], $parts[1], $parts[2])
    }

    function Select-HighestBaseline {
        param(
            [Parameter(Mandatory)][System.IO.FileInfo[]]$Candidates,
            [Parameter(Mandatory)][string]$Description
        )

        if ($Candidates.Count -eq 0) {
            throw "No exact $Description *_machine.csv finding list was found in '$ListsPath'."
        }

        $ranked = foreach ($file in $Candidates) {
            $v = Get-BaselineVersionParts -Name $file.Name
            [pscustomobject]@{
                File = $file
                Major = $v[0]
                Minor = $v[1]
                Patch = $v[2]
            }
        }

        $winner = $ranked |
            Sort-Object -Property Major, Minor, Patch, @{Expression = { $_.File.Name }; Descending = $false} -Descending:$false |
            Select-Object -Last 1

        return $winner.File
    }

    $selected = $null
    $reason = $null

    if ($family -eq 'Windows 11') {
        # The 0x6d69636b list is the project's Windows 11 machine list and is
        # currently documented for Windows 11 25H2.
        if ($displayVersion -eq '25H2') {
            $preferred = $machineLists | Where-Object { $_.Name -ieq 'finding_list_0x6d69636b_machine.csv' }
            if ($preferred.Count -ne 1) {
                throw "Exact Windows 11 25H2 machine list 'finding_list_0x6d69636b_machine.csv' was not found in '$ListsPath'."
            }
            $selected = $preferred[0]
            $reason = 'Windows 11 25H2 exact 0x6d69636b machine baseline'
        }
        else {
            if ([string]::IsNullOrWhiteSpace($displayVersion)) {
                throw "Could not determine the Windows 11 release version from DisplayVersion/build; refusing to guess a HailMary list."
            }

            $candidates = @($machineLists | Where-Object {
                $_.Name -match '(?i)Windows[_ -]?11' -and
                $_.Name -match [regex]::Escape($displayVersion)
            })

            $selected = Select-HighestBaseline -Candidates $candidates -Description "Windows 11 $displayVersion"
            $reason = "Windows 11 $displayVersion exact OS/version match; selected highest available baseline revision"
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($displayVersion) -or $displayVersion -notmatch '^(21H2|22H2)$') {
            throw "Could not determine an exact Windows Server 2022 release (expected DisplayVersion 21H2 or 22H2); refusing to guess a HailMary list. Detected build $osBuild."
        }

        $candidates = @($machineLists | Where-Object {
            $_.Name -match '(?i)windows[_ -]?server[_ -]?2022' -and
            $_.Name -match [regex]::Escape($displayVersion)
        })

        $selected = Select-HighestBaseline -Candidates $candidates -Description "Windows Server 2022 $displayVersion"
        $reason = "Windows Server 2022 $displayVersion exact OS/version match; selected highest available baseline revision"
    }

    if ($null -eq $selected) {
        throw "Automatic selection failed for $family $displayVersion."
    }

    if ($selected.Name -match '(?i)_user\.csv$') {
        throw "Safety stop: automatic selection chose a user.csv file, which is not allowed: $($selected.Name)"
    }

    return [pscustomobject]@{
        OsFamily = $family
        OsVersion = $osVersion
        OsBuild = $osBuild
        DisplayVersion = $displayVersion
        FindingList = $selected
        Score = $null
        Reason = $reason
        AvailableMachineLists = @($machineLists | Select-Object -ExpandProperty Name | Sort-Object)
    }
}

function Install-And-Run-HardeningKittyHailMary {
    $releaseRoot = $HardeningKittyRoot
    $zipPath = Join-Path $TempRoot 'HardeningKitty-latest.zip'
    $extractRoot = Join-Path $TempRoot 'HardeningKitty-latest'
    $moduleBase = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\HardeningKitty'

    try {
        if ($DryRun) {
            Write-Log 'DRY RUN: would download/install the latest HardeningKitty release and automatically select a *_machine.csv finding list for the detected OS.'
            return [pscustomobject]@{ Success = $true; DryRun = $true; FindingList = $null; Report = $null; OsFamily = $null; OsVersion = $null; OsBuild = $null; DisplayVersion = $null; SelectionReason = $null }
        }

        $null = New-Item -ItemType Directory -Path $releaseRoot -Force
        $null = New-Item -ItemType Directory -Path $extractRoot -Force
        Write-Log "Querying latest HardeningKitty release from $HardeningKittyReleaseApi"
        $release = Invoke-RestMethod -Uri $HardeningKittyReleaseApi -UseBasicParsing
        if (-not $release.zipball_url) { throw 'HardeningKitty latest-release API did not return a zipball_url.' }
        $versionName = [string]$release.name
        if ([string]::IsNullOrWhiteSpace($versionName)) { $versionName = [string]$release.tag_name }
        if ([string]::IsNullOrWhiteSpace($versionName)) { $versionName = 'latest' }
        $safeVersion = ($versionName -replace '[^A-Za-z0-9._-]', '_')

        Write-Log "Downloading HardeningKitty $versionName"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $release.zipball_url -OutFile $zipPath -UseBasicParsing -MaximumRedirection 5
        if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) { throw 'HardeningKitty archive was not downloaded.' }

        Write-Log 'Extracting HardeningKitty.'
        Expand-Archive -Path $zipPath -DestinationPath $extractRoot -Force
        $topFolders = @(Get-ChildItem -LiteralPath $extractRoot -Directory)
        if ($topFolders.Count -eq 0) { throw 'HardeningKitty archive did not contain an extracted repository folder.' }
        $sourceRoot = $topFolders[0].FullName

        $requiredFiles = @('HardeningKitty.psd1','HardeningKitty.psm1','lists')
        foreach ($required in $requiredFiles) {
            if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot $required))) {
                throw "HardeningKitty package is missing required item '$required'."
            }
        }

        $moduleVersion = ($versionName -replace '^v\.?','')
        if ([string]::IsNullOrWhiteSpace($moduleVersion)) { $moduleVersion = $safeVersion }
        $moduleVersionPath = Join-Path $moduleBase $moduleVersion
        $null = New-Item -ItemType Directory -Path $moduleVersionPath -Force
        Copy-Item -LiteralPath (Join-Path $sourceRoot 'HardeningKitty.psd1') -Destination $moduleVersionPath -Force
        Copy-Item -LiteralPath (Join-Path $sourceRoot 'HardeningKitty.psm1') -Destination $moduleVersionPath -Force
        Copy-Item -LiteralPath (Join-Path $sourceRoot 'lists') -Destination $moduleVersionPath -Recurse -Force

        Get-ChildItem -LiteralPath $moduleVersionPath -Recurse -File -ErrorAction Stop | Unblock-File -ErrorAction SilentlyContinue

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
        Import-Module (Join-Path $moduleVersionPath 'HardeningKitty.psm1') -Force -ErrorAction Stop

        $selection = Select-HardeningKittyMachineFindingList -ListsPath (Join-Path $moduleVersionPath 'lists')
        $findingList = $selection.FindingList.FullName
        $findingListLeaf = $selection.FindingList.Name

        Write-Log "Detected OS for HardeningKitty list selection: $($selection.OsFamily), version $($selection.OsVersion), build $($selection.OsBuild)$(if ($selection.DisplayVersion) { ", DisplayVersion $($selection.DisplayVersion)" } else { '' })."
        Write-Log "HardeningKitty machine finding list selected automatically: $findingListLeaf ($($selection.Reason))."

        $hkBackup = Join-Path $BackupRoot ('HardeningKitty-preHailMary-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.csv')
        Write-Log "Creating HardeningKitty pre-HailMary backup: $hkBackup"
        Push-Location $moduleVersionPath
        try {
            Invoke-HardeningKitty -Mode Config -Backup -BackupFile $hkBackup -FileFindingList $findingListLeaf -SkipMachineInformation -ErrorAction Stop *>&1 |
                Tee-Object -FilePath $HardeningKittyLogPath -Append | Out-Host

            Write-Log 'Running HardeningKitty HailMary. This can change many machine security settings.' 'CHANGE'
            $hailmaryOutput = Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList $findingListLeaf -SkipRestorePoint -SkipMachineInformation -ErrorAction Stop *>&1 |
                Tee-Object -FilePath $HardeningKittyLogPath -Append
            foreach ($line in $hailmaryOutput) {
                $text = [string]$line
                if ($text) { Write-Host "[HardeningKitty] $text" }
            }
        }
        finally {
            Pop-Location
        }

        Write-Log 'HardeningKitty HailMary completed.' 'CHANGE'
        return [pscustomobject]@{
            Success = $true
            DryRun = $false
            FindingList = $findingList
            Report = $HardeningKittyLogPath
            OsFamily = $selection.OsFamily
            OsVersion = $selection.OsVersion
            OsBuild = $selection.OsBuild
            DisplayVersion = $selection.DisplayVersion
            SelectionReason = $selection.Reason
        }
    }
    catch {
        Write-Log "HardeningKitty HailMary stage failed: $($_.Exception.Message). Continuing to README/policy/account hardening." 'WARN'
        return [pscustomobject]@{
            Success = $false
            DryRun = $false
            FindingList = $null
            Report = $HardeningKittyLogPath
            OsFamily = $null
            OsVersion = $null
            OsBuild = $null
            DisplayVersion = $null
            SelectionReason = $null
        }
    }
}

function Install-WsdCertificateFirst {
    $source = if ($CertificateUri) { $CertificateUri } else { $DefaultWsdCertificateUri }
    $certPath = Join-Path $TempRoot 'wsd.crt'

    try {
        if ([string]::IsNullOrWhiteSpace($source)) {
            $localCandidates = @(
                (Join-Path $PSScriptRoot 'wsd.crt'),
                (Join-Path (Get-Location) 'wsd.crt')
            ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique

            if ($localCandidates.Count -gt 0) {
                Copy-Item -LiteralPath $localCandidates[0] -Destination $certPath -Force
                Write-Log "Using local wsd.crt because no download URL was configured: $($localCandidates[0])" 'WARN'
            }
            else {
                Write-Log 'wsd.crt download URL is not configured and no local wsd.crt was found. Certificate installation was skipped; continuing with the rest of the run.' 'WARN'
                return
            }
        }
        else {
            Write-Log "Downloading wsd.crt FIRST from $source"
            Invoke-WebRequest -Uri $source -OutFile $certPath -UseBasicParsing -MaximumRedirection 5
        }

        if (-not (Test-Path -LiteralPath $certPath -PathType Leaf)) {
            throw 'wsd.crt was not found after the download/copy step.'
        }

        if ($DryRun) {
            Write-Log 'DRY RUN: would import wsd.crt into Cert:\LocalMachine\Root.'
            return
        }

        Import-Certificate -FilePath $certPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
        Write-Log "Imported wsd.crt into Cert:\LocalMachine\Root." 'CHANGE'
    }
    catch {
        Write-Log "wsd.crt installation failed: $($_.Exception.Message). Continuing with the rest of Harbinger's Purge; install the certificate manually afterward." 'WARN'
    }
}

function Write-Report {
    param(
        [Parameter(Mandatory)][object]$OsInfo,
        [Parameter(Mandatory)][object]$ParsedUsers,
        [string]$ReadmeSource,
        [object]$HardeningKittyResult
    )

    $report = New-Object System.Collections.Generic.List[string]
    $report.Add("Harbinger's Purge")
    $report.Add('Created by Channveer Singh')
    $report.Add('')
    $report.Add("Run time: $(Get-Date)")
    $report.Add("Dry run: $DryRun")
    $report.Add("OS: $($OsInfo.Caption) (Build $($OsInfo.Build))")
    $report.Add("README: $ReadmeSource")
    $report.Add('')
    $report.Add('HardeningKitty:')
    if ($HardeningKittyResult) {
        $hkStatus = if ($HardeningKittyResult.Success) { 'PASS' } else { 'WARN' }
        $report.Add("  Status: $hkStatus")
        if ($HardeningKittyResult.OsFamily) { $report.Add("  Detected OS: $($HardeningKittyResult.OsFamily)") }
        if ($HardeningKittyResult.FindingList) { $report.Add("  Finding list: $($HardeningKittyResult.FindingList)") }
        if ($HardeningKittyResult.SelectionReason) { $report.Add("  Selection reason: $($HardeningKittyResult.SelectionReason)") }
        if ($HardeningKittyResult.Report) { $report.Add("  HailMary log: $($HardeningKittyResult.Report)") }
    }
    $report.Add('  HailMary uses an automatically selected *_machine.csv finding list only; user.csv is never selected.')
    $report.Add('')

    $report.Add('Authorized Administrators:')
    foreach ($n in $ParsedUsers.Administrators) { $report.Add("  - $n") }
    $report.Add('Authorized Users:')
    foreach ($n in $ParsedUsers.Users) { $report.Add("  - $n") }
    $report.Add('')

    $report.Add('ACCOUNT RECONCILIATION:')
    $report.Add('  Account | Authorized | Exists | Enabled | Administrator | Status')
    foreach ($r in ($script:AccountResults | Sort-Object Account, Authorized -Descending)) {
        $report.Add(('  {0} | {1} | {2} | {3} | {4} | {5}' -f $r.Account, $r.Authorized, $r.Exists, $r.Enabled, $r.Administrator, $r.Status))
    }
    $report.Add('')

    $report.Add('ACCOUNT ACTION RESULTS:')
    if ($script:AccountActionResults.Count -eq 0) { $report.Add('  (none)') }
    else { foreach ($a in $script:AccountActionResults) { $report.Add(('  {0} | {1} | {2} | {3}' -f $a.Account, $a.Action, $a.Result, $a.Detail)) } }
    $report.Add('')

    $report.Add('PHASE RESULTS:')
    foreach ($phase in $script:PhaseResults) {
        $detail = if ($phase.Detail) { " - $($phase.Detail)" } else { '' }
        $report.Add("  - $($phase.Name): $($phase.Status)$detail")
    }
    $report.Add('')

    $report.Add('Changes:')
    if ($script:Changes.Count -eq 0) { $report.Add('  (none)') }
    else { foreach ($m in $script:Changes) { $report.Add("  - $m") } }
    $report.Add('')

    $report.Add('Warnings / Manual Review:')
    if ($script:Warnings.Count -eq 0) { $report.Add('  (none)') }
    else { foreach ($m in $script:Warnings) { $report.Add("  - $m") } }
    $report.Add('')

    $report.Add('Errors:')
    if ($script:Failures.Count -eq 0) { $report.Add('  (none)') }
    else { foreach ($m in $script:Failures) { $report.Add("  - $m") } }
    $report.Add('')

    $report.Add('Policy targets:')
    $report.Add('  Password history: 24')
    $report.Add('  Maximum password age: 30 days')
    $report.Add('  Minimum password age: 7 days')
    $report.Add('  Minimum password length: 14 characters')
    $report.Add('  Password complexity: Enabled')
    $report.Add('  Relax minimum password length limits: Enabled')
    $report.Add('  Reversible encryption: Disabled')
    $report.Add('  Account lockout duration: 30 minutes')
    $report.Add('  Account lockout threshold: 5 invalid logon attempts')
    $report.Add('  Reset account lockout counter after: 15 minutes')
    $report.Add('')
    $report.Add('Per-user baseline: Password never expires = OFF; Password required = ON; User may change password = OFF; User must change at next logon = OFF.')
    $report.Add('Administrator exception: ONLY the README-provided Administrator password is assessed. If that README password is weak, User may change password and User must change at next logon are enabled. The current VM password is never read or tested. An already-expired current password cannot have its next-logon requirement cleared without changing that password, so such cases are reported for manual follow-up.')
    $report.Add('Built-in Administrator: disabled when not listed as an authorized administrator. Guest, WDAGUtilityAccount, DefaultAccount, and defaultuser0 are disabled when present. Unauthorized local users are removed from Administrators and disabled.')

    Set-Content -LiteralPath $ReportPath -Value $report -Encoding UTF8
    Write-Log "Report written to $ReportPath"
}

# =============================
# Main
# =============================
try {
    Write-Log "=== Harbinger's Purge starting ==="
    Write-Log 'Author: Channveer Singh'
    Require-Administrator

    $osInfo = Get-OsInfo
    if (-not $osInfo.Kind) {
        throw "Unsupported OS: $($osInfo.Caption) build $($osInfo.Build). Harbinger's Purge only supports Windows 11 and Windows Server 2022."
    }
    Write-Log "Detected supported OS: $($osInfo.Kind) (build $($osInfo.Build))."

    # Certificate is intentionally FIRST. Failure is a warning, not a stop.
    Start-Phase 'Certificate installation'
    $warnBeforeCert = $script:Warnings.Count
    Install-WsdCertificateFirst
    $certStatus = if ($script:Warnings.Count -gt $warnBeforeCert) { 'WARN' } else { 'PASS' }
    Complete-Phase $certStatus 'Certificate step finished; a WARN means manual installation may still be needed.'

    Start-Phase 'HardeningKitty HailMary'
    $hkResult = Install-And-Run-HardeningKittyHailMary
    $hkStatus = if ($hkResult.Success) { 'PASS' } else { 'WARN' }
    $hkDetail = if ($hkResult.Success) { 'HardeningKitty HailMary completed using an automatically selected machine finding list.' } else { 'HardeningKitty HailMary did not complete; the script continued to README/policy/account hardening.' }
    Complete-Phase $hkStatus $hkDetail

    if ([string]::IsNullOrWhiteSpace($ReadmeUri)) {
        Write-Host ''
        Write-Host "Harbinger's Purge needs the CyberPatriot README for THIS image." -ForegroundColor Cyan
        $ReadmeUri = Read-Host 'Enter the CyberPatriot README URL or local README file path'
    }
    if ([string]::IsNullOrWhiteSpace($ReadmeUri)) {
        throw 'No README source was supplied. No account changes were made.'
    }

    Start-Phase 'README processing'
    $readme = Get-ReadmeResponse -Source $ReadmeUri
    $readmeText = Convert-HtmlToText -Html $readme.Html
    $parsed = Parse-AuthorizedUsers -Text $readmeText

    Write-Log ("README authorized administrators: {0}" -f ($parsed.Administrators -join ', '))
    Write-Log ("README authorized users: {0}" -f ($parsed.Users -join ', '))
    Complete-Phase 'PASS' ("Parsed {0} authorized administrators and {1} authorized users." -f $parsed.Administrators.Count, $parsed.Users.Count)

    $currentUser = Get-CurrentUsername
    Assert-CurrentUserAuthorized -Authorized $parsed.AllAuthorized -CurrentUser $currentUser
    Write-Log "Confirmed currently logged-in account '$currentUser' is authorized by the README."

    # Cache local users and Administrators membership once for the account-processing stages.
    $cachedLocalUsers = @(Get-LocalUser | Sort-Object Name)
    $cachedAdminSids = Get-AdministratorsSidSet
    if (-not (Test-LocalUserIsAdministrator -Name $currentUser -AdminSids $cachedAdminSids)) { throw "Safety stop: current logged-in account '$currentUser' is not a member of the local Administrators group." }
    Write-Log "Confirmed currently logged-in account '$currentUser' is a local administrator."

    $autologonUser = Get-AutologonUser
    if ($autologonUser) {
        Write-Log "Detected auto-logon account: $autologonUser" 'WARN'
    }

    Start-Phase 'Global password and account-lockout policy'
    $backup = Backup-SecurityPolicy
    Apply-ExactPolicies -BackupPath $backup
    Complete-Phase 'PASS' 'Global password and account-lockout targets were applied.'

    Start-Phase 'Administrator cleanup and unlisted-account handling'
    $cleanupErrorsBefore = $script:Failures.Count
    try {
        Remove-UnapprovedAdministratorsAndDisableUnlisted -ParsedUsers $parsed -CurrentUser $currentUser
    }
    catch {
        Write-Log "Account cleanup stage error: $($_.Exception.Message). Continuing to per-user settings and verification." 'ERROR'
    }
    $cleanupStatus = if ($script:Failures.Count -gt $cleanupErrorsBefore) { 'WARN' } else { 'PASS' }
    Complete-Phase $cleanupStatus 'Administrator membership and account-disable actions were processed; individual failures are recorded and do not stop later phases.'

    Start-Phase 'Per-user password settings'
    $userErrorsBefore = $script:Failures.Count
    # Refresh once after account cleanup so enabled/disabled state and admin membership are current.
    $cachedLocalUsers = @(Get-LocalUser | Sort-Object Name)
    $cachedAdminSids = Get-AdministratorsSidSet
    Apply-UserPasswordStates -ParsedUsers $parsed -AutologonUser $autologonUser -LocalUsers $cachedLocalUsers -AdminSids $cachedAdminSids
    $userStatus = if ($script:Failures.Count -gt $userErrorsBefore) { 'WARN' } else { 'PASS' }
    Complete-Phase $userStatus 'Each account was attempted independently; failures do not stop the remaining accounts.'

    # Build the complete README-vs-local account table after changes.
    Get-AccountReconciliation -ParsedUsers $parsed

    Start-Phase 'Post-change verification'
    if ($DryRun) {
        Write-Log 'DRY RUN: no post-change verification was performed.'
        Complete-Phase 'SKIPPED' 'Dry run requested.'
    }
    else {
        $verifyErrorsBefore = $script:Failures.Count
        try { Verify-Policies } catch { Write-Log "Policy verification failed: $($_.Exception.Message)" 'ERROR' }
        try {
            # One fresh cache for verification; native NetUserGetInfo handles the per-user reads quickly.
            $verifyLocalUsers = @(Get-LocalUser | Sort-Object Name)
            $verifyAdminSids = Get-AdministratorsSidSet
            Verify-UserStates -ParsedUsers $parsed -AutologonUser $autologonUser -LocalUsers $verifyLocalUsers -AdminSids $verifyAdminSids
        } catch { Write-Log "Account verification failed: $($_.Exception.Message)" 'ERROR' }
        $verifyStatus = if ($script:Failures.Count -gt $verifyErrorsBefore) { 'WARN' } else { 'PASS' }
        Complete-Phase $verifyStatus 'Verification completed; see the error/warning section for exact mismatches.'
    }

    Set-Content -LiteralPath $TranscriptPath -Value ($script:Log -join [Environment]::NewLine) -Encoding UTF8
    Write-Report -OsInfo $osInfo -ParsedUsers $parsed -ReadmeSource $readme.Source -HardeningKittyResult $hkResult
    Write-FinalSummary -DryRun:$DryRun

    Write-Host ''
    if ($DryRun) {
        Write-Host "Harbinger's Purge dry run completed." -ForegroundColor Cyan
    }
    else {
        Write-Host "Harbinger's Purge completed; review the summary above." -ForegroundColor Green
    }
    Write-Host "Report: $ReportPath" -ForegroundColor Green
    if ($script:Warnings.Count -gt 0) {
        Write-Host "Warnings/manual-review items: $($script:Warnings.Count)" -ForegroundColor Yellow
    }
    if ($script:Failures.Count -gt 0) {
        Write-Host "Errors: $($script:Failures.Count)" -ForegroundColor Red
        exit 2
    }
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    try { Set-Content -LiteralPath $TranscriptPath -Value ($script:Log -join [Environment]::NewLine) -Encoding UTF8 } catch {}
    Write-Host ''
    Write-Host "Harbinger's Purge encountered a fatal stage error." -ForegroundColor Red
    Write-FinalSummary -DryRun:$DryRun
    Write-Host "Review transcript: $TranscriptPath" -ForegroundColor Yellow
    exit 1
}
finally {
    if (-not $KeepBackupFiles) {
        Get-ChildItem -LiteralPath $TempRoot -File -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}
