<#
.SYNOPSIS
    Harbinger's Purge - CyberPatriot Windows 11 / Windows Server 2022 user hardening.

.DESCRIPTION
    1. Attempts to download/install wsd.crt FIRST (before all other hardening stages).
    2. Downloads/installs the latest HardeningKitty release and runs HailMary against the machine finding list.
    3. Reads the CyberPatriot README for THIS image.
    4. Parses README browser/software requirements and the Critical Services section.
    5. Ensures requested browsers/software are installed and, where the README requires it, updated to the latest stable package available from the configured package source.
    6. Ensures explicitly listed Critical Services are available/running without touching unrelated services.
    7. Compares local users to the README's Authorized Administrators and Authorized Users.
    8. Enforces explicitly named scenario account actions/removals conservatively.
    9. Disables enabled local accounts that are not authorized; Guest, WDAGUtilityAccount, DefaultAccount, and defaultuser0 are explicitly disabled when present.
    10. Applies the exact password and account-lockout policies requested.
    11. Applies the requested per-user password flags.
    12. Assesses ONLY password text explicitly supplied in the README for authorized administrator
       accounts. If a supplied README password does not meet the configured password requirements,
       that account gets User may change password = ON and User must change password at next logon = ON.
       Strong README passwords leave those flags OFF. The current VM password is never read or tested.
       The detected auto-logon account is left unchanged per the README safety warning.
    13. Verifies the resulting account states and administrator-group membership.
    14. Produces a report showing PASS / WARN / ERROR / MANUAL REVIEW items.

    HardeningKitty: Deterministically selects an OS/version-matched *_machine.csv finding list; user.csv is never selected.
    Windows 11 and Windows Server 2022 use explicit OS/version mappings to machine-only finding lists.
    If the required exact list is not present in the downloaded HardeningKitty release, HailMary is refused
    rather than guessing or falling back to a different release/list.

    Supported operating systems:
      - Windows 11
      - Windows Server 2022

.AUTHOR
    Channveer Singh

.TITLE
    Harbinger's Purge

.VERSION
    1.20.2 - Generalizes the Windows README parser for same-format scenarios, removes all scenario-specific hardcoding, supports explicit scenario account/software cleanup directives conservatively, uses explicit OS/release-matched HardeningKitty machine lists and fails closed when the mapped list is absent, protects README-prohibited accounts/actions, and keeps HailMary failures isolated.
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
$DefaultWsdCertificateUri = 'https://raw.githubusercontent.com/HarbringerGone/Harbingers-purge/refs/heads/main/wsd.crt'
# HardeningKitty settings. Machine lists only. The actual list is selected at runtime.
$HardeningKittyReleaseApi = 'https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest'
# Microsoft documents that WinGet is not available on Windows Server 2022.
# For Server 2022, Chocolatey is bootstrapped only when the README requires
# software/browser provisioning and Chocolatey is not already present.
$ChocolateyReleaseApi = 'https://api.github.com/repos/chocolatey/choco/releases/latest'
$ChocolateySource = 'https://community.chocolatey.org/api/v2/'

# Common CyberPatriot software aliases. Unknown names are resolved conservatively
# using exact package/display-name searches; ambiguous matches are rejected.
$SoftwareCatalog = @{
    'chrome'             = @{ Winget = 'Google.Chrome';             Choco = 'googlechrome' }
    'googlechrome'       = @{ Winget = 'Google.Chrome';             Choco = 'googlechrome' }
    'firefox'            = @{ Winget = 'Mozilla.Firefox';           Choco = 'firefox' }
    'firefoxesr'         = @{ Winget = 'Mozilla.Firefox';           Choco = 'firefox' }
    'edge'               = @{ Winget = 'Microsoft.Edge';             Choco = 'microsoft-edge' }
    'microsoftedge'      = @{ Winget = 'Microsoft.Edge';             Choco = 'microsoft-edge' }
    'brave'              = @{ Winget = 'Brave.Brave';               Choco = 'brave' }
    'opera'              = @{ Winget = 'Opera.Opera';               Choco = 'opera' }
    'vivaldi'            = @{ Winget = 'Vivaldi.Vivaldi';           Choco = 'vivaldi' }
    'notepadplusplus'    = @{ Winget = 'Notepad++.Notepad++';       Choco = 'notepadplusplus' }
    '7zip'               = @{ Winget = '7zip.7zip';                 Choco = '7zip' }
    'wireshark'          = @{ Winget = 'WiresharkFoundation.Wireshark'; Choco = 'wireshark' }
    'apache'             = @{ Winget = 'ApacheLounge.httpd';        Choco = 'apache-httpd' }
    'apachehttpd'        = @{ Winget = 'ApacheLounge.httpd';        Choco = 'apache-httpd' }
    'apachehttpserver'   = @{ Winget = 'ApacheLounge.httpd';        Choco = 'apache-httpd' }
}


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

# Initialize paths only after the runtime roots are defined.
$HardeningKittyRoot    = Join-Path $TempRoot 'HardeningKitty'
$HardeningKittyLogPath = Join-Path $ProgramDataRoot 'HardeningKitty-HailMary.log'

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
$script:SoftwareResults = New-Object System.Collections.Generic.List[object]
$script:ServiceResults = New-Object System.Collections.Generic.List[object]
$script:CurrentPhase = $null

# Main-stage state is initialized before execution so fatal errors can still produce a partial report.
$osInfo = $null
$parsed = $null
$requirements = [pscustomobject]@{ Software=@(); Services=@(); ScenarioRemovals=@(); ScenarioAccountActions=@(); ProhibitedActions=@() }
$hkResult = $null
$readmeText = $null

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
        $hkColor = if ($hkPhase.Status -eq 'PASS') { 'Green' } else { 'Yellow' }
        Write-Host ("HardeningKitty HailMary: {0}" -f $hkPhase.Status) -ForegroundColor $hkColor
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
        ForEach-Object { (($_ -replace '^\s*#{1,6}\s*', '')).Trim() } |
        Where-Object { $_ -ne '' }
    )
}

function Get-ReadmeSectionLines {
    param(
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][string]$HeaderPattern,
        [string[]]$StopHeaders = @()
    )

    $start = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match $HeaderPattern) {
            $start = $i
            break
        }
    }
    if ($start -lt 0) { return @() }

    $stop = $Lines.Count
    for ($i = $start + 1; $i -lt $Lines.Count; $i++) {
        $hit = $false
        foreach ($stopPattern in $StopHeaders) {
            if ($Lines[$i] -match $stopPattern) {
                $stop = $i
                $hit = $true
                break
            }
        }
        if ($hit) { break }
        if ($i -gt ($start + 1) -and $Lines[$i] -match '^#{1,6}\s+') {
            $stop = $i
            break
        }
    }
    if ($stop -le $start) { return @() }
    if ($stop -eq ($start + 1)) { return @($Lines[$start + 1]) }
    return @($Lines[($start + 1)..($stop - 1)])
}

function Get-CompetitionScenarioLines {
    param([Parameter(Mandatory)][string[]]$Lines)
    return Get-ReadmeSectionLines -Lines $Lines -HeaderPattern '(?i)^Competition Scenario\s*$' -StopHeaders @(
        '(?i)^Authorized Administrators:\s*$',
        '(?i)^Authorized Users:\s*$',
        '(?i)^Forensics Questions\s*$',
        '(?i)^Competition Guidelines\s*$',
        '(?i)^ANSWER KEY\s*$'
    )
}

function Test-NegatedInstructionLine {
    param([Parameter(Mandatory)][string]$Line)
    return $Line -match '(?i)\b(?:do\s+not|don''t|must\s+not|should\s+not|never|not\s+allowed|prohibited\s+from)\b'
}

function Normalize-ScenarioTarget {
    param([Parameter(Mandatory)][string]$Target)
    $t = $Target.Trim()
    $t = $t.Trim(' ', '.', ',', ';', ':', '"', "'", '', '', '', '', '`')
    $t = $t -replace '^the\s+', ''
    $t = $t -replace '^an?\s+', ''
    $t = $t -replace '^local\s+', ''
    return $t.Trim()
}

function Parse-ScenarioInstructions {
    param([Parameter(Mandatory)][string[]]$ScenarioLines)

    $accountActions = New-Object System.Collections.ArrayList
    $removals = New-Object System.Collections.ArrayList
    $protectedAccounts = New-Object System.Collections.ArrayList
    $protectedServices = New-Object System.Collections.ArrayList
    $prohibited = New-Object System.Collections.ArrayList
    $nameRegex = '[A-Za-z0-9][A-Za-z0-9._-]{0,62}'

    foreach ($raw in $ScenarioLines) {
        $line = ($raw -replace '^[-*]\s*', '').Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        if (Test-NegatedInstructionLine -Line $line) {
            $null = $prohibited.Add($line)
            $sm = [regex]::Match($line, '(?i)\bdo\s+not\s+(?:stop|start|disable|enable)\s+(?:the\s+)?(?:Windows\s+)?service\s+[\"`]?([^\"`.,;]+)')
            if ($sm.Success) {
                $serviceTarget = Normalize-ScenarioTarget -Target $sm.Groups[1].Value
                if ($serviceTarget) { $null = $protectedServices.Add($serviceTarget) }
            }
            else {
                $sm = [regex]::Match($line, '(?i)\bdo\s+not\s+(?:stop|disable)\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 ._-]{1,80}?)(?:\s+(?:service|client|daemon))?[.!;]*$')
                if ($sm.Success -and $line -notmatch '(?i)\b(?:account|user)\b') {
                    $serviceTarget = Normalize-ScenarioTarget -Target $sm.Groups[1].Value
                    if ($serviceTarget -and $serviceTarget -notmatch '(?i)^(?:users?|accounts?|hacking tools?|media files?)$') { $null = $protectedServices.Add($serviceTarget) }
                }
            }
            $pm = [regex]::Match($line, "(?i)\bdo\s+not\s+(?:disable|remove|delete)\s+(?:the\s+)?(?:local\s+)?(?:account|user)\s+[\"']?($nameRegex)[\"']?")
            if (-not $pm.Success) {
                $pm = [regex]::Match($line, "(?i)\b(?:account|user)\s+[\"']?($nameRegex)[\"']?\s+(?:should|must)\s+not\s+be\s+(?:disabled|removed|deleted)\b")
            }
            if ($pm.Success -and -not ($protectedAccounts | Where-Object { $_ -ieq $pm.Groups[1].Value })) {
                $null = $protectedAccounts.Add($pm.Groups[1].Value)
            }
            continue
        }

        $createPatterns = @(
            "(?i)\b(?:make|create|add)\s+(?:a\s+|an\s+)?(?:new\s+)?(?:local\s+)?(?:account|user|employee)\s+(?:for\s+[^.]+?\s+)?(?:named|called)\s+[\"']?$nameRegex[\"']?",
            "(?i)\b(?:new|additional)\s+(?:account|user|employee)\s+(?:named|called)\s+[\"']?$nameRegex[\"']?",
            "(?i)\b(?:account|user|employee)\s+[\"']?$nameRegex[\"']?\s+(?:should|must)\s+be\s+created\b",
            "(?i)\b(?:employee|user|account)\s+(?:named|called)\s+[\"']?$nameRegex[\"']?\s+(?:should|must)\s+be\s+created\b"
        )
        $created = $false
        foreach ($pattern in $createPatterns) {
            $m = [regex]::Match($line, $pattern)
            if (-not $m.Success) { continue }
            $nameM = [regex]::Match($m.Value, "(?i)(?:named|called)\s+[\"']?($nameRegex)[\"']?")
            $name = if ($nameM.Success) { $nameM.Groups[1].Value } else { '' }
            if ([string]::IsNullOrWhiteSpace($name)) {
                $m2 = [regex]::Match($line, "(?i)\b(?:account|user|employee)\s+[\"']?($nameRegex)[\"']?\s+(?:should|must)\s+be\s+created\b")
                if ($m2.Success) { $name = $m2.Groups[1].Value }
            }
            if ($name -and -not (@($accountActions | Where-Object { $_.Name -ieq $name -and $_.Action -eq 'CREATE' }).Count)) {
                $null = $accountActions.Add([pscustomobject]@{Type='Account';Name=$name;Action='CREATE';Source=$line})
            }
            $created = $true
            break
        }
        if ($created) { continue }

        $deleteM = [regex]::Match($line, "(?i)\b(?:delete|remove)\s+(?:the\s+)?(?:local\s+)?(?:account|user)\s+[\"']?($nameRegex)[\"']?")
        if (-not $deleteM.Success) {
            $deleteM = [regex]::Match($line, "(?i)\b(?:account|user)\s+[\"']?($nameRegex)[\"']?\s+(?:should|must)\s+be\s+(?:deleted|removed)\b")
        }
        if ($deleteM.Success) {
            $name = $deleteM.Groups[1].Value
            if (-not (@($accountActions | Where-Object { $_.Name -ieq $name -and $_.Action -in @('DELETE','DISABLE') }).Count)) {
                $null = $accountActions.Add([pscustomobject]@{Type='Account';Name=$name;Action='DELETE';Source=$line})
            }
            continue
        }

        $disableM = [regex]::Match($line, "(?i)\bdisable\s+(?:the\s+)?(?:local\s+)?(?:account|user)\s+[\"']?($nameRegex)[\"']?")
        if (-not $disableM.Success) {
            $disableM = [regex]::Match($line, "(?i)\b(?:account|user)\s+[\"']?($nameRegex)[\"']?\s+(?:should|must)\s+be\s+disabled\b")
        }
        if ($disableM.Success) {
            $name = $disableM.Groups[1].Value
            if (-not (@($accountActions | Where-Object { $_.Name -ieq $name -and $_.Action -eq 'DELETE' }).Count)) {
                $null = $accountActions.Add([pscustomobject]@{Type='Account';Name=$name;Action='DISABLE';Source=$line})
            }
            continue
        }

        if ($line -match '(?i)\b(?:remove|delete|uninstall)\b') {
            $verbMatch = [regex]::Match($line, '(?i)\b(?:remove|delete|uninstall)\b')
            if ($verbMatch.Success) {
                $tail = $line.Substring($verbMatch.Index + $verbMatch.Length).Trim()
                $tail = $tail -replace '^(?i)\s+(?:the|an?|local)\s+', ''
                $tail = $tail.Trim(' ', '.', ':')

                $quoted = [regex]::Matches($tail, '["`]([^"`]+)["`]')
                if ($quoted.Count -gt 0) {
                    foreach ($q in $quoted) {
                        $target = Normalize-ScenarioTarget -Target $q.Groups[1].Value
                        if ($target -and $target -notmatch '(?i)^(?:any|all|non-work|unrelated|hacking tools?|media files?)$') {
                            $null = $removals.Add([pscustomobject]@{Type='Target';Target=$target;Source=$line})
                        }
                    }
                }
                elseif ($tail -notmatch '(?i)^(?:any|all|non-work|unrelated).*(?:files|media|hacking tools?)') {
                    $candidateText = $tail -replace '(?i)\s+from\s+.+$', ''
                    foreach ($part in @($candidateText -split '\s*,\s*|\s+and\s+')) {
                        $target = Normalize-ScenarioTarget -Target $part
                        if ([string]::IsNullOrWhiteSpace($target)) { continue }
                        if ($target -match '(?i)^(?:any|all|non-work|unrelated|files?|media|hacking tools?)$') { continue }
                        if ($target.Length -gt 160) { continue }
                        if ($target -match '(?i)^(?:Windows|this computer|the computer|the system|Feature Updates?|Insider Preview Builds?)$') { continue }
                        $null = $removals.Add([pscustomobject]@{Type='Target';Target=$target;Source=$line})
                    }
                }
            }
        }
    }

    [pscustomobject]@{
        AccountActions = @($accountActions | Sort-Object Action,Name -Unique)
        Removals = @($removals | Sort-Object Target,Source -Unique)
        ProtectedAccounts = @($protectedAccounts | Sort-Object -Unique)
        ProtectedServices = @($protectedServices | Sort-Object -Unique)
        ProhibitedActions = @($prohibited | Sort-Object -Unique)
    }
}

function Parse-AuthorizedUsers {
    param([Parameter(Mandatory)][string]$Text)

    $lines = Get-CleanLines -Text $Text
    $adminHeader = -1
    $userHeader = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '(?i)^Authorized Administrators:\s*$') { $adminHeader = $i }
        if ($lines[$i] -match '(?i)^Authorized Users:\s*$') { $userHeader = $i }
    }
    if ($adminHeader -lt 0 -or $userHeader -lt 0 -or $userHeader -le $adminHeader) {
        throw 'Could not locate both "Authorized Administrators:" and "Authorized Users:" sections in the README.'
    }

    $admins = New-Object System.Collections.Generic.List[string]
    $users = New-Object System.Collections.Generic.List[string]
    $adminCredentials = @{}
    $currentAdmin = $null
    $userRegex = '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$'

    for ($i = $adminHeader + 1; $i -lt $userHeader; $i++) {
        $line = ($lines[$i] -replace '^[-*-]\s*', '').Trim()
        $line = $line -replace '\s+\((?:you|current user)\)\s*$', ''
        if ($line -match '(?i)^password\s*:\s*(.*)$' -and $currentAdmin) {
            $adminCredentials[$currentAdmin] = [string]$Matches[1]
            continue
        }
        $inline = [regex]::Match($line, "(?i)^($userRegex)\s+(?:password\s*:\s*)(.+)$")
        if ($inline.Success) {
            $currentAdmin = $inline.Groups[1].Value
            $admins.Add($currentAdmin)
            $adminCredentials[$currentAdmin] = $inline.Groups[2].Value
            continue
        }
        if ($line -match $userRegex) {
            $currentAdmin = $line
            $admins.Add($line)
        }
    }

    $userEnd = $lines.Count
    for ($i = $userHeader + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '(?i)^(Competition Guidelines|ANSWER KEY|REMINDERS)\s*$' -or $lines[$i] -match '^#{1,6}\s+') {
            $userEnd = $i
            break
        }
    }
    for ($i = $userHeader + 1; $i -lt $userEnd; $i++) {
        $line = ($lines[$i] -replace '^[-*-]\s*', '').Trim()
        if ($line -match $userRegex -and $line -notmatch '(?i)^(password|authorized|administrators|users)$') { $users.Add($line) }
    }

    $all = @($admins + $users | Sort-Object -Unique)
    if ($all.Count -eq 0) { throw 'README parsing produced zero authorized users. No account changes were made.' }

    $scenario = Parse-ScenarioInstructions -ScenarioLines (Get-CompetitionScenarioLines -Lines $lines)
    # Parse specific account-protection directives from Competition Guidelines too.
    $guidelineLines = Get-ReadmeSectionLines -Lines $lines -HeaderPattern '(?i)^Competition Guidelines\s*$' -StopHeaders @('(?i)^ANSWER KEY\s*$', '(?i)^REMINDERS\s*$')
    $guidelineScenario = Parse-ScenarioInstructions -ScenarioLines $guidelineLines

    $scenarioActions = @($scenario.AccountActions + $guidelineScenario.AccountActions | Sort-Object Action,Name,Source -Unique)
    $scenarioAccounts = @($scenarioActions | Where-Object { $_.Action -eq 'CREATE' } | Select-Object -ExpandProperty Name | Sort-Object -Unique)
    $protectedAccounts = @($scenario.ProtectedAccounts + $guidelineScenario.ProtectedAccounts | Sort-Object -Unique)
    $protectedServices = @($scenario.ProtectedServices + $guidelineScenario.ProtectedServices | Sort-Object -Unique)

    [pscustomobject]@{
        Administrators = @($admins | Sort-Object -Unique)
        Users = @($users | Sort-Object -Unique)
        AllAuthorized = $all
        ScenarioAccounts = $scenarioAccounts
        ScenarioAccountActions = $scenarioActions
        ScenarioRemovals = @($scenario.Removals + $guidelineScenario.Removals | Sort-Object Target,Source -Unique)
        ProtectedAccounts = $protectedAccounts
        ProtectedServices = $protectedServices
        ProhibitedActions = @($scenario.ProhibitedActions + $guidelineScenario.ProhibitedActions | Sort-Object -Unique)
        AdminPasswords = $adminCredentials
    }
}

function Normalize-RequirementName {
    param([Parameter(Mandatory)][string]$Name)
    return (($Name.ToLowerInvariant()) -replace '[^a-z0-9]', '')
}

function Add-UniqueSoftwareRequirement {
    param(
        [Parameter(Mandatory)][object]$List,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Browser','Software')][string]$Type,
        [Parameter(Mandatory)][bool]$UpdateRequired,
        [string]$Source = 'README'
    )

    $clean = $Name.Trim() -replace '\s+', ' '
    $clean = $clean.Trim(' ', ',', ';', ':', '.')
    if ([string]::IsNullOrWhiteSpace($clean) -or $clean -match '^(?i:none|n/a)$') { return }

    $key = Normalize-RequirementName -Name $clean
    foreach ($existing in $List) {
        if ((Normalize-RequirementName -Name $existing.Name) -eq $key) {
            if ($UpdateRequired) { $existing.UpdateRequired = $true }
            return
        }
    }

    $null = $List.Add([pscustomobject]@{
        Name = $clean
        Type = $Type
        UpdateRequired = $UpdateRequired
        Source = $Source
    })
}

function Split-SoftwareRequirementList {
    param([Parameter(Mandatory)][string]$ListText)

    $text = $ListText -replace '\s+', ' '
    $text = $text -replace ',\s+and\s+', ','
    return @(
        $text -split '\s*,\s*' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and $_ -notmatch '^(?i:these|which|they)$' }
    )
}

function Parse-RequiredSoftwareAndServices {
    param([Parameter(Mandatory)][string]$Text)

    $software = New-Object System.Collections.ArrayList
    $services = New-Object System.Collections.ArrayList
    $lines = Get-CleanLines -Text $Text
    $flat = ($lines -join ' ') -replace '\s+', ' '

    $browserPatterns = @(
        '(?i)default\s+(?:web\s+)?browser.*?latest\s+stable\s+(?:version\s+)?of\s+([A-Za-z0-9][^.;,]+)',
        '(?i)default\s+(?:web\s+)?browser.*?should\s+be\s+the\s+latest\s+(?:official\s+)?stable\s+(?:version\s+of\s+)?([A-Za-z0-9][^.;,]+)',
        '(?i)default\s+(?:web\s+)?browser.*?should\s+be\s+([A-Za-z0-9][^.;,]+?)(?=\.|;|$)'
    )
    foreach ($pattern in $browserPatterns) {
        foreach ($m in [regex]::Matches($flat, $pattern)) {
            $name = $m.Groups[1].Value.Trim()
            $name = $name -replace '(?i)\s+(?:for|on|across|to)\s+all\s+users.*$', ''
            $name = $name.Trim(' ', ',', ';', ':', '.')
            if ($name) { Add-UniqueSoftwareRequirement -List $software -Name $name -Type Browser -UpdateRequired $true -Source 'README default browser requirement' }
        }
    }

    $softwarePatterns = @(
        '(?i)(?:other\s+)?business(?:\s+related)?\s+software\s+(?:includes?|are|is)\s+(.+?)(?:\.|;)\s*(?:these|they)\s+should\s+remain\s+installed(?:\s+and\s+kept\s+up[- ]to[- ]date)?',
        '(?i)(?:software|applications?)\s+(?:include|includes)\s+(.+?)(?:\.|;)\s*(?:these|they)\s+should\s+remain\s+installed(?:\s+and\s+kept\s+up[- ]to[- ]date)?'
    )
    foreach ($pattern in $softwarePatterns) {
        foreach ($m in [regex]::Matches($flat, $pattern)) {
            $update = $m.Value -match '(?i)up[- ]to[- ]date|updated|latest\s+stable'
            foreach ($item in Split-SoftwareRequirementList -ListText $m.Groups[1].Value) {
                Add-UniqueSoftwareRequirement -List $software -Name $item -Type Software -UpdateRequired $update -Source 'README business/software requirement'
            }
        }
    }

    $serverPatterns = @(
        '(?i)\b(?:uses|runs)\s+(?:an?|the)\s+([^.;]+?)\s+web\s+server\b',
        '(?i)\b(?:web|application)\s+server\s+is\s+([^.;]+?)\b'
    )
    foreach ($pattern in $serverPatterns) {
        foreach ($m in [regex]::Matches($flat, $pattern)) {
            $serverName = $m.Groups[1].Value.Trim()
            $serverName = $serverName -replace '(?i)\s+(?:and|that|which)\s+.+$', ''
            $update = $m.Value -match '(?i)up[- ]to[- ]date|latest|updated'
            Add-UniqueSoftwareRequirement -List $software -Name $serverName -Type Software -UpdateRequired $update -Source 'README web-server requirement'
        }
    }

    $sectionHeaders = @(
        '(?i)^Required\s+(?:Software|Applications):(?:\s*(.*))?$',
        '(?i)^Business\s+(?:Critical\s+)?Software:(?:\s*(.*))?$',
        '(?i)^Required\s+Business\s+Software:(?:\s*(.*))?$',
        '(?i)^Business\s+Applications:(?:\s*(.*))?$',
        '(?i)^Business\s+Software:(?:\s*(.*))?$'
    )
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $matched = $false
        $inlineText = ''
        foreach ($hdr in $sectionHeaders) {
            $hm = [regex]::Match($lines[$i], $hdr)
            if ($hm.Success) { $matched = $true; $inlineText = [string]$hm.Groups[1].Value; break }
        }
        if (-not $matched) { continue }

        $block = New-Object System.Collections.ArrayList
        if ($inlineText) { $null = $block.Add($inlineText) }
        for ($j = $i + 1; $j -lt $lines.Count; $j++) {
            if ($lines[$j] -match '(?i)^(Critical Services:|Authorized Administrators:|Authorized Users:|Competition Guidelines|ANSWER KEY|REMINDERS)\s*$') { break }
            if ($lines[$j] -match '^#{1,6}\s+' -or $lines[$j] -match '^[A-Za-z][A-Za-z0-9 &/()_-]{0,100}:\s*$') { break }
            $null = $block.Add($lines[$j])
        }
        $blockText = ($block -join ' ') -replace '\s+', ' '
        if (-not $blockText) { continue }
        $update = $blockText -match '(?i)up[- ]to[- ]date|updated|latest\s+stable'
        foreach ($item in Split-SoftwareRequirementList -ListText $blockText) {
            Add-UniqueSoftwareRequirement -List $software -Name $item -Type Software -UpdateRequired $update -Source 'README explicit software section'
        }
    }

    $criticalIndex = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '(?i)^Critical Services:\s*(.*)$') { $criticalIndex = $i; break }
    }
    if ($criticalIndex -ge 0) {
        $cm = [regex]::Match($lines[$criticalIndex], '(?i)^Critical Services:\s*(.*)$')
        $first = [string]$cm.Groups[1].Value
        if ($first -and $first -notmatch '^(?i:none|n/a)$') {
            foreach ($item in Split-SoftwareRequirementList -ListText $first) {
                if ($item -and $item -notmatch '^(?i:none|n/a)$') { $null = $services.Add($item) }
            }
        }
        for ($i = $criticalIndex + 1; $i -lt $lines.Count; $i++) {
            $raw = $lines[$i]
            if ($raw -match '(?i)^(Authorized Administrators:|Authorized Users:|Competition Guidelines|ANSWER KEY|REMINDERS)\s*$') { break }
            if ($raw -match '^#{1,6}\s+' -or $raw -match '^[A-Za-z][A-Za-z0-9 &/()_-]{0,100}:\s*$') { break }
            $line = ($raw -replace '^[-*]\s*', '').Trim()
            if (-not $line -or $line -match '^(?i:none|n/a)$') { continue }
            foreach ($item in Split-SoftwareRequirementList -ListText $line) {
                $svc = $item.Trim()
                if ($svc -and $svc -notmatch '^(?i:none|n/a)$' -and -not ($services | Where-Object { $_ -ieq $svc })) { $null = $services.Add($svc) }
            }
        }
    }

    [pscustomobject]@{
        Software = @($software)
        Services = @($services | Sort-Object -Unique)
        ScenarioRemovals = @()
    }
}

function Resolve-WingetPackageId {
    param([Parameter(Mandatory)][string]$Name)

    $key = Normalize-RequirementName -Name $Name
    if ($SoftwareCatalog.ContainsKey($key) -and $SoftwareCatalog[$key].Winget) {
        return [string]$SoftwareCatalog[$key].Winget
    }

    $output = @(& winget.exe search --name $Name --source winget --count 20 --accept-source-agreements --disable-interactivity 2>&1)
    $rc = $LASTEXITCODE
    if ($rc -ne 0) { throw "WinGet search failed for '$Name' (exit code $rc)." }

    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($line in $output) {
        $t = [string]$line
        if ($t -match '^\s*-{3,}\s*$' -or $t -match '^\s*(Name|Id|Version|Source)\b') { continue }
        $fields = @($t -split '\s{2,}' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        if ($fields.Count -ge 2 -and [string]::Equals($fields[0], $Name, [StringComparison]::OrdinalIgnoreCase) -and $fields[$fields.Count - 1] -ieq 'winget') {
            $candidates.Add($fields[1])
        }
    }

    $unique = @($candidates | Sort-Object -Unique)
    if ($unique.Count -eq 1) { return [string]$unique[0] }
    if ($unique.Count -gt 1) { throw "WinGet found multiple exact display-name matches for '$Name': $($unique -join ', '). Refusing to guess." }
    throw "WinGet could not resolve '$Name' to one exact package in the winget source."
}

function Ensure-Chocolatey {
    $cmd = Get-Command choco.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    if ($DryRun) {
        Write-Log 'DRY RUN: would bootstrap Chocolatey because WinGet is unavailable and README software/browser provisioning requires a package provider.' 'CHANGE'
        return $null
    }

    Write-Log 'WinGet is unavailable; bootstrapping Chocolatey from its latest official release for README software/browser provisioning.' 'CHANGE'
    $release = Invoke-RestMethod -Uri $ChocolateyReleaseApi -UseBasicParsing
    $msiAsset = @($release.assets | Where-Object { $_.name -match '(?i)\.msi$' } | Select-Object -First 1)
    if ($null -eq $msiAsset -or [string]::IsNullOrWhiteSpace([string]$msiAsset.browser_download_url)) {
        throw 'Could not locate a Chocolatey CLI MSI in the latest release.'
    }

    $msi = Join-Path $TempRoot ('chocolatey-' + ($msiAsset.name -replace '[^A-Za-z0-9._-]','_'))
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $msiAsset.browser_download_url -OutFile $msi -UseBasicParsing -MaximumRedirection 5
    if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { throw 'Chocolatey MSI download failed.' }

    $proc = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i', $msi, '/qn', '/norestart') -Wait -PassThru -WindowStyle Hidden
    if ($proc.ExitCode -notin @(0,3010)) { throw "Chocolatey MSI installation failed with exit code $($proc.ExitCode)." }

    $env:Path = "$env:ALLUSERSPROFILE\chocolatey\bin;$env:Path"
    $cmd = Get-Command choco.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { throw 'Chocolatey installation finished but choco.exe was not found on PATH.' }
    Write-Log "Chocolatey is available at $($cmd.Source)."
    return $cmd.Source
}

function Resolve-ChocolateyPackageId {
    param([Parameter(Mandatory)][string]$Name)

    $key = Normalize-RequirementName -Name $Name
    if ($SoftwareCatalog.ContainsKey($key) -and $SoftwareCatalog[$key].Choco) {
        return [string]$SoftwareCatalog[$key].Choco
    }

    $output = @(& choco.exe search $Name --exact --limit-output --source="$ChocolateySource" 2>&1)
    $rc = $LASTEXITCODE
    if ($rc -ne 0) { throw "Chocolatey search failed for '$Name' (exit code $rc)." }

    $matches = New-Object System.Collections.Generic.List[string]
    foreach ($line in $output) {
        $t = [string]$line
        if ($t -match '^\s*([^|\s]+)\|[^|]+\s*$') { $matches.Add($Matches[1]) }
    }
    $unique = @($matches | Sort-Object -Unique)
    if ($unique.Count -eq 1) { return [string]$unique[0] }
    if ($unique.Count -gt 1) { throw "Chocolatey found multiple exact package matches for '$Name': $($unique -join ', '). Refusing to guess." }
    throw "Chocolatey could not resolve '$Name' to one exact package."
}

function Get-InstalledApplication {
    param([Parameter(Mandatory)][string]$DisplayName)

    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $results = New-Object System.Collections.ArrayList
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            try { $app = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop } catch { continue }
            $displayProp = $app.PSObject.Properties['DisplayName']
            if ($null -eq $displayProp) { continue }
            $display = [string]$displayProp.Value
            if ([string]::IsNullOrWhiteSpace($display)) { continue }
            if (-not ($display -ieq $DisplayName -or $display -like "$DisplayName *")) { continue }
            $versionProp = $app.PSObject.Properties['DisplayVersion']
            $quietProp = $app.PSObject.Properties['QuietUninstallString']
            $uninstallProp = $app.PSObject.Properties['UninstallString']
            $null = $results.Add([pscustomobject]@{
                DisplayName          = $display
                DisplayVersion       = if ($null -ne $versionProp) { [string]$versionProp.Value } else { '' }
                QuietUninstallString = if ($null -ne $quietProp) { [string]$quietProp.Value } else { '' }
                UninstallString      = if ($null -ne $uninstallProp) { [string]$uninstallProp.Value } else { '' }
            })
        }
    }
    return @($results)
}

function Get-ChromeVersionFast {
    $paths = @(
        (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe')
    )
    $versions = New-Object System.Collections.ArrayList
    foreach ($path in $paths) {
        if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        try { $null = $versions.Add([version](Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo.ProductVersion) } catch {}
    }
    if ($versions.Count -eq 0) { return $null }
    return ($versions | Sort-Object -Descending | Select-Object -First 1)
}

function Invoke-GoogleUpdateTasks {
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'GoogleUpdateTask*' })
    foreach ($task in $tasks) { try { Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop } catch {} }
    if ($tasks.Count -gt 0) { Start-Sleep -Seconds 6 }
}

function Install-Or-Update-GoogleChromeOfficial {
    $url = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
    $msiPath = Join-Path $TempRoot 'googlechromestandaloneenterprise64.msi'
    $before = Get-ChromeVersionFast
    Write-Log 'Using the official Google Chrome Enterprise 64-bit MSI because the package provider is unavailable or failed.' 'CHANGE'
    if ($before) { Write-Log "Detected installed Google Chrome version: $before" }
    Write-Log "Downloading Chrome from $url"
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing -MaximumRedirection 5
    if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf) -or (Get-Item -LiteralPath $msiPath).Length -le 0) { throw 'Google Chrome MSI download failed or was empty.' }
    $sig = Get-AuthenticodeSignature -FilePath $msiPath
    if ($sig.Status -ne 'Valid') { throw "Google Chrome MSI signature validation failed: $($sig.Status)." }
    $subject = [string]$sig.SignerCertificate.Subject
    if ($subject -notmatch '(?i)Google') { throw "Google Chrome MSI signer did not identify Google: $subject" }
    Write-Log 'Google Chrome MSI signature validated.'
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', "`"$msiPath`"", '/qn', '/norestart') -Wait -PassThru -WindowStyle Hidden
    if ($proc.ExitCode -notin @(0,1638,3010)) { throw "Google Chrome MSI installation failed with exit code $($proc.ExitCode)." }
    Start-Sleep -Seconds 2
    $after = Get-ChromeVersionFast
    if ($before -and $after -le $before) { Invoke-GoogleUpdateTasks; $after = Get-ChromeVersionFast }
    if ($after) {
        if ($before -and $after -gt $before) { Write-Log "Google Chrome updated: $before -> $after" 'CHANGE' }
        elseif ($before -and $after -eq $before) { Write-Log "Google Chrome remains at version $after after official MSI/update-task verification." 'INFO' }
        else { Write-Log "Google Chrome installed at version $after." 'CHANGE' }
    }
    return $after
}

function Invoke-MsiUninstall {
    param([Parameter(Mandatory)][string]$UninstallString)
    $m = [regex]::Match($UninstallString, '(?i)\{[0-9a-f-]+\}')
    if (-not $m.Success) { throw "Could not determine MSI product code from uninstall string: $UninstallString" }
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/x',$m.Value,'/qn','/norestart') -Wait -PassThru -WindowStyle Hidden
    if ($proc.ExitCode -notin @(0,1605,3010,1641)) { throw "MSI uninstall failed with exit code $($proc.ExitCode)." }
}

function Invoke-RegisteredUninstall {
    param([Parameter(Mandatory)][string]$UninstallCommand)
    $cmd = $UninstallCommand.Trim()
    if ([string]::IsNullOrWhiteSpace($cmd)) { throw 'No registered uninstall command was available.' }
    if ($cmd.StartsWith('"')) { $m = [regex]::Match($cmd, '^"([^"]+)"\s*(.*)$') } else { $m = [regex]::Match($cmd, '^([^\s]+)\s*(.*)$') }
    if (-not $m.Success) { throw "Could not parse registered uninstall command: $UninstallCommand" }
    $exe = $m.Groups[1].Value
    $args = $m.Groups[2].Value
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Registered uninstaller was not found: $exe" }
    Write-Log "Running the registered uninstaller: $UninstallCommand" 'CHANGE'
    $argList = if ([string]::IsNullOrWhiteSpace($args)) { @() } else { @($args) }
    $proc = Start-Process -FilePath $exe -ArgumentList $argList -Wait -PassThru
    if ($proc.ExitCode -notin @(0,3010,1641)) { throw "Registered uninstaller failed with exit code $($proc.ExitCode)." }
}

function Update-WiresharkWithReplacement {
    param([Parameter(Mandatory)][string]$PackageId)
    $apps = @(Get-InstalledApplication -DisplayName 'Wireshark')
    $localChoco = @(& choco.exe list --local-only --exact $PackageId --limit-output 2>&1)
    $managed = ($LASTEXITCODE -eq 0 -and ($localChoco -join "`n") -match "(?i)^$([regex]::Escape($PackageId))\|")
    if ($managed) {
        Write-Log 'Wireshark is Chocolatey-managed. Uninstalling the existing Chocolatey package before reinstalling the current package.' 'CHANGE'
        $out = @(& choco.exe uninstall $PackageId -y --no-progress 2>&1); $rc=$LASTEXITCODE
        if ($rc -ne 0) { throw "Chocolatey Wireshark uninstall failed with exit code $rc: $($out -join ' ')" }
    } elseif ($apps.Count -gt 0) {
        $app=$apps[0]; $uninstall=[string]$app.QuietUninstallString
        if ([string]::IsNullOrWhiteSpace($uninstall)) { $uninstall=[string]$app.UninstallString }
        if ([string]::IsNullOrWhiteSpace($uninstall)) { throw 'Wireshark is installed, but no registered uninstaller command was found.' }
        Write-Log "Removing existing Wireshark $($app.DisplayVersion) before the requested update." 'CHANGE'
        if ($uninstall -match '(?i)msiexec(?:\.exe)?') { Invoke-MsiUninstall -UninstallString $uninstall } else { Invoke-RegisteredUninstall -UninstallCommand $uninstall }
        Start-Sleep -Seconds 2
        if (@(Get-InstalledApplication -DisplayName 'Wireshark').Count -gt 0) { throw 'Wireshark still appears installed after its registered uninstaller completed.' }
    }
    $out=@(& choco.exe install $PackageId -y --no-progress --source="$ChocolateySource" 2>&1); $rc=$LASTEXITCODE
    if ($rc -ne 0) { throw "Chocolatey Wireshark install failed with exit code $rc: $($out -join ' ')" }
    Write-Log 'Wireshark installed/updated successfully after a clean replacement.' 'CHANGE'
}

function Invoke-SoftwareProvisioning {
    param([Parameter(Mandatory)][object]$Requirement)
    $name=[string]$Requirement.Name
    $key=Normalize-RequirementName -Name $name
    $action=if($Requirement.UpdateRequired){'INSTALL_OR_UPDATE'}else{'ENSURE_INSTALLED'}
    if($DryRun){ Write-Log "DRY RUN: would $action '$name'." 'CHANGE'; $script:SoftwareResults.Add([pscustomobject]@{Name=$name;Type=$Requirement.Type;RequiredAction=$action;Provider='AUTO';PackageId='';Result='WOULD CHANGE';Detail=$Requirement.Source}); return }

    # Chrome gets the same official-MSI fallback that works in the GUI, rather than
    # relying on Chocolatey's external package checksum metadata.
    if($key -in @('chrome','googlechrome')){
        $winget=Get-Command winget.exe -ErrorAction SilentlyContinue
        if($null -ne $winget){
            try{
                $packageId=[string]$SoftwareCatalog['googlechrome'].Winget
                $list=@(& $winget.Source list --id $packageId --exact --source winget --accept-source-agreements --disable-interactivity 2>&1)
                $installed=($LASTEXITCODE -eq 0 -and (($list -join "`n") -notmatch '(?i)No installed package found'))
                if($installed){
                    $out=@(& $winget.Source upgrade --id $packageId --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1); $rc=$LASTEXITCODE
                    if($rc -in @(0,1)){ $script:SoftwareResults.Add([pscustomobject]@{Name=$name;Type=$Requirement.Type;RequiredAction=$action;Provider='WinGet';PackageId=$packageId;Result='SUCCESS';Detail='WinGet upgrade completed or reported no applicable upgrade'}); return }
                    throw "WinGet Chrome upgrade failed with exit code $rc: $($out -join ' ')"
                } else {
                    $out=@(& $winget.Source install --id $packageId --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1); $rc=$LASTEXITCODE
                    if($rc -eq 0){ $script:SoftwareResults.Add([pscustomobject]@{Name=$name;Type=$Requirement.Type;RequiredAction=$action;Provider='WinGet';PackageId=$packageId;Result='SUCCESS';Detail='Chrome installed via WinGet'}); return }
                    throw "WinGet Chrome install failed with exit code $rc: $($out -join ' ')"
                }
            } catch { Write-Log "WinGet Chrome operation failed; using the official Google MSI fallback. $($_.Exception.Message)" 'WARN' }
        }
        try{
            $after=Install-Or-Update-GoogleChromeOfficial
            $script:SoftwareResults.Add([pscustomobject]@{Name=$name;Type=$Requirement.Type;RequiredAction=$action;Provider='Official Google MSI';PackageId='googlechromestandaloneenterprise64.msi';Result='SUCCESS';Detail=if($after){"Detected Chrome version $after after installation/update"}else{'MSI completed; executable version could not be detected'}})
        } catch {
            Write-Log "Could not satisfy software/browser requirement '$name': $($_.Exception.Message)" 'ERROR'
            $script:SoftwareResults.Add([pscustomobject]@{Name=$name;Type=$Requirement.Type;RequiredAction=$action;Provider='Official Google MSI';PackageId='googlechromestandaloneenterprise64.msi';Result='FAILED';Detail=$_.Exception.Message})
        }
        return
    }

    try{
        $winget=Get-Command winget.exe -ErrorAction SilentlyContinue
        if($null -ne $winget){
            try{
                $packageId=Resolve-WingetPackageId -Name $name
                $list=@(& $winget.Source list --id $packageId --exact --source winget --accept-source-agreements --disable-interactivity 2>&1)
                $installed=($LASTEXITCODE -eq 0 -and (($list -join "`n") -notmatch '(?i)No installed package found'))
                if($installed -and $Requirement.UpdateRequired){
                    $out=@(& $winget.Source upgrade --id $packageId --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1); $rc=$LASTEXITCODE
                    if($rc -notin @(0,1)){throw "WinGet upgrade failed with exit code ${rc}: $($out -join ' ')"}
                }elseif(-not $installed){
                    $out=@(& $winget.Source install --id $packageId --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1); $rc=$LASTEXITCODE
                    if($rc -ne 0){throw "WinGet install failed with exit code ${rc}: $($out -join ' ')"}
                }
                $script:SoftwareResults.Add([pscustomobject]@{Name=$name;Type=$Requirement.Type;RequiredAction=$action;Provider='WinGet';PackageId=$packageId;Result='SUCCESS';Detail='Installed/upgraded or already correct'}); return
            } catch { Write-Log "WinGet operation failed for '$name'; falling back to Chocolatey. $($_.Exception.Message)" 'WARN' }
        }

        $null=Ensure-Chocolatey
        if($key -eq 'notepadplusplus'){$packageId='notepadplusplus'}elseif($SoftwareCatalog.ContainsKey($key)){$packageId=[string]$SoftwareCatalog[$key].Choco}else{$packageId=Resolve-ChocolateyPackageId -Name $name}

        if(-not $Requirement.UpdateRequired -and ($key -in @('apache','apachehttpd','apachehttpserver'))){
            $installedApache=@(Get-InstalledApplication -DisplayName 'Apache HTTP Server')
            if($installedApache.Count -gt 0){ $script:SoftwareResults.Add([pscustomobject]@{Name=$name;Type=$Requirement.Type;RequiredAction=$action;Provider='Windows';PackageId=$packageId;Result='ALREADY CORRECT';Detail='Apache is installed; README requires presence only'}); Write-Log "'$name' is already installed; README only requires presence." 'INFO'; return }
            $out=@(& choco.exe install $packageId -y --no-progress --source="$ChocolateySource" 2>&1); $rc=$LASTEXITCODE
            if($rc -ne 0){throw "Chocolatey install failed with exit code ${rc}: $($out -join ' ')"}
        } elseif($key -eq 'wireshark' -and $Requirement.UpdateRequired){
            Update-WiresharkWithReplacement -PackageId $packageId
        } elseif($Requirement.UpdateRequired){
            Write-Log "Installing/updating '$name' with Chocolatey package '$packageId'." 'CHANGE'
            $out=@(& choco.exe upgrade $packageId -y --no-progress --source="$ChocolateySource" 2>&1); $rc=$LASTEXITCODE
            if($rc -ne 0){throw "Chocolatey provisioning failed with exit code ${rc}: $($out -join ' ')"}
        } else {
            $installed=@(Get-InstalledApplication -DisplayName $name)
            if($installed.Count -gt 0){ $script:SoftwareResults.Add([pscustomobject]@{Name=$name;Type=$Requirement.Type;RequiredAction=$action;Provider='Windows';PackageId=$packageId;Result='ALREADY CORRECT';Detail='Installed; README requires presence only'}); return }
            $out=@(& choco.exe install $packageId -y --no-progress --source="$ChocolateySource" 2>&1); $rc=$LASTEXITCODE
            if($rc -ne 0){throw "Chocolatey install failed with exit code ${rc}: $($out -join ' ')"}
        }
        $script:SoftwareResults.Add([pscustomobject]@{Name=$name;Type=$Requirement.Type;RequiredAction=$action;Provider='Chocolatey';PackageId=$packageId;Result='SUCCESS';Detail='Package installed or upgraded'})
    } catch {
        Write-Log "Could not satisfy software/browser requirement '$name': $($_.Exception.Message)" 'ERROR'
        $script:SoftwareResults.Add([pscustomobject]@{Name=$name;Type=$Requirement.Type;RequiredAction=$action;Provider='AUTO';PackageId='';Result='FAILED';Detail=$_.Exception.Message})
    }
}

function Set-DefaultBrowserForAllUsers {
    param([Parameter(Mandatory)][string]$BrowserName)

    # Windows-supported route: build a minimal DefaultAssociations XML from
    # the installed browser's registered capabilities, then import it with DISM.
    # DISM applies these defaults to users at first logon; it does not forcibly
    # rewrite the protected per-user UserChoice values of a currently logged-in user.
    $registeredRoots = @(
        'HKLM:\SOFTWARE\RegisteredApplications',
        'HKLM:\SOFTWARE\WOW6432Node\RegisteredApplications'
    )

    $candidate = $null
    foreach ($root in $registeredRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $props = Get-ItemProperty -LiteralPath $root -ErrorAction SilentlyContinue
        if ($null -eq $props) { continue }
        foreach ($prop in $props.PSObject.Properties) {
            $capPath = [string]$prop.Value
            if ([string]::IsNullOrWhiteSpace($capPath)) { continue }
            $capReg = "HKLM:\$capPath"
            $appName = [string]$prop.Name
            if ($appName -notmatch [regex]::Escape($BrowserName)) {
                $appNameValue = $null
                try { $appNameValue = [string](Get-ItemProperty -LiteralPath $capReg -Name ApplicationName -ErrorAction Stop).ApplicationName } catch {}
                if ([string]::IsNullOrWhiteSpace($appNameValue) -or $appNameValue -notmatch [regex]::Escape($BrowserName)) { continue }
                $appName = $appNameValue
            }
            $urlKey = "$capReg\URLAssociations"
            $fileKey = "$capReg\FileAssociations"
            if ((Test-Path -LiteralPath $urlKey) -or (Test-Path -LiteralPath $fileKey)) {
                $candidate = [pscustomobject]@{ Name=$appName; Capabilities=$capReg; UrlKey=$urlKey; FileKey=$fileKey }
                break
            }
        }
        if ($candidate) { break }
    }

    if ($null -eq $candidate) {
        throw "Could not locate registered default-app capabilities for browser '$BrowserName'."
    }

    $associations = New-Object System.Collections.Generic.List[string]
    foreach ($kind in @(
        [pscustomobject]@{ Key=$candidate.UrlKey; Ids=@('http','https') },
        [pscustomobject]@{ Key=$candidate.FileKey; Ids=@('.htm','.html') }
    )) {
        if (-not (Test-Path -LiteralPath $kind.Key)) { continue }
        $pobj = Get-ItemProperty -LiteralPath $kind.Key -ErrorAction Stop
        foreach ($id in $kind.Ids) {
            $progId = $null
            try { $progId = [string]$pobj.$id } catch {}
            if (-not [string]::IsNullOrWhiteSpace($progId)) {
                $xmlId = [System.Security.SecurityElement]::Escape($id)
                $xmlProg = [System.Security.SecurityElement]::Escape($progId)
                $xmlApp = [System.Security.SecurityElement]::Escape($candidate.Name)
                $associations.Add(('  <Association Identifier="{0}" ProgId="{1}" ApplicationName="{2}" />' -f $xmlId, $xmlProg, $xmlApp))
            }
        }
    }

    if ($associations.Count -eq 0) {
        throw "Browser '$BrowserName' is installed but exposes no usable HTTP/HTTPS/HTML default associations."
    }

    $xmlPath = Join-Path $TempRoot ('DefaultBrowser-' + (Normalize-RequirementName -Name $BrowserName) + '.xml')
    $xml = @('<?xml version="1.0" encoding="UTF-8"?>','<DefaultAssociations>') + @($associations) + @('</DefaultAssociations>')
    Set-Content -LiteralPath $xmlPath -Value $xml -Encoding UTF8

    if ($DryRun) {
        Write-Log "DRY RUN: would import $BrowserName as the device default for web associations using DISM. Existing current-user UserChoice values are not forcibly rewritten." 'CHANGE'
        return
    }

    & "$env:SystemRoot\System32\Dism.exe" /Online "/Import-DefaultAppAssociations:$xmlPath" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "DISM failed to import the default browser associations (exit code $LASTEXITCODE)."
    }
    Write-Log "Configured '$BrowserName' as the device default browser association set for future user sign-ins." 'CHANGE'
}

function Ensure-DefaultBrowserRequirements {
    param([Parameter(Mandatory)][object[]]$BrowserRequirements)

    foreach ($req in $BrowserRequirements) {
        try {
            Set-DefaultBrowserForAllUsers -BrowserName $req.Name
            $script:SoftwareResults.Add([pscustomobject]@{Name=$req.Name; Type='Browser'; RequiredAction='SET_DEFAULT'; Provider='DISM'; PackageId=''; Result=if ($DryRun) {'WOULD CHANGE'} else {'SUCCESS'}; Detail='HTTP/HTTPS/.htm/.html default association set for future user sign-ins'})
        }
        catch {
            Write-Log "Could not configure '$($req.Name)' as the default browser: $($_.Exception.Message)" 'ERROR'
            $script:SoftwareResults.Add([pscustomobject]@{Name=$req.Name; Type='Browser'; RequiredAction='SET_DEFAULT'; Provider='DISM'; PackageId=''; Result='FAILED'; Detail=$_.Exception.Message})
        }
    }
}

function Restore-ProtectedServices {
    param([Parameter(Mandatory)][object]$ParsedUsers)
    foreach ($requested in @($ParsedUsers.ProtectedServices)) {
        if ([string]::IsNullOrWhiteSpace([string]$requested)) { continue }
        try {
            $service = Resolve-CriticalService -RequestedName ([string]$requested)
            $cim = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f ($service.Name.Replace("'","''"))) -ErrorAction Stop
            if ($cim.StartMode -eq 'Disabled') {
                if ($DryRun) {
                    Write-Log "DRY RUN: would restore explicitly protected service '$requested' from Disabled to Automatic." 'CHANGE'
                    continue
                }
                Set-Service -Name $service.Name -StartupType Automatic -ErrorAction Stop
                Write-Log "Restored explicitly protected service '$requested' startup from Disabled to Automatic." 'CHANGE'
                Start-Service -Name $service.Name -ErrorAction Stop
                Write-Log "Started explicitly protected service '$requested'." 'CHANGE'
            }
            else {
                Write-Log "Explicitly protected service '$requested' is not disabled; no service-state change was needed." 'INFO'
            }
        }
        catch {
            Write-Log "Could not verify explicitly protected service '$requested': $($_.Exception.Message). Manual review required; no unrelated service was changed." 'WARN'
        }
    }
}

function Resolve-CriticalService {
    param([Parameter(Mandatory)][string]$RequestedName)

    $name = $RequestedName.Trim()
    $service = @(Get-Service -Name $name -ErrorAction SilentlyContinue)
    if ($service.Count -eq 1) { return $service[0] }
    $service = @(Get-Service -DisplayName $name -ErrorAction SilentlyContinue)
    if ($service.Count -eq 1) { return $service[0] }

    $normalized = Normalize-RequirementName -Name $name
    $matches = @(Get-Service -ErrorAction Stop | Where-Object {
        (Normalize-RequirementName -Name $_.Name) -eq $normalized -or
        (Normalize-RequirementName -Name $_.DisplayName) -eq $normalized
    })
    if ($matches.Count -eq 1) { return $matches[0] }
    if ($matches.Count -gt 1) { throw "Critical service '$RequestedName' matched multiple services; refusing to guess: $($matches.Name -join ', ')" }
    throw "Critical service '$RequestedName' was not found."
}

function Ensure-CriticalServices {
    param([Parameter(Mandatory)][string[]]$ServiceNames)

    foreach ($requested in $ServiceNames) {
        if ([string]::IsNullOrWhiteSpace($requested)) { continue }
        try {
            $service = Resolve-CriticalService -RequestedName $requested
            $cim = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f ($service.Name.Replace("'","''"))) -ErrorAction Stop

            if ($service.Status -eq 'Running') {
                $script:ServiceResults.Add([pscustomobject]@{Requested=$requested; ServiceName=$service.Name; DisplayName=$service.DisplayName; Result='ALREADY RUNNING'; Detail="StartMode=$($cim.StartMode)"})
                Write-Log "Critical service '$requested' is already running as '$($service.Name)'."
                continue
            }

            if ($cim.StartMode -eq 'Disabled') {
                if ($DryRun) {
                    Write-Log "DRY RUN: would change critical service '$requested' ($($service.Name)) from Disabled to Automatic and start it." 'CHANGE'
                    $script:ServiceResults.Add([pscustomobject]@{Requested=$requested; ServiceName=$service.Name; DisplayName=$service.DisplayName; Result='WOULD CHANGE'; Detail='Disabled -> Automatic -> Start'})
                    continue
                }
                Set-Service -Name $service.Name -StartupType Automatic -ErrorAction Stop
                Write-Log "Enabled startup for critical service '$requested' ($($service.Name))." 'CHANGE'
            }

            if ($DryRun) {
                Write-Log "DRY RUN: would start critical service '$requested' ($($service.Name))." 'CHANGE'
                $script:ServiceResults.Add([pscustomobject]@{Requested=$requested; ServiceName=$service.Name; DisplayName=$service.DisplayName; Result='WOULD CHANGE'; Detail='Start service'})
                continue
            }

            Start-Service -Name $service.Name -ErrorAction Stop
            $after = Get-Service -Name $service.Name -ErrorAction Stop
            if ($after.Status -ne 'Running') { throw 'Service did not reach the Running state.' }
            $script:ServiceResults.Add([pscustomobject]@{Requested=$requested; ServiceName=$service.Name; DisplayName=$service.DisplayName; Result='SUCCESS'; Detail="Running; prior StartMode=$($cim.StartMode)"})
            Write-Log "Started critical service '$requested' ($($service.Name))." 'CHANGE'
        }
        catch {
            Write-Log "Could not satisfy critical service '$requested': $($_.Exception.Message)" 'ERROR'
            $script:ServiceResults.Add([pscustomobject]@{Requested=$requested; ServiceName=''; DisplayName=''; Result='FAILED'; Detail=$_.Exception.Message})
        }
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
        Write-Log "'$Name': PasswordNeverExpires=OFF; PasswordRequired=ON; UserMayChangePassword=OFF. MustChangeAtNextLogon remains ON because the existing password is already expired; the script does not change passwords solely because they are expired." 'INFO'
    }
    else {
        Write-Log "'$Name': PasswordNeverExpires=OFF; PasswordRequired=ON; UserMayChangePassword=OFF; MustChangeAtNextLogon=OFF." 'CHANGE'
    }
}

function Set-WeakReadmePasswordState {
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$TemporarilyRemoveFromAdministrators
    )

    $flags = Get-NetUserFlagsFast -Name $Name
    $target = $flags
    $target = $target -band (-bnot $UF_DONT_EXPIRE_PASSWD) # Password never expires = OFF
    $target = $target -band (-bnot $UF_PASSWD_NOTREQD)     # Password required = ON
    $target = $target -band (-bnot $UF_PASSWD_CANT_CHANGE)  # User may change = ON
    $target = $target -bor  $UF_PASSWORD_EXPIRED           # Must change at next logon = ON

    if ($DryRun) {
        Write-Log "DRY RUN: would set '$Name': PasswordNeverExpires=OFF; PasswordRequired=ON; UserMayChangePassword=ON; MustChangeAtNextLogon=ON because the README password is weak." 'CHANGE'
        return
    }

    if ($target -eq $flags) {
        Write-Log "'$Name': weak README password response already matches target; no native write needed." 'INFO'
        return
    }

    $removedFromAdmins = $false
    try {
        # Match the same Windows behavior handling used by the baseline path:
        # temporarily remove a local administrator when we need to clear
        # UF_PASSWD_CANT_CHANGE, then restore the group membership.
        if ($TemporarilyRemoveFromAdministrators -and (($flags -band $UF_PASSWD_CANT_CHANGE) -ne 0)) {
            Remove-LocalGroupMember -Group 'Administrators' -Member "$env:COMPUTERNAME\$Name" -ErrorAction Stop
            $removedFromAdmins = $true
            Write-Log "Temporarily removed authorized administrator '$Name' from Administrators to enable password change because the README password is weak." 'INFO'
        }

        Set-NetUserFlagsFast -Name $Name -Flags $target
    }
    catch {
        $originalError = $_.Exception.Message
        if ($removedFromAdmins) {
            try {
                Add-LocalGroupMember -Group 'Administrators' -Member "$env:COMPUTERNAME\$Name" -ErrorAction Stop
                Write-Log "Restored administrator '$Name' after the weak-README password-flag change failed." 'INFO'
            }
            catch {
                Write-Log "Could not restore '$Name' to Administrators after the weak-README password-flag failure: $($_.Exception.Message)" 'ERROR'
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
            throw "Weak README password flags were applied to '$Name', but restoring Administrators membership failed: $($_.Exception.Message)"
        }
    }

    Write-Log "'$Name': UserMayChangePassword=ON; MustChangeAtNextLogon=ON because the README password is weak. The current VM password was NOT read or tested." 'CHANGE'
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

function New-RandomPasswordString {
    param([int]$Length=28)
    $chars='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=?'
    $bytes=New-Object byte[] $Length
    $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
    try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
    $sb=New-Object System.Text.StringBuilder
    foreach($b in $bytes){[void]$sb.Append($chars[[int]$b % $chars.Length])}
    $sb.ToString()
}

function Ensure-CurrentUserAdministrator {
    param(
        [Parameter(Mandatory)][string]$CurrentUser,
        [Parameter(Mandatory)][object]$ParsedUsers,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$AdminSids
    )
    $isReadmeAdmin = [bool]($ParsedUsers.Administrators | Where-Object { $_ -ieq $CurrentUser })
    if (-not $isReadmeAdmin) {
        throw "Safety stop: currently logged-in account '$CurrentUser' is not listed under Authorized Administrators in the README."
    }
    $user = Get-LocalUser -Name $CurrentUser -ErrorAction Stop
    if ($AdminSids.Contains($user.SID.Value)) { return }
    if ($DryRun) { Write-Log "DRY RUN: would add current authorized account '$CurrentUser' to local Administrators." 'CHANGE'; return }
    Add-LocalGroupMember -Group 'Administrators' -Member "$env:COMPUTERNAME\$CurrentUser" -ErrorAction Stop
    Write-Log "Added current authorized account '$CurrentUser' to the local Administrators group." 'CHANGE'
}

function Ensure-ScenarioRequiredAccounts {
    param([Parameter(Mandatory)][object]$ParsedUsers)
    foreach ($name in @($ParsedUsers.ScenarioAccounts)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $existing = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Write-Log "Scenario-required account '$name' already exists; no password was read or reset." 'INFO'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name;Action='Create scenario-required account';Result='ALREADY CORRECT';Detail='Account already exists'})
            continue
        }
        if ($DryRun) {
            Write-Log "DRY RUN: would create scenario-required local standard user '$name'." 'CHANGE'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name;Action='Create scenario-required account';Result='WOULD CHANGE';Detail='README explicitly requires this new account'})
            continue
        }
        try {
            $generated = New-RandomPasswordString -Length 28
            $secure = ConvertTo-SecureString -String $generated -AsPlainText -Force
            New-LocalUser -Name $name -Password $secure -PasswordNeverExpires:$false -UserMayNotChangePassword:$false -Description 'Created by Harbinger''s Purge because the README explicitly requires this account.' -ErrorAction Stop | Out-Null
            try { Add-LocalGroupMember -Group 'Users' -Member "$env:COMPUTERNAME\$name" -ErrorAction Stop } catch {}
            try { Remove-LocalGroupMember -Group 'Administrators' -Member "$env:COMPUTERNAME\$name" -ErrorAction SilentlyContinue } catch {}
            Write-Log "Created scenario-required local standard user '$name'. A random password was generated and was not written to the report or transcript." 'CHANGE'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name;Action='Create scenario-required account';Result='SUCCESS';Detail='Standard local account created with a generated password'})
        }
        catch {
            Write-Log "Could not create scenario-required account '$name': $($_.Exception.Message)" 'ERROR'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name;Action='Create scenario-required account';Result='FAILED';Detail=$_.Exception.Message})
        }
    }
}

function Invoke-ScenarioAccountActions {
    param([Parameter(Mandatory)][object]$ParsedUsers,[Parameter(Mandatory)][string]$CurrentUser)
    foreach ($item in @($ParsedUsers.ScenarioAccountActions)) {
        if ($item.Action -eq 'CREATE') { continue }
        $name = [string]$item.Name
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($name -ieq $CurrentUser) { Write-Log "Refusing explicit scenario account action '$($item.Action)' against the current logged-in account '$CurrentUser'." 'ERROR'; continue }
        if ($ParsedUsers.AllAuthorized | Where-Object { $_ -ieq $name }) { Write-Log "Refusing explicit removal/disable of authorized account '$name'; authorized accounts are protected." 'WARN'; continue }
        if ($ParsedUsers.ProtectedAccounts | Where-Object { $_ -ieq $name }) { Write-Log "Skipping explicit scenario account action for protected account '$name'." 'WARN'; continue }
        $local = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $local) { Write-Log "Scenario account '$name' is already absent." 'INFO'; continue }
        try {
            if ($item.Action -eq 'DISABLE') { Disable-SpecificLocalAccount -Name $name; continue }
            if ($item.Action -eq 'DELETE') {
                if ($DryRun) {
                    Write-Log "DRY RUN: would delete explicitly named scenario account '$name'." 'CHANGE'
                    $script:AccountActionResults.Add([pscustomobject]@{Account=$name;Action='Delete scenario account';Result='WOULD CHANGE';Detail='Explicit README scenario directive'})
                    continue
                }
                try { Remove-LocalUser -Name $name -ErrorAction Stop }
                catch {
                    $out = & "$env:SystemRoot\System32\net.exe" user $name /delete 2>&1
                    if ($LASTEXITCODE -ne 0) { throw "Could not delete '$name' with Remove-LocalUser or net user: $($out -join ' ')" }
                }
                Write-Log "Deleted explicitly named scenario account '$name'." 'CHANGE'
                $script:AccountActionResults.Add([pscustomobject]@{Account=$name;Action='Delete scenario account';Result='SUCCESS';Detail='Explicit README scenario directive'})
            }
        }
        catch {
            Write-Log "Could not satisfy explicit scenario account action '$($item.Action)' for '$name': $($_.Exception.Message)" 'ERROR'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name;Action="$($item.Action) scenario account";Result='FAILED';Detail=$_.Exception.Message})
        }
    }
}

function Resolve-ScenarioRemovalApplication {
    param([Parameter(Mandatory)][string]$Target)
    $apps = @(Get-InstalledApplication -DisplayName $Target)
    if ($apps.Count -eq 1) { return $apps[0] }
    if ($apps.Count -gt 1) { throw "Scenario removal target '$Target' matched multiple installed applications; refusing to guess." }
    return $null
}

function Invoke-ScenarioRemovals {
    param([Parameter(Mandatory)][object[]]$Items)
    foreach ($item in @($Items)) {
        $target = [string]$item.Target
        if ([string]::IsNullOrWhiteSpace($target)) { continue }
        try {
            if ([IO.Path]::IsPathRooted($target)) {
                if (Test-Path -LiteralPath $target -PathType Leaf) {
                    if ($DryRun) { Write-Log "DRY RUN: would remove explicitly named scenario file '$target'." 'CHANGE' }
                    else { Remove-Item -LiteralPath $target -Force -ErrorAction Stop; Write-Log "Removed explicitly named scenario file '$target'." 'CHANGE' }
                    continue
                }
                if (Test-Path -LiteralPath $target -PathType Container) {
                    if ($DryRun) { Write-Log "DRY RUN: would remove explicitly named scenario directory '$target'." 'CHANGE' }
                    else { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop; Write-Log "Removed explicitly named scenario directory '$target'." 'CHANGE' }
                    continue
                }
            }
            if ($target -match '(?i)\.(?:py|ps1|bat|cmd|vbs|js|jar|exe|dll|zip|msi)$') {
                Write-Log "README explicitly requests removal of file '$target', but no absolute path was supplied; refusing to search/delete by filename. Manual review required." 'WARN'
                continue
            }
            $app = Resolve-ScenarioRemovalApplication -Target $target
            if ($null -eq $app) { Write-Log "Explicit scenario removal target '$target' was not found as an installed application or exact path; no guess was made." 'WARN'; continue }
            $uninstall = [string]$app.QuietUninstallString
            if ([string]::IsNullOrWhiteSpace($uninstall)) { $uninstall = [string]$app.UninstallString }
            if ([string]::IsNullOrWhiteSpace($uninstall)) { throw "No registered uninstaller was found for '$target'." }
            if ($DryRun) { Write-Log "DRY RUN: would uninstall explicitly named scenario application '$target'." 'CHANGE'; continue }
            if ($uninstall -match '(?i)msiexec(?:\.exe)?') { Invoke-MsiUninstall -UninstallString $uninstall } else { Invoke-RegisteredUninstall -UninstallCommand $uninstall }
            Write-Log "Removed explicitly named scenario application '$target'." 'CHANGE'
        }
        catch { Write-Log "Could not satisfy explicit scenario removal '$target': $($_.Exception.Message)" 'ERROR' }
    }
}

function Ensure-AuthorizedAdministrators {
    param(
        [Parameter(Mandatory)][object]$ParsedUsers,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$AdminSids
    )
    foreach ($name in @($ParsedUsers.Administrators)) {
        if ([string]::IsNullOrWhiteSpace([string]$name)) { continue }
        try {
            $user = Get-LocalUser -Name $name -ErrorAction Stop
            if ($AdminSids.Contains($user.SID.Value)) { continue }
            if ($DryRun) {
                Write-Log "DRY RUN: would add authorized administrator '$name' to the local Administrators group." 'CHANGE'
                $script:AccountActionResults.Add([pscustomobject]@{Account=$name;Action='Add to Administrators';Result='WOULD CHANGE';Detail='Listed under Authorized Administrators'})
                continue
            }
            Add-LocalGroupMember -Group 'Administrators' -Member "$env:COMPUTERNAME\$name" -ErrorAction Stop
            Write-Log "Added authorized administrator '$name' to the local Administrators group." 'CHANGE'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name;Action='Add to Administrators';Result='SUCCESS';Detail='Listed under Authorized Administrators'})
        }
        catch {
            Write-Log "Could not ensure authorized administrator '$name' is in Administrators: $($_.Exception.Message)" 'ERROR'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name;Action='Add to Administrators';Result='FAILED';Detail=$_.Exception.Message})
        }
    }
}

function Remove-UnapprovedAdministratorsAndDisableUnlisted {
    param(
        [Parameter(Mandatory)][object]$ParsedUsers,
        [Parameter(Mandatory)][string]$CurrentUser
    )

    $authorizedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ParsedUsers.AllAuthorized) { [void]$authorizedSet.Add($name) }
    foreach ($name in @($ParsedUsers.ScenarioAccounts)) { [void]$authorizedSet.Add($name) }
    foreach ($name in @($ParsedUsers.ProtectedAccounts)) { [void]$authorizedSet.Add($name) }

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
    foreach ($name in @($ParsedUsers.ScenarioAccounts)) { [void]$authorizedSet.Add($name) }

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

    foreach ($name in @($ParsedUsers.ScenarioAccounts)) {
        $key = $name.ToLowerInvariant()
        if (-not $localByName.ContainsKey($key)) {
            $script:AccountResults.Add([pscustomobject]@{Account=$name; Authorized='SCENARIO REQUIRED'; Exists='NO'; Enabled='-'; Administrator='NO'; Status='MISSING'})
            continue
        }
        $u = $localByName[$key]
        $isAdmin = $false
        try { $isAdmin = $adminSids.Contains($u.SID.Value) } catch {}
        $status = if (-not $u.Enabled) { 'DISABLED' } elseif ($isAdmin) { 'SCENARIO ACCOUNT IS ADMIN' } else { 'PASS' }
        $script:AccountResults.Add([pscustomobject]@{Account=$name; Authorized='SCENARIO REQUIRED'; Exists='YES'; Enabled=if($u.Enabled){'YES'}else{'NO'}; Administrator=if($isAdmin){'YES'}else{'NO'}; Status=$status})
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
    foreach ($name in @($ParsedUsers.ScenarioAccounts)) { [void]$authorizedSet.Add($name) }

    # Only process authorized, enabled accounts. Use the already-fetched account list
    # and one cached Administrators SID set instead of re-enumerating them for each user.
    foreach ($u in $LocalUsers) {
        if (-not $authorizedSet.Contains($u.Name)) { continue }
        if (-not $u.Enabled) {
            Write-Log "Authorized account '$($u.Name)' is disabled; password flags were left unchanged." 'WARN'
            continue
        }

        $isAuthorizedAdmin = [bool]($ParsedUsers.Administrators | Where-Object { $_ -ieq $u.Name })
        $isLocalAdmin = $false
        if ($isAuthorizedAdmin) {
            try { $isLocalAdmin = $AdminSids.Contains($u.SID.Value) } catch {}
        }

        # The primary auto-logon account is a hard safety exception. Leave it
        # completely untouched: no README-password assessment and no per-user
        # password-flag changes. This must happen before any password logic.
        if ($AutologonUser -and $AutologonUser -ieq $u.Name) {
            Write-Log "'$($u.Name)' is the auto-logon account; all per-user password settings and README-password assessment were intentionally skipped." 'INFO'
            $script:AccountActionResults.Add([pscustomobject]@{
                Account=$u.Name
                Action='Per-user password handling'
                Result='SKIPPED - AUTO-LOGIN'
                Detail='Account intentionally left completely unchanged'
            })
            continue
        }

        # Assess only the README password text. There is deliberately no attempt
        # to read, recover, compare, or test the current VM password.
        $hasReadmePassword = $false
        $readmePasswordWeak = $false
        $readmePasswordCheck = $null

        if ($isAuthorizedAdmin -and $ParsedUsers.AdminPasswords.ContainsKey($u.Name)) {
            $hasReadmePassword = $true
            $candidate = [string]$ParsedUsers.AdminPasswords[$u.Name]
            $readmePasswordCheck = Test-PasswordMeetsPolicy -Password $candidate -Username $u.Name

            if ($readmePasswordCheck.IsWeak) {
                $readmePasswordWeak = $true
                $reasonText = $readmePasswordCheck.Reasons -join '; '
                Write-Log "README password for '$($u.Name)' does NOT meet the configured password requirements: $reasonText" 'WARN'

            }
            else {
                Write-Log "README password for '$($u.Name)' meets the configured password requirements; no change-password flags are required." 'INFO'
                $script:AccountActionResults.Add([pscustomobject]@{
                    Account=$u.Name
                    Action='Assess README password'
                    Result='MEETS REQUIREMENTS'
                    Detail='No change-password flags enabled'
                })
            }
        }

        try {
            $state = Get-UserFlagState -Name $u.Name

            if ($readmePasswordWeak) {
                # Weak README password: require a new password at next logon,
                # while permitting the user to choose it.
                $targetAlreadyCorrect = (
                    -not $state.PasswordNeverExpires -and
                    $state.PasswordRequired -and
                    $state.UserMayChangePassword -and
                    $state.MustChangeAtNextLogon
                )

                if ($targetAlreadyCorrect) {
                    Write-Log "'$($u.Name)': README password is weak and the required change-password flags are already enabled; skipped native write." 'INFO'
                    $script:AccountActionResults.Add([pscustomobject]@{
                        Account=$u.Name
                        Action='Apply README weak-password response'
                        Result='ALREADY CORRECT'
                        Detail='User may change ON; must change at next logon ON'
                    })
                }
                else {
                    Set-WeakReadmePasswordState -Name $u.Name -TemporarilyRemoveFromAdministrators:$isLocalAdmin
                    $script:AccountActionResults.Add([pscustomobject]@{
                        Account=$u.Name
                        Action='Apply README weak-password response'
                        Result='SUCCESS'
                        Detail='User may change ON; must change at next logon ON'
                    })
                }
            }
            else {
                # Normal baseline: only users with a README-supplied weak password get
                # the ON/ON exception above.
                $baselineAlreadyCorrect = (
                    -not $state.PasswordNeverExpires -and
                    $state.PasswordRequired -and
                    -not $state.UserMayChangePassword -and
                    -not $state.MustChangeAtNextLogon
                )

                if ($baselineAlreadyCorrect) {
                    Write-Log "'$($u.Name)': baseline password flags already correct; skipped." 'INFO'
                    $script:AccountActionResults.Add([pscustomobject]@{
                        Account=$u.Name
                        Action='Set password flags'
                        Result='ALREADY CORRECT'
                        Detail='Skipped native account write'
                    })
                }
                else {
                    Set-BaselineUserPasswordState -Name $u.Name -TemporarilyRemoveFromAdministrators:$isLocalAdmin -CurrentMustChange:$state.MustChangeAtNextLogon
                    $script:AccountActionResults.Add([pscustomobject]@{
                        Account=$u.Name
                        Action='Set password flags'
                        Result='SUCCESS'
                        Detail='Baseline flags applied; existing password-expired state is reported separately when applicable'
                    })
                }
            }
        }
        catch {
            Write-Log "Could not set password flags for '$($u.Name)': $($_.Exception.Message). Continuing to next account." 'ERROR'
            $failedAction = if ($readmePasswordWeak) { 'Apply README weak-password response' } else { 'Set password flags' }
            $script:AccountActionResults.Add([pscustomobject]@{
                Account=$u.Name
                Action=$failedAction
                Result='FAILED'
                Detail=$_.Exception.Message
            })
            continue
        }
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

function Verify-ScenarioRequiredAccounts {
    param([Parameter(Mandatory)][object]$ParsedUsers)
    foreach($name in @($ParsedUsers.ScenarioAccounts)){
        $u=Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if($null -eq $u){Write-Log "Verification mismatch: scenario-required account '$name' is missing." 'ERROR';continue}
        if(-not $u.Enabled){Write-Log "Verification mismatch: scenario-required account '$name' is disabled." 'ERROR';continue}
        $admins=Get-AdministratorsSidSet
        if($admins.Contains($u.SID.Value)){Write-Log "Verification mismatch: scenario-required account '$name' is a local administrator." 'ERROR';continue}
        Write-Log "Verified scenario-required account '$name' exists, is enabled, and is not an administrator." 'INFO'
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
                Write-Log "Verification: auto-logon account '$name' was intentionally left unchanged; no per-user password flags were assessed or modified." 'INFO'
                continue
            }

            $state = Get-UserFlagState -Name $name
            $expectedMayChange = $false
            $expectedMustChange = $false

            # Only a weak password explicitly supplied in the README changes the
            # expected flags. Strong README passwords remain on the normal baseline.
            if ($ParsedUsers.AdminPasswords.ContainsKey($name)) {
                $check = Test-PasswordMeetsPolicy -Password ([string]$ParsedUsers.AdminPasswords[$name]) -Username $name
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
                    Write-Log "Verification note for '$name': MustChangeAtNextLogon remains ON because the existing password is already expired; this was not treated as a weak-README-password trigger." 'INFO'
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

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $caption = [string]$os.Caption
    $version = [string]$os.Version
    $build = [int64]$os.BuildNumber
    $display = ''
    try { $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop; $display = [string]$cv.DisplayVersion } catch {}

    if ($caption -match '(?i)Windows 11') { $family = 'Windows 11' }
    elseif ($caption -match '(?i)Windows Server 2022' -or $build -eq 20348) { $family = 'Windows Server 2022' }
    else { throw "Unsupported Windows OS for automatic HardeningKitty list selection: $caption (version $version, build $build)." }

    if ([string]::IsNullOrWhiteSpace($display)) {
        if ($family -eq 'Windows 11') {
            switch ($build) {
                { $_ -ge 26200 } { $display = '25H2'; break }
                { $_ -ge 26100 } { $display = '24H2'; break }
                { $_ -ge 22631 } { $display = '23H2'; break }
                { $_ -ge 22621 } { $display = '22H2'; break }
                { $_ -ge 22000 } { $display = '21H2'; break }
            }
        }
        elseif ($build -eq 20348) { $display = '21H2' }
    }

    $machineLists = @(Get-ChildItem -LiteralPath $ListsPath -Filter '*_machine.csv' -File -ErrorAction Stop)
    if ($machineLists.Count -eq 0) { throw "No *_machine.csv finding lists were found in '$ListsPath'." }

    $wanted = $null
    if ($family -eq 'Windows 11') {
        switch ($display) {
            '24H2' { $wanted = 'finding_list_msft_security_baseline_windows_11_24h2_machine.csv' }
            '25H2' { $wanted = 'finding_list_0x6d69636b_machine.csv' }
            '23H2' { $wanted = 'finding_list_msft_security_baseline_windows_11_23h2_machine.csv' }
            '22H2' { $wanted = 'finding_list_msft_security_baseline_windows_11_22h2_machine.csv' }
            '21H2' { $wanted = 'finding_list_msft_security_baseline_windows_11_21h2_machine.csv' }
            default { throw "Unsupported or undetermined Windows 11 release '$display'; refusing to guess a HardeningKitty machine list." }
        }
    }
    else {
        switch ($display) {
            '21H2' { $wanted = 'finding_list_cis_microsoft_windows_server_2022_21h2_1.0.0_machine.csv' }
            '22H2' { $wanted = 'finding_list_cis_microsoft_windows_server_2022_22h2_2.0.0_machine.csv' }
            default { throw "Unsupported or undetermined Windows Server 2022 release '$display'; refusing to guess a HardeningKitty machine list." }
        }
    }

    $candidate = @($machineLists | Where-Object { $_.Name -ieq $wanted })
    if ($candidate.Count -ne 1) { throw "Exact OS/version-matched machine finding list '$wanted' was not found uniquely in '$ListsPath'." }
    if ($candidate[0].Name -match '(?i)_user\.csv$') { throw "Safety stop: selected finding list is a user list: $($candidate[0].Name)" }

    [pscustomobject]@{
        OsFamily = $family
        OsVersion = $version
        OsBuild = $build
        DisplayVersion = $display
        FindingList = $candidate[0]
        Score = $null
        Reason = "Exact $family $display machine finding list selected; no highest-version guessing."
        AvailableMachineLists = @($machineLists | Select-Object -ExpandProperty Name | Sort-Object)
    }
}

function Test-And-PrepareDefenderForHardeningKitty {
    try { $svc = Get-Service -Name 'WinDefend' -ErrorAction Stop }
    catch { Write-Log "Microsoft Defender Antivirus service (WinDefend) was not found: $($_.Exception.Message)" 'WARN'; return $false }
    Write-Log "Defender preflight: WinDefend status=$($svc.Status), startup=$($svc.StartType)."
    if ($svc.Status -eq 'Running') { return $true }
    if ($svc.StartType -eq 'Disabled') {
        Write-Log 'Defender preflight: WinDefend is Disabled. Harbinger''s Purge will not override a disabled startup state merely to force HardeningKitty to succeed.' 'WARN'
        return $false
    }
    try {
        if ($DryRun) { Write-Log 'DRY RUN: would start WinDefend if it is startable.' 'CHANGE'; return $false }
        Start-Service -Name 'WinDefend' -ErrorAction Stop
        Start-Sleep -Seconds 2
        $after = Get-Service -Name 'WinDefend' -ErrorAction Stop
        if ($after.Status -eq 'Running') { Write-Log 'Defender preflight: WinDefend is now running.' 'CHANGE'; return $true }
        Write-Log "Defender preflight: WinDefend did not reach Running state; current status=$($after.Status)." 'WARN'
        return $false
    }
    catch { Write-Log "Defender preflight could not start WinDefend: $($_.Exception.Message)" 'WARN'; return $false }
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
            Invoke-HardeningKitty -Mode Config -Backup -BackupFile $hkBackup -FileFindingList $findingList -SkipMachineInformation -ErrorAction Stop *>&1 |
                Tee-Object -FilePath $HardeningKittyLogPath -Append | Out-Host

            $defenderReady = Test-And-PrepareDefenderForHardeningKitty
            Write-Log 'Running HardeningKitty HailMary. This can change many machine security settings.' 'CHANGE'
            try {
                $hailmaryOutput = Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList $findingList -SkipRestorePoint -SkipMachineInformation -ErrorAction Stop *>&1 |
                    Tee-Object -FilePath $HardeningKittyLogPath -Append
                foreach ($line in $hailmaryOutput) {
                    $text = [string]$line
                    if ($text) { Write-Host "[HardeningKitty] $text" }
                }
            }
            catch {
                $hkMessage = [string]$_.Exception.Message
                if ($hkMessage -match '(?i)0x800106ba') {
                    Write-Log 'HardeningKitty hit Defender error 0x800106ba. Retrying once only if Defender can be made available without overriding a Disabled startup state.' 'WARN'
                    $defenderReadyRetry = Test-And-PrepareDefenderForHardeningKitty
                    if (-not $defenderReadyRetry) { throw $hkMessage }
                    $hailmaryOutput = Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList $findingList -SkipRestorePoint -SkipMachineInformation -ErrorAction Stop *>&1 |
                        Tee-Object -FilePath $HardeningKittyLogPath -Append
                    foreach ($line in $hailmaryOutput) {
                        $text = [string]$line
                        if ($text) { Write-Host "[HardeningKitty] $text" }
                    }
                }
                else { throw }
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
            $localCandidates = @((@(
                (Join-Path $PSScriptRoot 'wsd.crt'),
                (Join-Path (Get-Location) 'wsd.crt')
            ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique))

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
        [object]$HardeningKittyResult,
        [object]$ProvisioningRequirements
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
    $report.Add('  HailMary uses an exact OS/version-matched *_machine.csv finding list only; user.csv is never selected and no highest-version guessing is used.')
    $report.Add('')

    $report.Add('README SOFTWARE / BROWSER REQUIREMENTS:')
    if ($ProvisioningRequirements -and $ProvisioningRequirements.Software.Count -gt 0) {
        foreach ($req in $ProvisioningRequirements.Software) {
            $report.Add(('  - {0} | Type={1} | UpdateRequired={2} | Source={3}' -f $req.Name, $req.Type, $req.UpdateRequired, $req.Source))
        }
    } else { $report.Add('  (none recognized)') }
    $report.Add('')
    $report.Add('SOFTWARE / BROWSER ACTION RESULTS:')
    if ($script:SoftwareResults.Count -eq 0) { $report.Add('  (none)') }
    else { foreach ($r in $script:SoftwareResults) { $report.Add(('  {0} | {1} | {2} | {3} | {4} | {5}' -f $r.Name, $r.Type, $r.Provider, $r.PackageId, $r.Result, $r.Detail)) } }
    $report.Add('')
    $report.Add('README CRITICAL SERVICES:')
    if ($ProvisioningRequirements -and $ProvisioningRequirements.Services.Count -gt 0) { foreach ($svc in $ProvisioningRequirements.Services) { $report.Add("  - $svc") } } else { $report.Add('  None') }
    $report.Add('CRITICAL SERVICE ACTION RESULTS:')
    if ($script:ServiceResults.Count -eq 0) { $report.Add('  (none)') }
    else { foreach ($r in $script:ServiceResults) { $report.Add(('  {0} | {1} | {2} | {3}' -f $r.Requested, $r.ServiceName, $r.Result, $r.Detail)) } }
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
    $report.Add('README password handling: only password text explicitly supplied for authorized administrators is assessed. A README password that meets the configured requirements leaves UserMayChangePassword=OFF and MustChangeAtNextLogon=OFF. A README password that does not meet the requirements enables both flags so that user is prompted to choose a new password at next logon. The current VM password is never read or tested. The auto-logon account is completely exempt from per-user password assessment and changes, even when its README password is weak. Existing expired-password state is reported for awareness but never causes a forced password change by itself.')
    $report.Add('Built-in Administrator: disabled when not listed as an authorized administrator. Guest, WDAGUtilityAccount, DefaultAccount, and defaultuser0 are disabled when present. Unauthorized local users are removed from Administrators and disabled unless an explicit README prohibition protects that account.')
    $report.Add('Software provisioning: only README-named software/browser requirements are acted on. WinGet is preferred when available; Chocolatey is the fallback. Google Chrome uses the official Google MSI when the package-manager path is unavailable or unreliable. No unrelated software is upgraded.')
    $report.Add('Critical Services: only services explicitly listed in the README Critical Services section are touched. Running services are left as-is. Disabled listed services are changed to Automatic before starting. Stopped non-disabled services are started without changing startup mode.')
    $report.Add('Default browser: when the README identifies a default browser, its registered HTTP/HTTPS/.htm/.html associations are imported with DISM for future user sign-ins. The protected current-user Windows 11 UserChoice values are not forcibly rewritten.')
    if ($ProvisioningRequirements -and @($ProvisioningRequirements.ScenarioRemovals).Count -gt 0) {
        $report.Add('Explicit README scenario removals recognized; only concrete targets named by the README were acted on.')
        foreach ($item in @($ProvisioningRequirements.ScenarioRemovals)) { $report.Add(("  TARGET | {0} | {1}" -f $item.Target, $item.Source)) }
    }
    if ($ParsedUsers -and @($ParsedUsers.ScenarioAccountActions).Count -gt 0) {
        $report.Add('Explicit README scenario account actions:')
        foreach ($item in @($ParsedUsers.ScenarioAccountActions)) { $report.Add(("  {0} | {1} | {2}" -f $item.Action, $item.Name, $item.Source)) }
    }
    if ($ParsedUsers -and @($ParsedUsers.ProtectedAccounts).Count -gt 0) {
        $report.Add(("Protected accounts from README: {0}" -f ($ParsedUsers.ProtectedAccounts -join ', ')))
    }
    if ($ParsedUsers -and @($ParsedUsers.ProtectedServices).Count -gt 0) {
        $report.Add(("Protected services from README: {0}" -f ($ParsedUsers.ProtectedServices -join ', ')))
    }
    if ($ParsedUsers -and @($ParsedUsers.ProhibitedActions).Count -gt 0) {
        $report.Add('README prohibited-action directives were recorded; the script does not infer unrelated cleanup from broad categories.')
    }

    Set-Content -LiteralPath $ReportPath -Value $report -Encoding UTF8
    Write-Log "Report written to $ReportPath"
}

function Assert-ReadmeOsMatchesVm {
    param(
        [Parameter(Mandatory)][string]$ReadmeText,
        [Parameter(Mandatory)][object]$OsInfo
    )

    $lines = Get-CleanLines -Text $ReadmeText
    $sample = @($lines | Select-Object -First 80)
    $hasWin11 = @($sample | Where-Object { $_ -match '(?i)\bWindows\s+11\b' }).Count -gt 0
    $hasServer2022 = @($sample | Where-Object { $_ -match '(?i)\bWindows\s+Server\s+2022\b' }).Count -gt 0

    if ($OsInfo.Kind -eq 'Windows 11' -and $hasServer2022 -and -not $hasWin11) {
        throw 'README/VM mismatch: the README identifies Windows Server 2022, but this VM is Windows 11. Refusing to apply the scenario.'
    }
    if ($OsInfo.Kind -eq 'Windows Server 2022' -and $hasWin11 -and -not $hasServer2022) {
        throw 'README/VM mismatch: the README identifies Windows 11, but this VM is Windows Server 2022. Refusing to apply the scenario.'
    }
    if (-not $hasWin11 -and -not $hasServer2022) {
        Write-Log 'README does not explicitly identify Windows 11 or Windows Server 2022 in its opening section; continuing because the VM itself is a supported OS.' 'WARN'
    }
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
    Complete-Phase $certStatus (if ($certStatus -eq 'PASS') { 'Certificate import completed.' } else { 'Certificate step finished; manual installation may still be needed.' })

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
    Assert-ReadmeOsMatchesVm -ReadmeText $readmeText -OsInfo $osInfo
    $parsed = Parse-AuthorizedUsers -Text $readmeText

    Write-Log ("README authorized administrators: {0}" -f ($parsed.Administrators -join ', '))
    Write-Log ("README authorized users: {0}" -f ($parsed.Users -join ', '))
    Complete-Phase 'PASS' ("Parsed {0} authorized administrators and {1} authorized users." -f $parsed.Administrators.Count, $parsed.Users.Count)
    if (@($parsed.ScenarioAccounts).Count -gt 0) { Write-Log ("README scenario-required account(s): {0}" -f ($parsed.ScenarioAccounts -join ', ')) }
    if (@($parsed.ProtectedServices).Count -gt 0) {
        Write-Log ("README explicitly protects service(s) from stop/disable actions: {0}" -f ($parsed.ProtectedServices -join ', '))
        Restore-ProtectedServices -ParsedUsers $parsed
    }
    Write-Log ("Scenario parser recognized {0} account action(s), {1} concrete removal directive(s), and {2} protected account/service directive(s)." -f @($parsed.ScenarioAccountActions).Count, @($parsed.ScenarioRemovals).Count, (@($parsed.ProtectedAccounts).Count + @($parsed.ProtectedServices).Count))

    $currentUser = Get-CurrentUsername
    Assert-CurrentUserAuthorized -Authorized $parsed.AllAuthorized -CurrentUser $currentUser
    Write-Log "Confirmed currently logged-in account '$currentUser' is authorized by the README."

    # Cache local users and Administrators membership once for the account-processing stages.
    $cachedLocalUsers = @(Get-LocalUser | Sort-Object Name)
    $cachedAdminSids = Get-AdministratorsSidSet
    if (-not (Test-LocalUserIsAdministrator -Name $currentUser -AdminSids $cachedAdminSids)) {
        Ensure-CurrentUserAdministrator -CurrentUser $currentUser -ParsedUsers $parsed -AdminSids $cachedAdminSids
        $cachedAdminSids = Get-AdministratorsSidSet
    }
    Ensure-AuthorizedAdministrators -ParsedUsers $parsed -AdminSids $cachedAdminSids
    $cachedAdminSids = Get-AdministratorsSidSet
    Write-Log "Confirmed currently logged-in account '$currentUser' is a local administrator."

    $autologonUser = Get-AutologonUser
    if ($autologonUser) {
        Write-Log "Detected auto-logon account: $autologonUser; per-user password handling for this account will be skipped completely." 'INFO'
    }

    Start-Phase 'Scenario-required account provisioning'
    $scenarioAccountErrorsBefore = $script:Failures.Count
    try { Ensure-ScenarioRequiredAccounts -ParsedUsers $parsed } catch { Write-Log "Scenario-required account provisioning stage error: $($_.Exception.Message). Continuing." 'ERROR' }
    $scenarioAccountStatus = if ($script:Failures.Count -gt $scenarioAccountErrorsBefore) { 'WARN' } else { 'PASS' }
    Complete-Phase $scenarioAccountStatus 'README-explicit new account requirements were processed without inspecting or exposing current passwords.'
    if (@($parsed.ScenarioAccountActions | Where-Object { $_.Action -ne 'CREATE' }).Count -gt 0) { Invoke-ScenarioAccountActions -ParsedUsers $parsed -CurrentUser $currentUser }

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

    Start-Phase 'Required software, browsers, and Critical Services'
    $provisionErrorsBefore = $script:Failures.Count
    try {
        $requirements = Parse-RequiredSoftwareAndServices -Text $readmeText
        $requirements.ScenarioRemovals = @($parsed.ScenarioRemovals)
        $requirements.ScenarioAccountActions = @($parsed.ScenarioAccountActions)
        if ($requirements.Software.Count -eq 0) {
            Write-Log 'README did not contain a recognized browser/software requirement.'
        } else {
            Write-Log ("README software/browser requirements detected: {0}" -f ($requirements.Software.Name -join ', '))
            foreach ($req in $requirements.Software) { Invoke-SoftwareProvisioning -Requirement $req }
            $browserRequirements = @($requirements.Software | Where-Object { $_.Type -eq 'Browser' })
            if ($browserRequirements.Count -gt 0) { Ensure-DefaultBrowserRequirements -BrowserRequirements $browserRequirements }
        }
        if ($requirements.Services.Count -eq 0) {
            Write-Log 'README Critical Services section is empty or set to None; no unrelated services will be changed.'
        } else {
            Write-Log ("README Critical Services: {0}" -f ($requirements.Services -join ', '))
            Ensure-CriticalServices -ServiceNames $requirements.Services
        }
        if (@($requirements.ScenarioRemovals).Count -gt 0) {
            Write-Log ("README contains {0} explicit scenario removal directive(s); only those concrete targets will be acted on." -f @($requirements.ScenarioRemovals).Count) 'INFO'
            Invoke-ScenarioRemovals -Items $requirements.ScenarioRemovals
        }
    }
    catch {
        Write-Log "Required software/browser/service parsing stage failed: $($_.Exception.Message). Continuing to per-user settings and verification; no unparsed software/services will be guessed or changed." 'ERROR'
    }
    $provisionStatus = if ($script:Failures.Count -gt $provisionErrorsBefore) { 'WARN' } else { 'PASS' }
    Complete-Phase $provisionStatus 'README-driven browser/software requirements and explicitly listed Critical Services were processed independently; failures are recorded without stopping later phases.'

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
            Verify-ScenarioRequiredAccounts -ParsedUsers $parsed
            Verify-UserStates -ParsedUsers $parsed -AutologonUser $autologonUser -LocalUsers $verifyLocalUsers -AdminSids $verifyAdminSids
        } catch { Write-Log "Account verification failed: $($_.Exception.Message)" 'ERROR' }
        $verifyStatus = if ($script:Failures.Count -gt $verifyErrorsBefore) { 'WARN' } else { 'PASS' }
        Complete-Phase $verifyStatus 'Verification completed; see the error/warning section for exact mismatches.'
    }

    Set-Content -LiteralPath $TranscriptPath -Value ($script:Log -join [Environment]::NewLine) -Encoding UTF8
    Write-Report -OsInfo $osInfo -ParsedUsers $parsed -ReadmeSource $readme.Source -HardeningKittyResult $hkResult -ProvisioningRequirements $requirements
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
    $fatalMessage = [string]$_.Exception.Message
    Write-Log $fatalMessage 'ERROR'

    # Do not leave an interrupted phase looking as though it is still running.
    if ($script:CurrentPhase -and $script:CurrentPhase.Status -eq 'RUNNING') {
        $script:CurrentPhase.Status = 'ERROR'
        $script:CurrentPhase.Completed = Get-Date
        $script:CurrentPhase.Detail = "Fatal stage error: $fatalMessage"
    }

    # Always preserve the diagnostic transcript first.
    try {
        Set-Content -LiteralPath $TranscriptPath -Value ($script:Log -join [Environment]::NewLine) -Encoding UTF8
    } catch {}

    # If README processing succeeded far enough to populate the required report inputs,
    # write a partial report so the user can inspect exactly where execution stopped.
    $partialReportWritten = $false
    if ($osInfo -and $parsed) {
        try {
            Write-Report -OsInfo $osInfo -ParsedUsers $parsed -ReadmeSource $ReadmeUri -HardeningKittyResult $hkResult -ProvisioningRequirements $requirements
            $partialReportWritten = $true
        } catch {
            Write-Log "Could not write partial report after fatal error: $($_.Exception.Message)" 'WARN'
        }
    }

    # Persist any final warning/error log entries created while writing the report.
    try {
        Set-Content -LiteralPath $TranscriptPath -Value ($script:Log -join [Environment]::NewLine) -Encoding UTF8
    } catch {}

    Write-Host ''
    Write-Host "Harbinger's Purge encountered a fatal stage error." -ForegroundColor Red
    Write-FinalSummary -DryRun:$DryRun
    if ($partialReportWritten) { Write-Host "Partial report: $ReportPath" -ForegroundColor Yellow }
    Write-Host "Review transcript: $TranscriptPath" -ForegroundColor Yellow
    exit 1
}
finally {
    if (-not $KeepBackupFiles) {
        Get-ChildItem -LiteralPath $TempRoot -File -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}
