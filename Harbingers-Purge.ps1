<#
.SYNOPSIS
    Harbinger's Purge - CyberPatriot Windows 11 / Windows Server 2022 user hardening.

.DESCRIPTION
    1. Attempts to download/install wsd.crt FIRST (before README processing).
    2. Reads the CyberPatriot README for THIS image.
    3. Compares local users to the README's Authorized Administrators and Authorized Users.
    4. Disables enabled local accounts that are not authorized, except protected Windows-managed accounts.
    5. Applies the exact password and account-lockout policies requested.
    6. Applies the requested per-user password flags.
    7. Assesses ONLY the password text supplied in the README for the built-in Administrator account.
       If that README password is weak, Administrator gets User may change password = ON and
       User must change password at next logon = ON. The current password is never read or tested.
    8. Verifies the resulting account states and administrator-group membership.
    9. Produces a report showing PASS / WARN / ERROR / MANUAL REVIEW items.

    Supported operating systems:
      - Windows 11
      - Windows Server 2022

.AUTHOR
    Channveer Singh

.TITLE
    Harbinger's Purge

.VERSION
    1.4 - Adds detailed phase/action reporting, continues past individual account failures, disables required built-in/Windows-managed accounts, and cleans unauthorized Administrators membership.
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

function Get-AdsiLocalUser {
    param([Parameter(Mandatory)][string]$Name)
    return [ADSI]::new("WinNT://$env:COMPUTERNAME/$Name,user")
}

function Get-AdsiUserFlags {
    param([Parameter(Mandatory)][string]$Name)
    $user = Get-AdsiLocalUser -Name $Name
    return [int]$user.UserFlags.Value
}

function Set-AdsiUserFlags {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Flags
    )
    $user = Get-AdsiLocalUser -Name $Name
    $user.Put('UserFlags', $Flags)
    $user.SetInfo()
}

function Get-UserFlagState {
    param([Parameter(Mandatory)][string]$Name)
    $flags = Get-AdsiUserFlags -Name $Name
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
    param([Parameter(Mandatory)][string]$Name)

    $flags = Get-AdsiUserFlags -Name $Name
    $flags = $flags -band (-bnot $UF_DONT_EXPIRE_PASSWD)    # Password never expires = OFF
    $flags = $flags -band (-bnot $UF_PASSWD_NOTREQD)        # Password required = ON
    $flags = $flags -bor  $UF_PASSWD_CANT_CHANGE           # User may change = OFF
    $flags = $flags -band (-bnot $UF_PASSWORD_EXPIRED)      # Must change next logon = OFF

    if ($DryRun) {
        Write-Log "DRY RUN: would set '$Name': PasswordNeverExpires=OFF; PasswordRequired=ON; UserMayChangePassword=OFF; MustChangeAtNextLogon=OFF."
        return
    }

    Set-AdsiUserFlags -Name $Name -Flags $flags
    Write-Log "'$Name': PasswordNeverExpires=OFF; PasswordRequired=ON; UserMayChangePassword=OFF; MustChangeAtNextLogon=OFF." 'CHANGE'
}

function Set-AdministratorWeakPasswordState {
    param([Parameter(Mandatory)][string]$Name)

    $flags = Get-AdsiUserFlags -Name $Name
    $flags = $flags -band (-bnot $UF_DONT_EXPIRE_PASSWD)
    $flags = $flags -band (-bnot $UF_PASSWD_NOTREQD)
    $flags = $flags -band (-bnot $UF_PASSWD_CANT_CHANGE)     # User may change = ON
    $flags = $flags -bor $UF_PASSWORD_EXPIRED                # Must change at next logon = ON

    if ($DryRun) {
        Write-Log "DRY RUN: would set 'Administrator': UserMayChangePassword=ON; MustChangeAtNextLogon=ON because the README password is weak."
        return
    }

    Set-AdsiUserFlags -Name $Name -Flags $flags
    Write-Log "'Administrator': UserMayChangePassword=ON; MustChangeAtNextLogon=ON because the README password is weak." 'CHANGE'
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

function Remove-UnapprovedAdministratorsAndDisableUnlisted {
    param(
        [Parameter(Mandatory)][object]$ParsedUsers,
        [Parameter(Mandatory)][string]$CurrentUser
    )

    $authorizedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ParsedUsers.AllAuthorized) { [void]$authorizedSet.Add($name) }

    $authorizedAdminSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ParsedUsers.Administrators) { [void]$authorizedAdminSet.Add($name) }

    # Remove local, unapproved users from the local Administrators group first.
    foreach ($name in @(Get-LocalAdministratorsMemberNames)) {
        if ($authorizedAdminSet.Contains($name)) { continue }
        if ($name -ieq 'Administrator') { continue } # Built-in Administrator is handled separately.

        if ($name -ieq $CurrentUser) {
            throw "Safety stop: current logged-in account '$CurrentUser' is not an authorized administrator."
        }

        if ($DryRun) {
            Write-Log "DRY RUN: would remove unauthorized administrator '$name' from the local Administrators group."
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
            Write-Log "Required account '$name' does not exist on this VM." 'WARN'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name; Action='Disable account'; Result='NOT PRESENT'; Detail='Account does not exist'})
            continue
        }

        if (-not $local.Enabled) {
            Write-Log "Required account '$name' is already disabled."
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name; Action='Disable account'; Result='ALREADY CORRECT'; Detail='Account already disabled'})
            continue
        }

        try {
            Disable-SpecificLocalAccount -Name $name
        }
        catch {
            Write-Log "Could not disable required account '$name': $($_.Exception.Message)" 'ERROR'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$name; Action='Disable account'; Result='FAILED'; Detail=$_.Exception.Message})
        }
    }

    # Disable the built-in Administrator account when it is not listed by the README.
    $builtinAdmin = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
    if ($null -ne $builtinAdmin -and -not $authorizedAdminSet.Contains('Administrator')) {
        if ($builtinAdmin.Enabled) {
            try {
                Disable-SpecificLocalAccount -Name 'Administrator'
            }
            catch {
                Write-Log "Could not disable built-in 'Administrator': $($_.Exception.Message)" 'ERROR'
                $script:AccountActionResults.Add([pscustomobject]@{Account='Administrator'; Action='Disable account'; Result='FAILED'; Detail=$_.Exception.Message})
            }
        } else {
            Write-Log "Built-in 'Administrator' is already disabled."
            $script:AccountActionResults.Add([pscustomobject]@{Account='Administrator'; Action='Disable account'; Result='ALREADY CORRECT'; Detail='Account already disabled'})
        }
    }

    # Disable every other enabled local account not listed anywhere in the README.
    foreach ($u in @(Get-LocalUser | Sort-Object Name)) {
        if ($authorizedSet.Contains($u.Name)) { continue }
        if ($AlwaysDisableAccounts -contains $u.Name) { continue }
        if ($u.Name -ieq 'Administrator') { continue }
        if ($u.Name -ieq $CurrentUser) {
            throw "Safety stop: current logged-in account '$CurrentUser' is not authorized by the README."
        }
        if (-not $u.Enabled) { continue }

        try {
            Disable-SpecificLocalAccount -Name $u.Name
        }
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
        [string]$AutologonUser
    )

    $users = @(Get-LocalUser | Sort-Object Name)
    $authorizedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ParsedUsers.AllAuthorized) { [void]$authorizedSet.Add($name) }

    foreach ($u in $users) {
        if (-not $authorizedSet.Contains($u.Name)) { continue }
        if (-not $u.Enabled) {
            Write-Log "Authorized account '$($u.Name)' is disabled; password flags were left unchanged." 'WARN'
            continue
        }

        # CyberPatriot explicitly says the primary auto-login account is not required
        # to have its password changed. Leave ALL per-user password flags untouched
        # for that account. This also avoids Windows ERROR_LAST_ADMIN when the
        # auto-login account is the only currently usable local administrator.
        if ($AutologonUser -and $AutologonUser -ieq $u.Name) {
            Write-Log "'$($u.Name)' is the auto-logon account; per-user password flags were intentionally left unchanged." 'WARN'
            continue
        }

        try {
            Set-BaselineUserPasswordState -Name $u.Name
            $script:AccountActionResults.Add([pscustomobject]@{Account=$u.Name; Action='Set password flags'; Result='SUCCESS'; Detail='Baseline flags applied'})
        }
        catch {
            Write-Log "Could not set password flags for '$($u.Name)': $($_.Exception.Message). Continuing to next account." 'ERROR'
            $script:AccountActionResults.Add([pscustomobject]@{Account=$u.Name; Action='Set password flags'; Result='FAILED'; Detail=$_.Exception.Message})
            continue
        }

        # ONLY assess the password text provided in the README for the built-in Administrator.
        if ($u.Name -ieq 'Administrator') {

            if ($ParsedUsers.AdminPasswords.ContainsKey('Administrator')) {
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
            else {
                Write-Log 'README did not provide an Administrator password; no README-password assessment was possible.' 'WARN'
            }
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

function Verify-UserStates {
    param(
        [Parameter(Mandatory)][object]$ParsedUsers,
        [string]$AutologonUser
    )

    $adminSids = Get-AdministratorsSidSet
    $localUsers = @(Get-LocalUser | Sort-Object Name)
    $localByName = @{}
    foreach ($u in $localUsers) { $localByName[$u.Name.ToLowerInvariant()] = $u }

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
            # The primary auto-login account is intentionally excluded from per-user
            # password-state enforcement per the scenario. Verify that we left it alone
            # rather than expecting the normal baseline flags.
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
            if ($state.MustChangeAtNextLogon -ne $expectedMustChange) { Write-Log "Verification mismatch for '$name': MustChangeAtNextLogon expected $expectedMustChange, found $($state.MustChangeAtNextLogon)." 'ERROR' }

            if (-not $state.PasswordNeverExpires -and $state.PasswordRequired -and $state.UserMayChangePassword -eq $expectedMayChange -and $state.MustChangeAtNextLogon -eq $expectedMustChange) {
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
            $isAdmin = $adminSids.Contains($u.SID.Value)
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
        [string]$ReadmeSource
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
    $report.Add('Administrator exception: ONLY the README-provided Administrator password is assessed. If that README password is weak, User may change password and User must change at next logon are enabled. The current VM password is never read or tested.')

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
    Remove-UnapprovedAdministratorsAndDisableUnlisted -ParsedUsers $parsed -CurrentUser $currentUser
    $cleanupStatus = if ($script:Failures.Count -gt $cleanupErrorsBefore) { 'WARN' } else { 'PASS' }
    Complete-Phase $cleanupStatus 'Administrator membership and account-disable actions were processed.'

    Start-Phase 'Per-user password settings'
    $userErrorsBefore = $script:Failures.Count
    Apply-UserPasswordStates -ParsedUsers $parsed -AutologonUser $autologonUser
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
        try { Verify-UserStates -ParsedUsers $parsed -AutologonUser $autologonUser } catch { Write-Log "Account verification failed: $($_.Exception.Message)" 'ERROR' }
        $verifyStatus = if ($script:Failures.Count -gt $verifyErrorsBefore) { 'WARN' } else { 'PASS' }
        Complete-Phase $verifyStatus 'Verification completed; see the error/warning section for exact mismatches.'
    }

    Set-Content -LiteralPath $TranscriptPath -Value ($script:Log -join [Environment]::NewLine) -Encoding UTF8
    Write-Report -OsInfo $osInfo -ParsedUsers $parsed -ReadmeSource $readme.Source
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
