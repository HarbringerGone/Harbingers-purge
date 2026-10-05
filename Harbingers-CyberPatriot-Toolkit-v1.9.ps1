<#
.SYNOPSIS
    Harbinger's CyberPatriot Toolkit

.DESCRIPTION
    Menu-driven launcher for Harbinger's Purge plus a separate Ninite-style
    GUI installer/updater for README-requested browsers/apps and critical services.

    1 = Executor: launches Harbingers-Purge.ps1
    2 = Installer/Updater: opens a GUI that can scan a CyberPatriot README,
        detect requested browsers/apps/services, and install/update selected items.
    3 = Critical Services: apply only services explicitly listed by the README.

    Windows 11 and Windows Server 2022 only.

.AUTHOR
    Channveer Singh
#>

[CmdletBinding()]
param(
    [string]$PurgeScriptPath = (Join-Path $PSScriptRoot 'Harbingers-Purge.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Harbinger''s CyberPatriot Toolkit must be run as Administrator.' -ForegroundColor Yellow
    exit 1
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$TempRoot = Join-Path $env:TEMP 'HarbingersCyberPatriotToolkit'
$null = New-Item -ItemType Directory -Path $TempRoot -Force

$SoftwareCatalog = @{
    'chrome'           = @{ Winget='Google.Chrome'; Choco='googlechrome'; Display='Google Chrome' }
    'googlechrome'     = @{ Winget='Google.Chrome'; Choco='googlechrome'; Display='Google Chrome' }
    'firefox'          = @{ Winget='Mozilla.Firefox'; Choco='firefox'; Display='Mozilla Firefox' }
    'firefoxesr'       = @{ Winget='Mozilla.Firefox.ESR'; Choco='firefoxesr'; Display='Firefox ESR' }
    'edge'             = @{ Winget='Microsoft.Edge'; Choco='microsoft-edge'; Display='Microsoft Edge' }
    'brave'            = @{ Winget='Brave.Brave'; Choco='brave'; Display='Brave' }
    'opera'            = @{ Winget='Opera.Opera'; Choco='opera'; Display='Opera' }
    'vivaldi'          = @{ Winget='Vivaldi.Vivaldi'; Choco='vivaldi'; Display='Vivaldi' }
    'notepadplusplus'  = @{ Winget='Notepad++.Notepad++'; Choco='notepadplusplus'; Display='Notepad++' }
    '7zip'             = @{ Winget='7zip.7zip'; Choco='7zip'; Display='7-Zip' }
    'wireshark'        = @{ Winget='WiresharkFoundation.Wireshark'; Choco='wireshark'; Display='Wireshark' }
    'apache'           = @{ Winget='ApacheLounge.httpd'; Choco='apache-httpd'; Display='Apache HTTP Server' }
    'apachehttpd'      = @{ Winget='ApacheLounge.httpd'; Choco='apache-httpd'; Display='Apache HTTP Server' }
    'apachehttpserver' = @{ Winget='ApacheLounge.httpd'; Choco='apache-httpd'; Display='Apache HTTP Server' }
}

function Normalize-Name([string]$Name) {
    return (($Name.ToLowerInvariant()) -replace '[^a-z0-9]+','')
}

function Write-GuiLog([string]$Message) {
    if ($script:LogBox) {
        $script:LogBox.AppendText("[$(Get-Date -Format 'HH:mm:ss')] $Message`r`n")
        $script:LogBox.SelectionStart = $script:LogBox.TextLength
        $script:LogBox.ScrollToCaret()
    }
}

function Get-ReadmeText {
    param([string]$PathOrUrl)
    if ([string]::IsNullOrWhiteSpace($PathOrUrl)) { throw 'Select a README file or enter a README URL.' }
    if ($PathOrUrl -match '^https?://') {
        Write-GuiLog "Downloading README: $PathOrUrl"
        return (Invoke-WebRequest -Uri $PathOrUrl -UseBasicParsing -MaximumRedirection 5).Content
    }
    if (-not (Test-Path -LiteralPath $PathOrUrl -PathType Leaf)) { throw "README not found: $PathOrUrl" }
    return [IO.File]::ReadAllText((Resolve-Path -LiteralPath $PathOrUrl).Path)
}

function Convert-ReadmeContentToText([string]$Text) {
    if ($Text -match '(?is)<html\b|<body\b|<main\b|<article\b|<h[1-6]\b') {
        $clean = $Text
        $clean = [regex]::Replace($clean, '(?is)<(script|style|noscript)\b[^>]*>.*?</\1>', ' ')
        $clean = [regex]::Replace($clean, '(?i)<br\s*/?>', "`n")
        $clean = [regex]::Replace($clean, '(?i)</(p|div|li|h1|h2|h3|h4|h5|h6|section|article|tr)\s*>', "`n")
        $clean = [regex]::Replace($clean, '(?i)<li\b[^>]*>', "`n  * ")
        $clean = [regex]::Replace($clean, '<[^>]+>', ' ')
        $clean = [System.Net.WebUtility]::HtmlDecode($clean)
        $clean = $clean -replace [char]0xA0, ' '
        $clean = $clean -replace '`r', ''
        return $clean
    }
    return $Text
}

function Parse-Requirements([string]$Text) {
    $normalized = Convert-ReadmeContentToText $Text
    $lines = @($normalized -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $software = New-Object System.Collections.Generic.List[object]
    $services = New-Object System.Collections.Generic.List[string]

    # CyberPatriot scenario pages can be HTML, plain text, or slightly different
    # versions of the same README layout.  Do not depend on one exact heading.
    $sectionStart = -1
    $sectionEnd = $lines.Count
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '(?i)^(?:#+\s*)?(Competition Scenario|Business Software|Required Software|Software|Applications)\s*:?[\s]*$') {
            $sectionStart = $i
            break
        }
    }
    if ($sectionStart -ge 0) {
        for ($i = $sectionStart + 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '(?i)^(?:#+\s*)?(Critical Services|Authorized Administrators(?: and Users)?|Authorized Users|Competition Guidelines|Forensics Questions|Unique Identifier|ANSWER KEY|REMINDERS)\s*:?[\s]*$') {
                $sectionEnd = $i
                break
            }
        }
    }

    # Prefer the identified requirement section.  If the README does not have a
    # recognizable heading, fall back to all lines but require requirement-like
    # context so page navigation does not create false software entries.
    $requirementLines = if ($sectionStart -ge 0) {
        if ($sectionEnd -gt ($sectionStart + 1)) { @($lines[($sectionStart + 1)..($sectionEnd - 1)]) } else { @() }
    } else {
        @($lines)
    }

    # Canonical names plus common README spellings.  Every match is converted to
    # the canonical catalog name before it is placed in the GUI.
    $softwareRules = @(
        @{ Name='Google Chrome'; Key='googlechrome'; Browser=$true; Aliases=@('Google Chrome','Google Chrome Enterprise','Chrome') }
        @{ Name='Mozilla Firefox'; Key='firefox'; Browser=$true; Aliases=@('Mozilla Firefox','Firefox') }
        @{ Name='Firefox ESR'; Key='firefoxesr'; Browser=$true; Aliases=@('Firefox ESR','Mozilla Firefox ESR') }
        @{ Name='Microsoft Edge'; Key='edge'; Browser=$true; Aliases=@('Microsoft Edge','Edge') }
        @{ Name='Brave'; Key='brave'; Browser=$true; Aliases=@('Brave Browser','Brave') }
        @{ Name='Opera'; Key='opera'; Browser=$true; Aliases=@('Opera Browser','Opera') }
        @{ Name='Vivaldi'; Key='vivaldi'; Browser=$true; Aliases=@('Vivaldi Browser','Vivaldi') }
        @{ Name='Notepad++'; Key='notepadplusplus'; Browser=$false; Aliases=@('Notepad++','Notepad ++','Notepad Plus Plus','NotepadPlusPlus') }
        @{ Name='7-Zip'; Key='7zip'; Browser=$false; Aliases=@('7-Zip','7 Zip','7zip') }
        @{ Name='Wireshark'; Key='wireshark'; Browser=$false; Aliases=@('Wireshark') }
        @{ Name='Apache HTTP Server'; Key='apachehttpserver'; Browser=$false; Aliases=@('Apache HTTP Server','Apache HTTPD','Apache HTTPD Server','Apache') }
    )

    foreach ($line in $requirementLines) {
        $l = [string]$line
        if ([string]::IsNullOrWhiteSpace($l)) { continue }

        $isBullet = $l -match '^(?:[*-]|[0-9]+[.)])\s+'
        $hasRequirementContext = $isBullet -or ($l -match '(?i)\b(install|installed|software|application|browser|latest|stable|update|updated|up-to-date|keep|kept|required|business|default)\b')

        # In a heading-identified section, every line is relevant. In fallback
        # mode, use the context guard to avoid picking up site navigation labels.
        if ($sectionStart -lt 0 -and -not $hasRequirementContext) { continue }

        $update = $l -match '(?i)\b(latest|stable|up-to-date|updated|update|updated regularly|kept current|keep .*current|kept up-to-date|keep .*up-to-date)\b'
        $browserLine = $l -match '(?i)\b(default web browser|default browser|browser for all users|set .*default)\b'

        foreach ($rule in $softwareRules) {
            $matched = $false
            foreach ($alias in $rule.Aliases) {
                $pattern = '(?i)(?<![A-Za-z0-9])' + [regex]::Escape($alias) + '(?![A-Za-z0-9])'
                if ($l -match $pattern) { $matched = $true; break }
            }
            if (-not $matched) { continue }

            $existing = $software | Where-Object { $_.Name -ieq $rule.Name } | Select-Object -First 1
            if ($null -eq $existing) {
                $software.Add([pscustomobject]@{
                    Name           = $rule.Name
                    Key            = $rule.Key
                    UpdateRequired = [bool]$update
                    Browser        = [bool]$rule.Browser
                    SetAsDefault   = [bool]($rule.Browser -and $browserLine)
                    Source         = $l
                })
            } else {
                if ($update) { $existing.UpdateRequired = $true }
                if ($rule.Browser) { $existing.Browser = $true }
                if ($rule.Browser -and $browserLine) { $existing.SetAsDefault = $true }
            }
        }
    }

    # Critical Services must only come from the explicit Critical Services
    # section.  Never infer a service from account, password, software, or prose.
    $svcStart = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '(?i)^(?:#+\s*)?Critical Services\s*:?[\s]*$') {
            $svcStart = $i
            break
        }
    }

    if ($svcStart -ge 0) {
        for ($i = $svcStart + 1; $i -lt $lines.Count; $i++) {
            $svcLine = [string]$lines[$i]
            if ([string]::IsNullOrWhiteSpace($svcLine)) { continue }
            if ($svcLine -match '(?i)^(?:#+\s*)?(Authorized Administrators(?: and Users)?|Authorized Users|Competition Guidelines|Forensics Questions|Unique Identifier|ANSWER KEY|REMINDERS|Scenario Details|Business Software|Required Software|Software)\s*:?[\s]*$') { break }

            # Accept only explicit list entries.  HTML list items become '*'.
            if ($svcLine -match '^(?:[*-]|[0-9]+[.)])\s*(.+)$') {
                $serviceName = $Matches[1].Trim()
                if ($serviceName -match '(?i)^(none|n/a|none\.)$') { continue }
                $services.Add($serviceName)
            }
        }
    }

    return [pscustomobject]@{
        Software = @($software | Sort-Object Name -Unique)
        Services = @($services | Sort-Object -Unique)
    }
}

function Resolve-Package([string]$Name) {
    $key = Normalize-Name $Name
    if ($SoftwareCatalog.ContainsKey($key)) { return $SoftwareCatalog[$key] }

    foreach ($candidate in $SoftwareCatalog.Values) {
        if ((Normalize-Name $candidate.Display) -eq $key) {
            return $candidate
        }
    }

    return $null
}

function Get-ChocolateyLocalPackage([string]$PackageId) {
    $choco = Get-Command choco.exe -ErrorAction SilentlyContinue
    if (-not $choco) { return $false }

    $lines = @(& $choco.Source list --local-only --exact $PackageId --limit-output 2>$null)
    foreach ($line in $lines) {
        $parts = ([string]$line) -split '\|', 2
        if ($parts.Count -ge 1 -and $parts[0].Trim() -ieq $PackageId) { return $true }
    }
    return $false
}

function Get-InstalledApplication([string]$DisplayName) {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($root in $roots) {
        foreach ($app in @(Get-ItemProperty $root -ErrorAction SilentlyContinue)) {
            # Uninstall registry hives contain many entries that do not expose
            # DisplayName. Under StrictMode, directly reading a missing property
            # throws; inspect the property bag first.
            $displayProp = $app.PSObject.Properties['DisplayName']
            if ($null -eq $displayProp) { continue }
            $display = [string]$displayProp.Value
            if ([string]::IsNullOrWhiteSpace($display)) { continue }

            if ($display -ieq $DisplayName -or $display -like "$DisplayName *") {
                $versionProp = $app.PSObject.Properties['DisplayVersion']
                $quietProp = $app.PSObject.Properties['QuietUninstallString']
                $uninstallProp = $app.PSObject.Properties['UninstallString']
                [pscustomobject]@{
                    DisplayName          = $display
                    DisplayVersion       = if ($null -ne $versionProp) { [string]$versionProp.Value } else { '' }
                    QuietUninstallString = if ($null -ne $quietProp) { [string]$quietProp.Value } else { '' }
                    UninstallString      = if ($null -ne $uninstallProp) { [string]$uninstallProp.Value } else { '' }
                }
            }
        }
    }
}

function Get-ChromeVersions {
    $paths = @(
        (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe')
    )
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($path in $paths) {
        if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            try {
                $ver = [version](Get-Item -LiteralPath $path).VersionInfo.ProductVersion
                $found.Add([pscustomobject]@{ Path=$path; Version=$ver })
            } catch { }
        }
    }
    return @($found | Sort-Object Version -Descending)
}

function Get-ChromeVersion {
    $versions = @(Get-ChromeVersions)
    if ($versions.Count -gt 0) { return $versions[0].Version }
    return $null
}

function Invoke-ChromeUpdateTasks {
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'GoogleUpdateTask*' })
    foreach ($task in $tasks) {
        try {
            Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
            Write-GuiLog "Triggered Google updater task: $($task.TaskPath)$($task.TaskName)"
        } catch {
            Write-GuiLog "Could not trigger Google updater task $($task.TaskName): $($_.Exception.Message)"
        }
    }
    if ($tasks.Count -gt 0) { Start-Sleep -Seconds 8 }
}

function Invoke-MsiUninstall([string]$UninstallString) {
    $match = [regex]::Match($UninstallString, '(?i)\{[0-9a-f-]+\}')
    if (-not $match.Success) { throw "Could not determine MSI product code from uninstall string: $UninstallString" }
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/x',$match.Value,'/qn','/norestart') -Wait -PassThru
    if ($proc.ExitCode -notin @(0,1605,3010,1641)) { throw "MSI uninstall failed with exit code $($proc.ExitCode)." }
}

function Invoke-RegisteredUninstall([string]$UninstallCommand) {
    if ([string]::IsNullOrWhiteSpace($UninstallCommand)) {
        throw 'No registered uninstall command was available.'
    }

    $cmd = $UninstallCommand.Trim()
    $exe = $null
    $args = $null

    if ($cmd.StartsWith('"')) {
        $m = [regex]::Match($cmd, '^"([^"]+)"\s*(.*)$')
        if (-not $m.Success) { throw "Could not parse registered uninstall command: $UninstallCommand" }
        $exe = $m.Groups[1].Value
        $args = $m.Groups[2].Value
    } else {
        $m = [regex]::Match($cmd, '^([^\s]+)\s*(.*)$')
        if (-not $m.Success) { throw "Could not parse registered uninstall command: $UninstallCommand" }
        $exe = $m.Groups[1].Value
        $args = $m.Groups[2].Value
    }

    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw "Registered uninstaller was not found: $exe"
    }

    Write-GuiLog "Running the registered uninstaller: $UninstallCommand"
    $argList = if ([string]::IsNullOrWhiteSpace($args)) { @() } else { @($args) }
    $proc = Start-Process -FilePath $exe -ArgumentList $argList -Wait -PassThru
    if ($proc.ExitCode -notin @(0,3010,1641)) {
        throw "Registered uninstaller failed with exit code $($proc.ExitCode)."
    }
}

function Update-WiresharkWithReplacement([string]$PackageId, [bool]$PackageManagedByChocolatey) {
    $apps = @(Get-InstalledApplication 'Wireshark')
    if ($apps.Count -eq 0) {
        if ($PackageManagedByChocolatey) {
            Write-GuiLog 'Wireshark has Chocolatey package state but no uninstall registry entry. Removing the Chocolatey package state before reinstalling.'
            $out = @(& choco.exe uninstall $PackageId -y --no-progress 2>&1)
            $rc = $LASTEXITCODE
            if ($rc -ne 0) { throw "Chocolatey Wireshark uninstall failed with exit code ${rc}: $($out -join ' ')" }
        } else {
            Write-GuiLog 'Wireshark was not found in Windows uninstall registry; installing the current Chocolatey package.'
        }
    } elseif ($PackageManagedByChocolatey) {
        Write-GuiLog 'Wireshark is Chocolatey-managed. Uninstalling the existing Chocolatey package before reinstalling the current package.'
        $out = @(& choco.exe uninstall $PackageId -y --no-progress 2>&1)
        $rc = $LASTEXITCODE
        if ($rc -ne 0) { throw "Chocolatey Wireshark uninstall failed with exit code ${rc}: $($out -join ' ')" }
    } else {
        foreach ($app in $apps | Select-Object -First 1) {
            $uninstall = [string]$app.QuietUninstallString
            if ([string]::IsNullOrWhiteSpace($uninstall)) { $uninstall = [string]$app.UninstallString }
            if ([string]::IsNullOrWhiteSpace($uninstall)) {
                throw 'Wireshark is installed, but no registered uninstaller command was found.'
            }

            Write-GuiLog "Removing existing Wireshark $($app.DisplayVersion) before the requested update."
            if ($uninstall -match '(?i)msiexec(?:\.exe)?') {
                Invoke-MsiUninstall $uninstall
            } else {
                # Wireshark commonly registers its own quiet uninstaller rather than
                # an MSI command. Execute the exact registered command instead of
                # guessing replacement switches or paths.
                Invoke-RegisteredUninstall $uninstall
            }

            Start-Sleep -Seconds 2
            $stillThere = @(Get-InstalledApplication 'Wireshark')
            if ($stillThere.Count -gt 0) {
                throw 'Wireshark still appears installed after the registered uninstaller completed.'
            }
        }
    }

    $out = @(& choco.exe install $PackageId -y --no-progress 2>&1)
    $rc = $LASTEXITCODE
    if ($rc -ne 0) { throw "Chocolatey Wireshark reinstall failed with exit code ${rc}: $($out -join ' ')" }
    Write-GuiLog 'Wireshark installed/updated successfully after a clean replacement.'
}

function Ensure-Chocolatey {
    $c = Get-Command choco.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }

    Write-GuiLog 'WinGet unavailable. Installing Chocolatey for this software operation...'
    $installScript = Invoke-RestMethod -Uri 'https://community.chocolatey.org/install.ps1' -UseBasicParsing
    Invoke-Expression $installScript
    $env:Path = "$env:ALLUSERSPROFILE\chocolatey\bin;$env:Path"

    $c = Get-Command choco.exe -ErrorAction SilentlyContinue
    if (-not $c) { throw 'Chocolatey installation completed but choco.exe was not found.' }
    return $c.Source
}

function Install-GoogleChromeOfficial {
    $url = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
    $msiPath = Join-Path $TempRoot 'googlechromestandaloneenterprise64.msi'
    $before = Get-ChromeVersion

    Write-GuiLog 'WinGet unavailable. Using the official Google Chrome Enterprise 64-bit MSI.'
    if ($before) { Write-GuiLog "Detected installed Google Chrome version: $before" } else { Write-GuiLog 'No existing Google Chrome executable was detected before installation.' }
    Write-GuiLog "Downloading Chrome from $url"
    Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing

    if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf) -or
        (Get-Item -LiteralPath $msiPath).Length -le 0) {
        throw 'Google Chrome MSI download failed or was empty.'
    }

    $sig = Get-AuthenticodeSignature -FilePath $msiPath
    if ($sig.Status -ne 'Valid') {
        throw "Google Chrome MSI signature validation failed: $($sig.Status)."
    }

    $subject = [string]$sig.SignerCertificate.Subject
    if ($subject -notmatch '(?i)Google') {
        throw "Google Chrome MSI signer did not identify Google: $subject"
    }

    Write-GuiLog 'Google Chrome MSI signature validated.'
    $args = @('/i', "`"$msiPath`"", '/qn', '/norestart')
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru
    if ($proc.ExitCode -notin @(0,1638,3010)) {
        throw "Google Chrome MSI installation failed with exit code $($proc.ExitCode)."
    }
    if ($proc.ExitCode -eq 1638) { Write-GuiLog 'Google Chrome reports that a more recent product version is already installed; continuing with version verification.' }

    Start-Sleep -Seconds 2
    $after = Get-ChromeVersion
    if ($before -and $after -le $before) {
        Write-GuiLog 'The MSI did not produce a newer detected Chrome executable. Triggering installed Google Update tasks and checking again.'
        Invoke-ChromeUpdateTasks
        $after = Get-ChromeVersion
    }
    if ($after) {
        if ($before -and $after -gt $before) {
            Write-GuiLog "Google Chrome updated: $before -> $after"
        } elseif ($before -and $after -eq $before) {
            Write-GuiLog "Google Chrome remains at version $after; the official MSI completed but did not report a newer executable version."
            Write-GuiLog 'This usually means Chrome was already current or the existing installation is a separate per-user build.'
        } elseif (-not $before) {
            Write-GuiLog "Google Chrome installed at version $after."
        } else {
            Write-GuiLog "Google Chrome installer completed; detected executable version $after."
        }
    } else {
        Write-GuiLog 'Google Chrome MSI installer completed, but chrome.exe version could not be detected afterward.'
    }
}

function Install-Or-Update([object]$Item) {
    $pkg = Resolve-Package $Item.Name
    if (-not $pkg) { throw "No safe package mapping exists for '$($Item.Name)'. Refusing to guess." }

    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue

    if ($winget) {
        $id = $pkg.Winget
        try {
            Write-GuiLog "Using WinGet: $($Item.Name) [$id]"
            $installed = $false
            $listOut = @(& $winget.Source list --id $id --exact --source winget --accept-source-agreements 2>&1)
            $listRc = $LASTEXITCODE
            if ($listRc -eq 0 -and ($listOut -join "`n") -match [regex]::Escape($id)) { $installed = $true }

            if (-not $installed) {
                Write-GuiLog "Installing '$($Item.Name)' with WinGet."
                $out = @(& $winget.Source install --id $id --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1)
                $rc = $LASTEXITCODE
                if ($rc -ne 0) { throw "WinGet install failed with exit code ${rc}: $($out -join ' ')" }
            }
            elseif ($Item.UpdateRequired) {
                Write-GuiLog "Updating '$($Item.Name)' with WinGet."
                $out = @(& $winget.Source upgrade --id $id --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1)
                $rc = $LASTEXITCODE
                if ($rc -notin @(0,1)) { throw "WinGet upgrade failed with exit code ${rc}: $($out -join ' ')" }
                if ($rc -eq 1) { Write-GuiLog "'$($Item.Name)' is already current or WinGet reported no applicable upgrade." }
            }
            else {
                Write-GuiLog "'$($Item.Name)' is already installed; README only requires presence."
            }

            return
        } catch {
            Write-GuiLog "WinGet operation failed for $($Item.Name); falling back to Chocolatey/official installer. $($_.Exception.Message)"
        }
    }

    # Google Chrome is kept on the official, Google-signed MSI path when WinGet
    # cannot complete the request. Google documents this MSI as the enterprise
    # Windows installer and uses /i for major upgrades.
    if ($Item.Name -eq 'Google Chrome') {
        $existingChrome = Get-ChromeVersion
        if ($Item.UpdateRequired -or -not $existingChrome) {
            Install-GoogleChromeOfficial
        } else {
            Write-GuiLog "Google Chrome is already installed at version $existingChrome; README does not require an update for this item."
        }
        return
    }

    $null = Ensure-Chocolatey
    $installedByChoco = Get-ChocolateyLocalPackage -PackageId $pkg.Choco
    $installedByWindows = $null -ne (Get-InstalledApplication $Item.Name | Select-Object -First 1)
    $installed = $installedByChoco -or $installedByWindows

    if (-not $installed) {
        Write-GuiLog "Installing '$($Item.Name)' with Chocolatey package '$($pkg.Choco)'."
        $out = @(& choco.exe install $pkg.Choco -y --no-progress 2>&1)
        $rc = $LASTEXITCODE
        if ($rc -ne 0) { throw "Chocolatey install failed with exit code ${rc}: $($out -join ' ')" }
    }
    elseif ($Item.UpdateRequired) {
        if ($Item.Name -eq 'Wireshark') {
            Update-WiresharkWithReplacement -PackageId $pkg.Choco -PackageManagedByChocolatey:$installedByChoco
        } else {
            Write-GuiLog "Updating '$($Item.Name)' with Chocolatey package '$($pkg.Choco)'."
            $out = @(& choco.exe upgrade $pkg.Choco -y --no-progress 2>&1)
            $rc = $LASTEXITCODE
            if ($rc -ne 0) { throw "Chocolatey upgrade failed with exit code ${rc}: $($out -join ' ')" }
        }
    }
    else {
        Write-GuiLog "'$($Item.Name)' is already installed; README only requires presence."
    }
}

function Set-DefaultBrowser([string]$BrowserName) {
    $candidate=$null
    foreach ($root in @('HKLM:\SOFTWARE\RegisteredApplications','HKLM:\SOFTWARE\WOW6432Node\RegisteredApplications')) {
        if (-not (Test-Path $root)) { continue }
        $props=Get-ItemProperty $root -ErrorAction SilentlyContinue
        foreach ($p in $props.PSObject.Properties) {
            $cap="HKLM:\$($p.Value)"
            $app=[string]$p.Name
            try { $an=[string](Get-ItemProperty $cap -Name ApplicationName -ErrorAction Stop).ApplicationName } catch { $an=$app }
            if (($app -match [regex]::Escape($BrowserName)) -or ($an -match [regex]::Escape($BrowserName))) {
                $candidate=[pscustomobject]@{App=$app;Cap=$cap}; break
            }
        }
        if ($candidate) { break }
    }
    if (-not $candidate) { throw "Could not find registered default-app capabilities for $BrowserName." }

    $url="$($candidate.Cap)\URLAssociations"
    $file="$($candidate.Cap)\FileAssociations"
    $ass=@()
    foreach ($key in @($url,$file)) {
        if (-not (Test-Path $key)) { continue }
        $p=Get-ItemProperty $key
        foreach ($id in @('http','https','.htm','.html')) {
            try { $prog=[string]$p.$id } catch { $prog='' }
            if ($prog) { $ass += ('  <Association Identifier="{0}" ProgId="{1}" ApplicationName="{2}" />' -f $id, $prog, $candidate.App) }
        }
    }
    if (-not $ass) { throw "No HTTP/HTTPS/HTML associations were found for $BrowserName." }
    $xmlPath=Join-Path $TempRoot ('DefaultBrowser-'+(Normalize-Name $BrowserName)+'.xml')
    @('<?xml version="1.0" encoding="UTF-8"?>','<DefaultAssociations>')+$ass+@('</DefaultAssociations>') | Set-Content $xmlPath -Encoding UTF8
    & "$env:SystemRoot\System32\Dism.exe" /Online "/Import-DefaultAppAssociations:$xmlPath" 2>&1 | ForEach-Object { Write-GuiLog ([string]$_) }
    if ($LASTEXITCODE -ne 0) { throw "DISM failed with exit code $LASTEXITCODE." }
    Write-GuiLog "$BrowserName configured as the Windows default association set for future user sign-ins."
}

function Resolve-Service([string]$Name) {
    $aliases = @{
        'filesharesmb'                 = 'LanmanServer'
        'servermessageblocksmb'        = 'LanmanServer'
        'smb'                          = 'LanmanServer'
        'remotedesktopprotocolrdp'     = 'TermService'
        'remotedesktopservicesrdp'     = 'TermService'
        'rdp'                          = 'TermService'
        'windowsremotemanagementwinrm' = 'WinRM'
        'winrm'                        = 'WinRM'
        'windowseventlog'              = 'EventLog'
        'windowsdefenderfirewall'      = 'mpssvc'
        'printspooler'                 = 'Spooler'
        'taskscheduler'                = 'Schedule'
    }

    $requested = $Name.Trim()
    $requestedKey = Normalize-Name $requested

    if ($aliases.ContainsKey($requestedKey)) {
        $aliasName = $aliases[$requestedKey]
        $alias = @(Get-Service -Name $aliasName -ErrorAction SilentlyContinue)
        if ($alias.Count -eq 1) {
            Write-GuiLog "Mapped README Critical Service '$requested' to Windows service '$($alias[0].Name)'."
            return $alias[0]
        }
        throw "Mapped Critical service '$Name' to Windows service '$aliasName', but that service was not found."
    }

    $s=@(Get-Service -Name $requested -ErrorAction SilentlyContinue)
    if ($s.Count -eq 1) { return $s[0] }
    $s=@(Get-Service -DisplayName $requested -ErrorAction SilentlyContinue)
    if ($s.Count -eq 1) { return $s[0] }

    $s=@(Get-Service | Where-Object { (Normalize-Name $_.Name) -eq $requestedKey -or (Normalize-Name $_.DisplayName) -eq $requestedKey })
    if ($s.Count -eq 1) { return $s[0] }
    if ($s.Count -gt 1) { throw "Service '$Name' matched multiple services; refusing to guess." }
    throw "Critical service '$Name' was not found."
}

function Ensure-Service([string]$Name) {
    $s=Resolve-Service $Name
    if ($s.Status -ne 'Running') {
        $c=Get-CimInstance Win32_Service -Filter "Name='$($s.Name.Replace("'","''"))'"
        if ($c.StartMode -eq 'Disabled') { Set-Service -Name $s.Name -StartupType Automatic }
        Start-Service -Name $s.Name
    }
    $s=Get-Service -Name $s.Name
    if ($s.Status -ne 'Running') { throw "Service did not reach Running state." }
    Write-GuiLog "Critical service OK: $Name -> $($s.Name)"
}

function Launch-Purge {
    if (-not (Test-Path -LiteralPath $PurgeScriptPath -PathType Leaf)) {
        [Windows.Forms.MessageBox]::Show("Could not find:`n$PurgeScriptPath`n`nPlace Harbingers-Purge.ps1 beside this toolkit or pass -PurgeScriptPath.",'Harbinger''s Purge',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return
    }
    # Keep the executor window open so the final summary, report path, and any errors remain visible.
    $executorArgs = @('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PurgeScriptPath`"")
    Start-Process powershell.exe -Verb RunAs -ArgumentList $executorArgs | Out-Null
}

function Show-InstallerGui {
    $form=New-Object Windows.Forms.Form
    $form.Text="Harbinger's Purge - Installer / Updater v1.9"
    $form.Size=New-Object Drawing.Size(980,720)
    $form.StartPosition='CenterScreen'

    $top=New-Object Windows.Forms.Panel; $top.Dock='Top'; $top.Height=70
    $path=New-Object Windows.Forms.TextBox; $path.Left=10; $path.Top=12; $path.Width=720
    $browse=New-Object Windows.Forms.Button; $browse.Text='Browse README'; $browse.Left=740; $browse.Top=10; $browse.Width=105
    $scan=New-Object Windows.Forms.Button; $scan.Text='Scan README'; $scan.Left=850; $scan.Top=10; $scan.Width=105
    $top.Controls.AddRange(@($path,$browse,$scan)); $form.Controls.Add($top)

    $softwareLabel=New-Object Windows.Forms.Label; $softwareLabel.Text='README-requested browsers / applications'; $softwareLabel.Left=10; $softwareLabel.Top=82; $softwareLabel.Width=500
    $software=New-Object Windows.Forms.CheckedListBox; $software.Left=10; $software.Top=105; $software.Width=460; $software.Height=390
    $servicesLabel=New-Object Windows.Forms.Label; $servicesLabel.Text='Critical Services'; $servicesLabel.Left=490; $servicesLabel.Top=82; $servicesLabel.Width=300
    $services=New-Object Windows.Forms.CheckedListBox; $services.Left=490; $services.Top=105; $services.Width=465; $services.Height=390
    $form.Controls.AddRange(@($softwareLabel,$software,$servicesLabel,$services))

    $install=New-Object Windows.Forms.Button; $install.Text='Install / Update Selected'; $install.Left=10; $install.Top=510; $install.Width=220; $install.Height=40
    $svcBtn=New-Object Windows.Forms.Button; $svcBtn.Text='Apply Selected Services'; $svcBtn.Left=240; $svcBtn.Top=510; $svcBtn.Width=210; $svcBtn.Height=40
    $all=New-Object Windows.Forms.Button; $all.Text='Select All'; $all.Left=460; $all.Top=510; $all.Width=120; $all.Height=40
    $clear=New-Object Windows.Forms.Button; $clear.Text='Clear'; $clear.Left=590; $clear.Top=510; $clear.Width=120; $clear.Height=40
    $close=New-Object Windows.Forms.Button; $close.Text='Close'; $close.Left=835; $close.Top=510; $close.Width=120; $close.Height=40
    $form.Controls.AddRange(@($install,$svcBtn,$all,$clear,$close))

    $script:LogBox=New-Object Windows.Forms.TextBox; $script:LogBox.Multiline=$true; $script:LogBox.ScrollBars='Vertical'; $script:LogBox.ReadOnly=$true; $script:LogBox.Left=10; $script:LogBox.Top=565; $script:LogBox.Width=945; $script:LogBox.Height=105
    $form.Controls.Add($script:LogBox)

    $browse.Add_Click({
        $d=New-Object Windows.Forms.OpenFileDialog; $d.Filter='README/text files (*.txt;*.md)|*.txt;*.md|All files (*.*)|*.*'
        if ($d.ShowDialog() -eq 'OK') { $path.Text=$d.FileName }
    })

    $scan.Add_Click({
        try {
            $software.Items.Clear(); $services.Items.Clear(); $r=Parse-Requirements (Get-ReadmeText $path.Text)
            foreach ($x in $r.Software) { [void]$software.Items.Add($x) ; $software.SetItemChecked($software.Items.Count-1,$true) }
            foreach ($x in $r.Services) { [void]$services.Items.Add($x); $services.SetItemChecked($services.Items.Count-1,$true) }
            Write-GuiLog "README scan complete: $($r.Software.Count) software/browser requirement(s), $($r.Services.Count) critical service(s)."
            if ($r.Software.Count -gt 0) { Write-GuiLog ('Detected software: ' + (($r.Software | ForEach-Object { $_.Name }) -join ', ')) }
            if ($r.Services.Count -eq 0) { Write-GuiLog 'Critical Services: None (no service changes will be made).' }
        } catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'README scan failed') | Out-Null }
    })

    $install.Add_Click({
        foreach ($x in @($software.CheckedItems)) {
            try {
                Install-Or-Update $x
                if ($x.SetAsDefault) {
                    try { Set-DefaultBrowser $x.Name }
                    catch { Write-GuiLog "Default browser setup skipped/failed for $($x.Name): $($_.Exception.Message)" }
                }
            }
            catch { Write-GuiLog "FAILED: $($x.Name): $($_.Exception.Message)" }
        }
    })

    $svcBtn.Add_Click({ foreach ($x in @($services.CheckedItems)) { try { Ensure-Service ([string]$x) } catch { Write-GuiLog "FAILED SERVICE: $x : $($_.Exception.Message)" } } })
    $all.Add_Click({ for($i=0;$i -lt $software.Items.Count;$i++){ $software.SetItemChecked($i,$true) }; for($i=0;$i -lt $services.Items.Count;$i++){ $services.SetItemChecked($i,$true) } })
    $clear.Add_Click({ for($i=0;$i -lt $software.Items.Count;$i++){ $software.SetItemChecked($i,$false) }; for($i=0;$i -lt $services.Items.Count;$i++){ $services.SetItemChecked($i,$false) } })
    $close.Add_Click({ $form.Close() })

    Write-GuiLog 'Ready. Browse to the CyberPatriot README, then click Scan README.'
    [void]$form.ShowDialog()
}

function MainMenu {
    while ($true) {
        Clear-Host
        Write-Host '============================================================' -ForegroundColor Cyan
        Write-Host "        HARBINGER'S CYBERPATRIOT TOOLKIT" -ForegroundColor Cyan
        Write-Host '============================================================' -ForegroundColor Cyan
        Write-Host ''
        Write-Host '  Enter 1 for Executor' -ForegroundColor White
        Write-Host '  Enter 2 for Installer / Updater (GUI)' -ForegroundColor White
        Write-Host '  Enter 3 for Critical Services (GUI)' -ForegroundColor White
        Write-Host '  Enter 0 to Exit' -ForegroundColor White
        Write-Host ''
        $choice=Read-Host 'Selection'
        switch ($choice) {
            '1' { Launch-Purge; Read-Host 'Press Enter to return to the menu' | Out-Null }
            '2' { Show-InstallerGui }
            '3' {
                [Windows.Forms.MessageBox]::Show('Use Installer / Updater (option 2) to load the README and select the Critical Services. This keeps service changes tied to the README.','Critical Services') | Out-Null
                Show-InstallerGui
            }
            '0' { return }
            default { Write-Host 'Invalid selection.' -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
        }
    }
}

MainMenu
