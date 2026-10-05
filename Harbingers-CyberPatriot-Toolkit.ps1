<#
.SYNOPSIS
    Harbinger's CyberPatriot Toolkit - V2 Modern UI

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
$script:LogBox = $null

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

    # Prefer the Competition Scenario section when present. Some server READMEs
    # arrive through HTML conversion without heading markers, so accept optional
    # '#' characters and an optional colon. If the heading cannot be found,
    # scan the cleaned README using strict requirement-context checks.
    $scenarioStart = -1
    $scenarioEnd = $lines.Count
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '(?i)^\s*#*\s*Competition Scenario\s*:?\s*$') {
            $scenarioStart = $i
            break
        }
    }
    if ($scenarioStart -ge 0) {
        for ($i = $scenarioStart + 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '(?i)^\s*#*\s*(Authorized Administrators(?: and Users)?|Authorized Users)\s*:?\s*$') {
                $scenarioEnd = $i
                break
            }
        }
    }

    $requirementLines = if ($scenarioStart -ge 0) {
        @($lines[$scenarioStart..($scenarioEnd - 1)])
    } else {
        @($lines)
    }

    $browserKeys = @('chrome','googlechrome','firefox','firefoxesr','edge','brave','opera','vivaldi')
    $catalogSeen = @{}

    foreach ($line in $requirementLines) {
        $l = $line.Trim()
        if (-not $l) { continue }

        $update = $l -match '(?i)\b(latest|stable|up[- ]to[- ]date|updated|update|upgrade|kept current|keep .*current|kept up[- ]to[- ]date|keep .*up[- ]to[- ]date)\b'
        $browserLine = $l -match '(?i)\b(default\s+(?:web\s+)?browser|browser(?:\s+for\s+all\s+users)?)\b'
        $softwareLine = $l -match '(?i)\b(?:business\s+software|software|application|applications|program|programs|installed|install|update|updated|upgrade|up[- ]to[- ]date|required|must\s+remain|should\s+remain|keep\s+.*installed)\b'

        foreach ($key in $SoftwareCatalog.Keys) {
            $item = $SoftwareCatalog[$key]
            $display = [string]$item.Display

            $nameHit = $l -match '(?i)(?<![A-Za-z0-9])' + [regex]::Escape($display) + '(?![A-Za-z0-9])'
            $keyHit = $l -match '(?i)(?<![A-Za-z0-9])' + [regex]::Escape($key) + '(?![A-Za-z0-9])'

            if (-not ($nameHit -or $keyHit)) { continue }

            $isBrowser = $browserKeys -contains $key
            # A known product is accepted only when the line looks like a real
            # requirement. This avoids navigation/footer names creating entries.
            if (-not ($browserLine -or $softwareLine)) { continue }

            if (-not $catalogSeen.ContainsKey($key)) {
                $catalogSeen[$key] = $true
                $software.Add([pscustomobject]@{
                    Name           = $display
                    Key            = $key
                    UpdateRequired = [bool]$update
                    Browser        = [bool]$isBrowser
                    SetAsDefault   = [bool]($isBrowser -and $browserLine)
                    Source         = $l
                })
            } else {
                $existing = $software | Where-Object { $_.Key -eq $key } | Select-Object -First 1
                if ($existing) {
                    if ($update) { $existing.UpdateRequired = $true }
                    if ($isBrowser -and $browserLine) { $existing.SetAsDefault = $true }
                    if ($isBrowser) { $existing.Browser = $true }
                }
            }
        }
    }

    # Direct product-name fallback for the two frequent problem cases. This
    # catches phrases such as "the latest stable version of Google Chrome"
    # without preserving that phrase as the package name.
    $flatRelevant = ($requirementLines -join ' ') -replace '\s+', ' '
    if (($flatRelevant -match '(?i)\bGoogle\s+Chrome\b') -and ($flatRelevant -match '(?i)\b(default\s+(?:web\s+)?browser|latest\s+stable|software|required|installed|update|updated)\b') -and (-not $catalogSeen.ContainsKey('chrome'))) {
        $software.Add([pscustomobject]@{
            Name='Google Chrome'; Key='chrome'; UpdateRequired=$true; Browser=$true
            SetAsDefault=[bool]($flatRelevant -match '(?i)\bdefault\s+(?:web\s+)?browser\b')
            Source='README Google Chrome requirement'
        })
    }

    if (($flatRelevant -match '(?i)\bNotepad\+\+\b') -and ($flatRelevant -match '(?i)\b(?:software|required|installed|install|update|updated|upgrade|latest|up[- ]to[- ]date|keep)\b') -and (-not $catalogSeen.ContainsKey('notepadplusplus'))) {
        $software.Add([pscustomobject]@{
            Name='Notepad++'; Key='notepadplusplus'; UpdateRequired=[bool]($flatRelevant -match '(?i)\b(?:updated|update|upgrade|latest|up[- ]to[- ]date)\b')
            Browser=$false; SetAsDefault=$false; Source='README Notepad++ requirement'
        })
    }

    $svcStart = -1
    for ($i = 0; $i -lt $requirementLines.Count; $i++) {
        if ($requirementLines[$i] -match '(?i)^\s*#*\s*Critical Services\s*:\s*(.*)$') {
            $svcStart = $i
            break
        }
    }

    if ($svcStart -ge 0) {
        $header = [regex]::Match($requirementLines[$svcStart], '(?i)^\s*#*\s*Critical Services\s*:\s*(.*)$')
        $inline = [string]$header.Groups[1].Value
        if ($inline -and $inline -notmatch '^(?i:none|n/a)\.?\s*$') {
            foreach ($item in ($inline -split '\s*,\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $services.Add($item)
            }
        }

        for ($i = $svcStart + 1; $i -lt $requirementLines.Count; $i++) {
            $svcLine = $requirementLines[$i].Trim()
            if ($svcLine -match '(?i)^\s*#*\s*(Authorized Administrators(?: and Users)?|Authorized Users|Competition Guidelines|Forensics Questions|ANSWER KEY|REMINDERS)\s*:?\s*$') { break }
            if ($svcLine -match '^\s*#') { break }
            if ($svcLine -match '^\s*[-*]\s*(.+?)\s*$') {
                $serviceName = $Matches[1].Trim()
                if ($serviceName -and $serviceName -notmatch '^(?i:none|n/a)\.?$') {
                    $services.Add($serviceName)
                }
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

    if ((-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) -or ((Get-Item -LiteralPath $msiPath).Length -le 0)) {
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
    $s=@(Get-Service -Name $Name -ErrorAction SilentlyContinue)
    if ($s.Count -eq 1) { return $s[0] }
    $s=@(Get-Service -DisplayName $Name -ErrorAction SilentlyContinue)
    if ($s.Count -eq 1) { return $s[0] }
    $n=Normalize-Name $Name
    $s=@(Get-Service | Where-Object { (Normalize-Name $_.Name) -eq $n -or (Normalize-Name $_.DisplayName) -eq $n })
    if ($s.Count -eq 1) { return $s[0] }
    if ($s.Count -gt 1) { throw "Service '$Name' matched multiple services." }
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

# -----------------------------------------------------------------------------
# Harbinger's Purge - Modern Command Center UI
# -----------------------------------------------------------------------------

function New-HarbingerPanel {
    param(
        [int]$Left,
        [int]$Top,
        [int]$Width,
        [int]$Height,
        [System.Drawing.Color]$BackColor
    )
    $p = New-Object Windows.Forms.Panel
    $p.Left = $Left
    $p.Top = $Top
    $p.Width = $Width
    $p.Height = $Height
    $p.BackColor = $BackColor
    return $p
}

function New-HarbingerLabel {
    param(
        [string]$Text,
        [int]$Left,
        [int]$Top,
        [int]$Width,
        [int]$Height,
        [int]$Size = 10,
        [System.Drawing.Color]$ForeColor = ([System.Drawing.Color]::White),
        [bool]$Bold = $false
    )
    $l = New-Object Windows.Forms.Label
    $l.Text = $Text
    $l.Left = $Left
    $l.Top = $Top
    $l.Width = $Width
    $l.Height = $Height
    $l.ForeColor = $ForeColor
    $style = [System.Drawing.FontStyle]::Regular
    if ($Bold) { $style = [System.Drawing.FontStyle]::Bold }
    $l.Font = New-Object System.Drawing.Font('Segoe UI', $Size, $style)
    $l.AutoEllipsis = $true
    return $l
}

function New-HarbingerButton {
    param(
        [string]$Text,
        [int]$Left,
        [int]$Top,
        [int]$Width,
        [int]$Height,
        [scriptblock]$OnClick,
        [System.Drawing.Color]$BackColor = ([System.Drawing.Color]::FromArgb(31,41,55)),
        [System.Drawing.Color]$HoverColor = ([System.Drawing.Color]::FromArgb(45,55,72)),
        [System.Drawing.Color]$ForeColor = ([System.Drawing.Color]::White),
        [int]$FontSize = 10
    )
    $b = New-Object Windows.Forms.Button
    $b.Text = $Text
    $b.Left = $Left
    $b.Top = $Top
    $b.Width = $Width
    $b.Height = $Height
    $b.FlatStyle = [Windows.Forms.FlatStyle]::Flat
    $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $BackColor
    $b.ForeColor = $ForeColor
    $b.Font = New-Object System.Drawing.Font('Segoe UI Semibold', $FontSize, [System.Drawing.FontStyle]::Bold)
    $b.Cursor = [Windows.Forms.Cursors]::Hand
    $b.UseVisualStyleBackColor = $false
    $b.Tag = [pscustomobject]@{ Normal = $BackColor; Hover = $HoverColor }
    $b.Add_MouseEnter({ param($sender) $sender.BackColor = $sender.Tag.Hover })
    $b.Add_MouseLeave({ param($sender) $sender.BackColor = $sender.Tag.Normal })
    if ($null -ne $OnClick) { $b.Add_Click($OnClick) }
    return $b
}

function Add-HarbingerSectionTitle {
    param(
        [Windows.Forms.Control]$Parent,
        [string]$Text,
        [int]$Left,
        [int]$Top,
        [int]$Width
    )
    $title = New-HarbingerLabel -Text $Text -Left $Left -Top $Top -Width $Width -Height 24 -Size 11 -ForeColor ([System.Drawing.Color]::FromArgb(148,163,184)) -Bold $true
    $Parent.Controls.Add($title)
    return $title
}

function Get-HarbingerSystemSummary {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $ramGb = [math]::Round(([double]$os.TotalVisibleMemorySize / 1MB), 1)
        return [pscustomobject]@{
            Caption = [string]$os.Caption
            Build = [string]$os.BuildNumber
            Computer = [string]$env:COMPUTERNAME
            User = [string]$env:USERNAME
            Memory = "$ramGb GB"
        }
    } catch {
        return [pscustomobject]@{
            Caption = 'Windows'
            Build = 'Unknown'
            Computer = [string]$env:COMPUTERNAME
            User = [string]$env:USERNAME
            Memory = 'Unknown'
        }
    }
}

function Show-ReportsWindow {
    $report = Join-Path $env:USERPROFILE 'Desktop\Harbingers-Purge-Report.txt'
    $transcript = 'C:\ProgramData\HarbingersPurge\Harbingers-Purge-Transcript.txt'
    $existing = @()
    if (Test-Path -LiteralPath $report -PathType Leaf) { $existing += $report }
    if (Test-Path -LiteralPath $transcript -PathType Leaf) { $existing += $transcript }

    if ($existing.Count -eq 0) {
        [Windows.Forms.MessageBox]::Show('No Harbinger reports have been found yet. Run the Purge executor first.','Harbinger Reports',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }

    foreach ($path in $existing) {
        try {
            Start-Process -FilePath 'notepad.exe' -ArgumentList @($path) | Out-Null
        } catch {
            Start-Process -FilePath 'explorer.exe' -ArgumentList @('/select,', $path) | Out-Null
        }
    }
}

function Show-ModernInstallerGui {
    param([switch]$FocusServices)

    $bg = [System.Drawing.Color]::FromArgb(11,16,25)
    $surface = [System.Drawing.Color]::FromArgb(17,24,39)
    $surface2 = [System.Drawing.Color]::FromArgb(22,31,46)
    $border = [System.Drawing.Color]::FromArgb(51,65,85)
    $text = [System.Drawing.Color]::FromArgb(241,245,249)
    $muted = [System.Drawing.Color]::FromArgb(148,163,184)
    $accent = [System.Drawing.Color]::FromArgb(34,211,238)
    $accent2 = [System.Drawing.Color]::FromArgb(99,102,241)
    $good = [System.Drawing.Color]::FromArgb(74,222,128)

    $form = New-Object Windows.Forms.Form
    $form.Text = "Harbinger's Purge - Installer / Updater"
    $form.ClientSize = New-Object Drawing.Size(1180,760)
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object Drawing.Size(1180,760)
    $form.BackColor = $bg
    $form.ForeColor = $text
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.MaximizeBox = $false

    $header = New-HarbingerPanel -Left 0 -Top 0 -Width 1180 -Height 82 -BackColor $surface
    $form.Controls.Add($header)
    $header.Controls.Add((New-HarbingerLabel -Text 'HARBINGER''S PURGE' -Left 26 -Top 13 -Width 520 -Height 34 -Size 20 -ForeColor $text -Bold $true))
    $header.Controls.Add((New-HarbingerLabel -Text 'INSTALLER / UPDATER' -Left 28 -Top 48 -Width 280 -Height 22 -Size 9 -ForeColor $accent -Bold $true))

    $back = New-HarbingerButton -Text '<  COMMAND CENTER' -Left 940 -Top 23 -Width 205 -Height 38 -OnClick {
        $form.Close()
        Show-ModernDashboard
    } -BackColor $surface2 -HoverColor $border -ForeColor $text -FontSize 9
    $header.Controls.Add($back)

    $readmePanel = New-HarbingerPanel -Left 20 -Top 98 -Width 1140 -Height 88 -BackColor $surface
    $form.Controls.Add($readmePanel)
    Add-HarbingerSectionTitle -Parent $readmePanel -Text 'SCENARIO README' -Left 18 -Top 10 -Width 250 | Out-Null

    $path = New-Object Windows.Forms.TextBox
    $path.Left = 18
    $path.Top = 37
    $path.Width = 820
    $path.Height = 30
    $path.BackColor = [System.Drawing.Color]::FromArgb(15,23,42)
    $path.ForeColor = $text
    $path.BorderStyle = [Windows.Forms.BorderStyle]::FixedSingle
    $path.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $readmePanel.Controls.Add($path)

    $browse = New-HarbingerButton -Text 'BROWSE' -Left 850 -Top 35 -Width 125 -Height 32 -OnClick {
        $d = New-Object Windows.Forms.OpenFileDialog
        $d.Filter = 'README/text files (*.txt;*.md;*.html)|*.txt;*.md;*.html|All files (*.*)|*.*'
        if ($d.ShowDialog() -eq 'OK') { $path.Text = $d.FileName }
    } -BackColor $surface2 -HoverColor $border -FontSize 9
    $readmePanel.Controls.Add($browse)

    $scan = New-HarbingerButton -Text 'SCAN README' -Left 985 -Top 35 -Width 135 -Height 32 -OnClick {
        try {
            $software.Items.Clear()
            $services.Items.Clear()
            $r = Parse-Requirements (Get-ReadmeText $path.Text)
            foreach ($x in @($r.Software)) {
                [void]$software.Items.Add($x)
                $software.SetItemChecked($software.Items.Count - 1, $true)
            }
            foreach ($x in @($r.Services)) {
                [void]$services.Items.Add($x)
                $services.SetItemChecked($services.Items.Count - 1, $true)
            }
            $softwareCount.Text = [string]$r.Software.Count
            $serviceCount.Text = [string]$r.Services.Count
            $statusValue.Text = 'README SCANNED'
            $statusValue.ForeColor = $good
            Write-GuiLog "README scan complete: $($r.Software.Count) software/browser requirement(s), $($r.Services.Count) critical service(s)."
            if ($r.Services.Count -eq 0) {
                Write-GuiLog 'Critical Services: None (no service changes will be made).'
            }
        } catch {
            $statusValue.Text = 'SCAN FAILED'
            $statusValue.ForeColor = [System.Drawing.Color]::FromArgb(248,113,113)
            [Windows.Forms.MessageBox]::Show($_.Exception.Message,'README scan failed',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    } -BackColor $accent2 -HoverColor ([System.Drawing.Color]::FromArgb(79,82,190)) -FontSize 9
    $readmePanel.Controls.Add($scan)

    $softwareCard = New-HarbingerPanel -Left 20 -Top 202 -Width 560 -Height 318 -BackColor $surface
    $serviceCard = New-HarbingerPanel -Left 600 -Top 202 -Width 560 -Height 318 -BackColor $surface
    $form.Controls.Add($softwareCard)
    $form.Controls.Add($serviceCard)

    Add-HarbingerSectionTitle -Parent $softwareCard -Text 'SOFTWARE / BROWSERS' -Left 18 -Top 12 -Width 350 | Out-Null
    $softwareCount = New-HarbingerLabel -Text '0' -Left 480 -Top 9 -Width 50 -Height 30 -Size 14 -ForeColor $accent -Bold $true
    $softwareCount.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $softwareCard.Controls.Add($softwareCount)

    $software = New-Object Windows.Forms.CheckedListBox
    $software.Left = 18
    $software.Top = 42
    $software.Width = 524
    $software.Height = 255
    $software.BackColor = [System.Drawing.Color]::FromArgb(15,23,42)
    $software.ForeColor = $text
    $software.BorderStyle = [Windows.Forms.BorderStyle]::FixedSingle
    $software.CheckOnClick = $true
    $software.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $software.IntegralHeight = $false
    $softwareCard.Controls.Add($software)

    Add-HarbingerSectionTitle -Parent $serviceCard -Text 'CRITICAL SERVICES' -Left 18 -Top 12 -Width 350 | Out-Null
    $serviceCount = New-HarbingerLabel -Text '0' -Left 480 -Top 9 -Width 50 -Height 30 -Size 14 -ForeColor $accent -Bold $true
    $serviceCount.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $serviceCard.Controls.Add($serviceCount)

    $services = New-Object Windows.Forms.CheckedListBox
    $services.Left = 18
    $services.Top = 42
    $services.Width = 524
    $services.Height = 255
    $services.BackColor = [System.Drawing.Color]::FromArgb(15,23,42)
    $services.ForeColor = $text
    $services.BorderStyle = [Windows.Forms.BorderStyle]::FixedSingle
    $services.CheckOnClick = $true
    $services.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $services.IntegralHeight = $false
    $serviceCard.Controls.Add($services)

    $actionPanel = New-HarbingerPanel -Left 20 -Top 536 -Width 1140 -Height 64 -BackColor $surface2
    $form.Controls.Add($actionPanel)

    $install = New-HarbingerButton -Text 'INSTALL / UPDATE SELECTED' -Left 14 -Top 13 -Width 230 -Height 38 -OnClick {
        foreach ($x in @($software.CheckedItems)) {
            try {
                Install-Or-Update $x
                if ($x.SetAsDefault) {
                    try { Set-DefaultBrowser $x.Name }
                    catch { Write-GuiLog "Default browser setup skipped/failed for $($x.Name): $($_.Exception.Message)" }
                }
            } catch {
                Write-GuiLog "FAILED: $($x.Name): $($_.Exception.Message)"
            }
        }
    } -BackColor ([System.Drawing.Color]::FromArgb(22,163,74)) -HoverColor ([System.Drawing.Color]::FromArgb(21,128,61)) -FontSize 9
    $actionPanel.Controls.Add($install)

    $svcBtn = New-HarbingerButton -Text 'APPLY CRITICAL SERVICES' -Left 252 -Top 13 -Width 210 -Height 38 -OnClick {
        foreach ($x in @($services.CheckedItems)) {
            try { Ensure-Service ([string]$x) }
            catch { Write-GuiLog "FAILED SERVICE: $x : $($_.Exception.Message)" }
        }
    } -BackColor ([System.Drawing.Color]::FromArgb(79,70,229)) -HoverColor ([System.Drawing.Color]::FromArgb(67,56,202)) -FontSize 9
    $actionPanel.Controls.Add($svcBtn)

    $all = New-HarbingerButton -Text 'SELECT ALL' -Left 474 -Top 13 -Width 125 -Height 38 -OnClick {
        for ($i = 0; $i -lt $software.Items.Count; $i++) { $software.SetItemChecked($i, $true) }
        for ($i = 0; $i -lt $services.Items.Count; $i++) { $services.SetItemChecked($i, $true) }
    } -BackColor $surface -HoverColor $border -FontSize 9
    $actionPanel.Controls.Add($all)

    $clear = New-HarbingerButton -Text 'CLEAR' -Left 610 -Top 13 -Width 100 -Height 38 -OnClick {
        for ($i = 0; $i -lt $software.Items.Count; $i++) { $software.SetItemChecked($i, $false) }
        for ($i = 0; $i -lt $services.Items.Count; $i++) { $services.SetItemChecked($i, $false) }
    } -BackColor $surface -HoverColor $border -FontSize 9
    $actionPanel.Controls.Add($clear)

    $close = New-HarbingerButton -Text 'CLOSE' -Left 1020 -Top 13 -Width 105 -Height 38 -OnClick { $form.Close() } -BackColor $surface -HoverColor $border -FontSize 9
    $actionPanel.Controls.Add($close)

    $logPanel = New-HarbingerPanel -Left 20 -Top 616 -Width 1140 -Height 128 -BackColor $surface
    $form.Controls.Add($logPanel)
    Add-HarbingerSectionTitle -Parent $logPanel -Text 'ACTIVITY / LIVE LOG' -Left 18 -Top 8 -Width 300 | Out-Null

    $statusValue = New-HarbingerLabel -Text 'READY' -Left 935 -Top 8 -Width 180 -Height 24 -Size 9 -ForeColor $accent -Bold $true
    $statusValue.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $logPanel.Controls.Add($statusValue)

    $script:LogBox = New-Object Windows.Forms.TextBox
    $script:LogBox.Multiline = $true
    $script:LogBox.ScrollBars = 'Vertical'
    $script:LogBox.ReadOnly = $true
    $script:LogBox.Left = 18
    $script:LogBox.Top = 34
    $script:LogBox.Width = 1104
    $script:LogBox.Height = 80
    $script:LogBox.BackColor = [System.Drawing.Color]::FromArgb(2,6,23)
    $script:LogBox.ForeColor = [System.Drawing.Color]::FromArgb(203,213,225)
    $script:LogBox.BorderStyle = [Windows.Forms.BorderStyle]::FixedSingle
    $script:LogBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    $logPanel.Controls.Add($script:LogBox)

    Write-GuiLog 'Harbinger Command Center ready.'
    Write-GuiLog 'Browse to the CyberPatriot README, then scan it before installing or changing services.'

    if ($FocusServices) {
        $form.Add_Shown({ $services.Focus() })
    }

    [void]$form.ShowDialog()
}

function Show-InstallerGui {
    param([switch]$FocusServices)
    Show-ModernInstallerGui -FocusServices:$FocusServices
}

function Show-ModernDashboard {
    $bg = [System.Drawing.Color]::FromArgb(7,11,18)
    $surface = [System.Drawing.Color]::FromArgb(13,19,29)
    $surface2 = [System.Drawing.Color]::FromArgb(18,27,40)
    $border = [System.Drawing.Color]::FromArgb(43,56,74)
    $text = [System.Drawing.Color]::FromArgb(241,245,249)
    $muted = [System.Drawing.Color]::FromArgb(148,163,184)
    $accent = [System.Drawing.Color]::FromArgb(34,211,238)
    $purple = [System.Drawing.Color]::FromArgb(99,102,241)
    $green = [System.Drawing.Color]::FromArgb(34,197,94)

    $sys = Get-HarbingerSystemSummary

    $form = New-Object Windows.Forms.Form
    $form.Text = "Harbinger's Purge - Command Center"
    $form.ClientSize = New-Object Drawing.Size(1120,720)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = $bg
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedSingle
    $form.MaximizeBox = $false
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $sidebar = New-HarbingerPanel -Left 0 -Top 0 -Width 230 -Height 720 -BackColor $surface
    $form.Controls.Add($sidebar)
    $sidebar.Controls.Add((New-HarbingerLabel -Text 'HARBINGER''S' -Left 24 -Top 28 -Width 180 -Height 34 -Size 18 -ForeColor $text -Bold $true))
    $sidebar.Controls.Add((New-HarbingerLabel -Text 'PURGE' -Left 24 -Top 60 -Width 180 -Height 30 -Size 18 -ForeColor $accent -Bold $true))
    $sidebar.Controls.Add((New-HarbingerLabel -Text 'CYBERPATRIOT COMMAND CENTER' -Left 25 -Top 95 -Width 180 -Height 38 -Size 8 -ForeColor $muted -Bold $true))

    $launch = New-HarbingerButton -Text '1  EXECUTOR' -Left 18 -Top 168 -Width 194 -Height 52 -OnClick {
        Launch-Purge
    } -BackColor $accent -HoverColor ([System.Drawing.Color]::FromArgb(6,182,212)) -ForeColor ([System.Drawing.Color]::FromArgb(3,7,18)) -FontSize 11
    $sidebar.Controls.Add($launch)

    $installer = New-HarbingerButton -Text '2  INSTALLER / UPDATER' -Left 18 -Top 232 -Width 194 -Height 52 -OnClick {
        $form.Hide()
        Show-InstallerGui
        $form.Show()
    } -BackColor $surface2 -HoverColor $border -FontSize 10
    $sidebar.Controls.Add($installer)

    $services = New-HarbingerButton -Text '3  CRITICAL SERVICES' -Left 18 -Top 296 -Width 194 -Height 52 -OnClick {
        $form.Hide()
        Show-InstallerGui -FocusServices
        $form.Show()
    } -BackColor $surface2 -HoverColor $border -FontSize 10
    $sidebar.Controls.Add($services)

    $reports = New-HarbingerButton -Text '4  REPORTS' -Left 18 -Top 360 -Width 194 -Height 52 -OnClick {
        Show-ReportsWindow
    } -BackColor $surface2 -HoverColor $border -FontSize 10
    $sidebar.Controls.Add($reports)

    $exit = New-HarbingerButton -Text '0  EXIT' -Left 18 -Top 624 -Width 194 -Height 44 -OnClick {
        $form.Close()
    } -BackColor ([System.Drawing.Color]::FromArgb(31,25,30)) -HoverColor ([System.Drawing.Color]::FromArgb(55,35,42)) -ForeColor ([System.Drawing.Color]::FromArgb(248,113,113)) -FontSize 9
    $sidebar.Controls.Add($exit)

    $sidebar.Controls.Add((New-HarbingerLabel -Text 'v2 UI' -Left 26 -Top 680 -Width 100 -Height 22 -Size 8 -ForeColor $muted -Bold $true))
    $sidebar.Controls.Add((New-HarbingerLabel -Text 'Windows 11 / Server 2022' -Left 26 -Top 655 -Width 175 -Height 20 -Size 8 -ForeColor $muted))

    $content = New-HarbingerPanel -Left 230 -Top 0 -Width 890 -Height 720 -BackColor $bg
    $form.Controls.Add($content)

    $content.Controls.Add((New-HarbingerLabel -Text 'SECURITY OPERATIONS' -Left 34 -Top 28 -Width 500 -Height 34 -Size 20 -ForeColor $text -Bold $true))
    $content.Controls.Add((New-HarbingerLabel -Text 'README-driven hardening and provisioning for CyberPatriot training images.' -Left 36 -Top 63 -Width 690 -Height 26 -Size 10 -ForeColor $muted))

    $adminBadge = New-HarbingerPanel -Left 744 -Top 29 -Width 112 -Height 34 -BackColor ([System.Drawing.Color]::FromArgb(20,83,45))
    $adminLabel = New-HarbingerLabel -Text 'ADMIN OK' -Left 0 -Top 8 -Width 112 -Height 20 -Size 8 -ForeColor $green -Bold $true
    $adminLabel.TextAlign = [Windows.Forms.HorizontalAlignment]::Center
    $adminBadge.Controls.Add($adminLabel)
    $content.Controls.Add($adminBadge)

    $osCard = New-HarbingerPanel -Left 34 -Top 112 -Width 258 -Height 112 -BackColor $surface
    $toolCard = New-HarbingerPanel -Left 310 -Top 112 -Width 258 -Height 112 -BackColor $surface
    $nodeCard = New-HarbingerPanel -Left 586 -Top 112 -Width 270 -Height 112 -BackColor $surface
    $content.Controls.Add($osCard)
    $content.Controls.Add($toolCard)
    $content.Controls.Add($nodeCard)

    Add-HarbingerSectionTitle -Parent $osCard -Text 'OPERATING SYSTEM' -Left 16 -Top 12 -Width 220 | Out-Null
    $osCard.Controls.Add((New-HarbingerLabel -Text $sys.Caption -Left 16 -Top 42 -Width 228 -Height 26 -Size 10 -ForeColor $text -Bold $true))
    $osCard.Controls.Add((New-HarbingerLabel -Text "Build $($sys.Build)" -Left 16 -Top 70 -Width 228 -Height 22 -Size 9 -ForeColor $muted))

    Add-HarbingerSectionTitle -Parent $toolCard -Text 'TOOLKIT STATUS' -Left 16 -Top 12 -Width 220 | Out-Null
    $toolCard.Controls.Add((New-HarbingerLabel -Text 'Core modules loaded' -Left 16 -Top 42 -Width 228 -Height 24 -Size 10 -ForeColor $text -Bold $true))
    $toolCard.Controls.Add((New-HarbingerLabel -Text 'Parser / Installer / Executor' -Left 16 -Top 70 -Width 228 -Height 22 -Size 9 -ForeColor $green))

    Add-HarbingerSectionTitle -Parent $nodeCard -Text 'SESSION' -Left 16 -Top 12 -Width 220 | Out-Null
    $nodeCard.Controls.Add((New-HarbingerLabel -Text $sys.Computer -Left 16 -Top 42 -Width 236 -Height 24 -Size 10 -ForeColor $text -Bold $true))
    $nodeCard.Controls.Add((New-HarbingerLabel -Text "User: $($sys.User)    RAM: $($sys.Memory)" -Left 16 -Top 70 -Width 238 -Height 22 -Size 8 -ForeColor $muted))

    $hero = New-HarbingerPanel -Left 34 -Top 248 -Width 822 -Height 132 -BackColor $surface2
    $content.Controls.Add($hero)
    $hero.Controls.Add((New-HarbingerLabel -Text 'READY TO HARDEN THIS IMAGE?' -Left 22 -Top 18 -Width 450 -Height 30 -Size 15 -ForeColor $text -Bold $true))
    $hero.Controls.Add((New-HarbingerLabel -Text 'Run the Executor for full README-driven hardening, account reconciliation, policy enforcement, verification, and reporting.' -Left 22 -Top 52 -Width 520 -Height 54 -Size 9 -ForeColor $muted))
    $heroRun = New-HarbingerButton -Text 'RUN PURGE' -Left 650 -Top 38 -Width 145 -Height 56 -OnClick { Launch-Purge } -BackColor $accent -HoverColor ([System.Drawing.Color]::FromArgb(6,182,212)) -ForeColor ([System.Drawing.Color]::FromArgb(3,7,18)) -FontSize 11
    $hero.Controls.Add($heroRun)

    Add-HarbingerSectionTitle -Parent $content -Text 'QUICK ACTIONS' -Left 34 -Top 408 -Width 300 | Out-Null

    $qa1 = New-HarbingerPanel -Left 34 -Top 438 -Width 258 -Height 104 -BackColor $surface
    $qa2 = New-HarbingerPanel -Left 310 -Top 438 -Width 258 -Height 104 -BackColor $surface
    $qa3 = New-HarbingerPanel -Left 586 -Top 438 -Width 270 -Height 104 -BackColor $surface
    $content.Controls.Add($qa1)
    $content.Controls.Add($qa2)
    $content.Controls.Add($qa3)

    $qa1.Controls.Add((New-HarbingerLabel -Text 'README INSTALLER' -Left 16 -Top 14 -Width 210 -Height 24 -Size 10 -ForeColor $text -Bold $true))
    $qa1.Controls.Add((New-HarbingerLabel -Text 'Scan and update required apps.' -Left 16 -Top 44 -Width 210 -Height 22 -Size 8 -ForeColor $muted))
    $qa1Btn = New-HarbingerButton -Text 'OPEN' -Left 175 -Top 68 -Width 65 -Height 25 -OnClick { $form.Hide(); Show-InstallerGui; $form.Show() } -BackColor $purple -HoverColor ([System.Drawing.Color]::FromArgb(79,82,190)) -FontSize 8
    $qa1.Controls.Add($qa1Btn)

    $qa2.Controls.Add((New-HarbingerLabel -Text 'CRITICAL SERVICES' -Left 16 -Top 14 -Width 220 -Height 24 -Size 10 -ForeColor $text -Bold $true))
    $qa2.Controls.Add((New-HarbingerLabel -Text 'Only apply services from the README.' -Left 16 -Top 44 -Width 220 -Height 22 -Size 8 -ForeColor $muted))
    $qa2Btn = New-HarbingerButton -Text 'OPEN' -Left 175 -Top 68 -Width 65 -Height 25 -OnClick { $form.Hide(); Show-InstallerGui -FocusServices; $form.Show() } -BackColor $surface2 -HoverColor $border -FontSize 8
    $qa2.Controls.Add($qa2Btn)

    $qa3.Controls.Add((New-HarbingerLabel -Text 'REPORTS & LOGS' -Left 16 -Top 14 -Width 220 -Height 24 -Size 10 -ForeColor $text -Bold $true))
    $qa3.Controls.Add((New-HarbingerLabel -Text 'Review the latest Purge output.' -Left 16 -Top 44 -Width 220 -Height 22 -Size 8 -ForeColor $muted))
    $qa3Btn = New-HarbingerButton -Text 'OPEN' -Left 185 -Top 68 -Width 65 -Height 25 -OnClick { Show-ReportsWindow } -BackColor $surface2 -HoverColor $border -FontSize 8
    $qa3.Controls.Add($qa3Btn)

    $footer = New-HarbingerPanel -Left 34 -Top 575 -Width 822 -Height 102 -BackColor $surface
    $content.Controls.Add($footer)
    Add-HarbingerSectionTitle -Parent $footer -Text 'OPERATIONAL NOTES' -Left 18 -Top 12 -Width 220 | Out-Null
    $footer.Controls.Add((New-HarbingerLabel -Text 'Software and service decisions remain README-driven. The UI only controls how existing toolkit functions are presented and launched.' -Left 18 -Top 41 -Width 765 -Height 45 -Size 9 -ForeColor $muted))

    [void]$form.ShowDialog()
}

function MainMenu {
    Show-ModernDashboard
}

MainMenu
