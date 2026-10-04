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

function Parse-Requirements([string]$Text) {
    $lines = @($Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $software = New-Object System.Collections.Generic.List[object]
    $services = New-Object System.Collections.Generic.List[string]

    foreach ($line in $lines) {
        $l = $line.Trim()
        $update = $l -match '(?i)latest|up-to-date|updated|update|kept current|keep .*current'
        $browserLine = $l -match '(?i)default web browser|default browser|browser for all users'

        foreach ($key in $SoftwareCatalog.Keys) {
            $display = $SoftwareCatalog[$key].Display
            if ($l -match [regex]::Escape($display) -or $l -match [regex]::Escape($key)) {
                if (-not ($software | Where-Object { $_.Name -ieq $display })) {
                    $software.Add([pscustomobject]@{ Name=$display; Key=$key; UpdateRequired=($update -or $browserLine); Browser=($browserLine -or $display -match '(?i)chrome|firefox|edge|brave|opera|vivaldi'); Source=$l })
                } elseif ($update -or $browserLine) {
                    ($software | Where-Object { $_.Name -ieq $display } | ForEach-Object { $_.UpdateRequired=$true; $_.Browser=($true -or $_.Browser) })
                }
            }
        }
    }

    $svcStart = -1
    for ($i=0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '(?i)^Critical Services:\s*$') { $svcStart=$i; break } }
    if ($svcStart -ge 0) {
        for ($i=$svcStart+1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '(?i)^(Authorized Administrators:|Authorized Users:|Competition Guidelines|Windows 11|Windows Server|Forensics Questions|Unique Identifier|$)') { break }
            if ($lines[$i] -match '(?i)^none$|^n/a$') { continue }
            if ($lines[$i] -match '^[A-Za-z0-9_. -]+$') { $services.Add($lines[$i].Trim()) }
        }
    }

    return [pscustomobject]@{
        Software=@($software | Sort-Object Name -Unique)
        Services=@($services | Sort-Object -Unique)
    }
}

function Resolve-Package([string]$Name) {
    $key=Normalize-Name $Name
    if ($SoftwareCatalog.ContainsKey($key)) { return $SoftwareCatalog[$key] }
    $null
}

function Ensure-Chocolatey {
    $c=Get-Command choco.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    Write-GuiLog 'WinGet unavailable. Installing Chocolatey for this software operation...'
    $installScript = Invoke-RestMethod -Uri 'https://community.chocolatey.org/install.ps1' -UseBasicParsing
    Invoke-Expression $installScript
    $env:Path="$env:ALLUSERSPROFILE\chocolatey\bin;$env:Path"
    $c=Get-Command choco.exe -ErrorAction SilentlyContinue
    if (-not $c) { throw 'Chocolatey installation completed but choco.exe was not found.' }
    return $c.Source
}

function Install-Or-Update([object]$Item) {
    $pkg=Resolve-Package $Item.Name
    if (-not $pkg) { throw "No safe package mapping exists for '$($Item.Name)'. Refusing to guess." }

    $winget=Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($winget) {
        $id=$pkg.Winget
        Write-GuiLog "Using WinGet: $($Item.Name) [$id]"
        & $winget.Source install --id $id --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1 | ForEach-Object { Write-GuiLog ([string]$_) }
        $rc=$LASTEXITCODE
        if ($rc -ne 0) {
            & $winget.Source upgrade --id $id --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1 | ForEach-Object { Write-GuiLog ([string]$_) }
            $rc=$LASTEXITCODE
        }
        if ($rc -ne 0) { throw "WinGet failed for '$($Item.Name)' with exit code $rc." }
        return
    }

    $null=Ensure-Chocolatey
    Write-GuiLog "Using Chocolatey: $($Item.Name) [$($pkg.Choco)]"
    & choco.exe upgrade $pkg.Choco -y --no-progress 2>&1 | ForEach-Object { Write-GuiLog ([string]$_) }
    if ($LASTEXITCODE -ne 0) { throw "Chocolatey failed for '$($Item.Name)' with exit code $LASTEXITCODE." }
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
            if ($prog) { $ass += "  <Association Identifier=\"$id\" ProgId=\"$prog\" ApplicationName=\"$($candidate.App)\" />" }
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
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PurgeScriptPath`"")
}

function Show-InstallerGui {
    $form=New-Object Windows.Forms.Form
    $form.Text="Harbinger's Purge - Installer / Updater"
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
            if ($r.Services.Count -eq 0) { Write-GuiLog 'Critical Services: None (no service changes will be made).' }
        } catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'README scan failed') | Out-Null }
    })

    $install.Add_Click({
        foreach ($x in @($software.CheckedItems)) {
            try { Install-Or-Update $x; if ($x.Browser) { try { Set-DefaultBrowser $x.Name } catch { Write-GuiLog "Default browser setup skipped/failed for $($x.Name): $($_.Exception.Message)" } } }
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
