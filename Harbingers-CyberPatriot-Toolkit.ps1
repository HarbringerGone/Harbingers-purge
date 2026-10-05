<#
.SYNOPSIS
    Harbinger's CyberPatriot Toolkit
.DESCRIPTION
    Menu-driven Harbinger's Purge launcher with a combined Ninite-style
    Installer / Updater and Critical Services GUI.

    Option 1 = Purge
    Option 2 = Installer / Updater + Critical Services (GUI)
    Option 3 remains accepted as a legacy alias for Option 2.

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

$script:LogBox = $null
$script:StatusLabel = $null
$script:PathBox = $null
$script:SoftwareList = $null
$script:ServiceList = $null
$script:SoftwareCountLabel = $null
$script:ServiceCountLabel = $null

function Normalize-Name([string]$Name) {
    $n = (($Name.ToLowerInvariant()) -replace '[^a-z0-9]+','')
    if ($n -eq 'notepad') { return 'notepadplusplus' }
    return $n
}

function Write-GuiLog([string]$Message) {
    if ($script:LogBox) {
        $script:LogBox.AppendText("[$(Get-Date -Format 'HH:mm:ss')] $Message`r`n")
        $script:LogBox.SelectionStart = $script:LogBox.TextLength
        $script:LogBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Set-GuiStatus([string]$Text) {
    if ($script:StatusLabel) {
        $script:StatusLabel.Text = $Text
        [System.Windows.Forms.Application]::DoEvents()
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
    $browserNames = @('Google Chrome','Mozilla Firefox','Firefox ESR','Microsoft Edge','Brave','Opera','Vivaldi')

    $scenarioStart=-1
    $scenarioEnd=$lines.Count
    for ($i=0;$i -lt $lines.Count;$i++) {
        if ($lines[$i] -match '(?i)^#+\s*Competition Scenario\s*$') { $scenarioStart=$i; break }
    }
    if ($scenarioStart -ge 0) {
        for ($i=$scenarioStart+1;$i -lt $lines.Count;$i++) {
            $h=(($lines[$i] -replace '^\s*[-*]\s*','').Trim())
            if ($h -match '(?i)^Authorized Administrators(?: and Users)?\s*:??\s*$') { $scenarioEnd=$i; break }
        }
    }
    $requirementLines=if($scenarioStart -ge 0){@($lines[$scenarioStart..($scenarioEnd-1)])}else{@($lines)}

    foreach ($line in $requirementLines) {
        $update=$line -match '(?i)\b(latest|stable|up[- ]to[- ]date|updated|update|current|kept\s+up[- ]to[- ]date)\b'
        $context=$line -match '(?i)\b(?:default\s+(?:web\s+)?browser|browser for all users|web browser|business|software|application|web server|installed|kept|remain installed)\b'
        if (-not $context) { continue }
        foreach ($candidate in @($SoftwareCatalog.Values | Sort-Object Display -Unique)) {
            $display=[string]$candidate.Display
            if ($line -notmatch '(?i)(?<![A-Za-z0-9])'+[regex]::Escape($display)+'(?![A-Za-z0-9])') { continue }
            $isBrowser=$browserNames -contains $display
            $software.Add([pscustomobject]@{
                Name=$display
                Key=(Normalize-Name $display)
                UpdateRequired=[bool]$update
                Browser=[bool]$isBrowser
                SetAsDefault=[bool]($isBrowser -and ($line -match '(?i)\bdefault\s+(?:web\s+)?browser|browser for all users\b'))
                Source=$line
            })
        }
    }

    foreach ($pattern in @(
        '(?i)\b(?:uses|runs)\s+(?:an?|the)\s+Apache[^.;]*?\s+web\s+server\b',
        '(?i)\b(?:web|application)\s+server\s+is\s+Apache[^.;]*\b'
    )) {
        foreach ($m in [regex]::Matches(($lines -join ' '),$pattern)) {
            $software.Add([pscustomobject]@{Name='Apache HTTP Server';Key='apachehttpserver';UpdateRequired=[bool]($m.Value -match '(?i)latest|updated|up[- ]to[- ]date');Browser=$false;SetAsDefault=$false;Source='README web-server requirement'})
        }
    }

    $uniqueSoftware=@($software | Sort-Object Name -Unique)

    $criticalIndex=-1
    for($i=0;$i -lt $lines.Count;$i++) { if($lines[$i] -match '(?i)^Critical Services:\s*(.*)$'){ $criticalIndex=$i; break } }
    if($criticalIndex -ge 0){
        $cm=[regex]::Match($lines[$criticalIndex],'(?i)^Critical Services:\s*(.*)$')
        $inline=[string]$cm.Groups[1].Value
        if($inline -and $inline -notmatch '(?i)^(none|n/a)\.?$'){ $services.Add($inline.Trim()) }
        for($i=$criticalIndex+1;$i -lt $lines.Count;$i++){
            $raw=$lines[$i]
            $clean=(($raw -replace '^\s*[-*]\s*','').Trim())
            if($clean -match '(?i)^(Authorized Administrators(?: and Users)?|Authorized Users|Competition Guidelines|Forensics Questions|Unique Identifier|ANSWER KEY|REMINDERS)\s*:??\s*$'){ break }
            if($clean -match '^#{1,6}\s+'){ break }
            if($raw -match '^\s*(?:[*-])\s+(.+)$'){
                $svc=$Matches[1].Trim()
                if($svc -match '(?i)^(none|n/a)\.?$'){ continue }
                if($svc -match '(?i)^Authorized Administrators(?: and Users)?$'){ break }
                $services.Add($svc)
            } elseif($clean -match '(?i)^(Authorized Administrators(?: and Users)?|Authorized Users|Competition|Forensics|Unique Identifier|ANSWER KEY|REMINDERS)'){ break }
        }
    }

    [pscustomobject]@{Software=@($uniqueSoftware);Services=@($services | Sort-Object -Unique)}
}

function Resolve-Package([string]$Name) {
    $key=Normalize-Name $Name
    if($SoftwareCatalog.ContainsKey($key)){return $SoftwareCatalog[$key]}
    foreach($candidate in $SoftwareCatalog.Values){ if((Normalize-Name $candidate.Display) -eq $key){return $candidate} }
    return $null
}

function Ensure-Chocolatey {
    $cmd=Get-Command choco.exe -ErrorAction SilentlyContinue
    if($cmd){return $cmd.Source}
    Write-GuiLog 'WinGet unavailable. Installing Chocolatey for this software operation...'
    $release=Invoke-RestMethod -Uri 'https://api.github.com/repos/chocolatey/choco/releases/latest' -UseBasicParsing
    $asset=@($release.assets | Where-Object {$_.name -match '(?i)\.msi$'} | Select-Object -First 1)
    if(-not $asset){throw 'Could not locate the latest Chocolatey MSI.'}
    $msi=Join-Path $TempRoot $asset.name
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $msi -UseBasicParsing -MaximumRedirection 5
    $proc=Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i',$msi,'/qn','/norestart') -Wait -PassThru -WindowStyle Hidden
    if($proc.ExitCode -notin @(0,3010)){throw "Chocolatey MSI installation failed with exit code $($proc.ExitCode)."}
    $env:Path="$env:ALLUSERSPROFILE\chocolatey\bin;$env:Path"
    $cmd=Get-Command choco.exe -ErrorAction SilentlyContinue
    if(-not $cmd){throw 'Chocolatey installation finished but choco.exe was not found on PATH.'}
    return $cmd.Source
}

function Get-InstalledApplication([string]$DisplayName) {
    $roots=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    $results=New-Object System.Collections.ArrayList
    foreach($root in $roots){
        if(-not(Test-Path -LiteralPath $root)){continue}
        foreach($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)){
            try{$app=Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop}catch{continue}
            $dp=$app.PSObject.Properties['DisplayName']; if($null -eq $dp){continue}
            $display=[string]$dp.Value; if([string]::IsNullOrWhiteSpace($display)){continue}
            if(-not($display -ieq $DisplayName -or $display -like "$DisplayName *")){continue}
            $vp=$app.PSObject.Properties['DisplayVersion']; $qp=$app.PSObject.Properties['QuietUninstallString']; $up=$app.PSObject.Properties['UninstallString']
            $null=$results.Add([pscustomobject]@{DisplayName=$display;DisplayVersion=if($vp){[string]$vp.Value}else{''};QuietUninstallString=if($qp){[string]$qp.Value}else{''};UninstallString=if($up){[string]$up.Value}else{''}})
        }
    }
    return @($results)
}

function Invoke-MsiUninstall([string]$UninstallString) {
    $m=[regex]::Match($UninstallString,'(?i)\{[0-9a-f-]+\}'); if(-not $m.Success){throw "Could not determine MSI product code from uninstall string."}
    $p=Start-Process msiexec.exe -ArgumentList @('/x',$m.Value,'/qn','/norestart') -Wait -PassThru -WindowStyle Hidden
    if($p.ExitCode -notin @(0,1605,3010,1641)){throw "MSI uninstall failed with exit code $($p.ExitCode)."}
}

function Invoke-RegisteredUninstall([string]$UninstallCommand) {
    $cmd=$UninstallCommand.Trim(); if([string]::IsNullOrWhiteSpace($cmd)){throw 'No registered uninstall command was available.'}
    if($cmd.StartsWith('"')){$m=[regex]::Match($cmd,'^"([^"]+)"\s*(.*)$');$exe=$m.Groups[1].Value;$args=$m.Groups[2].Value}else{$parts=$cmd -split '\s+',2;$exe=$parts[0];$args=if($parts.Count -gt 1){$parts[1]}else{''}}
    $al=if([string]::IsNullOrWhiteSpace($args)){@()}else{@($args)}
    $p=Start-Process -FilePath $exe -ArgumentList $al -Wait -PassThru
    if($p.ExitCode -notin @(0,3010,1641)){throw "Registered uninstaller failed with exit code $($p.ExitCode)."}
}

function Update-WiresharkWithReplacement([string]$PackageId) {
    $apps=@(Get-InstalledApplication 'Wireshark')
    $managed=$false
    $choco=Get-Command choco.exe -ErrorAction SilentlyContinue
    if($choco){$local=@(& $choco.Source list --local-only --exact $PackageId --limit-output 2>&1);$managed=($LASTEXITCODE -eq 0 -and ($local -join "`n") -match "(?i)^$([regex]::Escape($PackageId))\|")}
    if($managed){Write-GuiLog 'Wireshark is Chocolatey-managed. Uninstalling the existing package before reinstalling.'; & $choco.Source uninstall $PackageId -y --no-progress | Out-Host}
    elseif($apps.Count -gt 0){$a=$apps[0];$u=if($a.QuietUninstallString){$a.QuietUninstallString}else{$a.UninstallString};if(-not $u){throw 'Wireshark is installed, but no registered uninstaller was found.'};Write-GuiLog "Removing existing Wireshark $($a.DisplayVersion) before update.";if($u -match '(?i)msiexec'){Invoke-MsiUninstall $u}else{Invoke-RegisteredUninstall $u}}
    $out=@(& $choco.Source install $PackageId -y --no-progress 2>&1);if($LASTEXITCODE -ne 0){throw "Chocolatey Wireshark install failed: $($out -join ' ')"}
    Write-GuiLog 'Wireshark installed/updated successfully.'
}

function Get-ChromeVersion {
    $paths=@((Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),(Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),(Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe'))
    $v=New-Object System.Collections.ArrayList
    foreach($p in $paths){if($p -and (Test-Path -LiteralPath $p -PathType Leaf)){try{$null=$v.Add([version](Get-Item -LiteralPath $p).VersionInfo.ProductVersion)}catch{}}}
    if($v.Count -eq 0){return $null}; return ($v | Sort-Object -Descending | Select-Object -First 1)
}

function Install-GoogleChromeOfficial {
    $url='https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
    $msi=Join-Path $TempRoot 'googlechromestandaloneenterprise64.msi'
    $before=Get-ChromeVersion
    if($before){Write-GuiLog "Detected installed Google Chrome version: $before"}
    Write-GuiLog 'Using the official Google Chrome Enterprise 64-bit MSI.'
    Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing -MaximumRedirection 5
    $sig=Get-AuthenticodeSignature -FilePath $msi
    if($sig.Status -ne 'Valid'){throw "Google Chrome MSI signature validation failed: $($sig.Status)."}
    if([string]$sig.SignerCertificate.Subject -notmatch '(?i)Google'){throw 'Google Chrome MSI signer did not identify Google.'}
    Write-GuiLog 'Google Chrome MSI signature validated.'
    $p=Start-Process msiexec.exe -ArgumentList @('/i',"`"$msi`"",'/qn','/norestart') -Wait -PassThru -WindowStyle Hidden
    if($p.ExitCode -notin @(0,1638,3010)){throw "Google Chrome MSI installation failed with exit code $($p.ExitCode)."}
    Start-Sleep -Seconds 2
    $after=Get-ChromeVersion
    if($after -and $before -and $after -gt $before){Write-GuiLog "Google Chrome updated: $before -> $after"}
    elseif($after){Write-GuiLog "Google Chrome remains at version $after; installer completed."}
}

function Set-DefaultBrowser([string]$BrowserName) {
    $candidate=$null
    foreach($root in @('HKLM:\SOFTWARE\RegisteredApplications','HKLM:\SOFTWARE\WOW6432Node\RegisteredApplications')){
        if(-not(Test-Path $root)){continue}
        $props=Get-ItemProperty $root -ErrorAction SilentlyContinue
        foreach($p in $props.PSObject.Properties){
            $cap="HKLM:\$($p.Value)";$app=[string]$p.Name;$an=$app
            try{$an=[string](Get-ItemProperty $cap -Name ApplicationName -ErrorAction Stop).ApplicationName}catch{}
            if(($an -match [regex]::Escape($BrowserName)) -or ($app -match [regex]::Escape($BrowserName))){$candidate=[pscustomobject]@{App=$app;Cap=$cap};break}
        }
        if($candidate){break}
    }
    if(-not $candidate){throw "Could not find registered default-app capabilities for $BrowserName."}
    $ass=New-Object System.Collections.Generic.List[string]
    foreach($pair in @([pscustomobject]@{Key="$($candidate.Cap)\URLAssociations";Ids=@('http','https')},[pscustomobject]@{Key="$($candidate.Cap)\FileAssociations";Ids=@('.htm','.html')})){
        if(-not(Test-Path $pair.Key)){continue};$p=Get-ItemProperty $pair.Key
        foreach($id in $pair.Ids){try{$prog=[string]$p.$id}catch{$prog=''};if($prog){$ass.Add(('  <Association Identifier="{0}" ProgId="{1}" ApplicationName="{2}" />' -f $id,$prog,$candidate.App))}}
    }
    if($ass.Count -eq 0){throw "No usable web associations were found for $BrowserName."}
    $xmlPath=Join-Path $TempRoot ('DefaultBrowser-'+(Normalize-Name $BrowserName)+'.xml')
    @('<?xml version="1.0" encoding="UTF-8"?>','<DefaultAssociations>')+@($ass)+@('</DefaultAssociations>') | Set-Content $xmlPath -Encoding UTF8
    & "$env:SystemRoot\System32\Dism.exe" /Online "/Import-DefaultAppAssociations:$xmlPath" 2>&1 | ForEach-Object { Write-GuiLog ([string]$_) }
    if($LASTEXITCODE -ne 0){throw "DISM failed with exit code $LASTEXITCODE."}
    Write-GuiLog "$BrowserName configured as the default association set for future user sign-ins."
}

function Install-Or-Update([object]$Item) {
    $name=[string]$Item.Name;$key=Normalize-Name $name;$pkg=Resolve-Package $name
    if(-not $pkg){throw "No supported package mapping exists for '$name'."}
    $winget=Get-Command winget.exe -ErrorAction SilentlyContinue
    if($key -in @('chrome','googlechrome')){
        try{Install-GoogleChromeOfficial;return}catch{Write-GuiLog "Chrome MSI path failed: $($_.Exception.Message); trying package provider."}
    }
    if($winget){
        $out=@(& $winget.Source upgrade --id $pkg.Winget --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1)
        if($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1){Write-GuiLog "WinGet processed '$name'.";return}
        $out=@(& $winget.Source install --id $pkg.Winget --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1)
        if($LASTEXITCODE -eq 0){Write-GuiLog "Installed '$name' with WinGet.";return}
        Write-GuiLog "WinGet unavailable/failed for '$name'; falling back to Chocolatey."
    }
    $null=Ensure-Chocolatey
    if($key -eq 'wireshark' -and $Item.UpdateRequired){Update-WiresharkWithReplacement $pkg.Choco;return}
    if($key -in @('apache','apachehttpd','apachehttpserver') -and -not $Item.UpdateRequired){
        if(@(Get-InstalledApplication 'Apache HTTP Server').Count -gt 0){Write-GuiLog "'Apache HTTP Server' is already installed; README only requires presence.";return}
    }
    if($Item.UpdateRequired){Write-GuiLog "Updating '$name' with Chocolatey package '$($pkg.Choco)'."; $out=@(& choco.exe upgrade $pkg.Choco -y --no-progress 2>&1)}
    else {Write-GuiLog "Installing '$name' with Chocolatey package '$($pkg.Choco)'."; $out=@(& choco.exe install $pkg.Choco -y --no-progress 2>&1)}
    if($LASTEXITCODE -ne 0){throw "Chocolatey operation failed for '$name': $($out -join ' ')"}
}

function Resolve-Service([string]$Name) {
    $s=@(Get-Service -Name $Name -ErrorAction SilentlyContinue);if($s.Count -eq 1){return $s[0]}
    $s=@(Get-Service -DisplayName $Name -ErrorAction SilentlyContinue);if($s.Count -eq 1){return $s[0]}
    $n=Normalize-Name $Name;$s=@(Get-Service | Where-Object {(Normalize-Name $_.Name) -eq $n -or (Normalize-Name $_.DisplayName) -eq $n})
    if($s.Count -eq 1){return $s[0]};if($s.Count -gt 1){throw "Service '$Name' matched multiple services."};throw "Critical service '$Name' was not found."
}

function Ensure-Service([string]$Name) {
    $s=Resolve-Service $Name
    if($s.Status -ne 'Running'){
        $c=Get-CimInstance Win32_Service -Filter "Name='$($s.Name.Replace("'","''"))'"
        if($c.StartMode -eq 'Disabled'){Set-Service -Name $s.Name -StartupType Automatic}
        Start-Service -Name $s.Name
    }
    if((Get-Service -Name $s.Name).Status -ne 'Running'){throw "Service did not reach Running state."}
    Write-GuiLog "Critical service OK: $Name -> $($s.Name)"
}

function Launch-Purge {
    if(-not(Test-Path -LiteralPath $PurgeScriptPath -PathType Leaf)){
        [Windows.Forms.MessageBox]::Show("Could not find:`n$PurgeScriptPath`n`nThe launcher should download it automatically; if this is a local run, place Harbingers-Purge.ps1 beside the toolkit.",'Harbinger''s Purge',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error)|Out-Null
        return
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PurgeScriptPath`"")|Out-Null
}

function Refresh-Counts {
    if($script:SoftwareCountLabel){$script:SoftwareCountLabel.Text="README items: $($script:SoftwareList.Items.Count)"}
    if($script:ServiceCountLabel){$script:ServiceCountLabel.Text="Critical services: $($script:ServiceList.Items.Count)"}
}

function Scan-ReadmeIntoGui {
    $r=Parse-Requirements (Get-ReadmeText $script:PathBox.Text)
    $script:SoftwareList.Items.Clear();$script:ServiceList.Items.Clear()
    foreach($x in $r.Software){[void]$script:SoftwareList.Items.Add($x);$script:SoftwareList.SetItemChecked($script:SoftwareList.Items.Count-1,$true)}
    foreach($x in $r.Services){[void]$script:ServiceList.Items.Add($x);$script:ServiceList.SetItemChecked($script:ServiceList.Items.Count-1,$true)}
    Refresh-Counts
    if($r.Services.Count -eq 0){Write-GuiLog 'Critical Services: None. No service changes will be made.';Set-GuiStatus 'README scanned - no Critical Services found.'}
    else{Write-GuiLog "Critical Services detected: $($r.Services.Count).";Set-GuiStatus 'README scanned - review services before applying.'}
    Write-GuiLog "README scan complete: $($r.Software.Count) software/browser requirement(s), $($r.Services.Count) critical service(s)."
}

function Apply-SoftwareSelection {
    foreach($x in @($script:SoftwareList.CheckedItems)){
        try{Install-Or-Update $x;if($x.SetAsDefault){try{Set-DefaultBrowser $x.Name}catch{Write-GuiLog "Default browser setup skipped/failed for $($x.Name): $($_.Exception.Message)"}}}
        catch{Write-GuiLog "FAILED SOFTWARE: $($x.Name): $($_.Exception.Message)"}
    }
}

function Apply-ServiceSelection {
    foreach($x in @($script:ServiceList.CheckedItems)){
        try{Ensure-Service ([string]$x)}catch{Write-GuiLog "FAILED SERVICE: $x : $($_.Exception.Message)"}
    }
}

function Show-InstallerGui {
    $form=New-Object Windows.Forms.Form
    $form.Text="Harbinger's Purge - Installer / Updater + Critical Services v2.1"
    $form.Size=New-Object Drawing.Size(1080,790)
    $form.StartPosition='CenterScreen'
    $form.BackColor=[Drawing.Color]::FromArgb(20,24,32)
    $form.ForeColor=[Drawing.Color]::White
    $form.MinimumSize=New-Object Drawing.Size(1000,730)

    $header=New-Object Windows.Forms.Panel;$header.Dock='Top';$header.Height=92;$header.BackColor=[Drawing.Color]::FromArgb(12,16,24)
    $title=New-Object Windows.Forms.Label;$title.Text="HARBINGER'S PURGE";$title.Left=24;$title.Top=12;$title.AutoSize=$true;$title.Font=New-Object Drawing.Font('Segoe UI',20,[Drawing.FontStyle]::Bold);$title.ForeColor=[Drawing.Color]::FromArgb(90,180,255)
    $subtitle=New-Object Windows.Forms.Label;$subtitle.Text='README-driven software, browser, and Critical Services deployment';$subtitle.Left=27;$subtitle.Top=50;$subtitle.AutoSize=$true;$subtitle.Font=New-Object Drawing.Font('Segoe UI',9);$subtitle.ForeColor=[Drawing.Color]::LightGray
    $header.Controls.AddRange(@($title,$subtitle));$form.Controls.Add($header)

    $readmeBox=New-Object Windows.Forms.GroupBox;$readmeBox.Text='README Source';$readmeBox.Left=18;$readmeBox.Top=105;$readmeBox.Width=1028;$readmeBox.Height=78;$readmeBox.ForeColor=[Drawing.Color]::White
    $path=New-Object Windows.Forms.TextBox;$path.Left=12;$path.Top=25;$path.Width=770;$path.Height=28;$path.BackColor=[Drawing.Color]::FromArgb(34,40,50);$path.ForeColor=[Drawing.Color]::White
    $browse=New-Object Windows.Forms.Button;$browse.Text='Browse';$browse.Left=794;$browse.Top=23;$browse.Width=100;$browse.Height=32
    $scan=New-Object Windows.Forms.Button;$scan.Text='Scan README';$scan.Left=900;$scan.Top=23;$scan.Width=112;$scan.Height=32
    $readmeBox.Controls.AddRange(@($path,$browse,$scan));$form.Controls.Add($readmeBox)

    $script:PathBox=$path
    $left=New-Object Windows.Forms.GroupBox;$left.Text='README Software / Browsers';$left.Left=18;$left.Top=196;$left.Width=500;$left.Height=345;$left.ForeColor=[Drawing.Color]::White
    $script:SoftwareList=New-Object Windows.Forms.CheckedListBox;$script:SoftwareList.Left=12;$script:SoftwareList.Top=30;$script:SoftwareList.Width=472;$script:SoftwareList.Height=260;$script:SoftwareList.CheckOnClick=$true;$script:SoftwareList.BackColor=[Drawing.Color]::FromArgb(27,32,42);$script:SoftwareList.ForeColor=[Drawing.Color]::White
    $script:SoftwareCountLabel=New-Object Windows.Forms.Label;$script:SoftwareCountLabel.Text='README items: 0';$script:SoftwareCountLabel.Left=14;$script:SoftwareCountLabel.Top=300;$script:SoftwareCountLabel.AutoSize=$true;$script:SoftwareCountLabel.ForeColor=[Drawing.Color]::LightGray
    $left.Controls.AddRange(@($script:SoftwareList,$script:SoftwareCountLabel));$form.Controls.Add($left)

    $right=New-Object Windows.Forms.GroupBox;$right.Text='Critical Services';$right.Left=538;$right.Top=196;$right.Width=508;$right.Height=345;$right.ForeColor=[Drawing.Color]::White
    $script:ServiceList=New-Object Windows.Forms.CheckedListBox;$script:ServiceList.Left=12;$script:ServiceList.Top=30;$script:ServiceList.Width=480;$script:ServiceList.Height=260;$script:ServiceList.CheckOnClick=$true;$script:ServiceList.BackColor=[Drawing.Color]::FromArgb(27,32,42);$script:ServiceList.ForeColor=[Drawing.Color]::White
    $script:ServiceCountLabel=New-Object Windows.Forms.Label;$script:ServiceCountLabel.Text='Critical services: 0';$script:ServiceCountLabel.Left=14;$script:ServiceCountLabel.Top=300;$script:ServiceCountLabel.AutoSize=$true;$script:ServiceCountLabel.ForeColor=[Drawing.Color]::LightGray
    $right.Controls.AddRange(@($script:ServiceList,$script:ServiceCountLabel));$form.Controls.Add($right)

    $actions=New-Object Windows.Forms.Panel;$actions.Left=18;$actions.Top=555;$actions.Width=1028;$actions.Height=64
    $install=New-Object Windows.Forms.Button;$install.Text='Install / Update Selected';$install.Left=0;$install.Top=0;$install.Width=215;$install.Height=42
    $services=New-Object Windows.Forms.Button;$services.Text='Apply Critical Services';$services.Left=225;$services.Top=0;$services.Width=205;$services.Height=42
    $runAll=New-Object Windows.Forms.Button;$runAll.Text='Run All Selected';$runAll.Left=440;$runAll.Top=0;$runAll.Width=180;$runAll.Height=42
    $all=New-Object Windows.Forms.Button;$all.Text='Select All';$all.Left=630;$all.Top=0;$all.Width=110;$all.Height=42
    $clear=New-Object Windows.Forms.Button;$clear.Text='Clear';$clear.Left=750;$clear.Top=0;$clear.Width=110;$clear.Height=42
    $close=New-Object Windows.Forms.Button;$close.Text='Close';$close.Left=870;$close.Top=0;$close.Width=110;$close.Height=42
    $actions.Controls.AddRange(@($install,$services,$runAll,$all,$clear,$close));$form.Controls.Add($actions)

    $status=New-Object Windows.Forms.Label;$status.Left=20;$status.Top=626;$status.Width=1020;$status.Height=22;$status.Text='Ready - scan a README to load exact requirements.';$status.ForeColor=[Drawing.Color]::FromArgb(100,210,130);$status.Font=New-Object Drawing.Font('Segoe UI',9,[Drawing.FontStyle]::Bold);$form.Controls.Add($status);$script:StatusLabel=$status

    $log=New-Object Windows.Forms.TextBox;$log.Multiline=$true;$log.ReadOnly=$true;$log.ScrollBars='Vertical';$log.Left=18;$log.Top=652;$log.Width=1028;$log.Height=100;$log.BackColor=[Drawing.Color]::FromArgb(12,16,24);$log.ForeColor=[Drawing.Color]::Gainsboro;$script:LogBox=$log;$form.Controls.Add($log)

    foreach($b in @($browse,$scan,$install,$services,$runAll,$all,$clear,$close)){$b.FlatStyle='System'}
    $browse.Add_Click({$d=New-Object Windows.Forms.OpenFileDialog;$d.Filter='README/text files (*.txt;*.md)|*.txt;*.md|All files (*.*)|*.*';if($d.ShowDialog()-eq 'OK'){$path.Text=$d.FileName;Set-GuiStatus 'README selected - click Scan README.'}})
    $scan.Add_Click({try{Set-GuiStatus 'Scanning README...';Scan-ReadmeIntoGui}catch{[Windows.Forms.MessageBox]::Show($_.Exception.Message,'README scan failed',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error)|Out-Null;Set-GuiStatus 'README scan failed.'}})
    $install.Add_Click({Set-GuiStatus 'Installing/updating selected software...';Apply-SoftwareSelection;Set-GuiStatus 'Software operation complete.'})
    $services.Add_Click({Set-GuiStatus 'Applying selected Critical Services...';Apply-ServiceSelection;Set-GuiStatus 'Critical Service operation complete.'})
    $runAll.Add_Click({Set-GuiStatus 'Running all selected operations...';Apply-SoftwareSelection;Apply-ServiceSelection;Set-GuiStatus 'All selected operations complete.'})
    $all.Add_Click({for($i=0;$i -lt $script:SoftwareList.Items.Count;$i++){$script:SoftwareList.SetItemChecked($i,$true)};for($i=0;$i -lt $script:ServiceList.Items.Count;$i++){$script:ServiceList.SetItemChecked($i,$true)}})
    $clear.Add_Click({for($i=0;$i -lt $script:SoftwareList.Items.Count;$i++){$script:SoftwareList.SetItemChecked($i,$false)};for($i=0;$i -lt $script:ServiceList.Items.Count;$i++){$script:ServiceList.SetItemChecked($i,$false)}})
    $close.Add_Click({$form.Close()})

    Write-GuiLog 'Ready. Browse to the CyberPatriot README, then click Scan README.'
    [void]$form.ShowDialog()
}

function MainMenu {
    while($true){
        Clear-Host
        Write-Host ''
        Write-Host '===============================================================' -ForegroundColor DarkCyan
        Write-Host "                 HARBINGER'S PURGE" -ForegroundColor Cyan
        Write-Host '             CYBERPATRIOT HARDENING TOOLKIT' -ForegroundColor DarkCyan
        Write-Host '===============================================================' -ForegroundColor DarkCyan
        Write-Host ''
        Write-Host '  [1]  PURGE' -ForegroundColor Green
        Write-Host '       Full README-driven security hardening and cleanup' -ForegroundColor Gray
        Write-Host ''
        Write-Host '  [2]  INSTALLER / UPDATER + CRITICAL SERVICES (GUI)' -ForegroundColor Yellow
        Write-Host '       README-driven software, browsers, and Critical Services' -ForegroundColor Gray
        Write-Host ''
        Write-Host '  [0]  EXIT' -ForegroundColor Red
        Write-Host ''
        Write-Host '---------------------------------------------------------------' -ForegroundColor DarkGray
        $choice=Read-Host 'Select an option'
        switch($choice){
            '1' {Launch-Purge;Read-Host 'Press Enter to return to the menu'|Out-Null}
            '2' {Show-InstallerGui}
            '3' {Show-InstallerGui}
            '0' {return}
            default {Write-Host 'Invalid selection. Choose 1, 2, or 0.' -ForegroundColor Red;Start-Sleep -Seconds 1}
        }
    }
}

MainMenu
