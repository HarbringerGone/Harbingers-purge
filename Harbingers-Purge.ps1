# Harbinger's Purge repair helper
# Downloads the current Purge script, fixes the README software catalog parser bug,
# and saves a new file without overwriting the original.
$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$uri = 'https://raw.githubusercontent.com/HarbringerGone/Harbingers-purge/main/Harbingers-Purge.ps1'
$sourcePath = Join-Path $env:TEMP 'Harbingers-Purge-source.ps1'
$outputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Harbingers-Purge-FIXED.ps1'

Write-Host '[Harbinger] Downloading current Purge script...' -ForegroundColor Cyan
Invoke-WebRequest -Uri $uri -OutFile $sourcePath -UseBasicParsing

$scriptText = [System.IO.File]::ReadAllText($sourcePath)
$bad = '$SoftwareCatalog.Values | Sort-Object Display -Unique'
$good = "@('Google Chrome','Mozilla Firefox','Firefox ESR','Microsoft Edge','Brave','Opera','Vivaldi','Notepad++','7-Zip','Wireshark','Apache HTTP Server')"

$count = ([regex]::Matches($scriptText, [regex]::Escape($bad))).Count
if ($count -ne 2) {
    throw "Expected to find the two known broken catalog expressions, but found $count. No output was written; source may have changed."
}
$scriptText = $scriptText.Replace($bad, $good)

# Do not overwrite the live script. Save a separate replacement for review.
[System.IO.File]::WriteAllText($outputPath, $scriptText, [System.Text.Encoding]::ASCII)

# Parse-check with the local Windows PowerShell parser before reporting success.
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($outputPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue
    $messages = $parseErrors | ForEach-Object { 'Line {0}: {1}' -f $_.Extent.StartLineNumber, $_.Message }
    throw ("PowerShell syntax check failed: " + ($messages -join '; '))
}

Write-Host ''
Write-Host "Created: $outputPath" -ForegroundColor Green
Write-Host 'Fixed the README parser crash caused by sorting catalog entries on a nonexistent Display property.' -ForegroundColor Green
Write-Host 'This helper does not run HailMary. Use the elevated launcher replacement to run Purge as Administrator.' -ForegroundColor Yellow
