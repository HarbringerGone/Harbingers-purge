<#
.SYNOPSIS
    Harbinger's Purge GitHub launcher.

.DESCRIPTION
    Downloads the current GUI toolkit, Purge executor, and wsd.crt from the
    GitHub main branch into a unique temporary directory and runs the toolkit
    in the current PowerShell window.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
    Supported operating systems: Windows 11 and Windows Server 2022.

    Important: this launcher does NOT rewrite or "repair" the downloaded
    Purge script. The Purge Executor must already be PowerShell 5.1-compatible.
    This prevents encoding/quote corruption in downloaded scripts.

.AUTHOR
    Channveer Singh
#>

[CmdletBinding()]
param(
    [string]$RepositoryOwner = 'HarbringerGone',
    [string]$RepositoryName = 'Harbingers-purge',
    [string]$Branch = 'main',
    [switch]$KeepDownloadedFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$tempRoot = $null
$runSucceeded = $false

function Write-LauncherStatus {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[Harbinger's Launcher] $Message" -ForegroundColor Cyan
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SupportedWindows {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem

    if ($os.ProductType -eq 3) {
        if ($os.Version -notlike '10.0.20348.*') {
            throw "Unsupported Windows Server version: $($os.Caption) ($($os.Version)). Harbinger's Purge supports Windows Server 2022 only."
        }
    }
    elseif ($os.ProductType -eq 1) {
        $build = [int]$os.BuildNumber
        if ($build -lt 22000) {
            throw "Unsupported Windows client version: $($os.Caption) (build $build). Harbinger's Purge supports Windows 11 only."
        }
    }
    else {
        throw "Unsupported Windows product type: $($os.Caption)."
    }

    Write-LauncherStatus "Supported OS detected: $($os.Caption) build $($os.BuildNumber)."
}

function Get-RawUrl {
    param([Parameter(Mandatory)][string]$FileName)
    return "https://raw.githubusercontent.com/$RepositoryOwner/$RepositoryName/refs/heads/$Branch/$FileName"
}

function Test-PowerShellSyntax {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )

    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$tokens,
        [ref]$parseErrors
    )

    if ($parseErrors -and $parseErrors.Count -gt 0) {
        $messages = ($parseErrors | ForEach-Object { $_.Message }) -join '; '
        throw "$Label has PowerShell syntax errors: $messages"
    }

    Write-LauncherStatus "$Label syntax check passed."
}

function Test-AsciiScript {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    foreach ($byte in $bytes) {
        if ($byte -gt 127) {
            throw "$Label contains non-ASCII bytes. Refusing to run it because encoding/quote corruption can break Windows PowerShell 5.1. Publish an ASCII-compatible version of the script."
        }
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This launcher is Windows-only.'
}

if (-not (Test-Administrator)) {
    throw "Administrator PowerShell is required. Open PowerShell with 'Run as administrator' and run the launcher again."
}

try {
    Test-SupportedWindows

    $tempRoot = Join-Path $env:TEMP ("HarbingersPurgeLaunch-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

    $toolkitPath = Join-Path $tempRoot 'Harbingers-CyberPatriot-Toolkit.ps1'
    $purgePath   = Join-Path $tempRoot 'Harbingers-Purge.ps1'
    $certPath    = Join-Path $tempRoot 'wsd.crt'

    $downloads = @(
        @{ Name = 'GUI Toolkit'; File = 'Harbingers-CyberPatriot-Toolkit.ps1'; Destination = $toolkitPath }
        @{ Name = 'Purge Executor'; File = 'Harbingers-Purge.ps1'; Destination = $purgePath }
        @{ Name = 'wsd.crt'; File = 'wsd.crt'; Destination = $certPath }
    )

    foreach ($item in $downloads) {
        $url = Get-RawUrl -FileName $item.File
        Write-LauncherStatus "Downloading $($item.Name)..."
        Invoke-WebRequest -Uri $url -OutFile $item.Destination -UseBasicParsing

        if (-not (Test-Path -LiteralPath $item.Destination -PathType Leaf)) {
            throw "Download failed: $($item.Name)."
        }

        if ((Get-Item -LiteralPath $item.Destination).Length -le 0) {
            throw "Downloaded file is empty: $($item.Name)."
        }
    }

    $certText = Get-Content -LiteralPath $certPath -Raw
    if (($certText -notmatch '-----BEGIN CERTIFICATE-----') -or
        ($certText -notmatch '-----END CERTIFICATE-----')) {
        throw 'The downloaded wsd.crt does not look like a PEM certificate.'
    }

    # IMPORTANT: Never rewrite the downloaded PowerShell scripts here.
    # Text-based compatibility repairs previously corrupted quote characters.
    Test-AsciiScript -Path $toolkitPath -Label 'GUI Toolkit'
    Test-AsciiScript -Path $purgePath -Label 'Purge Executor'

    Test-PowerShellSyntax -Path $toolkitPath -Label 'GUI Toolkit'
    Test-PowerShellSyntax -Path $purgePath -Label 'Purge Executor'

    Write-LauncherStatus 'All required files downloaded and syntax-checked successfully.'
    Write-LauncherStatus "Starting Harbinger's CyberPatriot Toolkit..."
    Write-Host ''

    & $toolkitPath -PurgeScriptPath $purgePath

    $runSucceeded = $true
    Write-Host ''
    Write-LauncherStatus 'Toolkit exited.'
}
catch {
    Write-Host ''
    Write-Host "Harbinger's Launcher ERROR:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ''

    if ($tempRoot) {
        Write-Host "Diagnostic files are kept at: $tempRoot" -ForegroundColor Yellow
    }

    Write-Host ''
    Read-Host 'Press Enter to close this launcher window' | Out-Null
}
finally {
    if ($tempRoot -and (Test-Path -LiteralPath $tempRoot) -and
        $runSucceeded -and -not $KeepDownloadedFiles) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
