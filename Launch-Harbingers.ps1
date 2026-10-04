<#
.SYNOPSIS
    Harbinger's Purge GitHub launcher.

.DESCRIPTION
    Downloads the current Harbinger's Purge toolkit, executor, and wsd.crt
    from the GitHub main branch into a unique temporary directory, then
    launches the toolkit menu.

    Supported operating systems:
      - Windows 11
      - Windows Server 2022

    Run this script as Administrator. The launcher verifies elevation and
    re-launches itself elevated when started non-elevated.

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

function Write-LauncherStatus {
    param(
        [Parameter(Mandatory)][string]$Message
    )
    Write-Host "[Harbinger's Launcher] $Message" -ForegroundColor Cyan
}

function Test-SupportedWindows {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem

    if ($os.ProductType -eq 3) {
        # Windows Server 2022 is version 10.0.20348.x
        if ($os.Version -notlike '10.0.20348.*') {
            throw "Unsupported Windows Server version: $($os.Caption) ($($os.Version)). Harbinger's Purge supports Windows Server 2022 only."
        }
    }
    elseif ($os.ProductType -eq 1) {
        # Windows 11 is build 22000 or later.
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

function Test-Administrator {
    return ([Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RawUrl {
    param(
        [Parameter(Mandatory)][string]$FileName
    )

    $encodedOwner = [uri]::EscapeDataString($RepositoryOwner)
    $encodedRepo  = [uri]::EscapeDataString($RepositoryName)
    $encodedBranch = [uri]::EscapeDataString($Branch)

    return "https://raw.githubusercontent.com/$encodedOwner/$encodedRepo/refs/heads/$encodedBranch/$FileName"
}

if (-not $IsWindows) {
    throw "This launcher is Windows-only."
}

if (-not (Test-Administrator)) {
    Write-LauncherStatus 'Administrator rights are required. Re-launching elevated...'

    if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
        throw 'The launcher must be saved as a .ps1 file before it can self-elevate.'
    }

    $argumentList = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', "`"$PSCommandPath`""
        '-RepositoryOwner', $RepositoryOwner
        '-RepositoryName', $RepositoryName
        '-Branch', $Branch
    )

    if ($KeepDownloadedFiles) {
        $argumentList += '-KeepDownloadedFiles'
    }

    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argumentList | Out-Null
    exit 0
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

        $length = (Get-Item -LiteralPath $item.Destination).Length
        if ($length -le 0) {
            throw "Downloaded file is empty: $($item.Name)."
        }
    }

    $certText = Get-Content -LiteralPath $certPath -Raw
    if ($certText -notmatch '-----BEGIN CERTIFICATE-----' -or
        $certText -notmatch '-----END CERTIFICATE-----') {
        throw 'The downloaded wsd.crt does not look like a PEM certificate.'
    }

    Write-LauncherStatus 'All required files downloaded successfully.'
    Write-LauncherStatus 'Starting Harbinger''s CyberPatriot Toolkit...'

    $toolkitArguments = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', "`"$toolkitPath`""
        '-PurgeScriptPath', "`"$purgePath`""
    )

    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $toolkitArguments -PassThru -Wait
    $exitCode = $process.ExitCode

    if ($KeepDownloadedFiles) {
        Write-LauncherStatus "Downloaded files kept at: $tempRoot"
    }
    else {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    exit $exitCode
}
catch {
    Write-Host ''
    Write-Host "Harbinger's Launcher ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ''
    Write-Host 'No hardening changes were made by the launcher itself.' -ForegroundColor Yellow
    if ($tempRoot -and (Test-Path -LiteralPath $tempRoot) -and -not $KeepDownloadedFiles) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit 1
}
