<#
.SYNOPSIS
    Harbinger's Purge GitHub launcher.

.DESCRIPTION
    Downloads the current Harbinger's Purge toolkit, executor, and wsd.crt
    from the GitHub main branch into a unique temporary directory, then
    launches the toolkit menu.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
    Supported operating systems: Windows 11 and Windows Server 2022.

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

function Write-LauncherStatus {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[Harbinger's Launcher] $Message" -ForegroundColor Cyan
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

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RawUrl {
    param([Parameter(Mandatory)][string]$FileName)

    return "https://raw.githubusercontent.com/$RepositoryOwner/$RepositoryName/refs/heads/$Branch/$FileName"
}

# Win32NT is the .NET-compatible Windows check for Windows PowerShell 5.1.
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "This launcher is Windows-only."
}

if (-not (Test-Administrator)) {
    Write-LauncherStatus 'Administrator rights are required. Re-launching elevated...'

    if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or
        -not (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
        throw 'The launcher must be saved as a .ps1 file before it can self-elevate.'
    }

    $arguments = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', "`"$PSCommandPath`""
        '-RepositoryOwner', $RepositoryOwner
        '-RepositoryName', $RepositoryName
        '-Branch', $Branch
    )

    if ($KeepDownloadedFiles) {
        $arguments += '-KeepDownloadedFiles'
    }

    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments | Out-Null
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

        if ((Get-Item -LiteralPath $item.Destination).Length -le 0) {
            throw "Downloaded file is empty: $($item.Name)."
        }
    }

    $certText = Get-Content -LiteralPath $certPath -Raw
    if (($certText -notmatch '-----BEGIN CERTIFICATE-----') -or
        ($certText -notmatch '-----END CERTIFICATE-----')) {
        throw 'The downloaded wsd.crt does not look like a PEM certificate.'
    }

    Write-LauncherStatus 'All required files downloaded successfully.'
    Write-LauncherStatus "Starting Harbinger's CyberPatriot Toolkit..."

    $toolkitArguments = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', "`"$toolkitPath`""
        '-PurgeScriptPath', "`"$purgePath`""
    )

    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $toolkitArguments -PassThru -Wait

    if ($KeepDownloadedFiles) {
        Write-LauncherStatus "Downloaded files kept at: $tempRoot"
    }
    else {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    exit $process.ExitCode
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
