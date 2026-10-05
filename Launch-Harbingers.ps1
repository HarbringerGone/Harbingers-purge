<#
.SYNOPSIS
    Harbinger's Purge canonical GitHub launcher.

.DESCRIPTION
    Downloads the canonical Harbinger toolkit, Purge executor, and wsd.crt
    from the repository's main branch into a unique temporary directory and
    runs the toolkit.

    The main branch is intentionally the only release source. There is no
    branch-selection parameter, so branch mix-ups cannot cause this launcher
    to silently pull another release.

    Supports Windows 11 client editions and Windows Server 2022 editions.
    Windows Server 2022 Server Core is handled by the toolkit's console
    fallback.

.AUTHOR
    Channveer Singh
#>

[CmdletBinding()]
param(
    [switch]$KeepDownloadedFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$RepositoryOwner = 'HarbringerGone'
$RepositoryName = 'Harbingers-purge'
$Branch = 'main'

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

function Get-OsInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $caption = [string]$os.Caption
    $build = 0
    [void][int]::TryParse([string]$os.BuildNumber, [ref]$build)
    $productType = [int]$os.ProductType
    $installationType = ''

    try {
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $installationType = [string]$cv.InstallationType
    } catch {}

    $kind = $null
    if ($productType -eq 1 -and (
        ($caption -match '(?i)\bWindows\s+11\b') -or
        ($build -ge 22000)
    )) {
        $kind = 'Windows 11'
    }
    elseif ($productType -in 2,3 -and $build -eq 20348) {
        $kind = 'Windows Server 2022'
    }

    [pscustomobject]@{
        Caption = $caption
        Build = $build
        ProductType = $productType
        InstallationType = $installationType
        Kind = $kind
    }
}

function Test-SupportedWindows {
    $os = Get-OsInfo
    if (-not $os.Kind) {
        throw "Unsupported OS: $($os.Caption) (ProductType $($os.ProductType), build $($os.Build)). Harbinger's Purge supports Windows 11 and Windows Server 2022."
    }

    $edition = ''
    try {
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $edition = [string]$cv.EditionID
    } catch {}

    $install = if ([string]::IsNullOrWhiteSpace($os.InstallationType)) { 'Unknown' } else { $os.InstallationType }
    $editionText = if ([string]::IsNullOrWhiteSpace($edition)) { 'Unknown' } else { $edition }

    Write-LauncherStatus "Supported OS detected: $($os.Kind) | edition=$editionText | install=$install | build=$($os.Build)."
    return $os
}

function Get-RawUrl {
    param([Parameter(Mandatory)][string]$FileName)
    $nonce = [guid]::NewGuid().ToString('N')
    return "https://raw.githubusercontent.com/${RepositoryOwner}/${RepositoryName}/refs/heads/${Branch}/${FileName}?nocache=${nonce}"
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
        $messages = @($parseErrors | ForEach-Object { $_.Message }) -join ' | '
        throw "$Label syntax check failed: $messages"
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
            throw "$Label contains non-ASCII bytes. Refusing to run it because Windows PowerShell 5.1 can misinterpret encoded scripts."
        }
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This launcher is Windows-only.'
}

if (-not (Test-Administrator)) {
    throw "Administrator PowerShell is required. Open PowerShell with 'Run as administrator' and run the launcher again."
}

if (-not [Environment]::Is64BitProcess) {
    $sysNative = Join-Path $env:windir 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $sysNative -PathType Leaf) {
        Write-LauncherStatus '32-bit PowerShell detected; relaunching under 64-bit Windows PowerShell.'
        & $sysNative -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
    throw 'A 64-bit PowerShell executable could not be located.'
}

try {
    $osInfo = Test-SupportedWindows

    $tempRoot = Join-Path $env:TEMP ("HarbingersPurgeLaunch-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

    $toolkitPath = Join-Path $tempRoot 'Harbingers-CyberPatriot-Toolkit.ps1'
    $purgePath = Join-Path $tempRoot 'Harbingers-Purge.ps1'
    $certPath = Join-Path $tempRoot 'wsd.crt'

    $downloads = @(
        @{ Name = 'GUI Toolkit'; File = 'Harbingers-CyberPatriot-Toolkit.ps1'; Destination = $toolkitPath }
        @{ Name = 'Purge Executor'; File = 'Harbingers-Purge.ps1'; Destination = $purgePath }
        @{ Name = 'wsd.crt'; File = 'wsd.crt'; Destination = $certPath }
    )

    foreach ($item in $downloads) {
        $url = Get-RawUrl -FileName $item.File
        Write-LauncherStatus "Downloading $($item.Name) from main..."
        Invoke-WebRequest -Uri $url -OutFile $item.Destination -UseBasicParsing -MaximumRedirection 5

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

    Test-AsciiScript -Path $toolkitPath -Label 'GUI Toolkit'
    Test-AsciiScript -Path $purgePath -Label 'Purge Executor'

    Test-PowerShellSyntax -Path $toolkitPath -Label 'GUI Toolkit'
    Test-PowerShellSyntax -Path $purgePath -Label 'Purge Executor'

    Write-LauncherStatus 'All required files downloaded and syntax-checked successfully.'
    Write-LauncherStatus "Starting Harbinger's CyberPatriot Toolkit from the canonical main release..."
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
