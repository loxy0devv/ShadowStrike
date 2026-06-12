#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs ShadowStrike Phantom from the release ZIP package.

.DESCRIPTION
    Copies binaries to Program Files, deploys ML models and runtime data to
    ProgramData, registers the Windows service, sets registry configuration,
    installs the kernel driver, and starts the service.

    Run from an elevated PowerShell prompt in the directory where the release
    ZIP was extracted (the directory containing ShadowStrikePhantomService.exe).

.PARAMETER InstallDir
    Target Program Files directory. Default: C:\Program Files\ShadowStrike\Phantom

.PARAMETER DataDir
    ProgramData directory for runtime data (logs, quarantine, models).
    Default: C:\ProgramData\ShadowStrike

.PARAMETER SkipDriver
    Skip kernel driver installation (useful on systems without test-signing enabled).

.PARAMETER SkipService
    Install files only; do not register or start the Windows service.

.EXAMPLE
    .\Install-ShadowStrike.ps1

.EXAMPLE
    .\Install-ShadowStrike.ps1 -SkipDriver
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\ShadowStrike\Phantom",
    [string]$DataDir    = "$env:ProgramData\ShadowStrike",
    [switch]$SkipDriver,
    [switch]$SkipService
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

function Write-Step([string]$msg) { Write-Host "  --> $msg" -ForegroundColor Cyan }
function Write-OK([string]$msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "ShadowStrike Phantom Installer" -ForegroundColor White
Write-Host "==============================" -ForegroundColor White
Write-Host "  Install dir : $InstallDir"
Write-Host "  Data dir    : $DataDir"
Write-Host ""

# ── 1. Verify source layout ───────────────────────────────────────────────────
Write-Step "Verifying package layout..."

$requiredFiles = @(
    'ShadowStrikePhantomService.exe',
    'ShadowStrikePhantomCLI.exe',
    'ShadowStrikePhantomTray.exe',
    'onnxruntime.dll',
    'onnxruntime_providers_shared.dll',
    'models\cortex_static.onnx',
    'models\cortex_behavioral.onnx',
    'models\cortex_memory.onnx',
    'models\cortex_network.onnx',
    'models\cortex_emulation.onnx'
)

$missing = $requiredFiles | Where-Object { -not (Test-Path (Join-Path $ScriptDir $_)) }
if ($missing) {
    Write-Error "Missing required files in package:`n$($missing -join "`n")`n`nRun this script from the extracted ZIP directory."
}
Write-OK "Package layout verified."

# ── 2. Stop and remove existing service (upgrade path) ───────────────────────
$svcName = 'ShadowStrikePhantomService'
if (Get-Service $svcName -ErrorAction SilentlyContinue) {
    Write-Step "Stopping existing service..."
    Stop-Service $svcName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Step "Removing existing service registration..."
    & "$InstallDir\ShadowStrikePhantomService.exe" --uninstall 2>$null
    Start-Sleep -Seconds 1
}

# ── 3. Create directory structure ─────────────────────────────────────────────
Write-Step "Creating directory structure..."

$dirs = @(
    $InstallDir,
    "$InstallDir\driver",
    $DataDir,
    "$DataDir\Logs",
    "$DataDir\Quarantine",
    "$DataDir\models"
)
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Force $d | Out-Null
}
Write-OK "Directories created."

# ── 4. Set ProgramData ACLs (SYSTEM=Full, Admins=Full, Users=Read) ─────────────
Write-Step "Applying ProgramData ACLs..."
$acl = Get-Acl $DataDir
$acl.SetAccessRuleProtection($false, $true)
foreach ($path in @("$DataDir\Logs", "$DataDir\Quarantine", "$DataDir\models")) {
    $a = Get-Acl $path
    $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Users', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl $path $a
}
Write-OK "ACLs applied."

# ── 5. Copy binaries to Program Files ─────────────────────────────────────────
Write-Step "Copying binaries to $InstallDir..."

$binaries = @(
    'ShadowStrikePhantomService.exe',
    'ShadowStrikePhantomCLI.exe',
    'ShadowStrikePhantomTray.exe',
    'onnxruntime.dll',
    'onnxruntime_providers_shared.dll'
)
# Optional: copy OpenSSL DLLs if present
foreach ($f in @('libcrypto-3-x64.dll', 'libssl-3-x64.dll')) {
    if (Test-Path (Join-Path $ScriptDir $f)) { $binaries += $f }
}

foreach ($f in $binaries) {
    Copy-Item (Join-Path $ScriptDir $f) $InstallDir -Force
}
Write-OK "Binaries copied: $($binaries -join ', ')"

# ── 6. Copy driver files ───────────────────────────────────────────────────────
if (Test-Path (Join-Path $ScriptDir 'driver\PhantomSensor.sys')) {
    Write-Step "Copying driver files..."
    Copy-Item (Join-Path $ScriptDir 'driver\PhantomSensor.sys') "$InstallDir\driver\" -Force
    $inf = Join-Path $ScriptDir 'driver\PhantomSensor.inf'
    if (Test-Path $inf) { Copy-Item $inf "$InstallDir\driver\" -Force }
    Write-OK "Driver files copied."
}

# ── 7. Deploy ML models to ProgramData\ShadowStrike\models\ ───────────────────
Write-Step "Deploying ML models to $DataDir\models..."

$modelFiles = Get-ChildItem (Join-Path $ScriptDir 'models') -Filter '*.onnx'
if (-not $modelFiles) {
    Write-Warn "No .onnx files found in models\ — ML scoring will be inactive."
} else {
    foreach ($f in $modelFiles) {
        Copy-Item $f.FullName "$DataDir\models\" -Force
    }
    Write-OK "Deployed $($modelFiles.Count) model file(s): $($modelFiles.Name -join ', ')"
}

# ── 8. Write registry configuration ───────────────────────────────────────────
Write-Step "Writing registry configuration..."

$regBase = 'HKLM:\SOFTWARE\ShadowStrike'
New-Item -Path "$regBase\PhantomCortex" -Force | Out-Null
New-Item -Path "$regBase\PhantomHome\Install" -Force | Out-Null
New-Item -Path "$regBase\PhantomHome\Dirs" -Force | Out-Null

# PhantomCortex ML model directory — read by CortexConfig at service startup
Set-ItemProperty -Path "$regBase\PhantomCortex" -Name 'ModelDirectory' `
    -Value "$DataDir\models" -Type String

# Install metadata
Set-ItemProperty -Path "$regBase\PhantomHome\Install" -Name 'InstallFolder' `
    -Value $InstallDir -Type String

# Data directory pointers (used by tray and CLI for status display)
Set-ItemProperty -Path "$regBase\PhantomHome\Dirs" -Name 'Logs'       -Value "$DataDir\Logs"       -Type String
Set-ItemProperty -Path "$regBase\PhantomHome\Dirs" -Name 'Quarantine' -Value "$DataDir\Quarantine" -Type String
Set-ItemProperty -Path "$regBase\PhantomHome\Dirs" -Name 'Models'     -Value "$DataDir\models"     -Type String

Write-OK "Registry configuration written."

# ── 9. Install kernel driver ───────────────────────────────────────────────────
if (-not $SkipDriver) {
    $inf = "$InstallDir\driver\PhantomSensor.inf"
    if (Test-Path $inf) {
        Write-Step "Installing kernel driver via pnputil..."
        $result = & pnputil /add-driver $inf /install 2>&1
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) {
            Write-OK "Driver installed (reboot may be required)."
        } else {
            Write-Warn "pnputil returned $LASTEXITCODE — driver install may have failed."
            Write-Warn "Enable test-signing first: bcdedit /set testsigning on  (then reboot)"
            Write-Warn $result
        }
    } else {
        Write-Warn "PhantomSensor.inf not found — skipping driver install."
    }
} else {
    Write-Warn "Driver installation skipped (-SkipDriver)."
}

# ── 10. Register Windows service ──────────────────────────────────────────────
if (-not $SkipService) {
    Write-Step "Registering Windows service..."
    $svcExe = "$InstallDir\ShadowStrikePhantomService.exe"
    & $svcExe --install
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Service registration returned $LASTEXITCODE — check logs in $DataDir\Logs\"
    } else {
        Write-OK "Service registered."
    }

    Write-Step "Starting service..."
    Start-Service $svcName -ErrorAction SilentlyContinue
    $svc = Get-Service $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-OK "Service is running."
    } else {
        Write-Warn "Service did not start automatically. Start manually: sc start $svcName"
    }
}

# ── 11. Add install dir to system PATH (optional, for CLI convenience) ─────────
$currentPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($currentPath -notlike "*$InstallDir*") {
    Write-Step "Adding $InstallDir to system PATH..."
    [System.Environment]::SetEnvironmentVariable('Path', "$currentPath;$InstallDir", 'Machine')
    Write-OK "PATH updated. Open a new terminal to use 'ShadowStrikePhantomCLI' from any directory."
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host ""
Write-Host "  Service  : sc query $svcName"
Write-Host "  CLI      : $InstallDir\ShadowStrikePhantomCLI.exe"
Write-Host "  Logs     : $DataDir\Logs\"
Write-Host "  Models   : $DataDir\models\"
Write-Host ""
Write-Host "If the driver requires a reboot, run: shutdown /r /t 0" -ForegroundColor Yellow
Write-Host ""
