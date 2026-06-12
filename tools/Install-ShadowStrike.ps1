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
function Write-Fail([string]$msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "ShadowStrike Phantom Installer" -ForegroundColor White
Write-Host "==============================" -ForegroundColor White
Write-Host "  Install dir : $InstallDir"
Write-Host "  Data dir    : $DataDir"
Write-Host ""

# ── 0. Pre-flight: check test-signing mode ────────────────────────────────────
if (-not $SkipDriver) {
    Write-Step "Checking test-signing mode..."
    $bcdOutput = & bcdedit /enum '{current}' 2>&1 | Out-String
    $testSigningOn = $bcdOutput -match 'testsigning\s+Yes'
    if (-not $testSigningOn) {
        Write-Host ""
        Write-Fail "Test-signing mode is NOT enabled."
        Write-Host ""
        Write-Host "  The kernel driver (PhantomSensor.sys) is test-signed and will be" -ForegroundColor Yellow
        Write-Host "  rejected by Windows unless test-signing mode is active." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Run the following in an admin PowerShell, then REBOOT, then re-run" -ForegroundColor Yellow
        Write-Host "  this installer:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "      bcdedit /set testsigning on" -ForegroundColor White
        Write-Host "      shutdown /r /t 0" -ForegroundColor White
        Write-Host ""
        Write-Host "  Alternatively, run with -SkipDriver to install everything except" -ForegroundColor Yellow
        Write-Host "  the kernel driver (real-time protection will be inactive)." -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }
    Write-OK "Test-signing mode is active."
}

# ── 1. Verify source layout ───────────────────────────────────────────────────
Write-Step "Verifying package layout..."

$requiredFiles = @(
    'ShadowStrikePhantomService.exe',
    'ShadowStrikePhantomCLI.exe',
    'ShadowStrikePhantomTray.exe',
    'ShadowStrikePhantomUninstaller.exe',
    'onnxruntime.dll',
    'onnxruntime_providers_shared.dll',
    'models\cortex_static.onnx',
    'models\cortex_behavioral.onnx',
    'models\cortex_memory.onnx',
    'models\cortex_network.onnx',
    'models\cortex_emulation.onnx',
    'driver\PhantomSensor.sys',
    'driver\PhantomSensor.inf'
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
    & sc.exe delete $svcName 2>$null | Out-Null
    Start-Sleep -Seconds 1
}
# Also stop and remove the kernel driver service if present from a prior install
if (Get-Service 'PhantomSensor' -ErrorAction SilentlyContinue) {
    Write-Step "Stopping existing PhantomSensor driver..."
    Stop-Service 'PhantomSensor' -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & sc.exe delete 'PhantomSensor' 2>$null | Out-Null
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
    'ShadowStrikePhantomUninstaller.exe',
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
    foreach ($f in @('PhantomSensor.sys', 'PhantomSensor.inf', 'PhantomSensor.cat')) {
        $src = Join-Path $ScriptDir "driver\$f"
        if (Test-Path $src) { Copy-Item $src "$InstallDir\driver\" -Force }
    }
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

Set-ItemProperty -Path "$regBase\PhantomCortex" -Name 'ModelDirectory' `
    -Value "$DataDir\models" -Type String
Set-ItemProperty -Path "$regBase\PhantomHome\Install" -Name 'InstallFolder' `
    -Value $InstallDir -Type String
Set-ItemProperty -Path "$regBase\PhantomHome\Dirs" -Name 'Logs'       -Value "$DataDir\Logs"       -Type String
Set-ItemProperty -Path "$regBase\PhantomHome\Dirs" -Name 'Quarantine' -Value "$DataDir\Quarantine" -Type String
Set-ItemProperty -Path "$regBase\PhantomHome\Dirs" -Name 'Models'     -Value "$DataDir\models"     -Type String

Write-OK "Registry configuration written."

# ── 9. Install kernel driver ───────────────────────────────────────────────────
$driverRunning = $false

if (-not $SkipDriver) {
    $inf = "$InstallDir\driver\PhantomSensor.inf"
    $sys = "$InstallDir\driver\PhantomSensor.sys"
    $cat = "$InstallDir\driver\PhantomSensor.cat"

    if (Test-Path $inf) {

        # Trust the signing certificate.
        # Prefer the .cat catalog; fall back to extracting the cert from the .sys binary.
        Write-Step "Trusting driver signing certificate..."
        $certTrusted = $false
        try {
            # Try .cat first (may not be present in all builds)
            $sigSource = if (Test-Path $cat) { $cat } elseif (Test-Path $sys) { $sys } else { $null }

            if ($sigSource) {
                $sig = Get-AuthenticodeSignature $sigSource
                if ($sig -and $sig.SignerCertificate) {
                    $certBytes = $sig.SignerCertificate.Export(
                        [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    foreach ($storeName in @('Root', 'TrustedPublisher')) {
                        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                            $storeName, 'LocalMachine')
                        $store.Open('ReadWrite')
                        $certObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                        $store.Add($certObj)
                        $store.Close()
                    }
                    $thumbprint = $sig.SignerCertificate.Thumbprint
                    # Persist thumbprint so the uninstaller can remove the cert cleanly
                    Set-ItemProperty -Path "$regBase\PhantomHome\Install" `
                        -Name 'DriverCertThumbprint' -Value $thumbprint -Type String
                    Write-OK "Certificate trusted (thumbprint: $thumbprint)."
                    $certTrusted = $true
                } else {
                    Write-Warn "No authenticode signature found on $sigSource."
                }
            } else {
                Write-Warn "Neither PhantomSensor.cat nor PhantomSensor.sys found — skipping cert trust."
            }
        } catch {
            Write-Warn "Could not import driver certificate: $_"
        }

        if (-not $certTrusted) {
            Write-Warn "Certificate trust failed. pnputil may reject the driver."
        }

        # Install driver into the driver store
        Write-Step "Installing kernel driver via pnputil..."
        $pnpOut = & pnputil /add-driver $inf /install 2>&1 | Out-String

        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) {
            Write-OK "Driver package added to driver store."

            # Parse the published name (e.g. "oem78.inf") from pnputil output
            $publishedName = $null
            if ($pnpOut -match 'Published Name:\s+(\S+\.inf)') {
                $publishedName = $Matches[1]
                Set-ItemProperty -Path "$regBase\PhantomHome\Install" `
                    -Name 'DriverPublishedName' -Value $publishedName -Type String
                Write-OK "Published driver name: $publishedName (saved to registry)."
            } else {
                Write-Warn "Could not parse published driver name from pnputil output."
                Write-Warn $pnpOut
            }

            # Start the PhantomSensor kernel driver service
            Write-Step "Starting kernel driver (PhantomSensor)..."
            # Use sc.exe with a background job so we can apply our own timeout
            $job = Start-Job { & sc.exe start PhantomSensor 2>&1 }
            $done = Wait-Job $job -Timeout 30
            if (-not $done) {
                Stop-Job $job
                Write-Warn "sc start PhantomSensor timed out after 30s."
            } else {
                $scOut = Receive-Job $job
                Remove-Job $job -Force
            }

            Start-Sleep -Seconds 3
            $drv = Get-Service 'PhantomSensor' -ErrorAction SilentlyContinue
            if ($drv -and $drv.Status -eq 'Running') {
                Write-OK "PhantomSensor driver is running."
                $driverRunning = $true
            } else {
                Write-Warn "PhantomSensor driver failed to start."
                Write-Warn "This usually means test-signing mode was not active before the last reboot."
                Write-Warn ""
                Write-Warn "ACTION REQUIRED:"
                Write-Warn "  1. Confirm test-signing is on:  bcdedit /enum {current}"
                Write-Warn "  2. If not listed as 'Yes', run:  bcdedit /set testsigning on"
                Write-Warn "  3. Reboot, then start the driver: sc start PhantomSensor"
                Write-Warn "  4. Then start the service:        sc start $svcName"
            }
        } else {
            Write-Warn "pnputil returned $LASTEXITCODE — driver install failed."
            Write-Warn "Ensure test-signing is active: bcdedit /set testsigning on  (then reboot)"
            Write-Warn $pnpOut
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
    $regOut = & $svcExe --install 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Service registration returned $LASTEXITCODE — check logs in $DataDir\Logs\"
        Write-Warn $regOut
    } else {
        Write-OK "Service registered."
    }

    if (-not $SkipDriver -and -not $driverRunning) {
        Write-Warn ""
        Write-Warn "Skipping service start — PhantomSensor kernel driver is not running."
        Write-Warn "The service will fail to connect to the driver's filter port."
        Write-Warn "Once the driver is loaded (after enabling test-signing + reboot),"
        Write-Warn "start the service with:  sc start $svcName"
    } else {
        Write-Step "Starting service..."
        # Use sc.exe via a background job with an explicit timeout so we don't hang
        $job = Start-Job { & sc.exe start $using:svcName 2>&1 }
        $done = Wait-Job $job -Timeout 60
        if (-not $done) {
            Stop-Job $job
            Remove-Job $job -Force
            Write-Warn "Service start timed out after 60s."
            Write-Warn "The service may still be initialising. Check with: sc query $svcName"
        } else {
            $scOut = Receive-Job $job
            Remove-Job $job -Force

            Start-Sleep -Seconds 5
            $svc = Get-Service $svcName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                Write-OK "Service is running."
            } else {
                Write-Warn "Service did not reach Running state."
                Write-Warn "Check: sc query $svcName"
                Write-Warn "Logs:  $DataDir\Logs\"
            }
        }
    }
}

# ── 11. Add install dir to system PATH ────────────────────────────────────────
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
Write-Host "  Driver   : sc query PhantomSensor"
Write-Host "  CLI      : $InstallDir\ShadowStrikePhantomCLI.exe"
Write-Host "  Logs     : $DataDir\Logs\"
Write-Host "  Models   : $DataDir\models\"
Write-Host ""
if (-not $driverRunning -and -not $SkipDriver) {
    Write-Host "WARNING: Driver not running. Enable test-signing + reboot, then:" -ForegroundColor Yellow
    Write-Host "  sc start PhantomSensor" -ForegroundColor Yellow
    Write-Host "  sc start $svcName" -ForegroundColor Yellow
    Write-Host ""
} elseif ($LASTEXITCODE -eq 3010) {
    Write-Host "A reboot is required to finish driver installation." -ForegroundColor Yellow
    Write-Host "Run: shutdown /r /t 0" -ForegroundColor Yellow
    Write-Host ""
}
