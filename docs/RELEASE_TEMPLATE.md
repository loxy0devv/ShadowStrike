# ShadowStrike Phantom — Release Package

**Version**: `{{REF}}`
**Build SHA**: `{{SHA}}`
**Date**: {{DATE}}

---

## Contents of this Package

| File / Directory | Description |
|-----------------|-------------|
| `ShadowStrikePhantomService.exe` | Windows service — detection engine, IPC server, ~3 400+ rules compiled in |
| `ShadowStrikePhantomCLI.exe` | Interactive terminal control interface (run in an elevated terminal) |
| `ShadowStrikePhantomTray.exe` | System-tray status notification app |
| `onnxruntime.dll` | ONNX Runtime — required for ML inference |
| `onnxruntime_providers_shared.dll` | ONNX Runtime execution provider |
| `models\cortex_static.onnx` | Static-analysis ML model (PE features) |
| `models\cortex_behavioral.onnx` | Behavioural-analysis ML model |
| `models\cortex_memory.onnx` | Memory-scan ML model |
| `models\cortex_network.onnx` | Network-traffic ML model |
| `models\cortex_emulation.onnx` | Emulation-trace ML model |
| `models\cortex_*_int8.onnx` | INT8 quantized variants of the above (5 files) |
| `driver\PhantomSensor.sys` | Kernel minifilter driver (test-signed) |
| `driver\PhantomSensor.inf` | Driver INF — used by pnputil for installation |
| `Install-ShadowStrike.ps1` | One-shot install script (run as Administrator) |
| `VERSION.txt` | Build version stamp |
| `RELEASE.md` | This file |

---

## Prerequisites

- **OS**: Windows 10 21H2 or later (x64). Windows 11 recommended.
- **Architecture**: x64 only.
- **Privileges**: Installation requires elevation (Administrator or SYSTEM).
- **Test-signing** (for driver): The kernel driver in this package is **test-signed**
  (not EV-signed). This means:
  - It will NOT load on production systems by default.
  - For development / evaluation use, enable test-signing mode (see below).
  - For production deployment, the driver must be signed with a valid EV
    code-signing certificate via Microsoft's Windows Hardware Dev Center or
    Azure Trusted Signing. Do NOT use test-signing mode in production environments.

---

## Quick Install (Recommended)

Extract the ZIP, then run the included PowerShell installer from an **elevated PowerShell** prompt:

```powershell
# From the directory where the ZIP was extracted:
.\Install-ShadowStrike.ps1
```

The script handles everything automatically:
- Creates `C:\Program Files\ShadowStrike\Phantom\` and copies all binaries there
- Creates `C:\ProgramData\ShadowStrike\` with subdirectories (`Logs\`, `Quarantine\`, `models\`)
- Deploys all 10 ML models to `%ProgramData%\ShadowStrike\models\`
- Sets `HKLM\SOFTWARE\ShadowStrike\PhantomCortex\ModelDirectory` to the models path
- Installs the kernel driver via pnputil
- Registers and starts `ShadowStrikePhantomService`
- Adds the install directory to the system PATH

If the driver requires test-signing, enable it first (see step 1 below), reboot, then re-run the installer.

---

## Manual Installation

> All commands below require an **elevated Command Prompt or PowerShell** (Run as Administrator).

### Step 1 — Enable test-signing (once; requires reboot)

```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

*After the reboot, a "Test Mode" watermark will appear on the desktop.*

### Step 2 — Install the kernel driver

```cmd
pnputil /add-driver driver\PhantomSensor.inf /install
```

Verify the driver loaded:
```cmd
sc query PhantomSensor
```
Expected: `STATE: 4  RUNNING`

### Step 3 — Copy files and deploy models

```powershell
$installDir = "C:\Program Files\ShadowStrike\Phantom"
$dataDir    = "C:\ProgramData\ShadowStrike"

# Create directories
New-Item -ItemType Directory -Force $installDir, "$dataDir\Logs", "$dataDir\Quarantine", "$dataDir\models"

# Copy binaries
Copy-Item ShadowStrikePhantomService.exe, ShadowStrikePhantomCLI.exe, `
          ShadowStrikePhantomTray.exe, onnxruntime.dll, `
          onnxruntime_providers_shared.dll $installDir

# Deploy ML models
Copy-Item models\*.onnx "$dataDir\models\"

# Set model directory registry key
New-Item -Path "HKLM:\SOFTWARE\ShadowStrike\PhantomCortex" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\ShadowStrike\PhantomCortex" `
    -Name ModelDirectory -Value "$dataDir\models" -Type String
```

### Step 4 — Install and start the service

```cmd
ShadowStrikePhantomService.exe --install
ShadowStrikePhantomService.exe --start
```

Or via the Service Control Manager:
```cmd
sc start PhantomService
```

### Step 5 — Launch the CLI

```cmd
ShadowStrikePhantomCLI.exe
```

The CLI connects to the service over a named pipe (`\\.\pipe\ShadowStrikeServicePipe`).
It runs in interactive mode by default. Pass a subcommand to run a single operation:

```cmd
ShadowStrikePhantomCLI.exe status
ShadowStrikePhantomCLI.exe detections --limit 50
ShadowStrikePhantomCLI.exe scan C:\Users\user\Downloads
ShadowStrikePhantomCLI.exe rules status
ShadowStrikePhantomCLI.exe help
```

---

## Directory Structure After Installation

```
C:\Program Files\ShadowStrike\Phantom\
├── ShadowStrikePhantomService.exe
├── ShadowStrikePhantomCLI.exe
├── ShadowStrikePhantomTray.exe
├── onnxruntime.dll
├── onnxruntime_providers_shared.dll
└── driver\
    ├── PhantomSensor.sys
    └── PhantomSensor.inf

C:\ProgramData\ShadowStrike\
├── Logs\             ← service and boot logs
├── Quarantine\       ← quarantined threat artefacts
└── models\
    ├── cortex_static.onnx
    ├── cortex_behavioral.onnx
    ├── cortex_memory.onnx
    ├── cortex_network.onnx
    ├── cortex_emulation.onnx
    ├── cortex_static_int8.onnx
    ├── cortex_behavioral_int8.onnx
    ├── cortex_memory_int8.onnx
    ├── cortex_network_int8.onnx
    └── cortex_emulation_int8.onnx
```

---

## Starting Order

1. Ensure the kernel driver (`PhantomSensor.sys`) is loaded first.
2. Start the `PhantomService` Windows service.
3. The CLI and Tray applications connect to the service; they can be started in any order after the service is running.

---

## Detection Rules

Detection rules (~3 400+ across four corpora) are compiled directly into
`ShadowStrikePhantomService.exe` as an XOR-obfuscated binary blob.
No plaintext rule files are required on disk at runtime.

To update rules, rebuild from source and redeploy the service binary.

Rule corpora included:
- **Native** (ShadowStrike hand-written) — organized by detection category
- **capa** (FireEye/Mandiant capability rules v9.4.0)
- **Sigma** (Windows detection rules)
- **Elastic** (Windows detection rules — NDJSON)

---

## ML Models

Five PhantomCortex models are included and deployed automatically by the installer:

| Model file | Detects |
|------------|---------|
| `cortex_static.onnx` | Static PE features — fast pre-execution verdict |
| `cortex_behavioral.onnx` | Runtime API call sequences and behaviour patterns |
| `cortex_memory.onnx` | In-memory artefacts — shellcode, injected regions |
| `cortex_network.onnx` | Network traffic patterns — C2, exfil, beaconing |
| `cortex_emulation.onnx` | Emulation traces — obfuscated / packed samples |

INT8 quantized variants (`*_int8.onnx`) are included for use on endpoints where
reduced memory footprint is required; swap them in by replacing the FP32 files.

The service logs model load status at startup — check `%ProgramData%\ShadowStrike\Logs\`
if ML scoring is not active. Ensure `HKLM\SOFTWARE\ShadowStrike\PhantomCortex\ModelDirectory`
points to the correct path.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Driver fails to load | Test-signing not enabled | Run `bcdedit /set testsigning on` and reboot |
| `Code integrity` error | Signature mismatch | Re-sign with valid cert, or use test-signing for dev |
| CLI reports "service not reachable" | Service not running | `sc start PhantomService` |
| Service exits immediately | Missing dependency DLL | Ensure `onnxruntime.dll` is alongside the .exe |
| High CPU during first run | Initial rule JIT compilation | Normal; subsides after warm-up |
| No ML detections | `ModelDirectory` registry key missing | Re-run `Install-ShadowStrike.ps1` or set key manually |
| No ML detections | Models directory empty or wrong path | Verify `%ProgramData%\ShadowStrike\models\` contains .onnx files |

---

## Limitations (this build)

- Driver is **test-signed only** — not suitable for production.
- The web UI has been removed; the CLI is the operator interface.
  A native GUI is planned for a future release.

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0).
See `LICENSE.txt` in the source repository.

---

*Generated automatically by GitHub Actions on {{DATE}}.*
