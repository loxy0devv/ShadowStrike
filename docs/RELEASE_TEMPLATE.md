# ShadowStrike Phantom — Release Package

**Version**: `{{REF}}`
**Build SHA**: `{{SHA}}`
**Date**: {{DATE}}

---

## Contents of this Package

| File | Description |
|------|-------------|
| `ShadowStrikePhantomService.exe` | Windows service — detection engine, IPC server, ~3 400+ rules compiled in |
| `ShadowStrikePhantomCLI.exe` | Interactive terminal control interface (run in an elevated terminal) |
| `ShadowStrikePhantomTray.exe` | System-tray status notification app |
| `ShadowStrikePhantomUI.exe` | Native Windows UI (preview) |
| `onnxruntime.dll` | ONNX Runtime — required for ML inference |
| `onnxruntime_providers_shared.dll` | ONNX Runtime execution provider |
| `driver\PhantomSensor.sys` | Kernel minifilter driver (test-signed) |
| `driver\PhantomSensor.inf` | Driver INF — used by pnputil for installation |
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

## Installation (Development / Evaluation)

> All commands below require an **elevated Command Prompt** (Run as Administrator).

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

### Step 3 — Install and start the service

```cmd
ShadowStrikePhantomService.exe --install
ShadowStrikePhantomService.exe --start
```

Or via the Service Control Manager:
```cmd
sc start PhantomService
```

### Step 4 — Launch the CLI

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

## Starting Order

1. Ensure the kernel driver (`PhantomSensor.sys`) is loaded first.
2. Start the `PhantomService` Windows service.
3. The CLI, Tray, and UI applications connect to the service; they can be started in any order after the service is running.

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

ML model files (`*.onnx`) are **not included** in this package due to size.

To enable ML scoring:
1. Train models using `PhantomCortex/training/scripts/train_all.py`
   (or obtain pre-trained models from the project's model repository).
2. Deploy the `.onnx` files to `%ProgramData%\ShadowStrike\models\`.
3. Set the model directory in registry:
   `HKLM\SOFTWARE\ShadowStrike\PhantomCortex\ModelDirectory`

The service operates fully without ML models — only the ML scoring stage
is inactive. All rule-based and behavioural detections work regardless.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Driver fails to load | Test-signing not enabled | Run `bcdedit /set testsigning on` and reboot |
| `Code integrity` error | Signature mismatch | Re-sign with valid cert, or use test-signing for dev |
| CLI reports "service not reachable" | Service not running | `sc start PhantomService` |
| Service exits immediately | Missing dependency DLL | Ensure `onnxruntime.dll` is alongside the .exe |
| High CPU during first run | Initial rule JIT compilation | Normal; subsides after warm-up |
| No ML detections | Models not deployed | Copy `.onnx` files to models directory (see above) |

---

## Limitations (this build)

- Driver is **test-signed only** — not suitable for production.
- ML models not bundled — deploy separately.
- The web UI has been removed; the CLI is the operator interface.
  A native GUI is planned for a future release.

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0).
See `LICENSE.txt` in the source repository.

---

*Generated automatically by GitHub Actions on {{DATE}}.*
