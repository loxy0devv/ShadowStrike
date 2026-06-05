# ShadowStrike Phantom — Build & Run Guide

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Visual Studio 2022 | 17.x | C++ Desktop workload required |
| Windows SDK | 10.0.22621+ | |
| WDK | 10.0.22621+ | Must match SDK version exactly |
| LLVM/Clang-cl | 17+ | Optional — for clang-tidy CI checks |
| Node.js | 20 LTS | Frontend dashboard only |
| Python | 3.11+ | Rule smoke-test helper only |

All native dependencies (gtest, nlohmann/json, OpenSSL, ONNX Runtime, YARA, yaml-cpp)
are pre-vendored under `vendor/` or `include/`. No vcpkg or NuGet step is required.

---

## Repository Layout

```
ShadowStrike/
├── PhantomCoreLib.vcxproj        Engine static library (all detection, scanning, IPC)
├── ShadowStrikePhantomService.vcxproj  Windows service executable
├── PhantomEDR.vcxproj            Unit + integration test binary
├── PhantomSensor/                Kernel minifilter driver (WDK)
│   └── PhantomSensor.vcxproj
├── src/PhantomCore/              Engine source
│   ├── Detection/                Detection layer (rules, correlator, static, deep)
│   ├── Devices/                  Webcam protection
│   └── Config/                   ProductTier / license manager
├── rules/phantom/                Native PhantomRule YAML corpus (~123 rules)
│   ├── process/  file/  network/  memory/  registry/  sequence/  static/
├── frontend/                     React dashboard (dev mode)
└── docs/                         Architecture and API docs
```

---

## Build — Kernel Driver (PhantomSensor.sys)

> Must be built first; the service links against the shared protocol headers.

1. Open **x64 Native Tools Command Prompt for VS 2022**.
2. ```
   cd ShadowStrike\PhantomSensor
   msbuild PhantomSensor.vcxproj /p:Configuration=Release /p:Platform=x64
   ```
3. Output: `PhantomSensor\x64\Release\PhantomSensor.sys` + `PhantomSensor.inf`

**Test-signing (development only):**
```cmd
bcdedit /set testsigning on   # reboot required once
makecert -r -pe -n "CN=ShadowStrike Test" -ss "Root" -sr LocalMachine TestSign.cer
signtool sign /fd sha256 /s Root /n "ShadowStrike Test" PhantomSensor.sys
```

---

## Build — Engine + Service (Release)

```cmd
msbuild PhantomCoreLib.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild ShadowStrikePhantomService.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output: `x64\Release\ShadowStrikePhantomService.exe`

### Build flags of interest

| MSBuild Property | Default | Effect |
|-----------------|---------|--------|
| `SS_DEV_MODE=1` | 0 | Enables REST API on localhost:9443 |
| `SS_RULE_PATH` | `rules\phantom` | Override rule corpus root |
| `SS_LOG_LEVEL` | `Info` | `Debug` / `Info` / `Warn` / `Error` |

Pass via: `/p:DefineConstants="SS_DEV_MODE=1;SS_LOG_LEVEL=Debug"`

---

## Build — Unit/Integration Tests

```cmd
msbuild PhantomEDR.vcxproj /p:Configuration=Debug /p:Platform=x64
x64\Debug\PhantomEDR.exe --gtest_filter="*"
```

Run only rule smoke-tests:
```cmd
x64\Debug\PhantomEDR.exe --gtest_filter="RuleSmokeTest*"
```

---

## Install & Run the Service

### 1. Install the minifilter driver

```cmd
# Elevated CMD
sc create PhantomSensor type= kernel start= demand binPath= "C:\ShadowStrike\PhantomSensor.sys"
sc start PhantomSensor
```

Or use the INF:
```cmd
pnputil /add-driver PhantomSensor.inf /install
```

### 2. Install & start the Windows service

```cmd
# Elevated CMD
sc create ShadowStrikePhantomService binPath= "C:\ShadowStrike\ShadowStrikePhantomService.exe" start= auto
sc start ShadowStrikePhantomService
```

Alternatively the binary self-installs:
```cmd
ShadowStrikePhantomService.exe --install
ShadowStrikePhantomService.exe --start
```

### 3. Verify startup

```cmd
# Service running?
sc query ShadowStrikePhantomService

# Driver attached?
fltMC filters

# Pipe reachable?
powershell -c "[System.IO.File]::Open('\.\pipe\ShadowStrikeServicePipe','Open','Read','ReadWrite')"
```

---

## Run the Frontend Dashboard (Dev Mode Only)

The dashboard requires the service to be running with `SS_DEV_MODE=1` so the
REST API on `https://localhost:9443` is active. It is **disabled in production builds**.

```bash
cd frontend
npm install
npm run dev          # starts Vite dev server at http://localhost:5173
```

Open `http://localhost:5173` in a browser. The Vite proxy forwards API calls to
`https://localhost:9443` (self-signed cert — click through browser warning once).

### Production build (embed in installer)

```bash
npm run build        # outputs to frontend/dist/
```

---

## Rule Corpus

Rules live under `rules/phantom/` and are hot-loaded at startup. To reload without
restarting the service:

```cmd
# via named-pipe CLI (once PhantomShell is built) or via REST (dev mode):
curl -X POST https://localhost:9443/api/v1/rules/reload -H "Authorization: Bearer dev-token"
```

Current corpus counts:

| Scope    | Count |
|----------|-------|
| process  | 30    |
| file     | 13    |
| network  | 15    |
| memory   | 10    |
| registry | 12    |
| sequence | 18    |
| static   | 25    |
| **Total**| **123** |

Plus ~3,291 imported rules (capa 1,045 · Sigma 2,233 · Elastic 13).

---

## Detection Engine Pipeline

```
ScanEngine::ScanFile()
  └─ Stage 0.5  DetectionEngine::AnalyzeFile()   ← all PhantomRules evaluated here
  └─ Stage 1    YARA corpus
  └─ Stage 2    ML (PhantomCortex ONNX models)
  └─ Stage 3    Heuristics / behavioral scoring
```

Real-time kernel events (ProcessNotify, ImageLoad, RegistryOp) are fed to `EventBus`
→ `Correlator` → verdict → `BehaviorBlocker` / `AccessControlManager`.

---

## Product Tiers

| Tier | License | Features |
|------|---------|----------|
| Community | None (AGPL default) | Core scan, RTP, behavioral, AI, local dashboard, basic threat intel |
| Professional | Signed `.lic` file | + Cloud console, EDR forensics, fleet management, signed driver |
| Enterprise | Signed `.lic` file | + SIEM/SOAR, XDR correlation, RBAC/SSO, compliance reporting |

License files are RSA-PSS-SHA256 signed. Development builds skip signature
verification (`kHasProductionKey = false` in `ProductTier.cpp`) — this flag
flips to `true` when the production signing key is embedded.

Override a feature for testing (logged to audit trail):
```cpp
ProductTierManager::Instance().OverrideFeature(FeatureCategory::ForensicsAdvanced, true);
```

---

## Named Pipe IPC Protocol

Production control plane: `\.\pipe\ShadowStrikeServicePipe`  
Wire format: 24-byte Envelope header + UTF-8 JSON payload  
Auth: `CommandType::AuthHandshake` with session token from `IpcAuthToken`

See `docs/APIs.md` for the full command table (CommandType 1–546).
