# ShadowStrike Phantom — Backend API Specification

**Document version:** 1.0.0  
**Last updated:** 2026-05-28  
**Stability:** Stable endpoints are marked ✅; internal/draft endpoints are marked 🔧

---

## Architecture overview

ShadowStrike exposes two API surfaces:

1. **BackendAPI** (`src/Products/Community/Shared/API/BackendAPI.hpp`)  
   In-process C++ API used by all callers: REST server, future native GUI, tests.  
   Thread-safe singleton. All methods are synchronous and return `Result<T>`.

2. **REST API** (`src/PhantomCore/API/RESTServer.hpp/.cpp`)  
   HTTP/HTTPS server bound to `127.0.0.1:9443`. Translates HTTP requests into
   `BackendAPI` calls. All REST routes require Bearer token authentication
   except `/api/v1/health`.

The frontend (future React SPA or native WinUI app) communicates **only** via
the REST API. It never calls BackendAPI directly.

---

## Authentication

### POST /api/v1/auth/login ✅

Login and obtain a session token.

**Request body (JSON):**
```json
{ "password": "string" }
```

**Response 200:**
```json
{
  "token": "64-char-hex-bearer-token",
  "csrfToken": "32-char-hex-csrf-token",
  "expiresIn": 1800
}
```

**Response 401:** Invalid credentials.  
**Security:** Rate-limited to 5 requests/second/IP. Constant-time comparison.

---

### POST /api/v1/auth/logout ✅

Invalidate the current session.  
**Headers:** `Authorization: Bearer <token>`  
**Response 204**

---

### GET /api/v1/auth/session ✅

Returns session metadata.  
**Response 200:**
```json
{ "userId": "local", "tier": "Home|EDR|XDR", "expiresIn": 900 }
```

---

## System

### GET /api/v1/health ✅ (no auth)

Health check for watchdog / CI.  
**Response 200:** `{ "status": "ok", "version": "3.0.0", "timestamp": 1234567890 }`

---

### GET /api/v1/status ✅

Returns protection status for the dashboard overview widget.  
**Response 200:**
```json
{
  "rtpEnabled": true,
  "behaviorBlockerRunning": true,
  "kernelSensorConnected": true,
  "mlEngineOperational": true,
  "detectionEngineLoaded": true,
  "tamperProtectionActive": true,
  "activeRuleCount": 3350,
  "loadedModelCount": 5
}
```

---

### GET /api/v1/stats ✅

Scan engine statistics.  
**Response 200:**
```json
{
  "totalScans": 12453,
  "infections": 17,
  "cacheHits": 8921,
  "ruleMatches": 301,
  "avgScanTimeMs": 42.3,
  "uptime_seconds": 86400
}
```

---

### GET /api/v1/license ✅

License information.  
**Response 200:**
```json
{
  "tier": "Home",
  "organization": "",
  "licenseId": "",
  "valid": true,
  "expiresAt": ""
}
```

`tier` is one of `"Home"`, `"EDR"`, `"XDR"`.

---

## Scanning

### POST /api/v1/scan/quick ✅ [ALL]

Start a quick scan (critical areas).  
**Response 200:** `{ "started": true }`

### POST /api/v1/scan/full ✅ [ALL]

Start a full system scan.  
**Response 200:** `{ "started": true }`

### POST /api/v1/scan/custom ✅ [ALL]

Start a scan on specified paths.  
**Request:**
```json
{ "paths": ["C:\\Users\\Public\\Downloads"] }
```
**Response 200:** `{ "started": true }`

### POST /api/v1/scan/stop ✅ [ALL]

Cancel active scans.  
**Response 200:** `{ "stopped": true }`

### GET /api/v1/scan/progress ✅ [ALL]

Current scan state.  
**Response 200:**
```json
{
  "status": "Running|Idle|Completed|Paused|Cancelled|Error",
  "pctComplete": 42.5,
  "filesScanned": 13200,
  "threatsFound": 0,
  "currentFile": "C:\\...",
  "elapsed_ms": 12000,
  "eta_ms": 16000
}
```

---

## Quarantine

### GET /api/v1/quarantine ✅ [ALL]

List quarantined items.  
**Query params:** `limit` (default 200), `offset` (default 0)  
**Response 200:**
```json
{
  "items": [
    {
      "id": "abc123",
      "originalPath": "C:\\...",
      "sha256": "...",
      "threatName": "Trojan.Stealer.Generic",
      "detectionSource": "StaticDetectionEngine",
      "confidence": 87.5,
      "quarantinedAt": "2026-05-28T12:00:00Z",
      "fileSize": 102400
    }
  ]
}
```

### POST /api/v1/quarantine/restore ✅ [ALL]

Restore a quarantined file to its original path.  
**Request:** `{ "id": "abc123" }`  
**Response 204**

### POST /api/v1/quarantine/delete ✅ [ALL]

Permanently delete a quarantined file.  
**Request:** `{ "id": "abc123" }`  
**Response 204**

---

## Exclusions / Allowlists

### GET /api/v1/exclusions ✅ [ALL]

List all exclusion rules.  
**Response 200:**
```json
{
  "exclusions": [
    {
      "id": "exc-001",
      "type": 0,
      "value": "C:\\DevTools\\",
      "description": "Development toolchain",
      "enabled": true
    }
  ]
}
```

**Exclusion types:**
| Value | Meaning |
|-------|---------|
| 0 | FilePath (exact) |
| 1 | Directory (recursive) |
| 2 | Extension (e.g. `.pdf`) |
| 3 | ProcessName |
| 4 | SHA256 hash |
| 5 | Signer subject CN |

### POST /api/v1/exclusions ✅ [ALL]

Add an exclusion rule.  
**Request:**
```json
{ "type": 1, "value": "C:\\MyApp\\", "description": "Internal app" }
```
**Response 201:** `{ "id": "exc-xxx", "type": 1, "value": "C:\\MyApp\\" }`

### DELETE /api/v1/exclusions/:id ✅ [ALL]

Remove an exclusion.  
**Response 204**

---

## Block / Allow / Ask Policies

Policies control how ShadowStrike responds to specific process, path, network, or device access events.

### GET /api/v1/policies ✅ [ALL]

List all policies.  
**Query params:** `scope` (optional integer filter)  
**Response 200:**
```json
{
  "policies": [
    {
      "id": "pol-001",
      "scope": 2,
      "decision": 3,
      "target": "C:\\SuspiciousApp\\app.exe",
      "note": "Blocked by analyst",
      "enabled": true
    }
  ]
}
```

**Policy scopes:**
| Value | Scope |
|-------|-------|
| 0 | Global |
| 1 | PerProcess |
| 2 | PerPath |
| 3 | PerNetwork |
| 4 | WebcamAccess |
| 5 | MicrophoneAccess |

**Access decisions:**
| Value | Decision |
|-------|---------|
| 0 | Allow |
| 1 | Block |
| 2 | Ask (prompt user) |
| 3 | AlwaysAllow (permanent trust) |
| 4 | AlwaysBlock (permanent block) |

### POST /api/v1/policies ✅ [ALL]

Create a policy entry.  
**Request:**
```json
{ "scope": 1, "decision": 1, "target": "C:\\Malware\\app.exe", "note": "Block reason" }
```
**Response 201:** `{ "id": "pol-xxx" }`

### DELETE /api/v1/policies/:id ✅ [ALL]

Remove a policy.  
**Response 204**

### PUT /api/v1/policies/:id/decision ✅ [ALL]

Update the decision on an existing policy.  
**Request:** `{ "decision": 0 }`  
**Response 204**

---

## Feature Toggles

### GET /api/v1/features ✅ [ALL]

List all feature toggles.  
**Response 200:**
```json
{
  "features": [
    {
      "id": "RealTimeProtection",
      "name": "Real-Time File & Process Scanning",
      "enabled": true,
      "tierLocked": false,
      "tier": "All"
    },
    {
      "id": "StaticAnalysis",
      "name": "Pre-Execution Static Analysis",
      "enabled": true,
      "tierLocked": false,
      "tier": "All"
    }
  ]
}
```

### PUT /api/v1/features/:id ✅ [ALL]

Enable or disable a feature.  
**Request:** `{ "enabled": false }`  
**Response 204**

**Feature IDs:**
`RealTimeProtection`, `BehaviorBlocker`, `NetworkFilter`, `ExploitPrevention`,
`RansomwareProtection`, `ZeroHourProtection`, `AMSIIntegration`,
`WebcamProtection`, `StaticAnalysis`, `DeepInspection`

---

## Trust Management

### GET /api/v1/trust ✅ [ALL]

List trusted entries (process paths, hashes, signers).  
**Response 200:**
```json
{
  "trusted": [
    { "id": "trust-001", "type": "signer", "value": "Acme Corp", "permanent": true, "note": "" }
  ]
}
```

**Trust types:** `"signer"`, `"hash"`, `"path"`, `"process"`

### POST /api/v1/trust ✅ [ALL]

Add a trusted entry.  
**Request:** `{ "type": "signer", "value": "My Corp", "note": "Internal PKI", "permanent": true }`  
**Response 201:** `{ "id": "trust-xxx" }`

### DELETE /api/v1/trust/:id ✅ [ALL]

Remove a trusted entry.  
**Response 204**

---

## Response Actions

### POST /api/v1/actions ✅ [ALL / EDR+]

Execute an immediate response action.  
**Request:**
```json
{
  "action": 0,
  "pid": 1234,
  "path": "",
  "quarantineItemId": "",
  "reason": "Analyst response"
}
```

**Action codes:**
| Code | Action | Tier |
|------|--------|------|
| 0 | KillProcess | ALL |
| 1 | SuspendProcess | ALL |
| 2 | QuarantineFile | ALL |
| 3 | DeleteFile | ALL |
| 4 | IsolateNetwork | EDR+ |
| 5 | RestoreFromQuarantine | ALL |
| 6 | TriggerScan | ALL |
| 7 | CollectForensics | EDR+ |
| 8 | RunPlaybook | XDR |

**Response 200:**
```json
{ "success": true, "message": "Process 1234 terminated", "forensicsCollectionId": "" }
```

---

## Alerts / Detections

### GET /api/v1/alerts ✅ [ALL]
### GET /api/v1/detections ✅ [ALL]

List recent alerts/detections.  
**Query params:** `limit` (default 100), `offset` (default 0), `minSeverity` (0-4)  
**Response 200:**
```json
{
  "detections": [
    {
      "id": "det-abc",
      "severity": 3,
      "threatName": "Win32/OfficeShell.Execution",
      "description": "Office application spawned an unusual child process.",
      "pid": 4512,
      "confidence": 80.0,
      "score": 55.5,
      "acknowledged": false,
      "actedUpon": false,
      "matchedRules": ["ss-proc-001"],
      "mitreTechniques": ["T1566.001", "T1059"]
    }
  ]
}
```

**Severity values:** 0=Informational, 1=Low, 2=Medium, 3=High, 4=Critical

### GET /api/v1/detections/:id ✅ [ALL]

Full detection detail including rule matches and ATT&CK mapping.

### POST /api/v1/alerts/:id/acknowledge ✅ [ALL]

Mark an alert as acknowledged.  
**Response 204**

---

## Telemetry Views

### GET /api/v1/telemetry/summary ✅ [ALL]

Aggregated telemetry for dashboard overview.  
**Response 200:**
```json
{
  "eventsLastHour": 4821,
  "eventsLastDay": 102450,
  "alertsLastHour": 3,
  "alertsLastDay": 17,
  "scansDone": 94,
  "threatsBlocked": 12,
  "filesQuarantined": 4
}
```

### GET /api/v1/process-tree ✅ [ALL]

Live process tree with risk scores.  
**Response 200:**
```json
{
  "processes": [
    {
      "pid": 1234, "parentPid": 5678, "name": "powershell.exe",
      "commandLine": "powershell.exe -enc ...",
      "riskScore": 45.0,
      "matchedRules": ["ss-proc-015"],
      "childPids": [2345]
    }
  ]
}
```

---

## Webcam Protection

### GET /api/v1/devices/webcam ✅ [ALL]

Camera device status and policy.  
**Response 200:**
```json
{
  "policy": 1,
  "deviceCount": 1,
  "accessAttempts": 5,
  "denied": 2,
  "allowed": 3,
  "pending": 0
}
```
**Policy:** 0=Allow, 1=Ask, 2=Block

### GET /api/v1/devices/webcam/policy ✅ [ALL]

Returns the same object as `/api/v1/devices/webcam`.

### PUT /api/v1/devices/webcam/policy ✅ [ALL]

Set camera access policy.  
**Request:** `{ "policy": 2 }`  
**Response 204**

### GET /api/v1/devices/webcam/trusted ✅ [ALL]

List trusted processes for camera access.  
**Response 200:**
```json
{
  "trusted": [
    { "id": "cam-001", "imagePath": "C:\\...\\Teams.exe", "signerSubject": "Microsoft", "isWildcard": false }
  ]
}
```

### POST /api/v1/devices/webcam/trusted ✅ [ALL]

Add a trusted process.  
**Request:** `{ "imagePath": "C:\\...\\Zoom.exe", "signerSubject": "Zoom Video Communications", "isWildcard": false }`  
**Response 201:** `{ "id": "cam-xxx" }`

### DELETE /api/v1/devices/webcam/trusted/:id ✅ [ALL]

Remove a trusted process.  
**Response 204**

### POST /api/v1/devices/webcam/allow ✅ [ALL]

Approve a pending camera access ask.  
**Request:** `{ "eventId": 42 }`  
**Response 204**

### POST /api/v1/devices/webcam/deny ✅ [ALL]

Deny a pending camera access ask.  
**Request:** `{ "eventId": 42 }`  
**Response 204**

---

## Per-Policy Configuration

### GET /api/v1/policyconfig ✅ [ALL]

List configuration keys for all or a specific category.  
**Query params:** `category` (optional, e.g. `RealTimeProtection`)  
**Response 200:**
```json
{
  "configs": [
    {
      "category": "RealTimeProtection",
      "key": "Enabled",
      "value": "true",
      "type": "bool",
      "description": "Enable real-time protection",
      "readOnly": false
    }
  ]
}
```

**Known categories and keys:**

| Category | Key | Type | Description |
|----------|-----|------|-------------|
| RealTimeProtection | Enabled | bool | Master RTP toggle |
| RealTimeProtection | SensitivityLevel | int | 1=Low, 2=Medium, 3=High |
| BehaviorBlocker | Enabled | bool | Behavioral blocking |
| Ransomware | Enabled | bool | Ransomware protection |
| NetworkFilter | Enabled | bool | Network traffic filtering |
| WebcamProtection | Policy | string | Allow/Ask/Block |
| Quarantine | AutoQuarantine | bool | Auto-quarantine threats |
| StaticAnalysis | Enabled | bool | Pre-execution static analysis |
| StaticAnalysis | BlockThreshold | float | Score threshold for early block (default 75) |
| DeepInspection | Enabled | bool | HyperDbg-aligned memory inspection |

### PUT /api/v1/policyconfig ✅ [ALL]

Set a single config key.  
**Request:** `{ "category": "RealTimeProtection", "key": "SensitivityLevel", "value": "3" }`  
**Response 204**

---

## Threat Intelligence (existing)

### GET /api/v1/threats ✅ [ALL]

Recent threat detections from ThreatIntelStore.

### GET /api/v1/threats/:id ✅ [ALL]

Threat detail by ID.

### GET /api/v1/threatintel/feeds ✅ [ALL]

Status of threat intel feeds (EMBER, Feodo, MalwareBazaar, etc.).

---

## Error Response Format

All error responses use:
```json
{ "error": <error_code_int>, "message": "<human-readable description>" }
```

HTTP status mapping:
| Code | HTTP Status |
|------|-------------|
| NotFound (1) | 404 |
| InvalidArgument (2) | 400 |
| FeatureNotAvailable (3) | 403 |
| PermissionDenied (4) | 403 |
| NotInitialized (5) | 503 |
| AlreadyExists (6) | 409 |
| RateLimited (9) | 429 |
| InternalError (7) | 500 |

---

## Security Model

- **Binding:** `127.0.0.1` only — never `0.0.0.0`
- **TLS:** Self-signed certificate (configurable). Disable only in CI.
- **Auth:** Bearer token, 256-bit random, 30-minute idle expiry
- **CSRF:** Double-submit cookie for state-changing requests
- **Rate limits:** 30 req/s sustained, 60 burst; auth endpoint: 5 req/s
- **Body limit:** 1 MB max
- **JSON depth:** 32 levels max
- **No version disclosure:** `Server: ShadowStrike` only

---

## Tier-specific availability

| Feature group | Home | EDR | XDR |
|--------------|------|-----|-----|
| Protection status | ✅ | ✅ | ✅ |
| Scan control | ✅ | ✅ | ✅ |
| Quarantine | ✅ | ✅ | ✅ |
| Exclusions | ✅ | ✅ | ✅ |
| Policies | ✅ | ✅ | ✅ |
| Feature toggles | ✅ | ✅ | ✅ |
| Trust management | ✅ | ✅ | ✅ |
| Kill / Suspend process | ✅ | ✅ | ✅ |
| Quarantine file | ✅ | ✅ | ✅ |
| Isolate network | ❌ | ✅ | ✅ |
| Collect forensics | ❌ | ✅ | ✅ |
| Run SOAR playbook | ❌ | ❌ | ✅ |
| Telemetry summary | ✅ | ✅ | ✅ |
| Process tree | ✅ | ✅ | ✅ |
| Webcam protection | ✅ | ✅ | ✅ |
| Policy config | ✅ | ✅ | ✅ |
| Fleet management | ❌ | ✅ | ✅ |
| SIEM integration | ❌ | ❌ | ✅ |
| XDR correlation | ❌ | ❌ | ✅ |

---

## GUI integration guide

The future frontend (React SPA or WinUI app) should:

1. **On startup:** Call `GET /api/v1/health` to verify service is running.
2. **Login:** `POST /api/v1/auth/login`, store `token` + `csrfToken` in memory (not localStorage).
3. **Every request:** Include `Authorization: Bearer <token>` and `X-CSRF-Token: <csrfToken>` headers.
4. **Dashboard widget:** Poll `GET /api/v1/status` every 5 seconds for the protection state badge.
5. **Event stream:** Subscribe to `GET /api/v1/events/stream` (SSE) for real-time alert popups.
6. **Webcam ask:** Register an event listener on the SSE stream for `event: webcam_ask`. On receipt, call `GET /api/v1/devices/webcam` to fetch the pending event, show the approval dialog, then call `/allow` or `/deny`.
7. **Tier gating:** Read `/api/v1/license` to determine which feature groups to show/hide in the UI.
8. **Token expiry:** If any API returns 401, redirect to login. Proactively refresh before the `expiresIn` timestamp.

---

## Internal / draft endpoints

These endpoints exist in code but are not yet fully stable:

| Endpoint | Status | Notes |
|----------|--------|-------|
| GET /api/v1/events/stream | 🔧 Draft | SSE stream; format may change |
| GET /api/v1/modules | 🔧 Draft | Module health format unstable |
| GET /api/v1/config / PUT /api/v1/config | 🔧 Internal | Low-level config dump; prefer `/policyconfig` |
| GET /api/v1/rtp/status | 🔧 Draft | Superseded by `/api/v1/status` |
| POST /api/v1/rtp/toggle | 🔧 Draft | Use `PUT /api/v1/features/RealTimeProtection` instead |

---

## Changelog

| Version | Changes |
|---------|---------|
| 1.0.0 | Initial spec. Exclusions, policies, trust, actions, webcam, policyconfig, process-tree, telemetry, detections. |
