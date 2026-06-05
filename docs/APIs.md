# ShadowStrike Phantom — API Reference

**Version:** 3.0 | **Date:** 2026-05-28

---

## Overview: Two Communication Planes

ShadowStrike has two API surfaces for controlling the backend. Use the right one for
the right context:

| Surface | Channel | Use Case | Auth |
|---------|---------|----------|------|
| **Native IPC** | Named Pipe `\\.\pipe\ShadowStrikeServicePipe` | Production native GUI (Qt/WinUI) | IpcAuthToken + Windows ACL |
| **REST API** | HTTPS `127.0.0.1:9443` | Dev/browser testing | Bearer token + CSRF |

**Production rule:** The native GUI always uses the Named Pipe IPC. The REST API is
enabled only when `Config/DevMode/RestApiEnabled = true` (default: false in release builds,
true in dev/debug builds). This means malware cannot interact with the REST API on
production endpoints without first enabling dev mode.

---

## Part 1: Native IPC Protocol (Production)

### Transport

- **Pipe name:** `\\.\pipe\ShadowStrikeServicePipe`  
- **Security descriptor:** `SDDL D:(A;;FA;;;SY)(A;;FA;;;BA)` — SYSTEM + Administrators only
- **Protocol:** Custom binary frame + JSON payload
- **Caller verification:** Every handler verifies caller SID and token integrity level
- **Integrity requirements:**
  - Read-only queries: Medium integrity or higher
  - Write/toggle operations: High integrity required (Administrator)
  - Destructive actions (kill, isolate, block): High integrity required

### Wire Format

```
 ┌──────────────────────── Envelope (24 bytes) ──────────────────────────┐
 │  magic     [4]  = 0x53534156 ("SSAV")                                  │
 │  version   [4]  = 1                                                     │
 │  commandType [4] = CommandType enum value                               │
 │  requestId [8]  = client-assigned correlation id                        │
 │  payloadLen [4] = byte length of JSON payload that follows              │
 └────────────────────────────────────────────────────────────────────────┘
 ┌──────────────────────── JSON Payload (variable) ───────────────────────┐
 │  UTF-8 JSON object (max 10 MiB, depth ≤ 8, nodes ≤ 4096)              │
 └────────────────────────────────────────────────────────────────────────┘
```

Response is the same format with the same `requestId` echoed back.

All responses include `{"ok": true}` or `{"ok": false, "error": {"code": "...", "message": "..."}}`.

### Authentication Handshake

1. Connect to pipe.
2. Send `AuthHandshake` (cmd=199) with `{"token": "<IpcAuthToken>"}`.
3. Service validates the token against the caller's Windows session ID.
4. All subsequent commands require an authenticated session.
5. Session expires on disconnect or service restart.

**IpcAuthToken** is generated per-session and distributed to trusted UIs via
the `EventPush` mechanism. The native GUI receives its token during process launch
via a startup argument or shared memory slot secured by the service.

---

### Command Reference

#### Category: Auth & Session

| Cmd# | Name | Integrity | Description |
|------|------|-----------|-------------|
| 199 | `AuthHandshake` | Medium | Present session token |
| 10 | `GetStatus` | Medium | Global protection status |
| 250 | `GetDashboard` | Medium | Dashboard summary |

---

#### Category: Protection Toggles

| Cmd# | Name | Integrity | Payload | Description |
|------|------|-----------|---------|-------------|
| 380 | `GetProtectionStatus` | Medium | — | All protection module states |
| 381 | `SetProtectionEnabled` | High | `{module: str, enabled: bool}` | Enable/disable a named module |
| 382 | `GetRealTimeStatus` | Medium | — | RTP running/paused state |
| 383 | `SetRealTimeEnabled` | High | `{enabled: bool, durationMs?: uint}` | Toggle RTP; durationMs=pause duration (0=indefinite) |
| 210 | `PauseProtection` | High | `{durationMs: uint, reason?: str}` | Pause all protections |
| 211 | `ResumeProtection` | High | — | Resume paused protections |

---

#### Category: Feature Toggles

| Cmd# | Name | Integrity | Payload | Description |
|------|------|-----------|---------|-------------|
| 360 | `ListFeatures` | Medium | — | All features with `{id, name, enabled}` |
| 361 | `SetFeatureEnabled` | High | `{id: int, enabled: bool}` | Toggle feature by FeatureCategory id |
| 362 | `GetFeatureStatus` | Medium | `{id: int}` | Single feature state |
| 363 | `ResetFeatureDefaults` | High | — | Clear all overrides (restore license defaults) |

**FeatureCategory IDs:**

| ID | Name | Min Tier |
|----|------|----------|
| 0 | Core | Community |
| 1 | HomeProtection | Community |
| 2 | ForensicsBasic | Community |
| 3 | ForensicsAdvanced | Professional (EDR) |
| 4 | ThreatIntel | Community |
| 5 | ThreatIntelAdvanced | Professional |
| 6 | Dashboard | Community |
| 7 | CloudConsole | Professional |
| 8 | FleetManagement | Enterprise |
| 9 | RemoteActions | Professional |
| 10 | SIEMIntegration | Enterprise |
| 11 | SOARIntegration | Enterprise |
| 12 | ComplianceReporting | Enterprise |
| 13 | CustomRules | Enterprise |
| 14 | RBAC | Enterprise |
| 15 | XDRCorrelation | Enterprise (XDR) |
| 16 | CloudTelemetry | Enterprise |
| 17 | KernelProtection | Professional |

---

#### Category: Scanning

| Cmd# | Name | Integrity | Payload | Description |
|------|------|-----------|---------|-------------|
| 20 | `StartScan` | Medium | `{type: "quick"|"full"|"custom", paths?: [str]}` | Start scan |
| 21 | `StopScan` | Medium | `{scanId: str}` | Cancel active scan |
| 222 | `GetScanProgress` | Medium | `{scanId: str}` | Poll progress `{percent, filesScanned, ...}` |

---

#### Category: Quarantine

| Cmd# | Name | Integrity | Payload | Description |
|------|------|-----------|---------|-------------|
| 230 | `ListQuarantine` | Medium | `{limit?: int, offset?: int}` | Paginated quarantine list |
| 403 | `QuarantineFile` | High | `{path: str}` | Move file to quarantine |
| 404 | `RestoreFromQuarantine` | High | `{id: str}` | Restore by item id |
| 405 | `DeleteFromQuarantine` | High | `{id: str}` | Permanently delete |

---

#### Category: Exclusions / Allowlists

| Cmd# | Name | Integrity | Payload | Description |
|------|------|-----------|---------|-------------|
| 300 | `ListExclusions` | Medium | — | All exclusion rules |
| 301 | `AddExclusion` | High | `{type: int, pattern: str, enabled?: bool, description?: str}` | Add exclusion |
| 302 | `RemoveExclusion` | High | `{index: int}` | Remove by array index |
| 303 | `UpdateExclusion` | High | `{index: int, type, pattern, ...}` | Replace existing |
| 304 | `ClearExclusions` | High | — | Remove all (destructive) |
| 305 | `ImportExclusions` | High | `{exclusions: [{type, pattern, ...}]}` | Bulk import |
| 306 | `ExportExclusions` | Medium | — | Export all as `{exclusions: [...]}` |

**ExclusionRule.type values:** 0=Path, 1=PathPrefix, 2=Extension, 3=ProcessName, 4=Hash

---

#### Category: Block/Allow/Ask Policies

| Cmd# | Name | Integrity | Payload | Description |
|------|------|-----------|---------|-------------|
| 320 | `GetAccessPolicy` | Medium | — | `{defaultAction: int}` (0=block, 1=allow, 2=ask) |
| 321 | `SetAccessPolicy` | High | `{defaultAction: int}` | Set global default |
| 322 | `ListPolicyRules` | Medium | — | Per-target policy rules |
| 323 | `AddPolicyRule` | High | `{target: str, action: int, description?: str}` | Add rule |
| 324 | `RemovePolicyRule` | High | `{id: str}` | Remove by id |
| 325 | `GetDefaultPolicy` | Medium | — | Alias for GetAccessPolicy |
| 326 | `SetDefaultPolicy` | High | `{defaultAction: int}` | Alias for SetAccessPolicy |

---

#### Category: Trust Management

| Cmd# | Name | Integrity | Payload | Description |
|------|------|-----------|---------|-------------|
| 340 | `ListTrustedItems` | Medium | — | All trusted items `[{id, type, value, comment}]` |
| 341 | `AddTrustedItem` | High | `{type: str, value: str, comment?: str}` | Trust a file/hash/process |
| 342 | `RemoveTrustedItem` | High | `{id: str}` | Remove trust |
| 343 | `IsTrusted` | Medium | `{value: str, type?: str}` | Query `{trusted: bool}` |
| 344 | `ListTrustedSigners` | Medium | — | Trusted Authenticode signers |
| 345 | `AddTrustedSigner` | High | `{subject: str, comment?: str}` | Trust all files from signer |
| 346 | `RemoveTrustedSigner` | High | `{id: str}` | Revoke signer trust |

**TrustedItem.type values:** `"sha256"`, `"md5"`, `"path"`, `"process"`, `"signer"`

---

#### Category: Response Actions

All require High integrity. These are privileged security operations.

| Cmd# | Name | Payload | Description |
|------|------|---------|-------------|
| 400 | `KillProcess` | `{pid: uint}` | Terminate process tree |
| 401 | `SuspendProcess` | `{pid: uint}` | Suspend all threads |
| 402 | `IsolateProcess` | `{pid: uint}` | Kill + quarantine executable |
| 406 | `RemediateFile` | `{path: str}` | Automated remediation |
| 407 | `NetworkIsolate` | `{pid: uint}` | Cut process network access |
| 408 | `BlockHash` | `{sha256: str, threatName?: str}` | Block file by SHA-256 permanently |

---

#### Category: Telemetry Views

| Cmd# | Name | Payload | Description |
|------|------|---------|-------------|
| 420 | `GetTelemetryStream` | — | Subscribe to live push events (service → client) |
| 421 | `QueryTelemetry` | `{limit?: int}` | Recent event log |
| 422 | `GetProcessTree` | — | Live process tree with evidence scores |
| 423 | `GetProcessDetail` | `{pid: uint}` | Full detail: score, rules matched, network, file, registry |
| 424 | `GetNetworkFlows` | — | Active + recent connections `[{pid, dstIp, dstPort, ...}]` |
| 425 | `GetFileEvents` | — | Recent file create/write/rename events |
| 426 | `GetRegistryEvents` | — | Recent registry modifications |
| 427 | `GetDnsQueries` | — | Recent DNS query log |

---

#### Category: Alert / Detection Views

| Cmd# | Name | Payload | Description |
|------|------|---------|-------------|
| 440 | `ListAlerts` | `{limit?: int}` | Recent alerts `[{id, title, severity, pid, ...}]` |
| 441 | `GetAlertDetail` | `{id: str}` | Full alert with rules, ATT&CK, evidence |
| 442 | `DismissAlert` | `{id: str}` | Mark as reviewed |
| 443 | `GetDetectionHistory` | `{limit?: int}` | Alias for ListAlerts |
| 444 | `GetDetectionDetail` | `{id: str}` | Alias for GetAlertDetail |
| 445 | `GetAttackChain` | `{pid: uint}` | Attack chain/storyline for a process |
| 446 | `ExportAlert` | `{id: str, format?: "json"|"csv"}` | Export alert data |

**Severity values:** 0=Informational, 1=Low, 2=Medium, 3=High, 4=Critical

---

#### Category: Webcam Protection

| Cmd# | Name | Integrity | Payload | Description |
|------|------|-----------|---------|-------------|
| 460 | `GetWebcamPolicy` | Medium | — | `{policy: "allow"|"ask"|"block"}` |
| 461 | `SetWebcamPolicy` | High | `{policy: str}` | Set camera access policy |
| 462 | `ListWebcamDevices` | Medium | — | `[{id, name, busy}]` |
| 463 | `GetWebcamAccessLog` | Medium | `{limit?: int}` | Recent access events |
| 464 | `AllowWebcamAccess` | Medium | `{eventId: uint64, note?: str}` | Approve pending Ask |
| 465 | `DenyWebcamAccess` | Medium | `{eventId: uint64, note?: str}` | Deny pending Ask |
| 466 | `ListWebcamTrusted` | Medium | — | Trusted processes |
| 467 | `AddWebcamTrusted` | High | `{imageName: str, imagePath?: str, signer?: str}` | Add trusted process |
| 468 | `RemoveWebcamTrusted` | High | `{id: str}` | Remove trusted process |

---

#### Category: Per-Policy Configuration

| Cmd# | Name | Payload | Description |
|------|------|---------|-------------|
| 480 | `GetTierInfo` | — | `{tier, tierName, organization, licenseId, maxEndpoints}` |
| 481 | `ListPolicies` | — | All `Policy/` config key names |
| 482 | `GetPolicy` | `{name: str}` | Single policy value |
| 483 | `SetPolicy` | `{name: str, value: any}` | Update policy key |
| 484 | `ResetPolicy` | `{name: str}` | Reset to tier default |
| 485 | `ExportPolicy` | — | All policies as JSON |
| 486 | `ImportPolicy` | `{policies: {name: value, ...}}` | Bulk import |

---

#### Category: Rule Management

| Cmd# | Name | Payload | Description |
|------|------|---------|-------------|
| 540 | `ListRules` | — | `{totalRules, ruleEngineEvaluations, matches}` |
| 541 | `GetRuleDetail` | `{id: str}` | Single rule detail (pending full export API) |
| 542 | `EnableRule` | `{id: str}` | Enable rule by id (pending RuleStore mutation) |
| 543 | `DisableRule` | `{id: str}` | Disable rule by id |
| 544 | `ReloadRules` | — | Hot-reload all rule corpora |
| 545 | `ImportCustomRule` | `{yaml: str}` | Import custom native rule (EDR+) |
| 546 | `DeleteCustomRule` | `{id: str}` | Delete custom rule (EDR+) |

---

#### Category: EDR-specific (requires FeatureCategory::ForensicsAdvanced)

| Cmd# | Name | Payload | Description |
|------|------|---------|-------------|
| 500 | `ListForensicArtifacts` | — | Collected evidence files |
| 501 | `CollectArtifact` | `{pid: uint}` | Trigger artifact collection for PID |
| 502 | `GetIncidents` | `{limit?: int}` | Incident list |
| 503 | `GetIncidentDetail` | `{id: str}` | Full incident detail + timeline |
| 504 | `CreateIncident` | `{title: str, description?: str}` | Manual incident creation |
| 505 | `RunPlaybook` | `{name: str, pid?: uint}` | Execute response playbook |
| 506 | `GetPlaybooks` | — | Available playbooks list |
| 507 | `GetHuntResults` | — | Recent hunt query results |
| 508 | `SubmitHuntQuery` | `{query: str, type?: "ioc"|"yara"|"sigma"}` | Execute threat hunt |
| 509 | `GetVulnScanResults` | — | Vulnerability findings |
| 510 | `StartVulnScan` | — | Trigger vulnerability scan |
| 511 | `GetLiveResponseShell` | `{command: str, pid?: uint}` | Execute command + return output |

---

#### Category: XDR-specific (requires FeatureCategory::XDRCorrelation)

| Cmd# | Name | Payload | Description |
|------|------|---------|-------------|
| 520 | `GetXDRCorrelations` | `{limit?: int}` | Cross-source correlation events |
| 521 | `GetXDRStoryline` | `{correlationId: str}` | Attack storyline |
| 522 | `GetNetworkDetections` | `{limit?: int}` | Network-layer detection results |
| 523 | `GetEmailThreats` | `{limit?: int}` | Email threat detections |
| 524 | `GetIdentityAlerts` | `{limit?: int}` | Identity/AD alerts |
| 525 | `RunSOARPlaybook` | `{name: str}` | Execute SOAR local playbook |
| 526 | `GetFleetStatus` | — | Fleet endpoint summary (XDR+) |

---

#### Category: Home-specific (verbs 10–291, see HomeIpcDispatcher)

| Cmd# | Name | Description |
|------|------|-------------|
| 200 | `ListModules` | All Home modules with state |
| 201 | `SetModuleEnabled` | Enable/disable Home module |
| 202 | `SetModuleMode` | Set protection mode (Off/Passive/Balanced/Aggressive) |
| 203 | `GetModuleConfig` | Module configuration blob |
| 204 | `SetModuleConfig` | Update module configuration |
| 240 | `GetReports` | Historical detection reports |
| 260 | `SubscribeEvents` | Acknowledge subscription (push is automatic) |
| 270 | `ListPGTIFeeds` | Threat intel feed status |
| 271 | `SetPGTIFeedEnabled` | Enable/disable feed |
| 272 | `RefreshPGTIFeeds` | Force refresh all feeds |
| 280 | `GetZeroTrustState` | Zero-Trust Guard configuration |
| 281 | `SetZeroTrustConfig` | Update Zero-Trust policy |
| 282 | `AnswerZeroTrustPrompt` | Resolve pending Zero-Trust prompt |
| 290 | `GetRecommendations` | Active security recommendations |
| 291 | `DismissRecommendation` | Dismiss recommendation by id |

---

### Push Events (Server → Client)

After authenticating, the client receives unsolicited push events when:

| Cmd# | Name | When Fired |
|------|------|-----------|
| 100 | `ThreatAlert` | Threat detected, before user action |
| 101 | `LogMessage` | Debug/info log line |
| 102 | `ProtectionStateChanged` | RTP paused/resumed |
| 103 | `ScanProgressEvent` | Scan progress update |
| 104 | `HeadlineStateChanged` | Protection level indicator changed |
| 106 | `PgtiFeedUpdated` | Threat intel feed health changed |
| 107 | `RecommendationsChanged` | New recommendations available |

Push events use the same envelope format with `requestId = 0` to indicate unsolicited.

---

## Part 2: REST API (Dev/Browser Mode)

**Base URL:** `https://127.0.0.1:9443/api/v1`  
**Auth:** `Authorization: Bearer <token>` from `POST /auth/login`  
**CSRF:** `X-CSRF-Token` header required on POST/PUT/DELETE  
**Enabled when:** `Config/DevMode/RestApiEnabled = true`

### Auth

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/login` | `{password: str}` → `{token: str, csrfToken: str}` |
| POST | `/auth/logout` | Invalidate session |
| GET | `/auth/session` | Current session info |
| GET | `/health` | No-auth health check |

### System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | Service status, RTP state, module count |
| GET | `/stats` | Detection statistics |
| GET | `/modules` | Module health list |
| GET | `/license` | Tier and license info |

### Scanning

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan/quick` | Start quick scan |
| POST | `/scan/full` | Start full scan |
| POST | `/scan/custom` | `{paths: [str]}` custom scan |
| POST | `/scan/stop` | Cancel scan |
| GET | `/scan/progress` | Active scan progress |

### Quarantine

| Method | Path | Description |
|--------|------|-------------|
| GET | `/quarantine` | List quarantined items |
| POST | `/quarantine/restore` | `{id: str}` restore |
| POST | `/quarantine/delete` | `{id: str}` permanent delete |

### Threats / Alerts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/threats` | Recent detections |
| GET | `/threats/:id` | Detection detail |
| GET | `/threatintel/feeds` | Feed status |

### Configuration

| Method | Path | Description |
|--------|------|-------------|
| GET | `/config` | Full configuration |
| PUT | `/config` | Update configuration key(s) |

### Devices / Webcam

| Method | Path | Description |
|--------|------|-------------|
| GET | `/devices/webcam` | Camera devices + policy |
| GET | `/devices/webcam/policy` | Current policy |
| PUT | `/devices/webcam/policy` | `{policy: "allow"|"ask"|"block"}` |
| GET | `/devices/webcam/access` | Access log |
| POST | `/devices/webcam/allow` | `{eventId: int}` approve Ask |
| POST | `/devices/webcam/deny` | `{eventId: int}` deny Ask |
| GET | `/devices/webcam/trusted` | Trusted processes |
| POST | `/devices/webcam/trusted` | Add trusted |
| DELETE | `/devices/webcam/trusted/:id` | Remove trusted |

### Events Stream

| Method | Path | Description |
|--------|------|-------------|
| GET | `/events/stream` | SSE stream of push events |

---

## Part 3: Architecture Decision Notes

```
PRODUCTION (native GUI — Qt/WinUI):
    [ShadowStrike GUI]
         ↓ Named Pipe IPC
    [ServiceCommunicator]      ← strict Windows ACLs
         ↓
    [SharedIpcDispatcher]      ← caller identity verified
    [HomeIpcDispatcher]        ← per-verb, 72+ handlers
    [EDRIpcDispatcher]         ← feature-gated
    [XDRIpcDispatcher]         ← feature-gated
         ↓
    [Protection Engine]
         ↓
    [PhantomSensor.sys]

DEV/TESTING (browser):
    [Browser / Dev Tool]
         ↓ HTTPS localhost:9443 (only when DevMode=true)
    [RESTServer]               ← bearer token + CSRF
         ↓
    [Protection Engine]
```

**Security properties of Named Pipe channel:**
- Caller SID verified at connection time (`GetNamedPipeClientProcessId` + token query)
- Integrity level enforced per-handler (High required for privileged ops)
- Caller image hash optionally validated against expected ShadowStrike GUI binary
- No DNS, no CORS, no browser vectors
- Pipe ACL blocks any process running at Medium or below integrity

**Why REST stays:**
- Dev mode: browser debugging before native GUI exists
- Automated testing: CI/CD test scripts
- Can be completely disabled in production builds via config flag
