# ShadowStrike Phantom — Setup & Usage Guide

## Requirements

- Windows 10 / 11 x64
- 64-bit PowerShell (comes with Windows)
- Administrator account

---

## Part 1 — Installation

### Step 1 — Enable test-signing (kernel driver requirement)

The kernel driver (`PhantomSensor.sys`) is signed with a self-signed certificate.
Windows will refuse to load it unless test-signing mode is on.

Open **PowerShell as Administrator** and run:

```powershell
bcdedit /set testsigning on
```

**Reboot your machine.** After reboot you will see a small "Test Mode" watermark
in the bottom-right corner of the desktop — that is normal and expected.

> If you are running a production build signed with a valid EV/WHQL certificate,
> skip this step. The installer will warn you if the driver fails to load.

---

### Step 2 — Download and extract the release

1. Go to the **Releases** page of this repository.
2. Download the latest `ShadowStrikePhantom-*.zip`.
3. Extract it to a temporary folder, e.g. `C:\Temp\ShadowStrikeSetup\`.

After extraction you should see:

```
ShadowStrikePhantomService.exe
ShadowStrikePhantomCLI.exe
ShadowStrikePhantomTray.exe
ShadowStrikePhantomUninstaller.exe
onnxruntime.dll
onnxruntime_providers_shared.dll
models\
  cortex_static.onnx
  cortex_behavioral.onnx
  cortex_memory.onnx
  cortex_network.onnx
  cortex_emulation.onnx
driver\
  PhantomSensor.sys
  PhantomSensor.inf
Install-ShadowStrike.ps1
```

---

### Step 3 — Open an elevated PowerShell in the extracted folder

Right-click the Start button → **Windows Terminal (Admin)** or **PowerShell (Admin)**, then navigate to the folder:

```powershell
cd C:\Temp\ShadowStrikeSetup
```

---

### Step 4 — Allow the install script to run

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This only applies to the current session and does not change your system policy.

---

### Step 5 — Run the installer

```powershell
.\Install-ShadowStrike.ps1
```

The script will:

1. Verify the package layout (all required files are present)
2. Stop and remove any existing installation (upgrade path)
3. Create `C:\Program Files\ShadowStrike\Phantom\` and `C:\ProgramData\ShadowStrike\`
4. Apply correct ACLs on ProgramData (SYSTEM + Admins = Full, Users = Read)
5. Copy all binaries to Program Files
6. Deploy ML models to `C:\ProgramData\ShadowStrike\models\`
7. Write registry configuration under `HKLM\SOFTWARE\ShadowStrike`
8. Install the kernel driver via `pnputil`
9. Register and start the `ShadowStrikePhantomService` Windows service
10. Add the install directory to the system PATH

---

### Step 6 — Reboot if the installer asks you to

If `pnputil` reports that a reboot is required (exit code 3010), reboot now:

```powershell
shutdown /r /t 0
```

After reboot the kernel driver will be fully loaded.

---

### Step 7 — Verify the installation

Open any PowerShell window (does not need to be elevated):

```powershell
sc query ShadowStrikePhantomService
```

Expected output contains `STATE: 4 RUNNING`. If the service is not running:

```powershell
# Start it manually (requires admin)
Start-Service ShadowStrikePhantomService
```

---

## Part 2 — Running ShadowStrike Programs

### Do I need to run things as Administrator?

| Program | Needs elevation? | How |
|---|---|---|
| `Install-ShadowStrike.ps1` | **Yes** | Open PowerShell as Admin, then run the script |
| `ShadowStrikePhantomService.exe` | Runs as SYSTEM automatically | Managed by Windows SCM — do not run directly |
| `ShadowStrikePhantomCLI.exe` | **Yes, recommended** | Right-click → Run as administrator, or run from an admin terminal |
| `ShadowStrikePhantomTray.exe` | No | Double-click normally; auto-starts with Windows after install |
| `ShadowStrikePhantomUninstaller.exe` | **Yes** (auto-prompted) | Double-click — Windows UAC prompt appears automatically |

---

### Using the CLI

The CLI requires the service to be running first (Step 7 above).

**Open an elevated PowerShell** (right-click PowerShell → Run as administrator), then:

```powershell
ShadowStrikePhantomCLI.exe
```

Because the install added the program directory to the system PATH, you can run
this from any folder. If PATH is not yet updated in your current terminal, open
a new one or use the full path:

```powershell
& "C:\Program Files\ShadowStrike\Phantom\ShadowStrikePhantomCLI.exe"
```

The CLI opens an **interactive terminal** (REPL). Type `help` at the prompt to
see all commands.

---

### CLI Commands Reference

#### Info

| Command | What it does |
|---|---|
| `status` | Engine health, active modules, scan status, threat summary |
| `version` | Build version, driver version, rule-set version, build date |

#### Protection

| Command | What it does |
|---|---|
| `protect enable` | Turn on real-time protection |
| `protect disable` | Turn off real-time protection |
| `protect status` | Show current real-time protection state |
| `modules list` | List all protection modules and their status |
| `modules enable <name>` | Enable a specific module |
| `modules disable <name>` | Disable a specific module |

#### Detection & Scanning

| Command | What it does |
|---|---|
| `detections` | List recent detections (newest first) |
| `detections --severity high` | Filter by severity (low / medium / high / critical) |
| `scan <path>` | On-demand scan of a file or directory |
| `scan <path> --quick` | Quick scan mode |
| `scan <path> --full` | Full deep scan |
| `tail` | Stream live detection events (Ctrl-C to stop) |
| `rules list` | Show all loaded detection rules |
| `rules reload` | Hot-reload rules without restarting the service |
| `rules status` | Rule statistics summary |

#### Quarantine & Lists

| Command | What it does |
|---|---|
| `quarantine list` | Show all quarantined files |
| `quarantine restore <id>` | Restore a quarantined file |
| `quarantine delete <id>` | Permanently delete a quarantined file |
| `exclusions list` | List scan exclusions (paths, processes, hashes) |
| `exclusions add <pattern>` | Add an exclusion |
| `exclusions remove <pattern>` | Remove an exclusion |
| `allowlist list` | Show trusted-file allowlist |
| `allowlist add <entry>` | Add a hash / path / certificate to the allowlist |
| `allowlist remove <entry>` | Remove an allowlist entry |

#### Policy & Config

| Command | What it does |
|---|---|
| `policy show` | Display all policy keys and current values |
| `policy set <key> <value>` | Update a policy key |
| `policy export` | Export full config to JSON |
| `policy import <file>` | Import config from a JSON file |

#### Threat Hunting

| Command | What it does |
|---|---|
| `hunt list` | List active and completed hunts |
| `hunt run <query>` | Run a proactive threat-hunting query |
| `hunt results <id>` | Retrieve results for a completed hunt |
| `hunt cancel <id>` | Cancel a running hunt |

#### Incidents & Alerts

| Command | What it does |
|---|---|
| `incidents list` | View all security incidents |
| `incidents get <id>` | Get details for a specific incident |
| `incidents assign <id> <user>` | Assign an incident to a user |
| `incidents close <id>` | Close an incident |
| `alerts list` | View security alerts |
| `alerts ack <id>` | Acknowledge an alert |
| `alerts dismiss <id>` | Dismiss an alert |
| `alerts escalate <id>` | Escalate an alert |

#### Containment & Remediation

| Command | What it does |
|---|---|
| `contain isolate <host>` | Isolate a host from the network |
| `contain release <host>` | Release a host from isolation |
| `contain status` | Show isolation status for all hosts |
| `remediate run <host> <type>` | Trigger a remediation action |
| `remediate status <id>` | Check remediation task status |
| `remediate undo <id>` | Undo a remediation action |
| `playbooks list` | List available response playbooks |
| `playbooks run <name> [host]` | Execute a playbook |
| `playbooks status <id>` | Check playbook execution status |

#### Forensics & Live Response

| Command | What it does |
|---|---|
| `forensics collect <host>` | Collect forensic artifacts from a host |
| `forensics list` | List forensic packages |
| `forensics get <id>` | Download a forensic package |
| `live sessions` | List active live-response sessions |
| `live run <host> <cmd>` | Run a command on a managed endpoint |
| `live kill <sid>` | Terminate a live-response session |

#### Assets & Vulnerabilities

| Command | What it does |
|---|---|
| `assets list` | List all managed assets |
| `assets get <id>` | Get details for an asset |
| `assets tag <id> <tag>` | Tag an asset |
| `vulns list` | List vulnerabilities across endpoints |
| `vulns scan <host>` | Trigger a vulnerability rescan |
| `vulns suppress <cve>` | Suppress a CVE from reporting |

#### Sandbox

| Command | What it does |
|---|---|
| `sandbox submit <file>` | Submit a file for detonation analysis |
| `sandbox status <id>` | Check detonation job status |
| `sandbox results <id>` | Retrieve detonation report |
| `sandbox list` | List all sandbox jobs |

#### Compliance & Device Control

| Command | What it does |
|---|---|
| `compliance status` | Overall compliance posture |
| `compliance report [framework]` | Generate compliance report (CIS / NIST / SOC2 / PCI) |
| `compliance run [framework]` | Run a compliance check |
| `devices list` | List detected USB / removable devices |
| `devices block <id>` | Block a device |
| `devices allow <id>` | Allow a device |
| `devices policy` | Show device control policy |

#### Telemetry & Reports

| Command | What it does |
|---|---|
| `telemetry status` | Telemetry pipeline status |
| `telemetry set <key> <val>` | Update a telemetry setting |
| `telemetry flush` | Flush the telemetry buffer immediately |
| `reports list` | List generated reports |
| `reports generate <type>` | Generate a report now |
| `reports schedule <type> <cron>` | Schedule recurring report generation |

#### XDR / Network / Identity / Email

| Command | What it does |
|---|---|
| `xdr correlations` | View cross-source XDR correlations |
| `xdr incidents` | XDR incident list |
| `xdr graph <id>` | View incident attack graph |
| `network alerts` | Network detection alerts |
| `network flows` | Traffic flow summary |
| `network block <ip>` | Add IP to block list |
| `network unblock <ip>` | Remove IP from block list |
| `identity alerts` | Identity-based threat alerts |
| `identity reset <user>` | Reset credentials for a user |
| `identity lock <user>` | Lock a user account |
| `email threats` | Email threat detections |
| `email quarantine <id>` | Quarantine an email |
| `email release <id>` | Release a quarantined email |
| `soar playbooks` | List SOAR playbooks |
| `soar run <name>` | Run a SOAR playbook |
| `soar status <id>` | Check SOAR execution status |

---

## Part 3 — Uninstallation

Double-click `ShadowStrikePhantomUninstaller.exe` in the install directory:

```
C:\Program Files\ShadowStrike\Phantom\ShadowStrikePhantomUninstaller.exe
```

Windows will show a UAC prompt automatically. Click **Yes**, then click
**Uninstall** in the dialog that appears. The uninstaller removes the service,
driver, program files, ProgramData, and registry keys.

This is the **only supported way to uninstall** — passing arguments or running
it silently from a script will not work by design.

After uninstalling, if you want to disable test-signing mode:

```powershell
bcdedit /set testsigning off
# then reboot
```

---

## Paths Reference

| What | Path |
|---|---|
| Binaries | `C:\Program Files\ShadowStrike\Phantom\` |
| ML models | `C:\ProgramData\ShadowStrike\models\` |
| Logs | `C:\ProgramData\ShadowStrike\Logs\` |
| Quarantine | `C:\ProgramData\ShadowStrike\Quarantine\` |
| Registry | `HKLM\SOFTWARE\ShadowStrike` |
| Driver | `C:\Windows\System32\drivers\PhantomSensor.sys` |
