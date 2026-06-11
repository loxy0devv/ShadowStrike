/*
 * ShadowStrike - Enterprise NGAV / EDR / XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * PhantomCLI — full-featured interactive terminal control surface.
 *
 * Exposes every user-configurable feature of ShadowStrike Phantom:
 *   Protection, Modules, Detections, Scans, Quarantine, Exclusions,
 *   Allowlist, Rules, Policy, Threat Hunting, Incidents, Alerts,
 *   Containment, Remediation, Playbooks, Forensics, Live Response,
 *   Assets, Vulnerabilities, Sandbox, Compliance, Device Control,
 *   Telemetry, Reporting, XDR Correlation, Network Detection,
 *   Identity Protection, Email Threats, SOAR.
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike {

// ============================================================================
// ANSI colour / formatting
// ============================================================================

namespace Ansi {
constexpr std::string_view Reset       = "\x1b[0m";
constexpr std::string_view Bold        = "\x1b[1m";
constexpr std::string_view Dim         = "\x1b[2m";
constexpr std::string_view Italic      = "\x1b[3m";
constexpr std::string_view Underline   = "\x1b[4m";

constexpr std::string_view Black       = "\x1b[30m";
constexpr std::string_view Red         = "\x1b[31m";
constexpr std::string_view Green       = "\x1b[32m";
constexpr std::string_view Yellow      = "\x1b[33m";
constexpr std::string_view Blue        = "\x1b[34m";
constexpr std::string_view Magenta     = "\x1b[35m";
constexpr std::string_view Cyan        = "\x1b[36m";
constexpr std::string_view White       = "\x1b[37m";

constexpr std::string_view BrightBlack   = "\x1b[90m";
constexpr std::string_view BrightRed     = "\x1b[91m";
constexpr std::string_view BrightGreen   = "\x1b[92m";
constexpr std::string_view BrightYellow  = "\x1b[93m";
constexpr std::string_view BrightBlue    = "\x1b[94m";
constexpr std::string_view BrightMagenta = "\x1b[95m";
constexpr std::string_view BrightCyan    = "\x1b[96m";
constexpr std::string_view BrightWhite   = "\x1b[97m";
} // namespace Ansi

// ============================================================================
// Menu infrastructure
// ============================================================================

struct MenuOption {
    int         number;     // 0 = Back
    std::string label;      // display text
    std::string shortcut;   // match word, e.g. "list", "restore"
    std::string argHint;    // "<id>" shown alongside label
    std::function<int(const std::vector<std::string>&)> action;
};

struct CliCommand {
    std::string name;
    std::string category;
    std::string synopsis;
    std::string description;
    std::function<int(const std::vector<std::string>&)> handler;
};

// ============================================================================
// PhantomCLI
// ============================================================================

class PhantomCLI {
public:
    PhantomCLI();
    ~PhantomCLI();

    int RunInteractive();
    int RunCommand(int argc, char* argv[]);

private:
    HANDLE m_pipe      = INVALID_HANDLE_VALUE;
    bool   m_color     = true;
    bool   m_exit      = false;  // set by "exit" in any submenu
    std::string m_ctx;           // submenu context for prompt, e.g. "quarantine"

    std::vector<CliCommand> m_commands;

    void RegisterCommands();
    void PrintBanner() const;
    void PrintPrompt() const;

    // Displays a numbered menu; if args non-empty, resolves directly.
    // Returns -1 if the user requested exit, else 0 or command return code.
    int RunMenu(std::string_view title,
                const std::vector<MenuOption>& options,
                const std::vector<std::string>& args);

    // ── IPC ──────────────────────────────────────────────────────────────────
    bool ConnectToService();
    void DisconnectService();
    bool IsServiceConnected() const noexcept;
    bool SendV2(uint32_t cmdType, const std::string& json, std::string& resp);
    bool Call(std::string_view key, const std::string& params, std::string& resp);

    // ── Command handlers ─────────────────────────────────────────────────────
    int CmdStatus    (const std::vector<std::string>&);
    int CmdProtect   (const std::vector<std::string>&);
    int CmdModules   (const std::vector<std::string>&);
    int CmdDetections(const std::vector<std::string>&);
    int CmdScan      (const std::vector<std::string>&);
    int CmdTail      (const std::vector<std::string>&);
    int CmdQuarantine(const std::vector<std::string>&);
    int CmdExclusions(const std::vector<std::string>&);
    int CmdAllowlist (const std::vector<std::string>&);
    int CmdRules     (const std::vector<std::string>&);
    int CmdPolicy    (const std::vector<std::string>&);
    int CmdHunt      (const std::vector<std::string>&);
    int CmdIncidents (const std::vector<std::string>&);
    int CmdAlerts    (const std::vector<std::string>&);
    int CmdContain   (const std::vector<std::string>&);
    int CmdRemediate (const std::vector<std::string>&);
    int CmdPlaybooks (const std::vector<std::string>&);
    int CmdForensics (const std::vector<std::string>&);
    int CmdLive      (const std::vector<std::string>&);
    int CmdAssets    (const std::vector<std::string>&);
    int CmdVulns     (const std::vector<std::string>&);
    int CmdSandbox   (const std::vector<std::string>&);
    int CmdCompliance(const std::vector<std::string>&);
    int CmdDevices   (const std::vector<std::string>&);
    int CmdTelemetry (const std::vector<std::string>&);
    int CmdReports   (const std::vector<std::string>&);
    int CmdXDR       (const std::vector<std::string>&);
    int CmdNetwork   (const std::vector<std::string>&);
    int CmdIdentity  (const std::vector<std::string>&);
    int CmdEmail     (const std::vector<std::string>&);
    int CmdSOAR      (const std::vector<std::string>&);
    int CmdVersion   (const std::vector<std::string>&);
    int CmdHelp      (const std::vector<std::string>&);
    int CmdClear     (const std::vector<std::string>&);

    // ── Formatting ───────────────────────────────────────────────────────────
    std::string C(std::string_view seq, std::string_view text) const;
    std::string ColorSeverity(std::string_view s) const;
    std::string ColorStatus  (std::string_view s) const;
    std::string ColorId      (std::string_view s) const;
    std::string ColorPath    (std::string_view s) const;

    void PrintSection (std::string_view title) const;
    void PrintSuccess (std::string_view msg)   const;
    void PrintError   (std::string_view msg)   const;
    void PrintWarning (std::string_view msg)   const;
    void PrintInfo    (std::string_view msg)   const;
    void PrintOffline ()                        const;

    void PrintTable(const std::vector<std::string>& headers,
                    const std::vector<std::vector<std::string>>& rows,
                    size_t maxWidth = 132) const;

    std::string FormatTimestamp(int64_t unixMs) const;
    std::string FormatBytes    (int64_t bytes)  const;

    std::string PromptLine(std::string_view prompt) const;

    std::atomic<uint64_t> m_reqId{1};
};

} // namespace ShadowStrike
