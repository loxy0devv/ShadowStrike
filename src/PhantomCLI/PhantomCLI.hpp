/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * PhantomCLI — interactive terminal control surface.
 *
 * Replaces the web UI for operator use until a dedicated GUI is ready.
 * Exposes: status, detections, scan, quarantine, exclusions, rules,
 * allowlist, policy, and live event tail — all via named commands.
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <memory>

namespace ShadowStrike {

// Forward declarations for IPC types shared with the service
struct ServiceStatus;
struct DetectionRecord;
struct QuarantineEntry;
struct ExclusionEntry;
struct PolicySettings;

// ============================================================================
// ANSI colour / formatting helpers
// ============================================================================

namespace Ansi {

constexpr std::string_view Reset   = "\x1b[0m";
constexpr std::string_view Bold    = "\x1b[1m";
constexpr std::string_view Dim     = "\x1b[2m";

// Foreground colours
constexpr std::string_view Black   = "\x1b[30m";
constexpr std::string_view Red     = "\x1b[31m";
constexpr std::string_view Green   = "\x1b[32m";
constexpr std::string_view Yellow  = "\x1b[33m";
constexpr std::string_view Blue    = "\x1b[34m";
constexpr std::string_view Magenta = "\x1b[35m";
constexpr std::string_view Cyan    = "\x1b[36m";
constexpr std::string_view White   = "\x1b[37m";
constexpr std::string_view BrightRed    = "\x1b[91m";
constexpr std::string_view BrightGreen  = "\x1b[92m";
constexpr std::string_view BrightYellow = "\x1b[93m";
constexpr std::string_view BrightBlue   = "\x1b[94m";
constexpr std::string_view BrightCyan   = "\x1b[96m";
constexpr std::string_view BrightWhite  = "\x1b[97m";

// Background colours
constexpr std::string_view BgRed    = "\x1b[41m";
constexpr std::string_view BgGreen  = "\x1b[42m";
constexpr std::string_view BgYellow = "\x1b[43m";
constexpr std::string_view BgBlue   = "\x1b[44m";

} // namespace Ansi

// ============================================================================
// Command dispatcher
// ============================================================================

struct CliCommand {
    std::string name;
    std::string synopsis;       // one-line usage, e.g. "scan <path>"
    std::string description;    // paragraph for help
    std::function<int(const std::vector<std::string>& args)> handler;
};

class PhantomCLI {
public:
    PhantomCLI();
    ~PhantomCLI();

    /// Run the interactive REPL (blocking until "exit" or EOF).
    int RunInteractive();

    /// Run a single command from a pre-parsed argv and exit.
    int RunCommand(int argc, char* argv[]);

private:
    // IPC pipe to the ShadowStrike service
    HANDLE m_pipe = INVALID_HANDLE_VALUE;

    bool   m_color  = true;   // ANSI color enabled
    bool   m_pager  = false;  // output pager for long lists

    // Command registry
    std::vector<CliCommand> m_commands;

    void   RegisterCommands();
    void   PrintBanner();
    void   PrintHelp(std::string_view filter = {});
    void   PrintPrompt();

    bool   ConnectToService();
    void   DisconnectService();
    bool   IsServiceConnected() const noexcept;

    // ---- Command handlers ---------------------------------------------------
    int CmdStatus(const std::vector<std::string>& args);
    int CmdDetections(const std::vector<std::string>& args);
    int CmdScan(const std::vector<std::string>& args);
    int CmdQuarantine(const std::vector<std::string>& args);
    int CmdExclusions(const std::vector<std::string>& args);
    int CmdAllowlist(const std::vector<std::string>& args);
    int CmdRules(const std::vector<std::string>& args);
    int CmdPolicy(const std::vector<std::string>& args);
    int CmdTail(const std::vector<std::string>& args);
    int CmdVersion(const std::vector<std::string>& args);
    int CmdHelp(const std::vector<std::string>& args);
    int CmdClear(const std::vector<std::string>& args);

    // ---- Formatting helpers -------------------------------------------------
    std::string ColorSeverity(std::string_view sev) const;
    std::string ColorStatus(std::string_view status) const;
    void        PrintTable(const std::vector<std::string>& headers,
                           const std::vector<std::vector<std::string>>& rows,
                           size_t maxWidth = 120) const;
    void        PrintSection(std::string_view title) const;
    std::string FormatTimestamp(int64_t unixMs) const;

    // ---- IPC helpers --------------------------------------------------------
    bool SendV2Request(uint32_t cmdType, const std::string& json, std::string& response);
    bool SendRequest(std::string_view jsonRequest, std::string& jsonResponse);
    bool CallService(std::string_view command,
                     const std::string& params,
                     std::string& response);

    std::atomic<uint64_t> m_reqId{1};
};

} // namespace ShadowStrike
