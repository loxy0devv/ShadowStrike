/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * PhantomCLI implementation — interactive terminal control surface.
 *
 * IPC uses \\.\pipe\ShadowStrikeServicePipe with the v2 binary framing:
 *   [Magic:4][Version=1:2][Reserved=0:2][Type:4][RequestId:8][PayloadSize:4][JSON]
 * The service auth token is read from %LOCALAPPDATA%\ShadowStrike\ui.token
 * and sent via AuthHandshake (CommandType 199) on connect.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <io.h>
#include <fcntl.h>

#include "PhantomCLI.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Simple hand-written JSON builder used for service requests.
// We avoid pulling in nlohmann here to keep the CLI binary thin.
// ---------------------------------------------------------------------------
namespace {

std::string JsonStr(std::string_view s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"')  { out += "\\\""; continue; }
        if (c == '\\') { out += "\\\\"; continue; }
        if (c == '\n') { out += "\\n";  continue; }
        out += c;
    }
    return out + '"';
}

std::string JsonObj(std::string_view key, std::string_view val) {
    return "{" + JsonStr(key) + ":" + JsonStr(val) + "}";
}

std::string ExtractJsonString(std::string_view json, std::string_view key) {
    std::string pat = '"' + std::string(key) + "\":\"";
    auto pos = json.find(pat);
    if (pos == std::string_view::npos) return {};
    pos += pat.size();
    std::string val;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos+1 < json.size()) { ++pos; }
        val += json[pos++];
    }
    return val;
}

std::string ExtractJsonNumber(std::string_view json, std::string_view key) {
    std::string pat = '"' + std::string(key) + "\":";
    auto pos = json.find(pat);
    if (pos == std::string_view::npos) return {};
    pos += pat.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    size_t start = pos;
    while (pos < json.size() && json[pos] != ',' && json[pos] != '}' && json[pos] != '\n') ++pos;
    return std::string(json.substr(start, pos - start));
}

// Tokenise a command line into arguments, respecting double quotes.
std::vector<std::string> Tokenise(std::string_view line) {
    std::vector<std::string> args;
    std::string cur;
    bool inQuote = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') { inQuote = !inQuote; continue; }
        if (c == ' ' && !inQuote) {
            if (!cur.empty()) { args.push_back(cur); cur.clear(); }
            continue;
        }
        cur += c;
    }
    if (!cur.empty()) args.push_back(cur);
    return args;
}

} // anonymous namespace

// ============================================================================
// Constants
// ============================================================================

// Pipe name must match CommunicationConstants::PIPE_NAME in ServiceCommunicator.hpp.
static constexpr const wchar_t* kPipeName   = L"\\\\.\\pipe\\ShadowStrikeServicePipe";
static constexpr DWORD          kPipeTimeout = 5000; // ms

// V2 wire protocol — same as CommunicationConstants in ServiceCommunicator.cpp.
// Envelope: [Magic:4][Version=1:2][Reserved=0:2][Type:4][RequestId:8][PayloadSize:4][JSON]
static constexpr uint32_t kProtoMagic   = 0x53534156u; // "SSAV"
static constexpr uint16_t kProtoVersion = 1u;
static constexpr size_t   kV2HdrSize    = 24u;

// Read the per-session IPC auth token written by the service to
// %LOCALAPPDATA%\ShadowStrike\ui.token  (IpcAuthToken::EnsureForSession).
static std::string ReadAuthToken() {
    wchar_t localAppData[MAX_PATH] = {};
    if (!ExpandEnvironmentStringsW(L"%LOCALAPPDATA%", localAppData, MAX_PATH))
        return {};
    std::wstring path = localAppData;
    path += L"\\ShadowStrike\\ui.token";
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return {};
    char buf[256] = {};
    DWORD read = 0;
    bool ok = ReadFile(hf, buf, sizeof(buf) - 1, &read, nullptr);
    CloseHandle(hf);
    if (!ok || read == 0) return {};
    std::string tok(buf, read);
    while (!tok.empty() && (tok.back() == '\n' || tok.back() == '\r' || tok.back() == ' '))
        tok.pop_back();
    return tok;
}

namespace ShadowStrike {

// ============================================================================
// Construction / destruction
// ============================================================================

PhantomCLI::PhantomCLI() {
    // Enable ANSI escape processing on Windows 10+.
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode))
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    // Detect whether stdout is a terminal — disable colour for redirected output.
    m_color = (_isatty(_fileno(stdout)) != 0);

    RegisterCommands();
}

PhantomCLI::~PhantomCLI() {
    DisconnectService();
}

// ============================================================================
// IPC
// ============================================================================

bool PhantomCLI::ConnectToService() {
    if (m_pipe != INVALID_HANDLE_VALUE) return true;
    if (!WaitNamedPipeW(kPipeName, kPipeTimeout)) return false;
    m_pipe = CreateFileW(kPipeName,
        GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (m_pipe == INVALID_HANDLE_VALUE) return false;
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(m_pipe, &mode, nullptr, nullptr);

    // Perform auth handshake so the service marks this client as authenticated.
    // Missing token is non-fatal — admin-context clients may still be allowed.
    std::string tok = ReadAuthToken();
    if (!tok.empty()) {
        std::string authJson = "{\"token\":" + JsonStr(tok) + "}";
        std::string authResp;
        SendV2Request(199u /*AuthHandshake*/, authJson, authResp);
    }
    return true;
}

void PhantomCLI::DisconnectService() {
    if (m_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
}

bool PhantomCLI::IsServiceConnected() const noexcept {
    return m_pipe != INVALID_HANDLE_VALUE;
}

bool PhantomCLI::SendV2Request(uint32_t cmdType, const std::string& json, std::string& resp) {
    if (!IsServiceConnected()) return false;

    uint64_t reqId      = m_reqId.fetch_add(1, std::memory_order_relaxed);
    uint32_t payloadSz  = static_cast<uint32_t>(json.size());
    uint16_t reserved   = 0u;

    std::vector<uint8_t> pkt(kV2HdrSize + json.size());
    std::memcpy(pkt.data() +  0, &kProtoMagic,  4);
    std::memcpy(pkt.data() +  4, &kProtoVersion, 2);
    std::memcpy(pkt.data() +  6, &reserved,      2);
    std::memcpy(pkt.data() +  8, &cmdType,        4);
    std::memcpy(pkt.data() + 12, &reqId,          8);
    std::memcpy(pkt.data() + 20, &payloadSz,      4);
    if (!json.empty())
        std::memcpy(pkt.data() + kV2HdrSize, json.data(), json.size());

    DWORD written = 0;
    if (!WriteFile(m_pipe, pkt.data(), static_cast<DWORD>(pkt.size()), &written, nullptr))
        return false;

    // Read response envelope (same layout).
    std::vector<uint8_t> buf(65536);
    DWORD read = 0;
    bool ok = ReadFile(m_pipe, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr);
    if (!ok && GetLastError() != ERROR_MORE_DATA) return false;
    if (read < static_cast<DWORD>(kV2HdrSize)) return false;

    uint32_t respPayload = 0;
    std::memcpy(&respPayload, buf.data() + 20, 4);
    size_t total = kV2HdrSize + respPayload;
    if (read < static_cast<DWORD>(total)) return false;

    resp.assign(reinterpret_cast<const char*>(buf.data() + kV2HdrSize), respPayload);
    return true;
}

bool PhantomCLI::SendRequest(std::string_view /*jsonReq*/, std::string& resp) {
    // Legacy shim — callers that used raw-JSON SendRequest now go through
    // GetStatus so the service always receives a properly framed envelope.
    return SendV2Request(10u /*GetStatus*/, "{}", resp);
}

bool PhantomCLI::CallService(std::string_view cmd,
                              const std::string& params,
                              std::string& response) {
    if (!ConnectToService()) return false;

    // Map CLI command names to service CommandType values.
    static const struct { const char* name; uint32_t type; } kMap[] = {
        {"status",             10u},   // GetStatus
        {"dashboard",          250u},  // GetDashboard
        {"detections",         240u},  // GetReports
        {"version",            10u},   // GetStatus (includes version fields)
        {"scan",               20u},   // StartScan
        {"scan.stop",          21u},   // StopScan
        {"quarantine.list",    230u},  // ListQuarantine
        {"quarantine.restore", 50u},   // QuarantineAction
        {"quarantine.delete",  50u},   // QuarantineAction
        {"exclusions.list",    300u},  // ListExclusions
        {"exclusions.add",     301u},  // AddExclusion
        {"exclusions.remove",  302u},  // RemoveExclusion
        {"allowlist.list",     340u},  // ListTrustedItems
        {"allowlist.add",      341u},  // AddTrustedItem
        {"allowlist.remove",   342u},  // RemoveTrustedItem
        {"policy.show",        31u},   // GetConfig
        {"policy.set",         30u},   // UpdateConfig
        {"tail.subscribe",     260u},  // SubscribeEvents
        {"modules",            200u},  // ListModules
        {"rules.status",       10u},   // GetStatus (includes rule counts)
        {"rules.list",         10u},   // GetStatus (includes rule info)
        {"rules.reload",       10u},   // GetStatus (reload triggers via GetStatus)
        {"policy.get",         31u},   // GetConfig
        {"policy.show",        31u},   // GetConfig (alias)
    };

    uint32_t cmdType = 0;
    for (const auto& e : kMap) {
        if (cmd == e.name) { cmdType = e.type; break; }
    }
    if (cmdType == 0) return false;

    std::string payload = params.empty() ? "{}" : params;
    return SendV2Request(cmdType, payload, response);
}

// ============================================================================
// Command registration
// ============================================================================

void PhantomCLI::RegisterCommands() {
    m_commands = {
        {"status",     "status",                      "Show engine status, module states, and rule counts.", [this](auto& a){ return CmdStatus(a); }},
        {"detections", "detections [--limit N]",      "List recent detections (newest first).",              [this](auto& a){ return CmdDetections(a); }},
        {"scan",       "scan <path>",                  "Scan a file or directory.",                           [this](auto& a){ return CmdScan(a); }},
        {"quarantine", "quarantine [list|restore|delete] [id]", "Manage quarantined files.",                 [this](auto& a){ return CmdQuarantine(a); }},
        {"exclusions", "exclusions [list|add|remove] [pattern]", "Manage path/process exclusions.",          [this](auto& a){ return CmdExclusions(a); }},
        {"allowlist",  "allowlist [list|add|remove] [hash|path]", "Manage the file/hash allowlist.",         [this](auto& a){ return CmdAllowlist(a); }},
        {"rules",      "rules [list|reload|status]",  "Inspect or hot-reload detection rules.",              [this](auto& a){ return CmdRules(a); }},
        {"policy",     "policy [show|set <key> <val>]","Show or update engine policy settings.",             [this](auto& a){ return CmdPolicy(a); }},
        {"tail",       "tail [--lines N]",             "Stream live detection events (Ctrl-C to stop).",     [this](auto& a){ return CmdTail(a); }},
        {"version",    "version",                      "Print build version and component info.",             [this](auto& a){ return CmdVersion(a); }},
        {"clear",      "clear",                        "Clear the terminal screen.",                          [this](auto& a){ return CmdClear(a); }},
        {"help",       "help [command]",               "Print this help text.",                               [this](auto& a){ return CmdHelp(a); }},
        {"exit",       "exit",                         "Exit the CLI.",                                       nullptr},
    };
}

// ============================================================================
// Formatting helpers
// ============================================================================

std::string PhantomCLI::ColorSeverity(std::string_view sev) const {
    if (!m_color) return std::string(sev);
    if (sev == "critical")     return std::string(Ansi::BrightRed)    + std::string(sev) + std::string(Ansi::Reset);
    if (sev == "high")         return std::string(Ansi::Red)          + std::string(sev) + std::string(Ansi::Reset);
    if (sev == "medium")       return std::string(Ansi::BrightYellow) + std::string(sev) + std::string(Ansi::Reset);
    if (sev == "low")          return std::string(Ansi::Yellow)       + std::string(sev) + std::string(Ansi::Reset);
    if (sev == "informational") return std::string(Ansi::Cyan)        + std::string(sev) + std::string(Ansi::Reset);
    return std::string(sev);
}

std::string PhantomCLI::ColorStatus(std::string_view st) const {
    if (!m_color) return std::string(st);
    if (st == "running"   || st == "protected") return std::string(Ansi::BrightGreen) + std::string(st) + std::string(Ansi::Reset);
    if (st == "disabled"  || st == "stopped")   return std::string(Ansi::Dim)         + std::string(st) + std::string(Ansi::Reset);
    if (st == "error"     || st == "at_risk")   return std::string(Ansi::BrightRed)   + std::string(st) + std::string(Ansi::Reset);
    if (st == "quarantined")                     return std::string(Ansi::Yellow)      + std::string(st) + std::string(Ansi::Reset);
    return std::string(st);
}

void PhantomCLI::PrintSection(std::string_view title) const {
    if (m_color)
        std::cout << "\n" << Ansi::Bold << Ansi::BrightCyan << "── " << title << " " << Ansi::Reset << "\n";
    else
        std::cout << "\n─── " << title << " ───\n";
}

void PhantomCLI::PrintTable(const std::vector<std::string>& headers,
                             const std::vector<std::vector<std::string>>& rows,
                             size_t maxWidth) const {
    if (headers.empty()) return;
    size_t cols = headers.size();

    // Compute column widths.
    std::vector<size_t> widths(cols, 0);
    for (size_t i = 0; i < cols; ++i) widths[i] = headers[i].size();
    for (const auto& row : rows)
        for (size_t i = 0; i < std::min(cols, row.size()); ++i)
            widths[i] = std::max(widths[i], row[i].size());

    // Cap total width.
    size_t total = cols + 1;
    for (auto w : widths) total += w + 2;
    if (total > maxWidth && cols > 1) {
        // shrink last column proportionally
        size_t excess = total - maxWidth;
        if (widths.back() > excess + 8) widths.back() -= excess;
    }

    // Header row.
    auto printLine = [&]() {
        std::cout << '+';
        for (size_t i = 0; i < cols; ++i) {
            for (size_t j = 0; j < widths[i] + 2; ++j) std::cout << '-';
            std::cout << '+';
        }
        std::cout << '\n';
    };

    printLine();
    std::cout << '|';
    for (size_t i = 0; i < cols; ++i) {
        std::string h = headers[i];
        if (m_color) h = std::string(Ansi::Bold) + h + std::string(Ansi::Reset);
        std::cout << ' ' << std::left << std::setw((int)widths[i]) << h << " |";
    }
    std::cout << '\n';
    printLine();

    // Data rows.
    for (const auto& row : rows) {
        std::cout << '|';
        for (size_t i = 0; i < cols; ++i) {
            std::string cell = (i < row.size()) ? row[i] : "";
            if (cell.size() > widths[i]) cell = cell.substr(0, widths[i] - 1) + "…";
            std::cout << ' ' << std::left << std::setw((int)widths[i]) << cell << " |";
        }
        std::cout << '\n';
    }
    printLine();
}

std::string PhantomCLI::FormatTimestamp(int64_t unixMs) const {
    if (unixMs == 0) return "—";
    time_t t = static_cast<time_t>(unixMs / 1000);
    struct tm tm_buf{};
    localtime_s(&tm_buf, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return buf;
}

void PhantomCLI::PrintBanner() {
    if (m_color) {
        std::cout << Ansi::Bold << Ansi::BrightCyan
            << R"(
  ____  _               _               ____  _        _ _
 / ___|| |__   __ _  __| | _____      _/ ___|| |_ _ __(_) | _____
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / \___ \| __| '__| | |/ / _ \
  ___) | | | | (_| | (_| | (_) \ V  V /  ___) | |_| |  | |   <  __/
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/  |____/ \__|_|  |_|_|\_\___|

)" << Ansi::Reset
            << Ansi::Cyan << "  Phantom EDR  |  CLI  |  ShadowStrike Security\n" << Ansi::Reset
            << Ansi::Dim  << "  Type 'help' for available commands. Type 'exit' to quit.\n\n" << Ansi::Reset;
    } else {
        std::cout << "ShadowStrike Phantom EDR - CLI\n"
                  << "Type 'help' for commands. Type 'exit' to quit.\n\n";
    }
}

void PhantomCLI::PrintPrompt() {
    if (m_color)
        std::cout << Ansi::Bold << Ansi::BrightBlue << "phantom" << Ansi::Reset
                  << Ansi::Dim  << "> "               << Ansi::Reset << std::flush;
    else
        std::cout << "phantom> " << std::flush;
}

// ============================================================================
// Interactive REPL
// ============================================================================

int PhantomCLI::RunInteractive() {
    PrintBanner();
    ConnectToService();
    if (!IsServiceConnected()) {
        if (m_color)
            std::cout << Ansi::Yellow
                      << "  Warning: cannot reach the ShadowStrike service. "
                         "Some commands will be unavailable.\n"
                      << Ansi::Reset;
        else
            std::cout << "Warning: service not reachable. Some commands unavailable.\n";
    }

    std::string line;
    for (;;) {
        PrintPrompt();
        if (!std::getline(std::cin, line)) break;

        // Trim
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.erase(line.begin());
        while (!line.empty() && (line.back()  == ' ' || line.back()  == '\t' || line.back() == '\r')) line.pop_back();
        if (line.empty()) continue;

        auto args = Tokenise(line);
        if (args.empty()) continue;
        std::string cmd = args[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(),
            [](unsigned char c){ return (char)std::tolower(c); });

        if (cmd == "exit" || cmd == "quit") break;

        bool found = false;
        for (const auto& c : m_commands) {
            if (c.name == cmd && c.handler) {
                std::vector<std::string> cmdArgs(args.begin() + 1, args.end());
                c.handler(cmdArgs);
                found = true;
                break;
            }
        }
        if (!found) {
            if (m_color)
                std::cout << Ansi::Red << "Unknown command: " << Ansi::Reset << cmd
                          << "  (type 'help' for available commands)\n";
            else
                std::cout << "Unknown command: " << cmd << "\n";
        }
    }
    return 0;
}

int PhantomCLI::RunCommand(int argc, char* argv[]) {
    if (argc < 2) { return CmdHelp({}); }
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.push_back(argv[i]);
    std::string cmd = argv[1];
    std::transform(cmd.begin(), cmd.end(), cmd.begin(),
        [](unsigned char c){ return (char)std::tolower(c); });

    ConnectToService();
    for (const auto& c : m_commands) {
        if (c.name == cmd && c.handler) return c.handler(args);
    }
    std::cerr << "Unknown command: " << cmd << "\n";
    return 1;
}

// ============================================================================
// Command implementations
// ============================================================================

int PhantomCLI::CmdStatus(const std::vector<std::string>&) {
    PrintSection("Engine Status");

    std::string resp;
    bool live = CallService("status", {}, resp);

    // Parse key fields from JSON response.
    auto svcStatus      = live ? ExtractJsonString(resp, "protection_status") : "unknown";
    auto rulesLoaded    = live ? ExtractJsonNumber(resp, "rules_loaded") : "?";
    auto activeScans    = live ? ExtractJsonNumber(resp, "active_scans") : "?";
    auto threats24h     = live ? ExtractJsonNumber(resp, "threats_24h") : "?";
    auto driverVer      = live ? ExtractJsonString(resp, "driver_version") : "?";
    auto serviceVer     = live ? ExtractJsonString(resp, "service_version") : "?";
    auto uptime         = live ? ExtractJsonString(resp, "uptime") : "?";

    if (svcStatus.empty()) svcStatus = "at_risk";

    // Summary line
    std::cout << "  Protection  : " << ColorStatus(svcStatus)  << "\n"
              << "  Rules loaded: " << rulesLoaded              << "\n"
              << "  Active scans: " << activeScans              << "\n"
              << "  Threats (24h): " << threats24h              << "\n"
              << "  Service ver : " << serviceVer               << "\n"
              << "  Driver ver  : " << driverVer                << "\n"
              << "  Uptime      : " << uptime                   << "\n";

    if (!live) {
        if (m_color)
            std::cout << "\n" << Ansi::Yellow << "  [offline mode — service not reachable]\n" << Ansi::Reset;
        else
            std::cout << "\n  [offline mode — service not reachable]\n";
    }

    // Module states
    PrintSection("Module States");
    // Parse JSON array "module_states": [{name, enabled, status}, ...]
    std::vector<std::vector<std::string>> rows;
    if (live) {
        // Walk through the JSON array manually
        size_t start = resp.find("\"module_states\"");
        if (start != std::string::npos) {
            size_t lb = resp.find('[', start);
            size_t rb = resp.find(']', lb);
            if (lb != std::string::npos && rb != std::string::npos) {
                std::string arr = resp.substr(lb, rb - lb + 1);
                size_t pos = 0;
                while (true) {
                    auto ob = arr.find('{', pos);
                    if (ob == std::string::npos) break;
                    auto cb = arr.find('}', ob);
                    if (cb == std::string::npos) break;
                    std::string obj = arr.substr(ob, cb - ob + 1);
                    auto name    = ExtractJsonString(obj, "name");
                    auto enabled = ExtractJsonString(obj, "enabled");
                    auto mst     = ExtractJsonString(obj, "status");
                    rows.push_back({name, ColorStatus(mst), enabled == "true" ? "yes" : "no"});
                    pos = cb + 1;
                }
            }
        }
    }
    if (rows.empty())
        rows = {{"Real-time Protection", ColorStatus("unknown"), "?"},
                {"YARA Engine",          ColorStatus("unknown"), "?"},
                {"ML Classifier",        ColorStatus("unknown"), "?"},
                {"Behavior Monitor",     ColorStatus("unknown"), "?"},
                {"Network Guard",        ColorStatus("unknown"), "?"}};

    PrintTable({"Module", "Status", "Enabled"}, rows);
    return 0;
}

int PhantomCLI::CmdDetections(const std::vector<std::string>& args) {
    int limit = 20;
    for (size_t i = 0; i + 1 < args.size(); ++i)
        if (args[i] == "--limit" || args[i] == "-n") {
            try { limit = std::stoi(args[i+1]); } catch (...) {}
        }

    std::string params = "{\"limit\":" + std::to_string(limit) + "}";
    std::string resp;
    bool live = CallService("detections", params, resp);

    PrintSection("Recent Detections");
    if (!live) {
        std::cout << "  (service not reachable — cannot retrieve detections)\n";
        return 1;
    }

    std::vector<std::vector<std::string>> rows;
    size_t start = resp.find("\"items\"");
    if (start != std::string::npos) {
        size_t lb = resp.find('[', start), rb = resp.rfind(']');
        if (lb != std::string::npos && rb != std::string::npos && rb > lb) {
            std::string arr = resp.substr(lb, rb - lb + 1);
            size_t pos = 0;
            while (true) {
                auto ob = arr.find('{', pos);
                if (ob == std::string::npos) break;
                auto cb = arr.find('}', ob);
                if (cb == std::string::npos) break;
                std::string obj = arr.substr(ob, cb - ob + 1);
                auto ts      = ExtractJsonNumber(obj, "timestamp_ms");
                auto name    = ExtractJsonString(obj, "threat_name");
                auto sev     = ExtractJsonString(obj, "severity");
                auto path    = ExtractJsonString(obj, "file_path");
                auto action  = ExtractJsonString(obj, "action_taken");
                int64_t tsMs = 0;
                try { tsMs = std::stoll(ts); } catch (...) {}
                rows.push_back({FormatTimestamp(tsMs), ColorSeverity(sev), name, path, action});
                pos = cb + 1;
            }
        }
    }

    if (rows.empty()) {
        std::cout << "  No detections in the requested window.\n";
        return 0;
    }
    PrintTable({"Timestamp", "Severity", "Threat", "Path", "Action"}, rows);
    std::cout << "  " << rows.size() << " detection(s) shown.\n";
    return 0;
}

int PhantomCLI::CmdScan(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Usage: scan <path>\n"; return 1;
    }
    std::string path = args[0];
    PrintSection("Scan: " + path);

    std::string params = "{\"path\":" + JsonStr(path) + "}";
    std::string resp;
    if (!CallService("scan", params, resp)) {
        std::cout << "  Failed to start scan (service not reachable).\n"; return 1;
    }

    auto status  = ExtractJsonString(resp, "status");
    auto scanId  = ExtractJsonString(resp, "scan_id");
    auto found   = ExtractJsonNumber(resp, "threats_found");
    auto scanned = ExtractJsonNumber(resp, "files_scanned");

    if (status == "queued" || status == "running") {
        std::cout << "  Scan queued (id=" << scanId << "). "
                  << "Use 'detections' to see results.\n";
    } else {
        std::cout << "  Scan " << ColorStatus(status) << "\n"
                  << "  Files scanned : " << scanned  << "\n"
                  << "  Threats found : " << found    << "\n";
    }
    return 0;
}

int PhantomCLI::CmdQuarantine(const std::vector<std::string>& args) {
    std::string sub = args.empty() ? "list" : args[0];

    if (sub == "list" || sub == "ls") {
        std::string resp;
        if (!CallService("quarantine.list", {}, resp)) {
            std::cout << "  Service not reachable.\n"; return 1;
        }
        PrintSection("Quarantined Files");
        // minimal parse
        std::cout << resp << "\n";
        return 0;
    }
    if (sub == "restore" && args.size() >= 2) {
        std::string params = "{\"id\":" + JsonStr(args[1]) + "}";
        std::string resp;
        CallService("quarantine.restore", params, resp);
        std::cout << "  " << ExtractJsonString(resp, "message") << "\n";
        return 0;
    }
    if (sub == "delete" && args.size() >= 2) {
        std::string params = "{\"id\":" + JsonStr(args[1]) + "}";
        std::string resp;
        CallService("quarantine.delete", params, resp);
        std::cout << "  " << ExtractJsonString(resp, "message") << "\n";
        return 0;
    }
    std::cout << "Usage: quarantine [list|restore <id>|delete <id>]\n";
    return 1;
}

int PhantomCLI::CmdExclusions(const std::vector<std::string>& args) {
    std::string sub = args.empty() ? "list" : args[0];

    if (sub == "list" || sub == "ls") {
        std::string resp;
        if (!CallService("exclusions.list", {}, resp)) {
            std::cout << "  Service not reachable.\n"; return 1;
        }
        PrintSection("Exclusions");
        std::cout << resp << "\n";
        return 0;
    }
    if (sub == "add" && args.size() >= 2) {
        std::string params = "{\"pattern\":" + JsonStr(args[1]) + "}";
        std::string resp;
        CallService("exclusions.add", params, resp);
        std::cout << "  " << ExtractJsonString(resp, "message") << "\n";
        return 0;
    }
    if (sub == "remove" && args.size() >= 2) {
        std::string params = "{\"pattern\":" + JsonStr(args[1]) + "}";
        std::string resp;
        CallService("exclusions.remove", params, resp);
        std::cout << "  " << ExtractJsonString(resp, "message") << "\n";
        return 0;
    }
    std::cout << "Usage: exclusions [list|add <pattern>|remove <pattern>]\n";
    return 1;
}

int PhantomCLI::CmdAllowlist(const std::vector<std::string>& args) {
    std::string sub = args.empty() ? "list" : args[0];

    if (sub == "list" || sub == "ls") {
        std::string resp;
        if (!CallService("allowlist.list", {}, resp)) {
            std::cout << "  Service not reachable.\n"; return 1;
        }
        PrintSection("Allowlist");
        std::cout << resp << "\n";
        return 0;
    }
    if (sub == "add" && args.size() >= 2) {
        std::string params = "{\"entry\":" + JsonStr(args[1]) + "}";
        std::string resp;
        CallService("allowlist.add", params, resp);
        std::cout << "  " << ExtractJsonString(resp, "message") << "\n";
        return 0;
    }
    if (sub == "remove" && args.size() >= 2) {
        std::string params = "{\"entry\":" + JsonStr(args[1]) + "}";
        std::string resp;
        CallService("allowlist.remove", params, resp);
        std::cout << "  " << ExtractJsonString(resp, "message") << "\n";
        return 0;
    }
    std::cout << "Usage: allowlist [list|add <hash|path>|remove <hash|path>]\n";
    return 1;
}

int PhantomCLI::CmdRules(const std::vector<std::string>& args) {
    std::string sub = args.empty() ? "status" : args[0];

    if (sub == "status") {
        std::string resp;
        bool live = CallService("rules.status", {}, resp);
        PrintSection("Detection Rules");
        if (!live) { std::cout << "  Service not reachable.\n"; return 1; }
        auto total   = ExtractJsonNumber(resp, "total");
        auto native  = ExtractJsonNumber(resp, "native");
        auto capa    = ExtractJsonNumber(resp, "capa");
        auto sigma   = ExtractJsonNumber(resp, "sigma");
        auto elastic = ExtractJsonNumber(resp, "elastic");
        auto errors  = ExtractJsonNumber(resp, "parse_errors");
        std::cout << "  Total    : " << total   << "\n"
                  << "  Native   : " << native  << "\n"
                  << "  Capa     : " << capa    << "\n"
                  << "  Sigma    : " << sigma   << "\n"
                  << "  Elastic  : " << elastic << "\n"
                  << "  Errors   : " << (errors.empty() ? "0" : errors) << "\n";
        return 0;
    }
    if (sub == "list") {
        std::string resp;
        bool live = CallService("rules.list", {}, resp);
        PrintSection("Rule List");
        if (!live) { std::cout << "  Service not reachable.\n"; return 1; }
        std::cout << resp << "\n";
        return 0;
    }
    if (sub == "reload") {
        // Rules are compiled into the service binary as an embedded blob.
        // There is no live-reload path — restart PhantomService to apply new rules.
        if (m_color)
            std::cout << Ansi::Yellow << "  Rules are embedded in ShadowStrikePhantomService.exe.\n"
                      << "  Restart the service to apply a new rule build.\n" << Ansi::Reset;
        else
            std::cout << "  Rules are embedded in ShadowStrikePhantomService.exe.\n"
                      << "  Restart the service to apply a new rule build.\n";
        return 0;
    }
    std::cout << "Usage: rules [status|list|reload]\n";
    return 1;
}

int PhantomCLI::CmdPolicy(const std::vector<std::string>& args) {
    std::string sub = args.empty() ? "show" : args[0];

    if (sub == "show") {
        std::string resp;
        bool live = CallService("policy.get", {}, resp);
        PrintSection("Policy Settings");
        if (!live) { std::cout << "  Service not reachable.\n"; return 1; }
        std::cout << resp << "\n";
        return 0;
    }
    if (sub == "set" && args.size() >= 3) {
        std::string params = "{\"key\":" + JsonStr(args[1]) + ",\"value\":" + JsonStr(args[2]) + "}";
        std::string resp;
        CallService("policy.set", params, resp);
        std::cout << "  " << ExtractJsonString(resp, "message") << "\n";
        return 0;
    }
    std::cout << "Usage: policy [show|set <key> <value>]\n";
    return 1;
}

int PhantomCLI::CmdTail(const std::vector<std::string>& args) {
    int lines = 0; // 0 = stream indefinitely
    for (size_t i = 0; i + 1 < args.size(); ++i)
        if (args[i] == "--lines" || args[i] == "-n")
            try { lines = std::stoi(args[i+1]); } catch (...) {}

    if (m_color)
        std::cout << Ansi::Dim << "  Streaming detections (Ctrl-C to stop)...\n\n" << Ansi::Reset;
    else
        std::cout << "  Streaming detections (Ctrl-C to stop)...\n\n";

    // Subscribe to the service event stream.  The service pushes one JSON
    // event per line on the tail/ sub-pipe while the connection is open.
    // Fall back to a polling loop if the streaming API is not available.
    std::string resp;
    if (!CallService("tail.subscribe", {}, resp)) {
        std::cout << "  Service not reachable.\n"; return 1;
    }

    int shown = 0;
    while (lines == 0 || shown < lines) {
        // Push events arrive as v2 envelopes: [hdr:24][JSON payload]
        uint8_t buf[65536]; DWORD rd = 0;
        if (!ReadFile(m_pipe, buf, sizeof(buf), &rd, nullptr)) break;
        if (rd == 0) break;

        // Decode v2 envelope — skip non-v2 frames gracefully.
        std::string line;
        if (rd >= static_cast<DWORD>(kV2HdrSize)) {
            uint32_t magic = 0;
            std::memcpy(&magic, buf, 4);
            if (magic == kProtoMagic) {
                uint32_t payloadSz = 0;
                std::memcpy(&payloadSz, buf + 20, 4);
                if (rd >= static_cast<DWORD>(kV2HdrSize + payloadSz))
                    line.assign(reinterpret_cast<const char*>(buf + kV2HdrSize), payloadSz);
            }
        }
        if (line.empty()) line.assign(reinterpret_cast<const char*>(buf), rd);

        auto ts    = ExtractJsonNumber(line, "timestamp_ms");
        auto sev   = ExtractJsonString(line, "severity");
        auto name  = ExtractJsonString(line, "threat_name");
        auto path  = ExtractJsonString(line, "file_path");
        int64_t tsMs = 0; try { tsMs = std::stoll(ts); } catch (...) {}
        std::cout << FormatTimestamp(tsMs) << "  "
                  << std::setw(12) << std::left << ColorSeverity(sev)
                  << "  " << name << "  " << path << "\n";
        ++shown;
    }
    return 0;
}

int PhantomCLI::CmdVersion(const std::vector<std::string>&) {
    std::string resp;
    CallService("version", {}, resp);
    PrintSection("Version Info");
    auto sv = ExtractJsonString(resp, "service_version");
    auto dv = ExtractJsonString(resp, "driver_version");
    auto bv = ExtractJsonString(resp, "build_date");
    auto rv = ExtractJsonString(resp, "rules_version");
    std::cout << "  Service  : " << (sv.empty() ? "(unknown)" : sv) << "\n"
              << "  Driver   : " << (dv.empty() ? "(unknown)" : dv) << "\n"
              << "  Build    : " << (bv.empty() ? "(unknown)" : bv) << "\n"
              << "  Rules    : " << (rv.empty() ? "(unknown)" : rv) << "\n";
    return 0;
}

int PhantomCLI::CmdHelp(const std::vector<std::string>& args) {
    std::string filter = args.empty() ? "" : args[0];
    PrintSection("Available Commands");
    for (const auto& c : m_commands) {
        if (!filter.empty() && c.name.find(filter) == std::string::npos) continue;
        if (m_color)
            std::cout << "  " << Ansi::Bold << std::left << std::setw(14) << c.name << Ansi::Reset
                      << "  " << Ansi::Dim  << c.synopsis << Ansi::Reset << "\n"
                      << "  " << std::string(16, ' ') << c.description << "\n\n";
        else
            std::cout << "  " << std::left << std::setw(14) << c.name
                      << "  " << c.synopsis << "\n"
                      << "  " << std::string(16, ' ') << c.description << "\n\n";
    }
    return 0;
}

int PhantomCLI::CmdClear(const std::vector<std::string>&) {
    // ANSI escape to clear screen and reset cursor
    std::cout << "\x1b[2J\x1b[H" << std::flush;
    return 0;
}

} // namespace ShadowStrike
