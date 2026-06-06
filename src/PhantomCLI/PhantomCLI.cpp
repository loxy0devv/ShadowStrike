/*
 * ShadowStrike – Enterprise NGAV / EDR / XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * PhantomCLI – full-featured interactive terminal control surface.
 *
 * IPC wire protocol (v2):
 *   [Magic:4][Version=1:2][Reserved=0:2][Type:4][RequestId:8][PayloadSize:4][JSON]
 * Pipe   : \\.\pipe\ShadowStrikeServicePipe
 * Token  : %LOCALAPPDATA%\ShadowStrike\ui.token  (written by the service)
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <io.h>
#include <fcntl.h>

#include "PhantomCLI.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// ============================================================================
// Anonymous-namespace helpers (JSON build/parse, tokeniser)
// ============================================================================
namespace {

std::string JStr(std::string_view s) {
    std::string o = "\"";
    for (char c : s) {
        if (c == '"')  { o += "\\\""; continue; }
        if (c == '\\') { o += "\\\\"; continue; }
        if (c == '\n') { o += "\\n";  continue; }
        if (c == '\r') { o += "\\r";  continue; }
        o += c;
    }
    return o + '"';
}

std::string JKV(std::string_view k, std::string_view v) {
    return "{" + JStr(k) + ":" + JStr(v) + "}";
}

std::string ExtractStr(std::string_view j, std::string_view key) {
    std::string pat = '"' + std::string(key) + "\":\"";
    auto p = j.find(pat);
    if (p == std::string_view::npos) return {};
    p += pat.size();
    std::string val;
    while (p < j.size() && j[p] != '"') {
        if (j[p] == '\\' && p + 1 < j.size()) { ++p; }
        val += j[p++];
    }
    return val;
}

std::string ExtractNum(std::string_view j, std::string_view key) {
    std::string pat = '"' + std::string(key) + "\":";
    auto p = j.find(pat);
    if (p == std::string_view::npos) return {};
    p += pat.size();
    while (p < j.size() && (j[p] == ' ' || j[p] == '\t')) ++p;
    size_t s = p;
    while (p < j.size() && j[p] != ',' && j[p] != '}' && j[p] != '\n') ++p;
    return std::string(j.substr(s, p - s));
}

std::vector<std::string> Tokenise(std::string_view line) {
    std::vector<std::string> out;
    std::string cur;
    bool q = false;
    for (char c : line) {
        if (c == '"') { q = !q; continue; }
        if (c == ' ' && !q) { if (!cur.empty()) { out.push_back(cur); cur.clear(); } continue; }
        cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}

// Simple JSON array walker: calls cb({object_string}) for each {...} found in arr.
void WalkJsonArray(std::string_view resp, std::string_view arrayKey,
                   std::function<void(std::string_view)> cb) {
    std::string pat = '"' + std::string(arrayKey) + '"';
    auto p = resp.find(pat);
    if (p == std::string_view::npos) return;
    auto lb = resp.find('[', p);
    if (lb == std::string_view::npos) return;
    size_t depth = 0, start = 0;
    for (size_t i = lb + 1; i < resp.size(); ++i) {
        if (resp[i] == '{') { if (depth == 0) start = i; ++depth; }
        else if (resp[i] == '}') {
            if (depth == 1) cb(resp.substr(start, i - start + 1));
            if (depth > 0) --depth;
        } else if (resp[i] == ']' && depth == 0) break;
    }
}

} // namespace

// ============================================================================
// Constants
// ============================================================================
static constexpr const wchar_t* kPipeName    = L"\\\\.\\pipe\\ShadowStrikeServicePipe";
static constexpr DWORD          kPipeTimeout = 5000;
static constexpr uint32_t       kProtoMagic  = 0x53534156u; // "SSAV"
static constexpr uint16_t       kProtoVer    = 1u;
static constexpr size_t         kHdrSz       = 24u;

static std::string ReadAuthToken() {
    wchar_t la[MAX_PATH] = {};
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%", la, MAX_PATH);
    std::wstring path = std::wstring(la) + L"\\ShadowStrike\\ui.token";
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return {};
    char buf[512] = {};
    DWORD rd = 0;
    ReadFile(hf, buf, (DWORD)sizeof(buf) - 1, &rd, nullptr);
    CloseHandle(hf);
    std::string tok(buf, rd);
    while (!tok.empty() && (tok.back()=='\n'||tok.back()=='\r'||tok.back()==' ')) tok.pop_back();
    return tok;
}

namespace ShadowStrike {

// ============================================================================
// Construction / destruction
// ============================================================================
PhantomCLI::PhantomCLI() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode))
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    m_color = (_isatty(_fileno(stdout)) != 0);
    RegisterCommands();
}

PhantomCLI::~PhantomCLI() { DisconnectService(); }

// ============================================================================
// IPC
// ============================================================================
bool PhantomCLI::ConnectToService() {
    if (m_pipe != INVALID_HANDLE_VALUE) return true;
    if (!WaitNamedPipeW(kPipeName, kPipeTimeout)) return false;
    m_pipe = CreateFileW(kPipeName, GENERIC_READ|GENERIC_WRITE, 0, nullptr,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (m_pipe == INVALID_HANDLE_VALUE) return false;
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(m_pipe, &mode, nullptr, nullptr);
    std::string tok = ReadAuthToken();
    if (!tok.empty()) {
        std::string resp;
        SendV2(199u, "{\"token\":" + JStr(tok) + "}", resp);
    }
    return true;
}

void PhantomCLI::DisconnectService() {
    if (m_pipe != INVALID_HANDLE_VALUE) { CloseHandle(m_pipe); m_pipe = INVALID_HANDLE_VALUE; }
}

bool PhantomCLI::IsServiceConnected() const noexcept { return m_pipe != INVALID_HANDLE_VALUE; }

bool PhantomCLI::SendV2(uint32_t cmdType, const std::string& json, std::string& resp) {
    if (!IsServiceConnected()) return false;
    uint64_t rid = m_reqId.fetch_add(1, std::memory_order_relaxed);
    uint32_t psz = (uint32_t)json.size();
    uint16_t rsv = 0;
    std::vector<uint8_t> pkt(kHdrSz + json.size());
    memcpy(pkt.data() +  0, &kProtoMagic, 4);
    memcpy(pkt.data() +  4, &kProtoVer,   2);
    memcpy(pkt.data() +  6, &rsv,          2);
    memcpy(pkt.data() +  8, &cmdType,      4);
    memcpy(pkt.data() + 12, &rid,          8);
    memcpy(pkt.data() + 20, &psz,          4);
    if (!json.empty()) memcpy(pkt.data() + kHdrSz, json.data(), json.size());
    DWORD wr = 0;
    if (!WriteFile(m_pipe, pkt.data(), (DWORD)pkt.size(), &wr, nullptr)) return false;
    std::vector<uint8_t> buf(131072);
    DWORD rd = 0;
    bool ok = ReadFile(m_pipe, buf.data(), (DWORD)buf.size(), &rd, nullptr);
    if (!ok && GetLastError() != ERROR_MORE_DATA) return false;
    if (rd < (DWORD)kHdrSz) return false;
    uint32_t rpsz = 0;
    memcpy(&rpsz, buf.data() + 20, 4);
    if (rd < (DWORD)(kHdrSz + rpsz)) return false;
    resp.assign((const char*)buf.data() + kHdrSz, rpsz);
    return true;
}

bool PhantomCLI::Call(std::string_view key, const std::string& params, std::string& resp) {
    if (!ConnectToService()) return false;
    static const struct { const char* k; uint32_t t; } kMap[] = {
        // Core
        {"status",             10u},
        {"scan.start",         20u},
        {"scan.stop",          21u},
        {"policy.set",         30u},
        {"policy.get",         31u},
        {"quarantine.action",  50u},
        {"auth",              199u},
        {"modules.list",      200u},
        {"modules.enable",    201u},
        {"modules.disable",   202u},
        {"protect.enable",    210u},
        {"protect.disable",   211u},
        {"quarantine.list",   230u},
        {"detections.list",   240u},
        {"dashboard",         250u},
        {"tail.subscribe",    260u},
        {"exclusions.list",   300u},
        {"exclusions.add",    301u},
        {"exclusions.remove", 302u},
        {"allowlist.list",    340u},
        {"allowlist.add",     341u},
        {"allowlist.remove",  342u},
        // EDR extended
        {"hunt.list",         400u},
        {"hunt.run",          401u},
        {"hunt.cancel",       402u},
        {"hunt.results",      403u},
        {"incidents.list",    410u},
        {"incidents.get",     411u},
        {"incidents.assign",  412u},
        {"incidents.close",   413u},
        {"incidents.comment", 414u},
        {"alerts.list",       420u},
        {"alerts.ack",        421u},
        {"alerts.dismiss",    422u},
        {"alerts.escalate",   423u},
        {"contain.isolate",   430u},
        {"contain.release",   431u},
        {"contain.status",    432u},
        {"remediate.run",     440u},
        {"remediate.status",  441u},
        {"remediate.undo",    442u},
        {"playbooks.list",    450u},
        {"playbooks.run",     451u},
        {"playbooks.status",  452u},
        {"playbooks.stop",    453u},
        {"forensics.collect", 460u},
        {"forensics.list",    461u},
        {"forensics.get",     462u},
        {"live.sessions",     470u},
        {"live.run",          471u},
        {"live.kill",         472u},
        {"assets.list",       480u},
        {"assets.get",        481u},
        {"assets.tag",        482u},
        {"vulns.list",        490u},
        {"vulns.scan",        491u},
        {"vulns.suppress",    492u},
        // XDR extended
        {"sandbox.submit",    500u},
        {"sandbox.status",    501u},
        {"sandbox.results",   502u},
        {"sandbox.list",      503u},
        {"compliance.status", 510u},
        {"compliance.report", 511u},
        {"compliance.run",    512u},
        {"devices.list",      520u},
        {"devices.block",     521u},
        {"devices.allow",     522u},
        {"devices.policy",    523u},
        {"telemetry.status",  530u},
        {"telemetry.set",     531u},
        {"telemetry.flush",   532u},
        {"reports.list",      540u},
        {"reports.generate",  541u},
        {"reports.schedule",  542u},
        {"xdr.correlations",  550u},
        {"xdr.incidents",     551u},
        {"xdr.graph",         552u},
        {"network.alerts",    560u},
        {"network.block",     561u},
        {"network.flows",     562u},
        {"network.unblock",   563u},
        {"identity.alerts",   570u},
        {"identity.reset",    571u},
        {"identity.lock",     572u},
        {"email.threats",     580u},
        {"email.quarantine",  581u},
        {"email.release",     582u},
        {"soar.playbooks",    590u},
        {"soar.run",          591u},
        {"soar.status",       592u},
        {"rules.list",        600u},
        {"rules.reload",      601u},
    };
    uint32_t cmdType = 0;
    for (const auto& e : kMap)
        if (key == e.k) { cmdType = e.t; break; }
    if (cmdType == 0) return false;
    std::string payload = params.empty() ? "{}" : params;
    return SendV2(cmdType, payload, resp);
}

// ============================================================================
// Formatting helpers
// ============================================================================
std::string PhantomCLI::C(std::string_view seq, std::string_view text) const {
    if (!m_color) return std::string(text);
    return std::string(seq) + std::string(text) + std::string(Ansi::Reset);
}

std::string PhantomCLI::ColorSeverity(std::string_view s) const {
    if (!m_color) return std::string(s);
    if (s == "critical")      return C(Ansi::BrightRed,    s);
    if (s == "high")          return C(Ansi::Red,          s);
    if (s == "medium")        return C(Ansi::BrightYellow, s);
    if (s == "low")           return C(Ansi::Yellow,       s);
    if (s == "informational") return C(Ansi::Cyan,         s);
    return std::string(s);
}

std::string PhantomCLI::ColorStatus(std::string_view s) const {
    if (!m_color) return std::string(s);
    if (s=="running"||s=="protected"||s=="healthy"||s=="enabled"||s=="active")
        return C(Ansi::BrightGreen, s);
    if (s=="disabled"||s=="stopped"||s=="inactive")  return C(Ansi::Dim, s);
    if (s=="error"||s=="at_risk"||s=="critical")      return C(Ansi::BrightRed, s);
    if (s=="warning"||s=="degraded")                  return C(Ansi::BrightYellow, s);
    if (s=="quarantined"||s=="isolated")              return C(Ansi::Yellow, s);
    if (s=="scanning"||s=="pending")                  return C(Ansi::BrightCyan, s);
    return std::string(s);
}

std::string PhantomCLI::ColorId(std::string_view s) const {
    return m_color ? C(Ansi::BrightBlue, s) : std::string(s);
}

std::string PhantomCLI::ColorPath(std::string_view s) const {
    return m_color ? C(Ansi::Cyan, s) : std::string(s);
}

void PhantomCLI::PrintSection(std::string_view title) const {
    if (m_color)
        std::cout << "\n" << Ansi::Bold << Ansi::BrightCyan
                  << "─── " << title << " " << Ansi::Reset << "\n";
    else
        std::cout << "\n─── " << title << " ───\n";
}

void PhantomCLI::PrintSuccess(std::string_view msg) const {
    if (m_color) std::cout << "  " << Ansi::BrightGreen << "✓ " << msg << Ansi::Reset << "\n";
    else         std::cout << "  [OK] " << msg << "\n";
}

void PhantomCLI::PrintError(std::string_view msg) const {
    if (m_color) std::cout << "  " << Ansi::BrightRed << "✗ " << msg << Ansi::Reset << "\n";
    else         std::cout << "  [ERR] " << msg << "\n";
}

void PhantomCLI::PrintWarning(std::string_view msg) const {
    if (m_color) std::cout << "  " << Ansi::BrightYellow << "⚠ " << msg << Ansi::Reset << "\n";
    else         std::cout << "  [WARN] " << msg << "\n";
}

void PhantomCLI::PrintInfo(std::string_view msg) const {
    if (m_color) std::cout << "  " << Ansi::Cyan << "ℹ " << msg << Ansi::Reset << "\n";
    else         std::cout << "  [INFO] " << msg << "\n";
}

void PhantomCLI::PrintOffline() const {
    PrintWarning("Service not reachable — running in offline mode.");
}

void PhantomCLI::PrintTable(const std::vector<std::string>& headers,
                              const std::vector<std::vector<std::string>>& rows,
                              size_t maxW) const {
    if (headers.empty()) return;
    size_t cols = headers.size();
    std::vector<size_t> w(cols, 0);
    for (size_t i = 0; i < cols; ++i) w[i] = headers[i].size();
    for (const auto& row : rows)
        for (size_t i = 0; i < std::min(cols, row.size()); ++i)
            w[i] = std::max(w[i], row[i].size());
    // cap last column to stay within maxW
    size_t total = 1;
    for (auto x : w) total += x + 3;
    if (total > maxW && cols > 1) {
        size_t excess = total - maxW;
        if (w.back() > excess + 6) w.back() -= excess;
    }
    auto line = [&](){
        std::cout << '+';
        for (size_t i = 0; i < cols; ++i) { for (size_t j=0;j<w[i]+2;++j) std::cout<<'-'; std::cout<<'+'; }
        std::cout << '\n';
    };
    line();
    std::cout << '|';
    for (size_t i = 0; i < cols; ++i) {
        std::string h = m_color ? (std::string(Ansi::Bold)+headers[i]+std::string(Ansi::Reset)) : headers[i];
        std::cout << ' ' << std::left << std::setw((int)w[i]) << h << " |";
    }
    std::cout << '\n'; line();
    for (const auto& row : rows) {
        std::cout << '|';
        for (size_t i = 0; i < cols; ++i) {
            std::string cell = i < row.size() ? row[i] : "";
            // strip ANSI for width calc — use raw length as approximation
            std::string raw = cell;
            // Remove ANSI escapes from raw for truncation check
            std::string stripped;
            bool esc = false;
            for (char c : raw) {
                if (c == '\x1b') { esc = true; continue; }
                if (esc) { if (c == 'm') esc = false; continue; }
                stripped += c;
            }
            if (stripped.size() > w[i]) cell = stripped.substr(0, w[i]-1) + "…";
            else cell = raw; // keep colour codes when it fits
            std::cout << ' ' << std::left << std::setw((int)w[i]) << cell << " |";
        }
        std::cout << '\n';
    }
    line();
}

std::string PhantomCLI::FormatTimestamp(int64_t ms) const {
    if (ms == 0) return "—";
    time_t t = (time_t)(ms / 1000);
    struct tm tb{};
    localtime_s(&tb, &t);
    char buf[32]; strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tb);
    return buf;
}

std::string PhantomCLI::FormatBytes(int64_t b) const {
    if (b < 0) return "?";
    if (b < 1024)                return std::to_string(b) + " B";
    if (b < 1024*1024)           return std::to_string(b/1024) + " KB";
    if (b < 1024*1024*1024)      return std::to_string(b/(1024*1024)) + " MB";
    return std::to_string(b/(1024*1024*1024)) + " GB";
}

std::string PhantomCLI::PromptLine(std::string_view ctx) const {
    if (m_color)
        std::cout << Ansi::Bold << Ansi::BrightBlue << "phantom"
                  << Ansi::Reset << Ansi::Dim << ":"
                  << Ansi::Reset << Ansi::BrightCyan << ctx
                  << Ansi::Reset << Ansi::Dim << "> " << Ansi::Reset << std::flush;
    else
        std::cout << "phantom:" << ctx << "> " << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) return "";
    while (!line.empty() && (line.back()=='\r'||line.back()==' ')) line.pop_back();
    return line;
}

void PhantomCLI::PrintBanner() const {
    if (m_color) {
        std::cout
            << Ansi::Bold << Ansi::BrightCyan
            << R"(
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████║   ██║   ██║  ██║██║██║  ██╗███████╗
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
)"
            << Ansi::Reset
            << Ansi::Cyan   << "  Phantom  EDR / XDR / NGAV  |  Interactive CLI  |  ShadowStrike Security\n"
            << Ansi::Reset
            << Ansi::Dim    << "  Type 'help' for commands · number or name to pick a menu item · 'exit' to quit\n\n"
            << Ansi::Reset;
    } else {
        std::cout << "ShadowStrike Phantom — EDR/XDR/NGAV CLI\n"
                  << "Type 'help' for commands. 'exit' to quit.\n\n";
    }
}

void PhantomCLI::PrintPrompt() const {
    if (m_color)
        std::cout << Ansi::Bold << Ansi::BrightBlue << "phantom"
                  << Ansi::Reset << Ansi::Dim << "> " << Ansi::Reset << std::flush;
    else
        std::cout << "phantom> " << std::flush;
}

// ============================================================================
// RunMenu — numbered interactive submenu
// ============================================================================
int PhantomCLI::RunMenu(std::string_view title,
                         const std::vector<MenuOption>& options,
                         const std::vector<std::string>& args) {
    // Direct resolution when args are provided.
    if (!args.empty()) {
        const std::string& sel = args[0];
        int num = 0; try { num = std::stoi(sel); } catch (...) {}
        std::vector<std::string> rest(args.begin()+1, args.end());
        for (const auto& o : options) {
            if ((num != 0 && o.number == num) ||
                (!o.shortcut.empty() && o.shortcut == sel)) {
                if (o.number == 0) return 0;
                if (o.action) return o.action(rest);
                return 0;
            }
        }
        PrintError("Unknown selection: " + sel);
        return 1;
    }

    // Interactive loop.
    std::string savedCtx = m_ctx;
    m_ctx = ToLower(std::string(title));
    // collapse spaces to make a clean context token
    m_ctx.erase(std::remove(m_ctx.begin(), m_ctx.end(), ' '), m_ctx.end());

    for (;;) {
        // Render the menu.
        PrintSection(title);
        for (const auto& o : options) {
            if (m_color) {
                if (o.number == 0)
                    std::cout << "  " << Ansi::Dim << " 0  " << o.label << Ansi::Reset << "\n";
                else
                    std::cout << "  " << Ansi::BrightBlue << std::setw(2) << o.number
                               << Ansi::Reset << "  " << o.label;
            } else {
                std::cout << "  " << std::setw(2) << o.number << "  " << o.label;
            }
            if (!o.argHint.empty()) {
                if (m_color) std::cout << "  " << Ansi::Dim << o.argHint << Ansi::Reset;
                else         std::cout << "  " << o.argHint;
            }
            std::cout << "\n";
        }
        std::cout << "\n";

        std::string line = PromptLine(m_ctx);
        if (line.empty()) continue;

        auto tokens = Tokenise(line);
        if (tokens.empty()) continue;
        std::string cmd = ToLower(tokens[0]);

        if (cmd == "exit" || cmd == "quit") {
            m_exit = true;
            m_ctx  = savedCtx;
            return -1;
        }
        if (cmd == "back" || cmd == "0" || cmd == "b") {
            m_ctx = savedCtx;
            return 0;
        }
        if (cmd == "help") {
            PrintInfo("Enter a number or the shortcut name shown in the menu.");
            PrintInfo("'back' or '0' returns to the previous menu.");
            PrintInfo("'exit' quits the CLI entirely.");
            continue;
        }

        int num = 0; try { num = std::stoi(cmd); } catch (...) {}
        std::vector<std::string> rest(tokens.begin()+1, tokens.end());

        bool found = false;
        for (const auto& o : options) {
            if ((num != 0 && o.number == num) ||
                (!o.shortcut.empty() && o.shortcut == cmd)) {
                found = true;
                if (o.number == 0) { m_ctx = savedCtx; return 0; }
                if (o.action) o.action(rest);
                if (m_exit) { m_ctx = savedCtx; return -1; }
                break;
            }
        }
        if (!found)
            PrintError("Invalid selection '" + cmd + "'. Enter a number or type 'help'.");
    }
}

// ============================================================================
// Command registration
// ============================================================================
void PhantomCLI::RegisterCommands() {
    // Each entry: {name, category, synopsis, description, handler}
    m_commands = {
        // ── Status & Info
        {"status",      "info",        "status",
         "Show engine health, active modules, scan status and threat summary.",
         [this](auto& a){ return CmdStatus(a); }},
        {"version",     "info",        "version",
         "Print build version, driver version, rule-set version and build date.",
         [this](auto& a){ return CmdVersion(a); }},
        // ── Protection
        {"protect",     "protection",  "protect [enable|disable|status]",
         "Enable/disable real-time protection or check its current state.",
         [this](auto& a){ return CmdProtect(a); }},
        {"modules",     "protection",  "modules [list|enable <name>|disable <name>]",
         "List all protection modules and toggle them on or off.",
         [this](auto& a){ return CmdModules(a); }},
        // ── Detection & Scanning
        {"detections",  "detection",   "detections [--limit N] [--severity S] [--since ISO]",
         "List recent detections, newest first.  Filter by severity or time window.",
         [this](auto& a){ return CmdDetections(a); }},
        {"scan",        "detection",   "scan <path> [--quick|--full|--custom]",
         "Initiate an on-demand file/directory scan.",
         [this](auto& a){ return CmdScan(a); }},
        {"tail",        "detection",   "tail [--lines N] [--severity S]",
         "Stream live detection events from the service (Ctrl-C to stop).",
         [this](auto& a){ return CmdTail(a); }},
        {"rules",       "detection",   "rules [list|reload|status]",
         "Inspect loaded detection rules by category, or trigger a hot-reload.",
         [this](auto& a){ return CmdRules(a); }},
        // ── Quarantine & Lists
        {"quarantine",  "quarantine",  "quarantine [list|restore <id>|delete <id>]",
         "Browse, restore, or permanently delete quarantined files.",
         [this](auto& a){ return CmdQuarantine(a); }},
        {"exclusions",  "lists",       "exclusions [list|add <pat>|remove <pat>]",
         "Manage path/process/hash scan exclusions.",
         [this](auto& a){ return CmdExclusions(a); }},
        {"allowlist",   "lists",       "allowlist [list|add <entry>|remove <entry>]",
         "Manage the trusted-file allowlist (hash, path, cert).",
         [this](auto& a){ return CmdAllowlist(a); }},
        // ── Policy & Config
        {"policy",      "policy",      "policy [show|set <key> <value>|export|import <file>]",
         "View or update engine policy keys and export/import the full config.",
         [this](auto& a){ return CmdPolicy(a); }},
        // ── Threat Hunting
        {"hunt",        "hunting",     "hunt [list|run <query>|cancel <id>|results <id>]",
         "Run and manage proactive threat-hunting queries across telemetry.",
         [this](auto& a){ return CmdHunt(a); }},
        // ── Incidents & Alerts
        {"incidents",   "response",    "incidents [list|get <id>|assign <id> <user>|close <id>]",
         "View, assign, and close security incidents.",
         [this](auto& a){ return CmdIncidents(a); }},
        {"alerts",      "response",    "alerts [list|ack <id>|dismiss <id>|escalate <id>]",
         "Manage security alerts — acknowledge, dismiss, or escalate.",
         [this](auto& a){ return CmdAlerts(a); }},
        // ── Containment & Remediation
        {"contain",     "response",    "contain [isolate <host>|release <host>|status]",
         "Isolate or release a host from the network.",
         [this](auto& a){ return CmdContain(a); }},
        {"remediate",   "response",    "remediate [run <host> <type>|status <id>|undo <id>]",
         "Trigger automated or manual remediation actions.",
         [this](auto& a){ return CmdRemediate(a); }},
        {"playbooks",   "response",    "playbooks [list|run <name> [host]|status <id>|stop <id>]",
         "List and execute SOAR-style response playbooks.",
         [this](auto& a){ return CmdPlaybooks(a); }},
        // ── Forensics & Live Response
        {"forensics",   "forensics",   "forensics [collect <host>|list|get <id>]",
         "Trigger forensic artifact collection and retrieve packages.",
         [this](auto& a){ return CmdForensics(a); }},
        {"live",        "forensics",   "live [sessions|run <host> <cmd>|kill <sid>]",
         "Open and manage live response sessions on managed endpoints.",
         [this](auto& a){ return CmdLive(a); }},
        // ── Assets & Vulnerabilities
        {"assets",      "assets",      "assets [list|get <id>|tag <id> <tag>]",
         "Browse and tag managed assets (endpoints, servers, workstations).",
         [this](auto& a){ return CmdAssets(a); }},
        {"vulns",       "assets",      "vulns [list|scan <host>|suppress <cve>]",
         "View vulnerabilities on managed endpoints and trigger rescans.",
         [this](auto& a){ return CmdVulns(a); }},
        // ── Sandbox
        {"sandbox",     "sandbox",     "sandbox [submit <file>|status <id>|results <id>|list]",
         "Submit files for sandbox detonation and retrieve reports.",
         [this](auto& a){ return CmdSandbox(a); }},
        // ── Compliance & Device Control
        {"compliance",  "compliance",  "compliance [status|report [framework]|run [framework]]",
         "Check compliance posture and generate reports (CIS, NIST, SOC2, PCI).",
         [this](auto& a){ return CmdCompliance(a); }},
        {"devices",     "compliance",  "devices [list|block <id>|allow <id>|policy show]",
         "Manage USB/removable device control policies.",
         [this](auto& a){ return CmdDevices(a); }},
        // ── Telemetry & Reporting
        {"telemetry",   "telemetry",   "telemetry [status|set <key> <val>|flush]",
         "Configure telemetry collection and pipeline settings.",
         [this](auto& a){ return CmdTelemetry(a); }},
        {"reports",     "telemetry",   "reports [list|generate <type>|schedule <type> <cron>]",
         "Generate and schedule security reports.",
         [this](auto& a){ return CmdReports(a); }},
        // ── XDR / Network / Identity / Email
        {"xdr",         "xdr",         "xdr [correlations|incidents|graph <id>]",
         "View XDR cross-source correlations and incident graph.",
         [this](auto& a){ return CmdXDR(a); }},
        {"network",     "xdr",         "network [alerts|flows|block <ip>|unblock <ip>]",
         "Network detection alerts, traffic flows, and IP block-list management.",
         [this](auto& a){ return CmdNetwork(a); }},
        {"identity",    "xdr",         "identity [alerts|reset <user>|lock <user>]",
         "Identity-based threat alerts and account response actions.",
         [this](auto& a){ return CmdIdentity(a); }},
        {"email",       "xdr",         "email [threats|quarantine <id>|release <id>]",
         "Email threat detections and quarantine management.",
         [this](auto& a){ return CmdEmail(a); }},
        {"soar",        "xdr",         "soar [playbooks|run <name>|status <id>]",
         "SOAR orchestration — browse and trigger cross-product playbooks.",
         [this](auto& a){ return CmdSOAR(a); }},
        // ── Utility
        {"clear",       "util",        "clear",
         "Clear the terminal screen.",
         [this](auto& a){ return CmdClear(a); }},
        {"help",        "util",        "help [command|category]",
         "List all commands or get detailed help for a specific command.",
         [this](auto& a){ return CmdHelp(a); }},
        {"exit",        "util",        "exit",
         "Exit the CLI.",
         nullptr},
    };
}

// ============================================================================
// RunInteractive / RunCommand
// ============================================================================
int PhantomCLI::RunInteractive() {
    PrintBanner();
    ConnectToService();
    if (!IsServiceConnected())
        PrintWarning("Cannot reach ShadowStrike service — some commands will be unavailable.");
    else
        PrintSuccess("Connected to ShadowStrike service.");

    std::string line;
    for (;;) {
        PrintPrompt();
        if (!std::getline(std::cin, line)) break;
        while (!line.empty() && (line.front()==' '||line.front()=='\t')) line.erase(line.begin());
        while (!line.empty() && (line.back()==' '||line.back()=='\t'||line.back()=='\r')) line.pop_back();
        if (line.empty()) continue;

        auto args = Tokenise(line);
        if (args.empty()) continue;
        std::string cmd = ToLower(args[0]);
        if (cmd == "exit" || cmd == "quit") break;

        bool found = false;
        for (const auto& c : m_commands) {
            if (c.name == cmd && c.handler) {
                std::vector<std::string> rest(args.begin()+1, args.end());
                c.handler(rest);
                found = true;
                if (m_exit) goto done;
                break;
            }
        }
        if (!found)
            PrintError("Unknown command '" + cmd + "'. Type 'help' for a list.");
    }
done:
    return 0;
}

int PhantomCLI::RunCommand(int argc, char* argv[]) {
    if (argc < 2) return CmdHelp({});
    std::string cmd = ToLower(argv[1]);
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.push_back(argv[i]);
    ConnectToService();
    for (const auto& c : m_commands)
        if (c.name == cmd && c.handler) return c.handler(args);
    std::cerr << "Unknown command: " << cmd << "\n";
    return 1;
}

// ============================================================================
// CmdStatus
// ============================================================================
int PhantomCLI::CmdStatus(const std::vector<std::string>&) {
    std::string resp;
    bool live = Call("status", {}, resp);
    PrintSection("Engine Status");
    if (!live) { PrintOffline(); return 0; }

    auto prot    = ExtractStr(resp, "protection_status");
    auto svcVer  = ExtractStr(resp, "service_version");
    auto drvVer  = ExtractStr(resp, "driver_version");
    auto uptime  = ExtractStr(resp, "uptime");
    auto rules   = ExtractNum(resp, "rules_loaded");
    auto scans   = ExtractNum(resp, "active_scans");
    auto t24     = ExtractNum(resp, "threats_24h");
    if (prot.empty()) prot = "unknown";

    std::cout << "  Protection   : " << ColorStatus(prot)        << "\n"
              << "  Rules loaded : " << (rules.empty()?"?":rules) << "\n"
              << "  Active scans : " << (scans.empty()?"0":scans) << "\n"
              << "  Threats (24h): " << (t24.empty()?"0":t24)    << "\n"
              << "  Service ver  : " << (svcVer.empty()?"?":svcVer) << "\n"
              << "  Driver ver   : " << (drvVer.empty()?"?":drvVer) << "\n"
              << "  Uptime       : " << (uptime.empty()?"?":uptime) << "\n";

    PrintSection("Module States");
    std::vector<std::vector<std::string>> rows;
    WalkJsonArray(resp, "module_states", [&](std::string_view obj){
        rows.push_back({
            ExtractStr(obj,"name"),
            ColorStatus(ExtractStr(obj,"status")),
            ExtractStr(obj,"enabled")=="true" ? "yes" : "no"
        });
    });
    if (rows.empty())
        rows = {{"Real-time Protection","?","?"}, {"YARA Engine","?","?"},
                {"ML Classifier","?","?"},        {"Behavior Monitor","?","?"},
                {"Network Guard","?","?"}};
    PrintTable({"Module","Status","Enabled"}, rows);
    return 0;
}

// ============================================================================
// CmdProtect
// ============================================================================
int PhantomCLI::CmdProtect(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Show protection status",   "status",  "",     [this](auto&){
            std::string r; bool ok = Call("status",{},r);
            PrintSection("Protection Status");
            if (!ok) { PrintOffline(); return 1; }
            auto st = ExtractStr(r,"protection_status");
            PrintInfo("Current state: " + ColorStatus(st.empty()?"unknown":st));
            return 0;
        }},
        {2, "Enable real-time protection",  "enable",  "", [this](auto&){
            std::string r; Call("protect.enable","{}",r);
            auto msg = ExtractStr(r,"message");
            PrintSuccess(msg.empty()?"Protection enabled.":msg); return 0;
        }},
        {3, "Disable real-time protection", "disable", "", [this](auto&){
            std::string r; Call("protect.disable","{}",r);
            auto msg = ExtractStr(r,"message");
            PrintWarning(msg.empty()?"Protection disabled.":msg); return 0;
        }},
        {0, "Back",                          "back",    "", nullptr},
    };
    return RunMenu("Protection", opts, args);
}

// ============================================================================
// CmdModules
// ============================================================================
int PhantomCLI::CmdModules(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List all modules",         "list",    "", [this](auto&){
            std::string r; bool ok = Call("modules.list","{}",r);
            PrintSection("Protection Modules");
            if (!ok) { PrintOffline(); return 1; }
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"modules",[&](std::string_view o){
                rows.push_back({ExtractStr(o,"name"),ColorStatus(ExtractStr(o,"status")),
                                ExtractStr(o,"enabled")=="true"?"yes":"no",
                                ExtractStr(o,"version")});
            });
            if (rows.empty()) PrintInfo("No module data returned.");
            else PrintTable({"Module","Status","Enabled","Version"},rows);
            return 0;
        }},
        {2, "Enable a module",          "enable",  "<name>", [this](auto& a){
            if (a.empty()) { PrintError("Usage: enable <module-name>"); return 1; }
            std::string r; Call("modules.enable","{\"name\":"+JStr(a[0])+"}",r);
            PrintSuccess(ExtractStr(r,"message")); return 0;
        }},
        {3, "Disable a module",         "disable", "<name>", [this](auto& a){
            if (a.empty()) { PrintError("Usage: disable <module-name>"); return 1; }
            std::string r; Call("modules.disable","{\"name\":"+JStr(a[0])+"}",r);
            PrintWarning(ExtractStr(r,"message")); return 0;
        }},
        {0, "Back", "back", "", nullptr},
    };
    return RunMenu("Modules", opts, args);
}

// ============================================================================
// CmdDetections
// ============================================================================
int PhantomCLI::CmdDetections(const std::vector<std::string>& args) {
    // parse flags even in non-interactive context
    int limit = 20; std::string sev, since;
    for (size_t i = 0; i < args.size(); ++i) {
        if ((args[i]=="--limit"||args[i]=="-n") && i+1<args.size())
            { try{limit=std::stoi(args[i+1]);}catch(...){} ++i; }
        else if (args[i]=="--severity"&&i+1<args.size()) { sev=args[++i]; }
        else if (args[i]=="--since"&&i+1<args.size())    { since=args[++i]; }
    }
    // If args look like a submenu choice, fall through to menu.
    bool isFlag = !args.empty() && args[0].size()>1 && args[0][0]=='-';
    if (args.empty() || isFlag) {
        std::vector<MenuOption> opts = {
            {1, "List recent detections",          "list",    "[--limit N] [--severity S]", [this,limit,sev](auto& a2){
                int lim = limit; std::string s = sev;
                for (size_t i=0;i<a2.size();++i){
                    if((a2[i]=="--limit"||a2[i]=="-n")&&i+1<a2.size()){try{lim=std::stoi(a2[i+1]);}catch(...){}++i;}
                    if(a2[i]=="--severity"&&i+1<a2.size()) s=a2[++i];
                }
                std::string par="{\"limit\":"+std::to_string(lim);
                if(!s.empty()) par+=",\"severity\":"+JStr(s);
                par+="}";
                std::string r; bool ok=Call("detections.list",par,r);
                PrintSection("Recent Detections");
                if(!ok){PrintOffline();return 1;}
                std::vector<std::vector<std::string>> rows;
                WalkJsonArray(r,"items",[&](std::string_view o){
                    int64_t ms=0; try{ms=std::stoll(ExtractNum(o,"timestamp_ms"));}catch(...){}
                    rows.push_back({FormatTimestamp(ms),ColorSeverity(ExtractStr(o,"severity")),
                                    ExtractStr(o,"threat_name"),ColorPath(ExtractStr(o,"file_path")),
                                    ExtractStr(o,"action_taken")});
                });
                if(rows.empty()) PrintInfo("No detections in requested window.");
                else { PrintTable({"Time","Severity","Threat","Path","Action"},rows); PrintInfo(std::to_string(rows.size())+" detection(s)."); }
                return 0;
            }},
            {2, "Filter by severity (critical/high/medium/low)", "filter", "<severity>", [this](auto& a2){
                std::string par="{\"limit\":50,\"severity\":"+JStr(a2.empty()?"high":a2[0])+"}";
                std::string r; bool ok=Call("detections.list",par,r);
                PrintSection("Detections — " + (a2.empty()?std::string("high"):a2[0]));
                if(!ok){PrintOffline();return 1;}
                std::vector<std::vector<std::string>> rows;
                WalkJsonArray(r,"items",[&](std::string_view o){
                    int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"timestamp_ms"));}catch(...){}
                    rows.push_back({FormatTimestamp(ms),ColorSeverity(ExtractStr(o,"severity")),
                                    ExtractStr(o,"threat_name"),ColorPath(ExtractStr(o,"file_path")),ExtractStr(o,"action_taken")});
                });
                if(rows.empty()) PrintInfo("No results."); else PrintTable({"Time","Severity","Threat","Path","Action"},rows);
                return 0;
            }},
            {3, "Stream live events (tail)", "tail", "", [this](auto& a2){ return CmdTail(a2); }},
            {0, "Back", "back", "", nullptr},
        };
        return RunMenu("Detections", opts, {});
    }
    // Called directly with --flags
    std::string par="{\"limit\":"+std::to_string(limit);
    if (!sev.empty()) par+=",\"severity\":"+JStr(sev);
    if (!since.empty()) par+=",\"since\":"+JStr(since);
    par+="}";
    std::string r; bool ok=Call("detections.list",par,r);
    PrintSection("Recent Detections");
    if (!ok) { PrintOffline(); return 1; }
    std::vector<std::vector<std::string>> rows;
    WalkJsonArray(r,"items",[&](std::string_view o){
        int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"timestamp_ms"));}catch(...){}
        rows.push_back({FormatTimestamp(ms),ColorSeverity(ExtractStr(o,"severity")),
                        ExtractStr(o,"threat_name"),ColorPath(ExtractStr(o,"file_path")),ExtractStr(o,"action_taken")});
    });
    if (rows.empty()) PrintInfo("No detections in requested window.");
    else { PrintTable({"Time","Severity","Threat","Path","Action"},rows); PrintInfo(std::to_string(rows.size())+" detection(s)."); }
    return 0;
}

// ============================================================================
// CmdScan
// ============================================================================
int PhantomCLI::CmdScan(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Scan a path",          "scan",    "<path>", [this](auto& a){
            if(a.empty()){PrintError("Usage: scan <path>");return 1;}
            std::string type="full";
            for(size_t i=0;i<a.size();++i){
                if(a[i]=="--quick") type="quick";
                if(a[i]=="--full")  type="full";
                if(a[i]=="--custom")type="custom";
            }
            std::string par="{\"path\":"+JStr(a[0])+",\"type\":"+JStr(type)+"}";
            std::string r; bool ok=Call("scan.start",par,r);
            PrintSection("Scan: "+a[0]);
            if(!ok){PrintOffline();return 1;}
            auto sid=ExtractStr(r,"scan_id"); auto st=ExtractStr(r,"status");
            auto found=ExtractNum(r,"threats_found"); auto scanned=ExtractNum(r,"files_scanned");
            PrintInfo("Scan id: "+ColorId(sid));
            if(st=="queued"||st=="running") PrintInfo("Scan "+ColorStatus(st)+". Use 'detections' to see results.");
            else { std::cout<<"  Files scanned : "<<scanned<<"\n  Threats found : "<<found<<"\n"; }
            return 0;
        }},
        {2, "Stop a running scan",  "stop",    "<scan-id>", [this](auto& a){
            if(a.empty()){PrintError("Usage: stop <scan-id>");return 1;}
            std::string r; Call("scan.stop","{\"scan_id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Scan stop requested: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back", "back", "", nullptr},
    };
    return RunMenu("Scan", opts, args);
}

// ============================================================================
// CmdTail
// ============================================================================
int PhantomCLI::CmdTail(const std::vector<std::string>& args) {
    int lines = 0; std::string sev;
    for (size_t i=0;i<args.size();++i) {
        if((args[i]=="--lines"||args[i]=="-n")&&i+1<args.size()){try{lines=std::stoi(args[i+1]);}catch(...){}++i;}
        if(args[i]=="--severity"&&i+1<args.size()) sev=args[++i];
    }
    PrintInfo("Streaming live events (Ctrl-C to stop)...");
    std::string r;
    if (!Call("tail.subscribe","{}",r)) { PrintOffline(); return 1; }
    int shown=0;
    while (lines==0||shown<lines) {
        uint8_t buf[131072]; DWORD rd=0;
        if (!ReadFile(m_pipe, buf, sizeof(buf), &rd, nullptr)) break;
        if (rd==0) break;
        std::string payload;
        if (rd>=(DWORD)kHdrSz) {
            uint32_t magic=0; memcpy(&magic,buf,4);
            if (magic==kProtoMagic) {
                uint32_t psz=0; memcpy(&psz,buf+20,4);
                if (rd>=(DWORD)(kHdrSz+psz)) payload.assign((const char*)buf+kHdrSz,psz);
            }
        }
        if (payload.empty()) payload.assign((const char*)buf,rd);
        auto ts=ExtractNum(payload,"timestamp_ms"); auto sv=ExtractStr(payload,"severity");
        auto name=ExtractStr(payload,"threat_name"); auto path=ExtractStr(payload,"file_path");
        if (!sev.empty() && sv!=sev) continue;
        int64_t ms=0; try{ms=std::stoll(ts);}catch(...){}
        std::cout<<FormatTimestamp(ms)<<"  "<<std::left<<std::setw(14)<<ColorSeverity(sv)
                 <<"  "<<name<<"  "<<ColorPath(path)<<"\n";
        ++shown;
    }
    return 0;
}

// ============================================================================
// CmdQuarantine
// ============================================================================
int PhantomCLI::CmdQuarantine(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List quarantined files",       "list",    "",        [this](auto&){
            std::string r; bool ok=Call("quarantine.list","{}",r);
            PrintSection("Quarantine");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"items",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"quarantine_time_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"original_name"),
                                ColorPath(ExtractStr(o,"original_path")),
                                ColorSeverity(ExtractStr(o,"severity")),FormatTimestamp(ms),
                                FormatBytes(std::stoll(ExtractNum(o,"size").empty()?"0":ExtractNum(o,"size")))});
            });
            if(rows.empty()) PrintInfo("Quarantine is empty.");
            else PrintTable({"ID","Name","Original Path","Severity","Quarantined","Size"},rows);
            return 0;
        }},
        {2, "Restore a file from quarantine", "restore", "<id>", [this](auto& a){
            if(a.empty()){PrintError("Usage: restore <id>");return 1;}
            std::string r; Call("quarantine.action","{\"action\":\"restore\",\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Restore: "+ExtractStr(r,"message")); return 0;
        }},
        {3, "Delete a quarantined file",      "delete",  "<id>", [this](auto& a){
            if(a.empty()){PrintError("Usage: delete <id>");return 1;}
            std::string r; Call("quarantine.action","{\"action\":\"delete\",\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Delete: "+ExtractStr(r,"message")); return 0;
        }},
        {4, "Delete ALL quarantined files",   "purge",   "",     [this](auto&){
            std::string r; Call("quarantine.action","{\"action\":\"purge\"}",r);
            PrintWarning("Purge: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back", "back", "", nullptr},
    };
    return RunMenu("Quarantine", opts, args);
}

// ============================================================================
// CmdExclusions
// ============================================================================
int PhantomCLI::CmdExclusions(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List exclusions",       "list",   "",            [this](auto&){
            std::string r; bool ok=Call("exclusions.list","{}",r);
            PrintSection("Exclusions");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"items",[&](std::string_view o){
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"type"),
                                ColorPath(ExtractStr(o,"pattern")),ExtractStr(o,"scope"),ExtractStr(o,"created_by")});
            });
            if(rows.empty()) PrintInfo("No exclusions configured.");
            else PrintTable({"ID","Type","Pattern","Scope","Created By"},rows);
            return 0;
        }},
        {2, "Add a path exclusion",  "add",    "<pattern>",   [this](auto& a){
            if(a.empty()){PrintError("Usage: add <pattern>");return 1;}
            std::string type="path";
            for(auto& x:a) if(x=="--hash") type="hash"; else if(x=="--process") type="process";
            std::string par="{\"pattern\":"+JStr(a[0])+",\"type\":"+JStr(type)+"}";
            std::string r; Call("exclusions.add",par,r);
            PrintSuccess("Added exclusion: "+ExtractStr(r,"message")); return 0;
        }},
        {3, "Remove an exclusion",   "remove", "<id|pattern>", [this](auto& a){
            if(a.empty()){PrintError("Usage: remove <id|pattern>");return 1;}
            std::string par="{\"pattern\":"+JStr(a[0])+"}";
            std::string r; Call("exclusions.remove",par,r);
            PrintSuccess("Removed: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Exclusions", opts, args);
}

// ============================================================================
// CmdAllowlist
// ============================================================================
int PhantomCLI::CmdAllowlist(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List allowlist entries",  "list",   "",            [this](auto&){
            std::string r; bool ok=Call("allowlist.list","{}",r);
            PrintSection("Allowlist");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"items",[&](std::string_view o){
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"type"),
                                ExtractStr(o,"value"),ExtractStr(o,"description"),ExtractStr(o,"added_by")});
            });
            if(rows.empty()) PrintInfo("Allowlist is empty.");
            else PrintTable({"ID","Type","Value","Description","Added By"},rows);
            return 0;
        }},
        {2, "Add an entry (hash/path/cert)", "add", "<hash|path>", [this](auto& a){
            if(a.empty()){PrintError("Usage: add <hash|path>");return 1;}
            std::string type="hash";
            for(auto& x:a) if(x=="--path") type="path"; else if(x=="--cert") type="cert";
            std::string par="{\"value\":"+JStr(a[0])+",\"type\":"+JStr(type)+"}";
            std::string r; Call("allowlist.add",par,r);
            PrintSuccess("Added: "+ExtractStr(r,"message")); return 0;
        }},
        {3, "Remove an entry",          "remove", "<id|value>",   [this](auto& a){
            if(a.empty()){PrintError("Usage: remove <id|value>");return 1;}
            std::string r; Call("allowlist.remove","{\"value\":"+JStr(a[0])+"}",r);
            PrintSuccess("Removed: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Allowlist", opts, args);
}

// ============================================================================
// CmdRules
// ============================================================================
int PhantomCLI::CmdRules(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Rule summary / statistics", "status", "", [this](auto&){
            std::string r; bool ok=Call("status","{}",r);
            PrintSection("Detection Rules");
            if(!ok){PrintOffline();return 1;}
            auto total=ExtractNum(r,"rules_loaded"); auto native=ExtractNum(r,"rules_native");
            auto capa=ExtractNum(r,"rules_capa");    auto sigma=ExtractNum(r,"rules_sigma");
            auto elastic=ExtractNum(r,"rules_elastic"); auto errors=ExtractNum(r,"parse_errors");
            std::cout<<"  Total   : "<<(total.empty()?"?":total)<<"\n"
                     <<"  Native  : "<<(native.empty()?"?":native)<<"\n"
                     <<"  Capa    : "<<(capa.empty()?"?":capa)<<"\n"
                     <<"  Sigma   : "<<(sigma.empty()?"?":sigma)<<"\n"
                     <<"  Elastic : "<<(elastic.empty()?"?":elastic)<<"\n"
                     <<"  Errors  : "<<(errors.empty()?"0":errors)<<"\n";
            return 0;
        }},
        {2, "List all rules",            "list",   "", [this](auto&){
            std::string r; bool ok=Call("rules.list","{}",r);
            PrintSection("Rule List");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"rules",[&](std::string_view o){
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"name"),ExtractStr(o,"source"),
                                ColorSeverity(ExtractStr(o,"severity")),ExtractStr(o,"enabled")=="true"?"yes":"no"});
            });
            if(rows.empty()) PrintInfo("No rule data returned.");
            else PrintTable({"ID","Name","Source","Severity","Enabled"},rows);
            return 0;
        }},
        {3, "Reload rules (restart service)", "reload", "", [this](auto&){
            PrintWarning("Rules are embedded in ShadowStrikePhantomService.exe.");
            PrintInfo("Restart the service binary to apply a newly compiled rule build.");
            return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Rules", opts, args);
}

// ============================================================================
// CmdPolicy
// ============================================================================
int PhantomCLI::CmdPolicy(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Show current policy",        "show",   "",                   [this](auto&){
            std::string r; bool ok=Call("policy.get","{}",r);
            PrintSection("Policy Settings");
            if(!ok){PrintOffline();return 1;}
            std::cout<<r<<"\n"; return 0;
        }},
        {2, "Set a policy key",           "set",    "<key> <value>",      [this](auto& a){
            if(a.size()<2){PrintError("Usage: set <key> <value>");return 1;}
            std::string par="{\"key\":"+JStr(a[0])+",\"value\":"+JStr(a[1])+"}";
            std::string r; Call("policy.set",par,r);
            PrintSuccess("Updated: "+ExtractStr(r,"message")); return 0;
        }},
        {3, "Export policy to JSON file",  "export", "[file]",            [this](auto& a){
            std::string r; bool ok=Call("policy.get","{}",r);
            if(!ok){PrintOffline();return 1;}
            std::string path = a.empty() ? "phantom_policy.json" : a[0];
            HANDLE hf=CreateFileA(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
            if(hf==INVALID_HANDLE_VALUE){PrintError("Cannot write: "+path);return 1;}
            DWORD wr=0; WriteFile(hf,r.data(),(DWORD)r.size(),&wr,nullptr); CloseHandle(hf);
            PrintSuccess("Policy exported to: "+path); return 0;
        }},
        {4, "Import policy from JSON file","import", "<file>",            [this](auto& a){
            if(a.empty()){PrintError("Usage: import <file>");return 1;}
            HANDLE hf=CreateFileA(a[0].c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
            if(hf==INVALID_HANDLE_VALUE){PrintError("Cannot open: "+a[0]);return 1;}
            std::string json; char buf[4096]; DWORD rd=0;
            while(ReadFile(hf,buf,sizeof(buf),&rd,nullptr)&&rd>0) json.append(buf,rd);
            CloseHandle(hf);
            std::string r; Call("policy.set",json,r);
            PrintSuccess("Policy imported: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Policy", opts, args);
}

// ============================================================================
// CmdHunt
// ============================================================================
int PhantomCLI::CmdHunt(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List active/completed hunts", "list",    "",            [this](auto&){
            std::string r; bool ok=Call("hunt.list","{}",r);
            PrintSection("Threat Hunting Jobs");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"hunts",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"created_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"name"),
                                ColorStatus(ExtractStr(o,"status")),FormatTimestamp(ms),
                                ExtractNum(o,"matches")});
            });
            if(rows.empty()) PrintInfo("No hunt jobs found.");
            else PrintTable({"ID","Name","Status","Created","Matches"},rows);
            return 0;
        }},
        {2, "Run a new hunt query",        "run",     "<query>",     [this](auto& a){
            if(a.empty()){PrintError("Usage: run <query>");return 1;}
            std::string par="{\"query\":"+JStr(a[0])+"}";
            if(a.size()>1) par="{\"query\":"+JStr(a[0])+",\"name\":"+JStr(a[1])+"}";
            std::string r; Call("hunt.run",par,r);
            auto id=ExtractStr(r,"hunt_id");
            PrintSuccess("Hunt started: "+ColorId(id)); return 0;
        }},
        {3, "View hunt results",           "results", "<id>",        [this](auto& a){
            if(a.empty()){PrintError("Usage: results <hunt-id>");return 1;}
            std::string r; bool ok=Call("hunt.results","{\"id\":"+JStr(a[0])+"}",r);
            PrintSection("Hunt Results — "+a[0]);
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"matches",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"event_time_ms"));}catch(...){}
                rows.push_back({FormatTimestamp(ms),ExtractStr(o,"rule"),
                                ColorPath(ExtractStr(o,"process")),ExtractStr(o,"pid"),ExtractStr(o,"host")});
            });
            if(rows.empty()) PrintInfo("No matches found.");
            else { PrintTable({"Time","Rule","Process","PID","Host"},rows); PrintInfo(std::to_string(rows.size())+" match(es)."); }
            return 0;
        }},
        {4, "Cancel a running hunt",       "cancel",  "<id>",        [this](auto& a){
            if(a.empty()){PrintError("Usage: cancel <hunt-id>");return 1;}
            std::string r; Call("hunt.cancel","{\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Cancelled: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Threat Hunting", opts, args);
}

// ============================================================================
// CmdIncidents
// ============================================================================
int PhantomCLI::CmdIncidents(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List all incidents",    "list",    "[--status open|closed]", [this](auto& a){
            std::string par="{}";
            for(size_t i=0;i+1<a.size();++i) if(a[i]=="--status") par="{\"status\":"+JStr(a[i+1])+"}";
            std::string r; bool ok=Call("incidents.list",par,r);
            PrintSection("Incidents");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"incidents",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"created_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"title"),
                                ColorSeverity(ExtractStr(o,"severity")),ColorStatus(ExtractStr(o,"status")),
                                ExtractStr(o,"assigned_to"),FormatTimestamp(ms)});
            });
            if(rows.empty()) PrintInfo("No incidents found.");
            else PrintTable({"ID","Title","Severity","Status","Assigned","Created"},rows);
            return 0;
        }},
        {2, "Get incident detail",   "get",     "<id>",                   [this](auto& a){
            if(a.empty()){PrintError("Usage: get <id>");return 1;}
            std::string r; bool ok=Call("incidents.get","{\"id\":"+JStr(a[0])+"}",r);
            PrintSection("Incident — "+a[0]);
            if(!ok){PrintOffline();return 1;}
            std::cout<<r<<"\n"; return 0;
        }},
        {3, "Assign incident",       "assign",  "<id> <user>",            [this](auto& a){
            if(a.size()<2){PrintError("Usage: assign <id> <user>");return 1;}
            std::string r; Call("incidents.assign","{\"id\":"+JStr(a[0])+",\"user\":"+JStr(a[1])+"}",r);
            PrintSuccess("Assigned: "+ExtractStr(r,"message")); return 0;
        }},
        {4, "Close an incident",     "close",   "<id>",                   [this](auto& a){
            if(a.empty()){PrintError("Usage: close <id>");return 1;}
            std::string r; Call("incidents.close","{\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Closed: "+ExtractStr(r,"message")); return 0;
        }},
        {5, "Add comment",           "comment", "<id> <text>",            [this](auto& a){
            if(a.size()<2){PrintError("Usage: comment <id> <text>");return 1;}
            std::string r; Call("incidents.comment","{\"id\":"+JStr(a[0])+",\"text\":"+JStr(a[1])+"}",r);
            PrintSuccess("Comment added."); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Incidents", opts, args);
}

// ============================================================================
// CmdAlerts
// ============================================================================
int PhantomCLI::CmdAlerts(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List alerts",         "list",     "[--limit N]", [this](auto& a){
            int lim=50;
            for(size_t i=0;i+1<a.size();++i) if(a[i]=="--limit") try{lim=std::stoi(a[i+1]);}catch(...){}
            std::string r; bool ok=Call("alerts.list","{\"limit\":"+std::to_string(lim)+"}",r);
            PrintSection("Alerts");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"alerts",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"time_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"title"),
                                ColorSeverity(ExtractStr(o,"severity")),ColorStatus(ExtractStr(o,"state")),
                                FormatTimestamp(ms)});
            });
            if(rows.empty()) PrintInfo("No alerts found.");
            else PrintTable({"ID","Title","Severity","State","Time"},rows);
            return 0;
        }},
        {2, "Acknowledge alert",   "ack",      "<id>",        [this](auto& a){
            if(a.empty()){PrintError("Usage: ack <id>");return 1;}
            std::string r; Call("alerts.ack","{\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Acknowledged: "+ExtractStr(r,"message")); return 0;
        }},
        {3, "Dismiss alert",       "dismiss",  "<id>",        [this](auto& a){
            if(a.empty()){PrintError("Usage: dismiss <id>");return 1;}
            std::string r; Call("alerts.dismiss","{\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Dismissed: "+ExtractStr(r,"message")); return 0;
        }},
        {4, "Escalate to incident","escalate", "<id>",        [this](auto& a){
            if(a.empty()){PrintError("Usage: escalate <id>");return 1;}
            std::string r; Call("alerts.escalate","{\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Escalated: "+ExtractStr(r,"message")+" → incident "+ColorId(ExtractStr(r,"incident_id"))); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Alerts", opts, args);
}

// ============================================================================
// CmdContain
// ============================================================================
int PhantomCLI::CmdContain(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Isolation status for all hosts", "status", "",       [this](auto&){
            std::string r; bool ok=Call("contain.status","{}",r);
            PrintSection("Containment Status");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"hosts",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"since_ms"));}catch(...){}
                rows.push_back({ExtractStr(o,"hostname"),ColorStatus(ExtractStr(o,"isolation_state")),
                                FormatTimestamp(ms),ExtractStr(o,"isolated_by")});
            });
            if(rows.empty()) PrintInfo("No host containment records.");
            else PrintTable({"Host","State","Since","By"},rows);
            return 0;
        }},
        {2, "Isolate a host",                 "isolate","<hostname>", [this](auto& a){
            if(a.empty()){PrintError("Usage: isolate <hostname>");return 1;}
            std::string r; Call("contain.isolate","{\"host\":"+JStr(a[0])+"}",r);
            PrintSuccess("Isolated: "+ExtractStr(r,"message")); return 0;
        }},
        {3, "Release a host from isolation",  "release","<hostname>", [this](auto& a){
            if(a.empty()){PrintError("Usage: release <hostname>");return 1;}
            std::string r; Call("contain.release","{\"host\":"+JStr(a[0])+"}",r);
            PrintSuccess("Released: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Containment", opts, args);
}

// ============================================================================
// CmdRemediate
// ============================================================================
int PhantomCLI::CmdRemediate(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Run remediation on a host",  "run",    "<host> <type>", [this](auto& a){
            if(a.size()<2){PrintError("Usage: run <host> <type: kill_process|delete_file|quarantine_file|clear_persistence>");return 1;}
            std::string par="{\"host\":"+JStr(a[0])+",\"type\":"+JStr(a[1]);
            if(a.size()>2) par+=",\"target\":"+JStr(a[2]);
            par+="}";
            std::string r; Call("remediate.run",par,r);
            PrintSuccess("Remediation started: "+ColorId(ExtractStr(r,"task_id"))); return 0;
        }},
        {2, "Check remediation status",   "status", "<task-id>",     [this](auto& a){
            if(a.empty()){PrintError("Usage: status <task-id>");return 1;}
            std::string r; bool ok=Call("remediate.status","{\"id\":"+JStr(a[0])+"}",r);
            PrintSection("Remediation — "+a[0]);
            if(!ok){PrintOffline();return 1;}
            std::cout<<"  State  : "<<ColorStatus(ExtractStr(r,"state"))<<"\n"
                     <<"  Detail : "<<ExtractStr(r,"detail")<<"\n";
            return 0;
        }},
        {3, "Undo last remediation action","undo",   "<task-id>",     [this](auto& a){
            if(a.empty()){PrintError("Usage: undo <task-id>");return 1;}
            std::string r; Call("remediate.undo","{\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Undo: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Remediation", opts, args);
}

// ============================================================================
// CmdPlaybooks
// ============================================================================
int PhantomCLI::CmdPlaybooks(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List available playbooks", "list",   "",                   [this](auto&){
            std::string r; bool ok=Call("playbooks.list","{}",r);
            PrintSection("Playbooks");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"playbooks",[&](std::string_view o){
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"name"),
                                ExtractStr(o,"trigger"),ExtractStr(o,"description")});
            });
            if(rows.empty()) PrintInfo("No playbooks configured.");
            else PrintTable({"ID","Name","Trigger","Description"},rows);
            return 0;
        }},
        {2, "Run a playbook",           "run",    "<name> [host]",      [this](auto& a){
            if(a.empty()){PrintError("Usage: run <playbook-name> [host]");return 1;}
            std::string par="{\"name\":"+JStr(a[0]);
            if(a.size()>1) par+=",\"host\":"+JStr(a[1]);
            par+="}";
            std::string r; Call("playbooks.run",par,r);
            PrintSuccess("Playbook started: "+ColorId(ExtractStr(r,"execution_id"))); return 0;
        }},
        {3, "Check playbook execution", "status", "<exec-id>",          [this](auto& a){
            if(a.empty()){PrintError("Usage: status <exec-id>");return 1;}
            std::string r; bool ok=Call("playbooks.status","{\"id\":"+JStr(a[0])+"}",r);
            PrintSection("Playbook Execution — "+a[0]);
            if(!ok){PrintOffline();return 1;}
            std::cout<<"  State   : "<<ColorStatus(ExtractStr(r,"state"))<<"\n"
                     <<"  Steps   : "<<ExtractNum(r,"steps_total")<<"  Completed: "<<ExtractNum(r,"steps_done")<<"\n"
                     <<"  Detail  : "<<ExtractStr(r,"detail")<<"\n";
            return 0;
        }},
        {4, "Stop a running playbook",  "stop",   "<exec-id>",          [this](auto& a){
            if(a.empty()){PrintError("Usage: stop <exec-id>");return 1;}
            std::string r; Call("playbooks.stop","{\"id\":"+JStr(a[0])+"}",r);
            PrintWarning("Stopped: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Playbooks", opts, args);
}

// ============================================================================
// CmdForensics
// ============================================================================
int PhantomCLI::CmdForensics(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Trigger forensic collection", "collect","<host>",       [this](auto& a){
            if(a.empty()){PrintError("Usage: collect <host>");return 1;}
            std::string par="{\"host\":"+JStr(a[0]);
            for(size_t i=1;i<a.size();++i) if(a[i]=="--full") par+=",\"full\":true";
            par+="}";
            std::string r; Call("forensics.collect",par,r);
            PrintSuccess("Collection started: "+ColorId(ExtractStr(r,"package_id"))); return 0;
        }},
        {2, "List forensic packages",      "list",   "",              [this](auto&){
            std::string r; bool ok=Call("forensics.list","{}",r);
            PrintSection("Forensic Packages");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"packages",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"collected_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"host"),
                                ColorStatus(ExtractStr(o,"status")),FormatTimestamp(ms),
                                FormatBytes(std::stoll(ExtractNum(o,"size_bytes").empty()?"0":ExtractNum(o,"size_bytes")))});
            });
            if(rows.empty()) PrintInfo("No forensic packages found.");
            else PrintTable({"ID","Host","Status","Collected","Size"},rows);
            return 0;
        }},
        {3, "Download a package",          "get",    "<id>",          [this](auto& a){
            if(a.empty()){PrintError("Usage: get <package-id>");return 1;}
            std::string r; bool ok=Call("forensics.get","{\"id\":"+JStr(a[0])+"}",r);
            PrintSection("Forensic Package — "+a[0]);
            if(!ok){PrintOffline();return 1;}
            auto url=ExtractStr(r,"download_url");
            PrintInfo("Download URL: "+url);
            return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Forensics", opts, args);
}

// ============================================================================
// CmdLive
// ============================================================================
int PhantomCLI::CmdLive(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List active live-response sessions","sessions","",           [this](auto&){
            std::string r; bool ok=Call("live.sessions","{}",r);
            PrintSection("Live Response Sessions");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"sessions",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"started_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"host"),
                                ColorStatus(ExtractStr(o,"state")),FormatTimestamp(ms),ExtractStr(o,"operator")});
            });
            if(rows.empty()) PrintInfo("No active sessions.");
            else PrintTable({"ID","Host","State","Started","Operator"},rows);
            return 0;
        }},
        {2, "Run a command on an endpoint",     "run",     "<host> <cmd>", [this](auto& a){
            if(a.size()<2){PrintError("Usage: run <host> <command>");return 1;}
            std::string cmd; for(size_t i=1;i<a.size();++i){if(i>1)cmd+=" ";cmd+=a[i];}
            std::string par="{\"host\":"+JStr(a[0])+",\"command\":"+JStr(cmd)+"}";
            std::string r; bool ok=Call("live.run",par,r);
            PrintSection("Live Response — "+a[0]+" $ "+cmd);
            if(!ok){PrintOffline();return 1;}
            std::cout<<ExtractStr(r,"output")<<"\n";
            return 0;
        }},
        {3, "Kill a live-response session",     "kill",    "<session-id>", [this](auto& a){
            if(a.empty()){PrintError("Usage: kill <session-id>");return 1;}
            std::string r; Call("live.kill","{\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Session killed: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Live Response", opts, args);
}

// ============================================================================
// CmdAssets
// ============================================================================
int PhantomCLI::CmdAssets(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List all managed assets", "list",  "[--type workstation|server]", [this](auto& a){
            std::string par="{}";
            for(size_t i=0;i+1<a.size();++i) if(a[i]=="--type") par="{\"type\":"+JStr(a[i+1])+"}";
            std::string r; bool ok=Call("assets.list",par,r);
            PrintSection("Managed Assets");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"assets",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"last_seen_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"hostname"),ExtractStr(o,"ip"),
                                ExtractStr(o,"os"),ColorStatus(ExtractStr(o,"health")),FormatTimestamp(ms)});
            });
            if(rows.empty()) PrintInfo("No assets found.");
            else PrintTable({"ID","Hostname","IP","OS","Health","Last Seen"},rows);
            return 0;
        }},
        {2, "Get asset detail",        "get",   "<id>",                        [this](auto& a){
            if(a.empty()){PrintError("Usage: get <asset-id>");return 1;}
            std::string r; bool ok=Call("assets.get","{\"id\":"+JStr(a[0])+"}",r);
            PrintSection("Asset — "+a[0]);
            if(!ok){PrintOffline();return 1;}
            std::cout<<r<<"\n"; return 0;
        }},
        {3, "Tag an asset",            "tag",   "<id> <tag>",                  [this](auto& a){
            if(a.size()<2){PrintError("Usage: tag <id> <tag>");return 1;}
            std::string r; Call("assets.tag","{\"id\":"+JStr(a[0])+",\"tag\":"+JStr(a[1])+"}",r);
            PrintSuccess("Tagged: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Assets", opts, args);
}

// ============================================================================
// CmdVulns
// ============================================================================
int PhantomCLI::CmdVulns(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List vulnerabilities",    "list",     "[--severity critical|high]", [this](auto& a){
            std::string par="{}";
            for(size_t i=0;i+1<a.size();++i) if(a[i]=="--severity") par="{\"severity\":"+JStr(a[i+1])+"}";
            std::string r; bool ok=Call("vulns.list",par,r);
            PrintSection("Vulnerabilities");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"vulns",[&](std::string_view o){
                rows.push_back({ExtractStr(o,"cve"),ColorSeverity(ExtractStr(o,"severity")),
                                ExtractStr(o,"host"),ExtractStr(o,"product"),
                                ExtractStr(o,"cvss_score"),ExtractStr(o,"patch_available")=="true"?"yes":"no"});
            });
            if(rows.empty()) PrintInfo("No vulnerabilities found.");
            else PrintTable({"CVE","Severity","Host","Product","CVSS","Patch"},rows);
            return 0;
        }},
        {2, "Rescan a host",           "scan",     "<host>",                     [this](auto& a){
            if(a.empty()){PrintError("Usage: scan <host>");return 1;}
            std::string r; Call("vulns.scan","{\"host\":"+JStr(a[0])+"}",r);
            PrintSuccess("Scan started: "+ColorId(ExtractStr(r,"scan_id"))); return 0;
        }},
        {3, "Suppress a CVE",          "suppress", "<cve>",                      [this](auto& a){
            if(a.empty()){PrintError("Usage: suppress <cve-id>");return 1;}
            std::string r; Call("vulns.suppress","{\"cve\":"+JStr(a[0])+"}",r);
            PrintWarning("Suppressed: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Vulnerabilities", opts, args);
}

// ============================================================================
// CmdSandbox
// ============================================================================
int PhantomCLI::CmdSandbox(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Submit file for detonation", "submit",  "<file-path>", [this](auto& a){
            if(a.empty()){PrintError("Usage: submit <file-path>");return 1;}
            std::string par="{\"path\":"+JStr(a[0]);
            for(auto& x:a) if(x=="--priority") par+=",\"priority\":\"high\"";
            par+="}";
            std::string r; Call("sandbox.submit",par,r);
            PrintSuccess("Submitted: "+ColorId(ExtractStr(r,"task_id"))); return 0;
        }},
        {2, "Check detonation status",    "status",  "<task-id>",   [this](auto& a){
            if(a.empty()){PrintError("Usage: status <task-id>");return 1;}
            std::string r; bool ok=Call("sandbox.status","{\"id\":"+JStr(a[0])+"}",r);
            PrintSection("Sandbox — "+a[0]);
            if(!ok){PrintOffline();return 1;}
            std::cout<<"  State    : "<<ColorStatus(ExtractStr(r,"state"))<<"\n"
                     <<"  Verdict  : "<<ColorSeverity(ExtractStr(r,"verdict"))<<"\n"
                     <<"  Score    : "<<ExtractNum(r,"score")<<"\n";
            return 0;
        }},
        {3, "View full detonation report","results", "<task-id>",   [this](auto& a){
            if(a.empty()){PrintError("Usage: results <task-id>");return 1;}
            std::string r; bool ok=Call("sandbox.results","{\"id\":"+JStr(a[0])+"}",r);
            PrintSection("Sandbox Report — "+a[0]);
            if(!ok){PrintOffline();return 1;}
            std::cout<<r<<"\n"; return 0;
        }},
        {4, "List sandbox jobs",          "list",    "",            [this](auto&){
            std::string r; bool ok=Call("sandbox.list","{}",r);
            PrintSection("Sandbox Jobs");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"jobs",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"submitted_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ColorPath(ExtractStr(o,"filename")),
                                ColorStatus(ExtractStr(o,"state")),ColorSeverity(ExtractStr(o,"verdict")),
                                ExtractNum(o,"score"),FormatTimestamp(ms)});
            });
            if(rows.empty()) PrintInfo("No sandbox jobs.");
            else PrintTable({"ID","File","State","Verdict","Score","Submitted"},rows);
            return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Sandbox", opts, args);
}

// ============================================================================
// CmdCompliance
// ============================================================================
int PhantomCLI::CmdCompliance(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Overall compliance posture", "status","",                    [this](auto&){
            std::string r; bool ok=Call("compliance.status","{}",r);
            PrintSection("Compliance Status");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"frameworks",[&](std::string_view o){
                rows.push_back({ExtractStr(o,"name"),ExtractNum(o,"score")+"%",
                                ColorStatus(ExtractStr(o,"status")),ExtractNum(o,"passed"),ExtractNum(o,"failed")});
            });
            if(rows.empty()) std::cout<<r<<"\n";
            else PrintTable({"Framework","Score","Status","Passed","Failed"},rows);
            return 0;
        }},
        {2, "Generate compliance report",  "report","[cis|nist|soc2|pci]",  [this](auto& a){
            std::string fw = a.empty() ? "cis" : a[0];
            std::string r; bool ok=Call("compliance.report","{\"framework\":"+JStr(fw)+"}",r);
            PrintSection("Compliance Report — "+fw);
            if(!ok){PrintOffline();return 1;}
            std::cout<<r<<"\n"; return 0;
        }},
        {3, "Run compliance scan",         "run",  "[framework]",            [this](auto& a){
            std::string fw = a.empty() ? "all" : a[0];
            std::string r; Call("compliance.run","{\"framework\":"+JStr(fw)+"}",r);
            PrintSuccess("Scan started: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Compliance", opts, args);
}

// ============================================================================
// CmdDevices
// ============================================================================
int PhantomCLI::CmdDevices(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List detected USB/removable devices","list",  "",      [this](auto&){
            std::string r; bool ok=Call("devices.list","{}",r);
            PrintSection("Device Control");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"devices",[&](std::string_view o){
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"type"),
                                ExtractStr(o,"vendor"),ExtractStr(o,"serial"),
                                ExtractStr(o,"host"),ColorStatus(ExtractStr(o,"policy"))});
            });
            if(rows.empty()) PrintInfo("No device events recorded.");
            else PrintTable({"ID","Type","Vendor","Serial","Host","Policy"},rows);
            return 0;
        }},
        {2, "Block a device",                     "block", "<id>",  [this](auto& a){
            if(a.empty()){PrintError("Usage: block <device-id>");return 1;}
            std::string r; Call("devices.block","{\"id\":"+JStr(a[0])+"}",r);
            PrintWarning("Blocked: "+ExtractStr(r,"message")); return 0;
        }},
        {3, "Allow a device",                     "allow", "<id>",  [this](auto& a){
            if(a.empty()){PrintError("Usage: allow <device-id>");return 1;}
            std::string r; Call("devices.allow","{\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Allowed: "+ExtractStr(r,"message")); return 0;
        }},
        {4, "Show device control policy",          "policy","",      [this](auto&){
            std::string r; bool ok=Call("devices.policy","{}",r);
            PrintSection("Device Policy");
            if(!ok){PrintOffline();return 1;}
            std::cout<<r<<"\n"; return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Device Control", opts, args);
}

// ============================================================================
// CmdTelemetry
// ============================================================================
int PhantomCLI::CmdTelemetry(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Show telemetry pipeline status","status","",               [this](auto&){
            std::string r; bool ok=Call("telemetry.status","{}",r);
            PrintSection("Telemetry Status");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"sources",[&](std::string_view o){
                rows.push_back({ExtractStr(o,"name"),ColorStatus(ExtractStr(o,"state")),
                                ExtractNum(o,"events_per_sec"),ExtractStr(o,"destination")});
            });
            if(rows.empty()) std::cout<<r<<"\n";
            else PrintTable({"Source","State","Events/s","Destination"},rows);
            return 0;
        }},
        {2, "Set telemetry key",            "set",   "<key> <val>",   [this](auto& a){
            if(a.size()<2){PrintError("Usage: set <key> <value>");return 1;}
            std::string r; Call("telemetry.set","{\"key\":"+JStr(a[0])+",\"value\":"+JStr(a[1])+"}",r);
            PrintSuccess("Updated: "+ExtractStr(r,"message")); return 0;
        }},
        {3, "Force flush telemetry buffer", "flush", "",               [this](auto&){
            std::string r; Call("telemetry.flush","{}",r);
            PrintSuccess("Flushed: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Telemetry", opts, args);
}

// ============================================================================
// CmdReports
// ============================================================================
int PhantomCLI::CmdReports(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List generated reports",     "list",     "",                       [this](auto&){
            std::string r; bool ok=Call("reports.list","{}",r);
            PrintSection("Reports");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"reports",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"generated_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"type"),
                                ExtractStr(o,"title"),FormatTimestamp(ms),
                                FormatBytes(std::stoll(ExtractNum(o,"size_bytes").empty()?"0":ExtractNum(o,"size_bytes")))});
            });
            if(rows.empty()) PrintInfo("No reports found.");
            else PrintTable({"ID","Type","Title","Generated","Size"},rows);
            return 0;
        }},
        {2, "Generate a report",          "generate", "<type>",                 [this](auto& a){
            if(a.empty()){PrintError("Usage: generate <type: executive|threat|compliance|inventory>");return 1;}
            std::string r; Call("reports.generate","{\"type\":"+JStr(a[0])+"}",r);
            PrintSuccess("Report queued: "+ColorId(ExtractStr(r,"report_id"))); return 0;
        }},
        {3, "Schedule a recurring report","schedule", "<type> <cron-expr>",     [this](auto& a){
            if(a.size()<2){PrintError("Usage: schedule <type> <cron-expression>");return 1;}
            std::string par="{\"type\":"+JStr(a[0])+",\"cron\":"+JStr(a[1])+"}";
            std::string r; Call("reports.schedule",par,r);
            PrintSuccess("Scheduled: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Reports", opts, args);
}

// ============================================================================
// CmdXDR
// ============================================================================
int PhantomCLI::CmdXDR(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "View cross-source correlations","correlations","",      [this](auto&){
            std::string r; bool ok=Call("xdr.correlations","{}",r);
            PrintSection("XDR Correlations");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"correlations",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"time_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"title"),
                                ColorSeverity(ExtractStr(o,"severity")),ExtractStr(o,"sources"),
                                FormatTimestamp(ms)});
            });
            if(rows.empty()) PrintInfo("No correlations found.");
            else PrintTable({"ID","Title","Severity","Sources","Time"},rows);
            return 0;
        }},
        {2, "View XDR incidents",           "incidents",  "",       [this](auto&){
            std::string r; bool ok=Call("xdr.incidents","{}",r);
            PrintSection("XDR Incidents");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"incidents",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"created_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"title"),
                                ColorSeverity(ExtractStr(o,"severity")),ColorStatus(ExtractStr(o,"status")),
                                FormatTimestamp(ms)});
            });
            if(rows.empty()) PrintInfo("No XDR incidents.");
            else PrintTable({"ID","Title","Severity","Status","Created"},rows);
            return 0;
        }},
        {3, "View incident attack graph",   "graph",      "<id>",   [this](auto& a){
            if(a.empty()){PrintError("Usage: graph <incident-id>");return 1;}
            std::string r; bool ok=Call("xdr.graph","{\"id\":"+JStr(a[0])+"}",r);
            PrintSection("Attack Graph — "+a[0]);
            if(!ok){PrintOffline();return 1;}
            std::cout<<r<<"\n"; return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("XDR Correlation", opts, args);
}

// ============================================================================
// CmdNetwork
// ============================================================================
int PhantomCLI::CmdNetwork(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Network detection alerts","alerts",  "",       [this](auto&){
            std::string r; bool ok=Call("network.alerts","{}",r);
            PrintSection("Network Detection Alerts");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"alerts",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"time_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"src_ip"),ExtractStr(o,"dst_ip"),
                                ExtractStr(o,"protocol"),ColorSeverity(ExtractStr(o,"severity")),FormatTimestamp(ms)});
            });
            if(rows.empty()) PrintInfo("No network alerts.");
            else PrintTable({"ID","Src IP","Dst IP","Proto","Severity","Time"},rows);
            return 0;
        }},
        {2, "View network flows",       "flows",   "",       [this](auto&){
            std::string r; bool ok=Call("network.flows","{}",r);
            PrintSection("Network Flows (recent)");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"flows",[&](std::string_view o){
                rows.push_back({ExtractStr(o,"src_ip"),ExtractStr(o,"src_port"),
                                ExtractStr(o,"dst_ip"),ExtractStr(o,"dst_port"),
                                ExtractStr(o,"protocol"),ExtractNum(o,"bytes")});
            });
            if(rows.empty()) PrintInfo("No flow data.");
            else PrintTable({"Src IP","Src Port","Dst IP","Dst Port","Proto","Bytes"},rows);
            return 0;
        }},
        {3, "Block an IP address",      "block",   "<ip>",   [this](auto& a){
            if(a.empty()){PrintError("Usage: block <ip>");return 1;}
            std::string r; Call("network.block","{\"ip\":"+JStr(a[0])+"}",r);
            PrintWarning("Blocked: "+ExtractStr(r,"message")); return 0;
        }},
        {4, "Unblock an IP address",    "unblock", "<ip>",   [this](auto& a){
            if(a.empty()){PrintError("Usage: unblock <ip>");return 1;}
            std::string r; Call("network.unblock","{\"ip\":"+JStr(a[0])+"}",r);
            PrintSuccess("Unblocked: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Network Detection", opts, args);
}

// ============================================================================
// CmdIdentity
// ============================================================================
int PhantomCLI::CmdIdentity(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Identity threat alerts", "alerts","",            [this](auto&){
            std::string r; bool ok=Call("identity.alerts","{}",r);
            PrintSection("Identity Threats");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"alerts",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"time_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"user"),ExtractStr(o,"title"),
                                ColorSeverity(ExtractStr(o,"severity")),FormatTimestamp(ms)});
            });
            if(rows.empty()) PrintInfo("No identity alerts.");
            else PrintTable({"ID","User","Title","Severity","Time"},rows);
            return 0;
        }},
        {2, "Reset user credentials",  "reset", "<username>", [this](auto& a){
            if(a.empty()){PrintError("Usage: reset <username>");return 1;}
            std::string r; Call("identity.reset","{\"user\":"+JStr(a[0])+"}",r);
            PrintSuccess("Reset triggered: "+ExtractStr(r,"message")); return 0;
        }},
        {3, "Lock a user account",     "lock",  "<username>", [this](auto& a){
            if(a.empty()){PrintError("Usage: lock <username>");return 1;}
            std::string r; Call("identity.lock","{\"user\":"+JStr(a[0])+"}",r);
            PrintWarning("Locked: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Identity Protection", opts, args);
}

// ============================================================================
// CmdEmail
// ============================================================================
int PhantomCLI::CmdEmail(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "Email threat detections",  "threats",    "",     [this](auto&){
            std::string r; bool ok=Call("email.threats","{}",r);
            PrintSection("Email Threats");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"threats",[&](std::string_view o){
                int64_t ms=0;try{ms=std::stoll(ExtractNum(o,"time_ms"));}catch(...){}
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"sender"),ExtractStr(o,"subject"),
                                ColorSeverity(ExtractStr(o,"verdict")),ExtractStr(o,"category"),FormatTimestamp(ms)});
            });
            if(rows.empty()) PrintInfo("No email threats found.");
            else PrintTable({"ID","Sender","Subject","Verdict","Category","Time"},rows);
            return 0;
        }},
        {2, "Quarantine an email",      "quarantine", "<id>", [this](auto& a){
            if(a.empty()){PrintError("Usage: quarantine <email-id>");return 1;}
            std::string r; Call("email.quarantine","{\"id\":"+JStr(a[0])+"}",r);
            PrintWarning("Quarantined: "+ExtractStr(r,"message")); return 0;
        }},
        {3, "Release a quarantined email","release",  "<id>", [this](auto& a){
            if(a.empty()){PrintError("Usage: release <email-id>");return 1;}
            std::string r; Call("email.release","{\"id\":"+JStr(a[0])+"}",r);
            PrintSuccess("Released: "+ExtractStr(r,"message")); return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("Email Threats", opts, args);
}

// ============================================================================
// CmdSOAR
// ============================================================================
int PhantomCLI::CmdSOAR(const std::vector<std::string>& args) {
    std::vector<MenuOption> opts = {
        {1, "List SOAR playbooks",        "playbooks","",          [this](auto&){
            std::string r; bool ok=Call("soar.playbooks","{}",r);
            PrintSection("SOAR Playbooks");
            if(!ok){PrintOffline();return 1;}
            std::vector<std::vector<std::string>> rows;
            WalkJsonArray(r,"playbooks",[&](std::string_view o){
                rows.push_back({ColorId(ExtractStr(o,"id")),ExtractStr(o,"name"),
                                ExtractStr(o,"trigger"),ExtractStr(o,"integrations"),
                                ExtractStr(o,"enabled")=="true"?"yes":"no"});
            });
            if(rows.empty()) PrintInfo("No SOAR playbooks configured.");
            else PrintTable({"ID","Name","Trigger","Integrations","Enabled"},rows);
            return 0;
        }},
        {2, "Run a SOAR playbook",        "run",      "<name>",    [this](auto& a){
            if(a.empty()){PrintError("Usage: run <playbook-name>");return 1;}
            std::string r; Call("soar.run","{\"name\":"+JStr(a[0])+"}",r);
            PrintSuccess("SOAR execution started: "+ColorId(ExtractStr(r,"execution_id"))); return 0;
        }},
        {3, "Check SOAR execution status","status",   "<exec-id>", [this](auto& a){
            if(a.empty()){PrintError("Usage: status <exec-id>");return 1;}
            std::string r; bool ok=Call("soar.status","{\"id\":"+JStr(a[0])+"}",r);
            PrintSection("SOAR Execution — "+a[0]);
            if(!ok){PrintOffline();return 1;}
            std::cout<<"  State   : "<<ColorStatus(ExtractStr(r,"state"))<<"\n"
                     <<"  Steps   : "<<ExtractNum(r,"steps_total")<<" / "<<ExtractNum(r,"steps_done")<<"\n"
                     <<"  Output  : "<<ExtractStr(r,"output")<<"\n";
            return 0;
        }},
        {0, "Back","back","",nullptr},
    };
    return RunMenu("SOAR", opts, args);
}

// ============================================================================
// CmdVersion
// ============================================================================
int PhantomCLI::CmdVersion(const std::vector<std::string>&) {
    std::string r; Call("status","{}",r);
    PrintSection("Version Information");
    auto sv=ExtractStr(r,"service_version"); auto dv=ExtractStr(r,"driver_version");
    auto bd=ExtractStr(r,"build_date");      auto rv=ExtractStr(r,"rules_version");
    auto cc=ExtractStr(r,"commit_hash");
    std::cout<<"  Service : "<<(sv.empty()?"(unknown)":sv)<<"\n"
             <<"  Driver  : "<<(dv.empty()?"(unknown)":dv)<<"\n"
             <<"  Rules   : "<<(rv.empty()?"(unknown)":rv)<<"\n"
             <<"  Build   : "<<(bd.empty()?"(unknown)":bd)<<"\n"
             <<"  Commit  : "<<(cc.empty()?"(unknown)":cc)<<"\n";
    return 0;
}

// ============================================================================
// CmdHelp
// ============================================================================
int PhantomCLI::CmdHelp(const std::vector<std::string>& args) {
    std::string filter = args.empty() ? "" : args[0];

    // If given a specific command name, show its detail.
    if (!filter.empty() && filter[0] != '-') {
        for (const auto& c : m_commands) {
            if (c.name == filter) {
                PrintSection(c.name);
                if (m_color)
                    std::cout<<"  "<<Ansi::Bold<<"Synopsis : "<<Ansi::Reset<<c.synopsis<<"\n"
                             <<"  "<<Ansi::Bold<<"Category : "<<Ansi::Reset<<c.category<<"\n"
                             <<"  "<<Ansi::Bold<<"Info     : "<<Ansi::Reset<<c.description<<"\n\n";
                else
                    std::cout<<"  Synopsis : "<<c.synopsis<<"\n"
                             <<"  Category : "<<c.category<<"\n"
                             <<"  Info     : "<<c.description<<"\n\n";
                return 0;
            }
        }
    }

    // Categorised help listing.
    static const char* kCatOrder[] = {
        "info","protection","detection","quarantine","lists","policy",
        "hunting","response","forensics","assets","sandbox","compliance",
        "telemetry","xdr","util"
    };
    static const char* kCatLabel[] = {
        "Status & Info","Protection & Modules","Detection & Scanning","Quarantine",
        "Exclusions & Allowlist","Policy & Config","Threat Hunting",
        "Incidents, Alerts & Response","Forensics & Live Response","Assets & Vulnerabilities",
        "Sandbox","Compliance & Device Control","Telemetry & Reports",
        "XDR / Network / Identity / Email / SOAR","Utilities"
    };
    constexpr int nCat = 15;

    if (m_color)
        std::cout<<"\n"<<Ansi::Bold<<Ansi::BrightCyan<<"ShadowStrike Phantom CLI — Command Reference"<<Ansi::Reset<<"\n\n";
    else
        std::cout<<"\nShadowStrike Phantom CLI — Command Reference\n\n";

    for (int ci = 0; ci < nCat; ++ci) {
        std::string cat = kCatOrder[ci];
        bool printed = false;
        for (const auto& c : m_commands) {
            if (c.category != cat) continue;
            if (!filter.empty() && c.name.find(filter)==std::string::npos &&
                c.synopsis.find(filter)==std::string::npos) continue;
            if (!printed) {
                if (m_color)
                    std::cout<<"  "<<Ansi::Bold<<Ansi::Yellow<<kCatLabel[ci]<<Ansi::Reset<<"\n";
                else
                    std::cout<<"  "<<kCatLabel[ci]<<"\n";
                printed = true;
            }
            if (m_color)
                std::cout<<"    "<<Ansi::Bold<<std::left<<std::setw(14)<<c.name<<Ansi::Reset
                         <<"  "<<Ansi::Dim<<c.synopsis<<Ansi::Reset<<"\n"
                         <<"    "<<std::string(16,' ')<<c.description<<"\n\n";
            else
                std::cout<<"    "<<std::left<<std::setw(14)<<c.name
                         <<"  "<<c.synopsis<<"\n"
                         <<"    "<<std::string(16,' ')<<c.description<<"\n\n";
        }
    }

    if (m_color)
        std::cout<<Ansi::Dim<<"  Tip: type a command name alone to open its interactive submenu.\n"
                 <<"  Tip: 'help <command>' shows detailed usage for a specific command.\n"
                 <<Ansi::Reset<<"\n";
    else
        std::cout<<"  Tip: type a command name alone to open its interactive submenu.\n\n";
    return 0;
}

// ============================================================================
// CmdClear
// ============================================================================
int PhantomCLI::CmdClear(const std::vector<std::string>&) {
    std::cout << "\x1b[2J\x1b[H" << std::flush;
    PrintBanner();
    return 0;
}

} // namespace ShadowStrike

