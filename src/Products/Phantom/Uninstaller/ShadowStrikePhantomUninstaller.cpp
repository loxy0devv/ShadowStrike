/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * ShadowStrikePhantomUninstaller.cpp
 *
 * Win32 dialog-based GUI uninstaller for ShadowStrike Phantom (NGAV/EDR).
 *
 * Design constraints enforced here:
 *   - Subsystem WINDOWS; no console window is ever allocated.
 *   - No /silent, /quiet, /q, or any headless bypass flag is accepted.
 *   - All three dialog steps (Welcome, Progress, Complete) are mandatory;
 *     the uninstall actions only run after the user clicks "Uninstall" on
 *     Step 1.
 *   - requireAdministrator in the manifest causes UAC elevation before
 *     WinMain is reached.  A belt-and-suspenders token check at startup
 *     aborts with a hard error if the process somehow starts unelevated
 *     (e.g. manifest tampering).
 *   - Interactive-session check: if GetSystemMetrics(SM_REMOTESESSION)
 *     indicates a session type that cannot show interactive UI (or if the
 *     process desktop cannot be queried), we bail out immediately rather
 *     than silently removing software.
 *
 * Uninstall sequence (performed on a worker thread; Step 2 progress dialog
 * remains responsive via PostMessage):
 *    1. Stop service:             sc stop ShadowStrikePhantomService
 *    2. Delete service entry:     sc delete ShadowStrikePhantomService
 *    3. Stop driver service:      sc stop PhantomSensor
 *    4. Delete driver service:    sc delete PhantomSensor
 *    5. Remove driver from store: pnputil /delete-driver <published-name> /uninstall /force
 *    6. Remove trusted cert:      CertDeleteCertificateFromStore (Root + TrustedPublisher)
 *    7. Delete install tree:      C:\Program Files\ShadowStrike\  (recursive)
 *    8. Delete data tree:         C:\ProgramData\ShadowStrike\    (recursive)
 *    9. Remove registry key:      HKLM\SOFTWARE\ShadowStrike      (recursive)
 *   10. Scrub PATH:               remove ShadowStrike entries from HKLM system PATH
 *
 * NOTE: The pnputil published name (e.g. "oem78.inf") and cert thumbprint are
 * read from HKLM\SOFTWARE\ShadowStrike\PhantomHome\Install before the registry
 * tree is deleted in step 9.
 *
 * Build requirements:
 *   C++17 (/std:c++17), x64 only, /MT (static CRT), SubSystem Windows.
 *   Linked libraries: user32.lib advapi32.lib shell32.lib shlwapi.lib
 *                     version.lib crypt32.lib
 */

// ============================================================================
// Headers
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <wincrypt.h>

#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <algorithm>

#include "resource.h"

// ============================================================================
// Pragmas / libs
// ============================================================================

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "crypt32.lib")

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' "  \
    "version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ============================================================================
// Constants
// ============================================================================

namespace {

constexpr const wchar_t* kServiceName       = L"ShadowStrikePhantomService";
constexpr const wchar_t* kDriverServiceName = L"PhantomSensor";
constexpr const wchar_t* kDriverInf         = L"PhantomSensor.inf"; // fallback only
constexpr const wchar_t* kInstallDir        = L"C:\\Program Files\\ShadowStrike\\";
constexpr const wchar_t* kDataDir           = L"C:\\ProgramData\\ShadowStrike\\";
constexpr const wchar_t* kRegKey            = L"SOFTWARE\\ShadowStrike";
constexpr const wchar_t* kInstallRegKey     = L"SOFTWARE\\ShadowStrike\\PhantomHome\\Install";

// Custom window messages posted from the worker thread to the progress dialog
constexpr UINT WM_WORKER_PROGRESS = WM_USER + 100; // wParam = 0-100, lParam = step text ptr
constexpr UINT WM_WORKER_DONE     = WM_USER + 101; // wParam = 0 (success) or 1 (partial)

// Maximum time (ms) to wait for the worker thread to finish before giving up
constexpr DWORD kWorkerTimeoutMs = 5 * 60 * 1000; // 5 minutes

} // namespace

// ============================================================================
// Global state
// ============================================================================

static HINSTANCE g_hInstance = nullptr;

// Shared state between worker thread and progress dialog
struct WorkerContext {
    HWND    hwndProgress = nullptr;  // handle of progress dialog
    bool    partialFailure = false;  // set by worker if any step had non-fatal errors
    std::wstring errorSummary;       // human-readable error accumulation
};

static WorkerContext g_workerCtx;

// ============================================================================
// Security / session helpers
// ============================================================================

/**
 * Returns true when the current process token carries a high-integrity
 * elevated administrator token.  requireAdministrator in the manifest should
 * guarantee this, but we validate defensively.
 */
static bool IsRunningElevated() noexcept
{
    HANDLE hToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    TOKEN_ELEVATION elevation{};
    DWORD cbSize = sizeof(elevation);
    const BOOL ok = ::GetTokenInformation(
        hToken, TokenElevation, &elevation, cbSize, &cbSize);
    ::CloseHandle(hToken);

    return ok && (elevation.TokenIsElevated != 0);
}

/**
 * Returns true when we are confident the process is running in an interactive
 * desktop session where a visible dialog can appear.
 *
 * We refuse to run if:
 *   - The process station has no interactive window station, OR
 *   - SM_REMOTESESSION indicates a legacy RDP session without interactive
 *     capabilities (belt-and-suspenders; RDP can show dialogs, but a
 *     session-0 non-interactive service cannot).
 *
 * The definitive guard is the UAC requirement + mandatory user click on the
 * Welcome dialog.  This check is an additional sanity gate.
 */
static bool IsInteractiveSession() noexcept
{
    // Check if our window station is interactive
    HWINSTA hWinSta = ::GetProcessWindowStation();
    if (!hWinSta)
        return false;

    wchar_t wsName[256]{};
    DWORD needed = 0;
    ::GetUserObjectInformationW(hWinSta, UOI_NAME, wsName, sizeof(wsName), &needed);

    // Non-interactive stations include "Service-0x0-3e7$" etc.
    if (::_wcsnicmp(wsName, L"WinSta0", 7) != 0)
        return false;

    return true;
}

// ============================================================================
// Registry helpers
// ============================================================================

/**
 * Recursively deletes a registry key and all its subkeys.
 * Mirrors RegDeleteTreeW (available since Vista), but we implement manually
 * to avoid a dependency on newer SDKs and to accumulate errors gracefully.
 */
static bool RegDeleteKeyRecursive(HKEY hRoot, const wchar_t* subKey)
{
    // Try the easy path first (Vista+)
    LONG rc = ::RegDeleteTreeW(hRoot, subKey);
    if (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND)
        return true;

    // Fallback: manual recursion
    HKEY hKey = nullptr;
    rc = ::RegOpenKeyExW(hRoot, subKey, 0, KEY_ALL_ACCESS, &hKey);
    if (rc == ERROR_FILE_NOT_FOUND)
        return true;
    if (rc != ERROR_SUCCESS)
        return false;

    bool ok = true;
    for (;;) {
        wchar_t childName[256]{};
        DWORD cchChild = static_cast<DWORD>(std::size(childName));
        LONG enumRc = ::RegEnumKeyExW(hKey, 0, childName, &cchChild,
                                      nullptr, nullptr, nullptr, nullptr);
        if (enumRc == ERROR_NO_MORE_ITEMS)
            break;
        if (enumRc != ERROR_SUCCESS) {
            ok = false;
            break;
        }
        if (!RegDeleteKeyRecursive(hKey, childName))
            ok = false;
    }

    ::RegCloseKey(hKey);

    if (ok)
        ok = (::RegDeleteKeyW(hRoot, subKey) == ERROR_SUCCESS);

    return ok;
}

// ============================================================================
// PATH scrubbing
// ============================================================================

/**
 * Removes any PATH entries that contain the ShadowStrike install directory
 * from the system-wide PATH in the registry.
 *
 * Modifies HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment.
 */
static void ScrubSystemPath()
{
    constexpr const wchar_t* kEnvKey =
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";

    HKEY hKey = nullptr;
    if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, kEnvKey, 0,
                        KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return;

    // Query current PATH value (may be REG_SZ or REG_EXPAND_SZ)
    DWORD dwType = 0;
    DWORD cbData = 0;
    ::RegQueryValueExW(hKey, L"Path", nullptr, &dwType, nullptr, &cbData);

    if (cbData == 0 || (dwType != REG_SZ && dwType != REG_EXPAND_SZ)) {
        ::RegCloseKey(hKey);
        return;
    }

    std::vector<wchar_t> buf(cbData / sizeof(wchar_t) + 1, L'\0');
    if (::RegQueryValueExW(hKey, L"Path", nullptr, &dwType,
                           reinterpret_cast<BYTE*>(buf.data()), &cbData) != ERROR_SUCCESS) {
        ::RegCloseKey(hKey);
        return;
    }

    // Split on ';', filter, rejoin
    std::wstring pathStr(buf.data());
    std::wstring result;
    result.reserve(pathStr.size());

    size_t pos = 0;
    while (pos <= pathStr.size()) {
        size_t semi = pathStr.find(L';', pos);
        if (semi == std::wstring::npos)
            semi = pathStr.size();

        std::wstring_view entry(pathStr.data() + pos, semi - pos);

        // Case-insensitive substring match for "ShadowStrike"
        std::wstring entryLower(entry);
        std::transform(entryLower.begin(), entryLower.end(),
                       entryLower.begin(), ::towlower);

        if (entryLower.find(L"shadowstrike") == std::wstring::npos) {
            if (!result.empty())
                result += L';';
            result.append(entry);
        }

        if (semi == pathStr.size())
            break;
        pos = semi + 1;
    }

    // Write back only if we actually removed something
    if (result != pathStr) {
        const DWORD cbNew = static_cast<DWORD>((result.size() + 1) * sizeof(wchar_t));
        ::RegSetValueExW(hKey, L"Path", 0, dwType,
                         reinterpret_cast<const BYTE*>(result.c_str()), cbNew);

        // Notify the system that the environment changed
        DWORD_PTR dwResult = 0;
        ::SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                              reinterpret_cast<LPARAM>(L"Environment"),
                              SMTO_ABORTIFHUNG, 5000, &dwResult);
    }

    ::RegCloseKey(hKey);
}

// ============================================================================
// Shell-execute helper (synchronous)
// ============================================================================

/**
 * Runs a command synchronously with CreateProcess, waits for it to exit,
 * and returns the process exit code.  Output is discarded (this is a GUI app
 * with no console).
 *
 * @param commandLine  Full command line (may be modified by CreateProcess).
 * @param timeoutMs    Maximum time to wait (INFINITE = wait forever).
 * @returns exit code of the child process, or MAXDWORD on launch failure.
 */
static DWORD RunCommand(std::wstring commandLine, DWORD timeoutMs = INFINITE)
{
    STARTUPINFOW si{};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;   // suppress any console window the child may create

    PROCESS_INFORMATION pi{};

    if (!::CreateProcessW(nullptr, commandLine.data(),
                          nullptr, nullptr, FALSE,
                          CREATE_NO_WINDOW,
                          nullptr, nullptr, &si, &pi))
        return MAXDWORD;

    ::WaitForSingleObject(pi.hProcess, timeoutMs);

    DWORD exitCode = MAXDWORD;
    ::GetExitCodeProcess(pi.hProcess, &exitCode);

    ::CloseHandle(pi.hProcess);
    ::CloseHandle(pi.hThread);

    return exitCode;
}

// ============================================================================
// Directory removal (recursive, robust)
// ============================================================================

/**
 * Recursively deletes a directory tree using SHFileOperationW.
 * SHFileOperation requires double-null-terminated path strings.
 */
static bool DeleteDirectoryTree(const wchar_t* path)
{
    // Build double-null-terminated source string
    std::wstring src(path);
    src.push_back(L'\0'); // extra null terminator

    SHFILEOPSTRUCTW op{};
    op.wFunc  = FO_DELETE;
    op.pFrom  = src.c_str();
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT | FOF_ALLOWUNDO;

    int result = ::SHFileOperationW(&op);
    return (result == 0) && !op.fAnyOperationsAborted;
}

// ============================================================================
// Registry read helper
// ============================================================================

static std::wstring RegReadString(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName)
{
    HKEY hKey = nullptr;
    if (::RegOpenKeyExW(hRoot, subKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return {};

    DWORD dwType = 0, cbData = 0;
    ::RegQueryValueExW(hKey, valueName, nullptr, &dwType, nullptr, &cbData);

    if (cbData == 0 || (dwType != REG_SZ && dwType != REG_EXPAND_SZ)) {
        ::RegCloseKey(hKey);
        return {};
    }

    std::vector<wchar_t> buf(cbData / sizeof(wchar_t) + 1, L'\0');
    ::RegQueryValueExW(hKey, valueName, nullptr, &dwType,
                       reinterpret_cast<BYTE*>(buf.data()), &cbData);
    ::RegCloseKey(hKey);
    return std::wstring(buf.data());
}

// ============================================================================
// Certificate removal helper
// ============================================================================

/**
 * Removes the certificate with the given hex thumbprint from both the
 * LocalMachine\Root and LocalMachine\TrustedPublisher stores.
 *
 * thumbprint: hex string as produced by PowerShell's .Thumbprint property
 *             (e.g. "A1B2C3D4..."), 40 uppercase hex chars for SHA-1.
 */
static bool RemoveTrustedCert(const std::wstring& thumbprint)
{
    if (thumbprint.empty() || thumbprint.size() % 2 != 0)
        return false;

    // Convert hex string to binary hash blob
    std::vector<BYTE> hash;
    hash.reserve(thumbprint.size() / 2);
    for (size_t i = 0; i + 1 < thumbprint.size(); i += 2) {
        wchar_t hex[3] = { thumbprint[i], thumbprint[i + 1], L'\0' };
        hash.push_back(static_cast<BYTE>(::wcstoul(hex, nullptr, 16)));
    }

    CRYPT_HASH_BLOB hashBlob{};
    hashBlob.cbData = static_cast<DWORD>(hash.size());
    hashBlob.pbData = hash.data();

    bool allOk = true;
    for (const wchar_t* storeName : { L"Root", L"TrustedPublisher" }) {
        HCERTSTORE hStore = ::CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, 0, 0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG,
            storeName);
        if (!hStore) {
            allOk = false;
            continue;
        }

        PCCERT_CONTEXT pCert = ::CertFindCertificateInStore(
            hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_HASH, &hashBlob, nullptr);

        if (pCert) {
            // CertDeleteCertificateFromStore frees pCert even on failure
            if (!::CertDeleteCertificateFromStore(pCert))
                allOk = false;
        }

        ::CertCloseStore(hStore, 0);
    }
    return allOk;
}

// ============================================================================
// Progress notification helpers
// ============================================================================

/**
 * Posts a progress update to the progress dialog from the worker thread.
 * The step text must remain valid until the dialog processes the message
 * — we heap-allocate a copy and the dialog proc frees it.
 */
static void PostProgress(HWND hwnd, int percent, const wchar_t* stepText)
{
    if (!hwnd)
        return;

    wchar_t* text = ::_wcsdup(stepText); // dialog proc calls free()
    ::PostMessageW(hwnd, WM_WORKER_PROGRESS,
                   static_cast<WPARAM>(percent),
                   reinterpret_cast<LPARAM>(text));
}

// ============================================================================
// Uninstall worker (runs on a dedicated thread)
// ============================================================================

/**
 * Performs all uninstall actions in sequence.  Posts WM_WORKER_PROGRESS
 * messages to the progress dialog as each step completes, then posts
 * WM_WORKER_DONE when finished.
 *
 * Non-fatal errors are accumulated in g_workerCtx.errorSummary.
 */
static void UninstallWorker()
{
    HWND hwnd = g_workerCtx.hwndProgress;
    bool& partial = g_workerCtx.partialFailure;
    std::wstring& errors = g_workerCtx.errorSummary;

    auto Fail = [&](const wchar_t* msg) {
        partial = true;
        if (!errors.empty()) errors += L'\n';
        errors += msg;
    };

    // Read install-time metadata from the registry BEFORE we delete it in step 9.
    // The published driver name (e.g. "oem78.inf") is required by pnputil; the
    // original filename "PhantomSensor.inf" is a fallback only.
    std::wstring publishedDriverName = RegReadString(
        HKEY_LOCAL_MACHINE, kInstallRegKey, L"DriverPublishedName");
    std::wstring certThumbprint = RegReadString(
        HKEY_LOCAL_MACHINE, kInstallRegKey, L"DriverCertThumbprint");

    // -----------------------------------------------------------------------
    // Step 1 — Stop ShadowStrikePhantomService (10 %)
    // -----------------------------------------------------------------------
    PostProgress(hwnd, 0, L"Stopping ShadowStrikePhantomService\x2026");

    {
        std::wstring cmd = std::wstring(L"sc stop ") + kServiceName;
        DWORD rc = RunCommand(cmd, 30'000);
        // rc 0 = success, 1060 = service not exist, 1062 = not started — all acceptable
        if (rc != 0 && rc != 1060 && rc != 1062 && rc != MAXDWORD) {
            ::Sleep(3000); // give the service a moment to drain
        }
    }
    PostProgress(hwnd, 10, L"Service stopped.");

    // -----------------------------------------------------------------------
    // Step 2 — Delete ShadowStrikePhantomService registration (20 %)
    // -----------------------------------------------------------------------
    PostProgress(hwnd, 10, L"Removing service registration\x2026");

    {
        std::wstring cmd = std::wstring(L"sc delete ") + kServiceName;
        DWORD rc = RunCommand(cmd, 15'000);
        if (rc != 0 && rc != 1060) { // 1060 = service does not exist
            Fail(L"sc delete ShadowStrikePhantomService returned a non-zero exit code.");
        }
    }
    PostProgress(hwnd, 20, L"Service registration removed.");

    // -----------------------------------------------------------------------
    // Step 3 — Stop PhantomSensor kernel driver service (30 %)
    // -----------------------------------------------------------------------
    PostProgress(hwnd, 20, L"Stopping PhantomSensor kernel driver\x2026");

    {
        std::wstring cmd = std::wstring(L"sc stop ") + kDriverServiceName;
        DWORD rc = RunCommand(cmd, 30'000);
        if (rc != 0 && rc != 1060 && rc != 1062 && rc != MAXDWORD) {
            ::Sleep(2000);
        }
    }
    PostProgress(hwnd, 30, L"Driver service stopped.");

    // -----------------------------------------------------------------------
    // Step 4 — Delete PhantomSensor driver service entry (35 %)
    // -----------------------------------------------------------------------
    PostProgress(hwnd, 30, L"Removing driver service entry\x2026");

    {
        std::wstring cmd = std::wstring(L"sc delete ") + kDriverServiceName;
        DWORD rc = RunCommand(cmd, 15'000);
        if (rc != 0 && rc != 1060) {
            Fail(L"sc delete PhantomSensor returned a non-zero exit code.");
        }
    }
    PostProgress(hwnd, 35, L"Driver service entry removed.");

    // -----------------------------------------------------------------------
    // Step 5 — Remove driver from driver store via pnputil (50 %)
    // -----------------------------------------------------------------------
    PostProgress(hwnd, 35, L"Removing PhantomSensor from driver store\x2026");

    {
        // Use the published name saved during install (e.g. "oem78.inf").
        // pnputil /delete-driver requires the published name, not the original filename.
        // Fall back to the original name if the registry value is missing (fresh install
        // that predates the new installer).
        const std::wstring driverArg = publishedDriverName.empty()
                                       ? kDriverInf
                                       : publishedDriverName;
        std::wstring cmd = L"pnputil /delete-driver " + driverArg + L" /uninstall /force";
        DWORD rc = RunCommand(cmd, 60'000);
        // 0 = success, 259 (ERROR_NO_MORE_ITEMS) = driver not found in store
        if (rc != 0 && rc != 259 && rc != MAXDWORD) {
            Fail(L"pnputil /delete-driver reported an error. "
                 L"A reboot may be required to complete driver removal.");
        }
    }
    PostProgress(hwnd, 50, L"Driver removal requested.");

    // -----------------------------------------------------------------------
    // Step 6 — Remove signing certificate from trust stores (55 %)
    // -----------------------------------------------------------------------
    PostProgress(hwnd, 50, L"Removing driver signing certificate from trust stores\x2026");

    if (!certThumbprint.empty()) {
        if (!RemoveTrustedCert(certThumbprint)) {
            Fail(L"Could not fully remove the driver signing certificate from "
                 L"Root/TrustedPublisher stores. "
                 L"Manual removal via certmgr.msc (Local Computer) may be needed.");
        }
    }
    PostProgress(hwnd, 55, L"Certificate trust removed.");

    // -----------------------------------------------------------------------
    // Step 7 — Delete install directory (70 %)
    // -----------------------------------------------------------------------
    PostProgress(hwnd, 55, L"Deleting program files\x2026");

    if (::PathFileExistsW(kInstallDir)) {
        if (!DeleteDirectoryTree(kInstallDir)) {
            // Retry once — files might still be locked by the driver we just stopped
            ::Sleep(1000);
            if (!DeleteDirectoryTree(kInstallDir)) {
                Fail(L"Could not fully remove C:\\Program Files\\ShadowStrike\\. "
                     L"Some files may need manual deletion after reboot.");
            }
        }
    }
    PostProgress(hwnd, 70, L"Program files removed.");

    // -----------------------------------------------------------------------
    // Step 8 — Delete data directory (80 %)
    // -----------------------------------------------------------------------
    PostProgress(hwnd, 70, L"Deleting program data\x2026");

    if (::PathFileExistsW(kDataDir)) {
        if (!DeleteDirectoryTree(kDataDir)) {
            Fail(L"Could not fully remove C:\\ProgramData\\ShadowStrike\\. "
                 L"Some files may need manual deletion.");
        }
    }
    PostProgress(hwnd, 80, L"Program data removed.");

    // -----------------------------------------------------------------------
    // Step 9 — Remove HKLM\SOFTWARE\ShadowStrike (90 %)
    // -----------------------------------------------------------------------
    PostProgress(hwnd, 80, L"Removing registry keys\x2026");

    if (!RegDeleteKeyRecursive(HKEY_LOCAL_MACHINE, kRegKey)) {
        Fail(L"Could not fully remove HKLM\\SOFTWARE\\ShadowStrike. "
             L"Some registry keys may need manual deletion.");
    }
    PostProgress(hwnd, 90, L"Registry keys removed.");

    // -----------------------------------------------------------------------
    // Step 10 — Scrub PATH (100 %)
    // -----------------------------------------------------------------------
    PostProgress(hwnd, 90, L"Updating system PATH\x2026");

    ScrubSystemPath();
    PostProgress(hwnd, 100, L"Uninstall complete.");

    // -----------------------------------------------------------------------
    // Signal completion
    // -----------------------------------------------------------------------
    ::PostMessageW(hwnd, WM_WORKER_DONE,
                   static_cast<WPARAM>(partial ? 1 : 0), 0);
}

// ============================================================================
// Dialog procedures
// ============================================================================

// ---------------------------------------------------------------------------
// Step 1 — Welcome dialog
// ---------------------------------------------------------------------------

static INT_PTR CALLBACK WelcomeDlgProc(HWND hDlg, UINT msg,
                                        WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG:
        // Bold the header text via font replacement
        {
            HFONT hBase = reinterpret_cast<HFONT>(
                ::SendDlgItemMessageW(hDlg, IDC_WELCOME_HEADER, WM_GETFONT, 0, 0));

            LOGFONTW lf{};
            if (hBase && ::GetObjectW(hBase, sizeof(lf), &lf)) {
                lf.lfWeight = FW_BOLD;
                lf.lfHeight = static_cast<LONG>(lf.lfHeight * 1.2);
                HFONT hBold = ::CreateFontIndirectW(&lf);
                if (hBold)
                    ::SendDlgItemMessageW(hDlg, IDC_WELCOME_HEADER,
                                         WM_SETFONT,
                                         reinterpret_cast<WPARAM>(hBold), TRUE);
            }
        }
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_UNINSTALL:
            // User confirmed — proceed to progress dialog
            ::EndDialog(hDlg, IDOK);
            return TRUE;

        case IDC_BTN_CANCEL:
        case IDCANCEL:
            ::EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;

    case WM_CTLCOLORSTATIC:
        // Paint the header stripe background white
        {
            HWND hCtrl = reinterpret_cast<HWND>(lParam);
            int id = ::GetDlgCtrlID(hCtrl);
            if (id == IDC_WELCOME_HEADER) {
                HDC hdc = reinterpret_cast<HDC>(wParam);
                ::SetBkColor(hdc, RGB(0xFF, 0xFF, 0xFF));
                ::SetTextColor(hdc, RGB(0x00, 0x00, 0x00));
                return reinterpret_cast<INT_PTR>(::GetStockObject(WHITE_BRUSH));
            }
        }
        break;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Step 2 — Progress dialog
// ---------------------------------------------------------------------------

static INT_PTR CALLBACK ProgressDlgProc(HWND hDlg, UINT msg,
                                          WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG: {
        // Configure progress bar
        HWND hBar = ::GetDlgItem(hDlg, IDC_PROGRESS_BAR);
        ::SendMessageW(hBar, PBM_SETRANGE32, 0, 100);
        ::SendMessageW(hBar, PBM_SETSTEP, 1, 0);

        // Store dialog handle for the worker thread
        g_workerCtx.hwndProgress = hDlg;

        // Disable the close button — user must wait for completion
        HMENU hSys = ::GetSystemMenu(hDlg, FALSE);
        if (hSys) {
            ::EnableMenuItem(hSys, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
        }

        // Launch worker thread
        std::thread(UninstallWorker).detach();

        return TRUE;
    }

    case WM_WORKER_PROGRESS: {
        int percent = static_cast<int>(wParam);
        wchar_t* stepText = reinterpret_cast<wchar_t*>(lParam);

        // Update progress bar
        HWND hBar = ::GetDlgItem(hDlg, IDC_PROGRESS_BAR);
        ::SendMessageW(hBar, PBM_SETPOS, static_cast<WPARAM>(percent), 0);

        // Update detail label
        if (stepText) {
            ::SetDlgItemTextW(hDlg, IDC_PROGRESS_DETAIL, stepText);
            ::free(stepText);
        }
        return TRUE;
    }

    case WM_WORKER_DONE:
        // Worker finished — close the progress dialog and hand off to caller
        g_workerCtx.hwndProgress = nullptr;
        ::EndDialog(hDlg, static_cast<INT_PTR>(wParam)); // 0 = success, 1 = partial
        return TRUE;

    case WM_SYSCOMMAND:
        // Block Alt+F4 / close button while uninstall is in progress
        if ((wParam & 0xFFF0) == SC_CLOSE)
            return TRUE;
        break;

    case WM_CLOSE:
        // Silently ignore close attempts during uninstall
        return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Step 3 — Completion dialog
// ---------------------------------------------------------------------------

static INT_PTR CALLBACK CompleteDlgProc(HWND hDlg, UINT msg,
                                          WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG: {
        // lParam carries the "partial failure" flag (0 or 1)
        bool partialFail = (lParam != 0);

        if (partialFail) {
            ::SetDlgItemTextW(hDlg, IDC_COMPLETE_HEADER,
                              L"Uninstall Completed with Warnings");

            std::wstring body =
                L"ShadowStrike Phantom has been partially removed.\n\n"
                L"One or more steps could not be completed automatically:\n\n";
            body += g_workerCtx.errorSummary;
            body += L"\n\nA system restart may be required to finish removal.";

            ::SetDlgItemTextW(hDlg, IDC_COMPLETE_BODY, body.c_str());
        } else {
            ::SetDlgItemTextW(hDlg, IDC_COMPLETE_HEADER,
                              L"Uninstall Complete");
            ::SetDlgItemTextW(hDlg, IDC_COMPLETE_BODY,
                              L"ShadowStrike Phantom has been successfully removed "
                              L"from this computer.\n\n"
                              L"Thank you for using ShadowStrike.");
        }

        // Bold the header
        HFONT hBase = reinterpret_cast<HFONT>(
            ::SendDlgItemMessageW(hDlg, IDC_COMPLETE_HEADER, WM_GETFONT, 0, 0));
        LOGFONTW lf{};
        if (hBase && ::GetObjectW(hBase, sizeof(lf), &lf)) {
            lf.lfWeight = FW_BOLD;
            lf.lfHeight = static_cast<LONG>(lf.lfHeight * 1.2);
            HFONT hBold = ::CreateFontIndirectW(&lf);
            if (hBold)
                ::SendDlgItemMessageW(hDlg, IDC_COMPLETE_HEADER,
                                     WM_SETFONT,
                                     reinterpret_cast<WPARAM>(hBold), TRUE);
        }
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_FINISH:
        case IDOK:
        case IDCANCEL:
            ::EndDialog(hDlg, IDOK);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

// ============================================================================
// WinMain
// ============================================================================

int APIENTRY wWinMain(
    _In_     HINSTANCE hInstance,
    _In_opt_ HINSTANCE /*hPrevInstance*/,
    _In_     LPWSTR    /*lpCmdLine*/,
    _In_     int       /*nCmdShow*/)
{
    g_hInstance = hInstance;

    // -----------------------------------------------------------------------
    // NOTE: Command-line arguments are intentionally NOT parsed.
    //
    // This uninstaller provides NO silent, /quiet, /q, /headless, or any
    // other flag that would skip the interactive dialog flow.  Any argument
    // present in lpCmdLine is silently ignored.  The mandatory user-click on
    // the Welcome dialog (Step 1) is the only way to proceed.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Interactive session guard
    // -----------------------------------------------------------------------
    if (!IsInteractiveSession()) {
        // We cannot show a dialog in a non-interactive session.
        // Abort silently (no MessageBox either — it may deadlock in session 0).
        return 2;
    }

    // -----------------------------------------------------------------------
    // Elevation guard (belt-and-suspenders; manifest already demands admin)
    // -----------------------------------------------------------------------
    if (!IsRunningElevated()) {
        ::MessageBoxW(nullptr,
                      L"ShadowStrike Phantom Uninstaller requires administrator "
                      L"privileges.\n\nPlease right-click the uninstaller and "
                      L"choose \"Run as administrator\".",
                      L"ShadowStrike Phantom Uninstaller",
                      MB_OK | MB_ICONERROR);
        return 1;
    }

    // -----------------------------------------------------------------------
    // Initialise common controls (progress bar, visual styles)
    // -----------------------------------------------------------------------
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    ::InitCommonControlsEx(&icc);

    // -----------------------------------------------------------------------
    // Step 1 — Welcome / confirmation dialog
    // -----------------------------------------------------------------------
    INT_PTR welcomeResult = ::DialogBoxParamW(
        hInstance,
        MAKEINTRESOURCEW(IDD_WELCOME),
        nullptr,
        WelcomeDlgProc,
        0);

    if (welcomeResult != IDOK) {
        // User cancelled — exit cleanly without touching anything
        return 0;
    }

    // -----------------------------------------------------------------------
    // Step 2 — Progress dialog (launches worker thread internally)
    // -----------------------------------------------------------------------
    INT_PTR progressResult = ::DialogBoxParamW(
        hInstance,
        MAKEINTRESOURCEW(IDD_PROGRESS),
        nullptr,
        ProgressDlgProc,
        0);

    // progressResult: 0 = fully successful, 1 = partial failure
    bool partialFailure = (progressResult != 0);

    // -----------------------------------------------------------------------
    // Step 3 — Completion dialog
    // -----------------------------------------------------------------------
    ::DialogBoxParamW(
        hInstance,
        MAKEINTRESOURCEW(IDD_COMPLETE),
        nullptr,
        CompleteDlgProc,
        static_cast<LPARAM>(partialFailure ? 1 : 0));

    return partialFailure ? 1 : 0;
}
