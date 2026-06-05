/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ServiceExtAPI.cpp — Advapi32 extended Service Control Manager API handler implementations
 *
 * Covers ChangeServiceConfigA/W, ChangeServiceConfig2A/W,
 * EnumServicesStatusA/W, EnumServicesStatusExA/W,
 * QueryServiceStatusEx, QueryServiceConfigA/W,
 * GetServiceDisplayNameA/W, GetServiceKeyNameA/W,
 * ControlService, StartServiceCtrlDispatcherA/W,
 * RegisterServiceCtrlHandlerExA/W, SetServiceStatus.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma warning(disable : 4834)
#include "ServiceExtAPI.hpp"
#include "../APIDispatcher.hpp"

namespace Phantom::WinAPI::Advapi32 {

static constexpr uint32_t ERROR_SUCCESS           = 0;
static constexpr uint32_t ERROR_NOT_SUPPORTED     = 50;
static constexpr uint32_t ERROR_INVALID_HANDLE    = 6;

// ============================================================================
// ChangeServiceConfigA/W — accept silently
// ============================================================================

bool HandleChangeServiceConfigA(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}
bool HandleChangeServiceConfigW(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// ChangeServiceConfig2A/W — accept silently
// ============================================================================

bool HandleChangeServiceConfig2A(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}
bool HandleChangeServiceConfig2W(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// EnumServicesStatusA/W — return empty list
// ============================================================================

static bool EnumServicesStatusImpl(APIContext& ctx, bool /*isWide*/) {
    GuestAddress pcbBytesNeeded = ctx.GetArgPtr(4);
    GuestAddress lpServicesReturned = ctx.GetArgPtr(5);

    if (lpServicesReturned) ctx.Memory().WriteU32(lpServicesReturned, 0);
    if (pcbBytesNeeded)     ctx.Memory().WriteU32(pcbBytesNeeded, 0);

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleEnumServicesStatusA(APIContext& ctx) { return EnumServicesStatusImpl(ctx, false); }
bool HandleEnumServicesStatusW(APIContext& ctx) { return EnumServicesStatusImpl(ctx, true); }

// ============================================================================
// EnumServicesStatusExA/W — return empty list
// ============================================================================

bool HandleEnumServicesStatusExA(APIContext& ctx) { return EnumServicesStatusImpl(ctx, false); }
bool HandleEnumServicesStatusExW(APIContext& ctx) { return EnumServicesStatusImpl(ctx, true); }

// ============================================================================
// QueryServiceStatusEx — return a running SERVICE_STATUS_PROCESS
// ============================================================================

bool HandleQueryServiceStatusEx(APIContext& ctx) {
    GuestAddress lpBuffer  = ctx.GetArgPtr(2);
    uint32_t     cbBufSize = ctx.GetArg32(3);
    GuestAddress pcbNeeded = ctx.GetArgPtr(4);

    // Minimum size of SERVICE_STATUS_PROCESS = 36 bytes
    static constexpr uint32_t kStatusSize = 36;

    if (pcbNeeded) ctx.Memory().WriteU32(pcbNeeded, kStatusSize);

    if (lpBuffer != 0 && cbBufSize >= kStatusSize) {
        // dwServiceType = SERVICE_WIN32_OWN_PROCESS (0x10)
        ctx.Memory().WriteU32(lpBuffer + 0,  0x10);
        // dwCurrentState = SERVICE_RUNNING (0x4)
        ctx.Memory().WriteU32(lpBuffer + 4,  0x4);
        // dwControlsAccepted = SERVICE_ACCEPT_STOP
        ctx.Memory().WriteU32(lpBuffer + 8,  0x1);
        // dwWin32ExitCode = 0
        ctx.Memory().WriteU32(lpBuffer + 12, 0);
        // dwServiceSpecificExitCode = 0
        ctx.Memory().WriteU32(lpBuffer + 16, 0);
        // dwCheckPoint = 0
        ctx.Memory().WriteU32(lpBuffer + 20, 0);
        // dwWaitHint = 0
        ctx.Memory().WriteU32(lpBuffer + 24, 0);
        // dwProcessId = 0
        ctx.Memory().WriteU32(lpBuffer + 28, 0);
        // dwServiceFlags = 0
        ctx.Memory().WriteU32(lpBuffer + 32, 0);
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// QueryServiceConfigA/W — return minimal config
// ============================================================================

bool HandleQueryServiceConfigA(APIContext& ctx) {
    GuestAddress pcbBytesNeeded = ctx.GetArgPtr(3);
    if (pcbBytesNeeded) ctx.Memory().WriteU32(pcbBytesNeeded, 0);
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}
bool HandleQueryServiceConfigW(APIContext& ctx) {
    GuestAddress pcbBytesNeeded = ctx.GetArgPtr(3);
    if (pcbBytesNeeded) ctx.Memory().WriteU32(pcbBytesNeeded, 0);
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// GetServiceDisplayNameA/W — return empty string
// ============================================================================

bool HandleGetServiceDisplayNameA(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}
bool HandleGetServiceDisplayNameW(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// GetServiceKeyNameA/W — return empty string
// ============================================================================

bool HandleGetServiceKeyNameA(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}
bool HandleGetServiceKeyNameW(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// ControlService — accept all control codes
// ============================================================================

bool HandleControlService(APIContext& ctx) {
    GuestAddress lpServiceStatus = ctx.GetArgPtr(2);
    if (lpServiceStatus != 0) {
        // Write SERVICE_STATUS: type=0x10, state=SERVICE_STOPPED(0x1), rest=0
        for (int i = 0; i < 7; ++i) {
            ctx.Memory().WriteU32(lpServiceStatus + static_cast<uint32_t>(i * 4), i == 0 ? 0x10u : 0u);
        }
    }
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// StartServiceCtrlDispatcherA/W — no-op (we are not a service process)
// ============================================================================

bool HandleStartServiceCtrlDispatcherA(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}
bool HandleStartServiceCtrlDispatcherW(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// RegisterServiceCtrlHandlerExA/W — return a fake handler handle
// ============================================================================

bool HandleRegisterServiceCtrlHandlerExA(APIContext& ctx) {
    ctx.SetReturnHandle(1);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}
bool HandleRegisterServiceCtrlHandlerExW(APIContext& ctx) {
    ctx.SetReturnHandle(1);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// SetServiceStatus — no-op
// ============================================================================

bool HandleSetServiceStatus(APIContext& ctx) {
    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterServiceExtAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "advapi32.dll", "ChangeServiceConfigA",            HandleChangeServiceConfigA,            11, false },
        { "advapi32.dll", "ChangeServiceConfigW",            HandleChangeServiceConfigW,            11, false },
        { "advapi32.dll", "ChangeServiceConfig2A",           HandleChangeServiceConfig2A,           3,  false },
        { "advapi32.dll", "ChangeServiceConfig2W",           HandleChangeServiceConfig2W,           3,  false },
        { "advapi32.dll", "EnumServicesStatusA",             HandleEnumServicesStatusA,             7,  false },
        { "advapi32.dll", "EnumServicesStatusW",             HandleEnumServicesStatusW,             7,  false },
        { "advapi32.dll", "EnumServicesStatusExA",           HandleEnumServicesStatusExA,           8,  false },
        { "advapi32.dll", "EnumServicesStatusExW",           HandleEnumServicesStatusExW,           8,  false },
        { "advapi32.dll", "QueryServiceStatusEx",            HandleQueryServiceStatusEx,            5,  false },
        { "advapi32.dll", "QueryServiceConfigA",             HandleQueryServiceConfigA,             4,  false },
        { "advapi32.dll", "QueryServiceConfigW",             HandleQueryServiceConfigW,             4,  false },
        { "advapi32.dll", "GetServiceDisplayNameA",          HandleGetServiceDisplayNameA,          4,  false },
        { "advapi32.dll", "GetServiceDisplayNameW",          HandleGetServiceDisplayNameW,          4,  false },
        { "advapi32.dll", "GetServiceKeyNameA",              HandleGetServiceKeyNameA,              4,  false },
        { "advapi32.dll", "GetServiceKeyNameW",              HandleGetServiceKeyNameW,              4,  false },
        { "advapi32.dll", "ControlService",                  HandleControlService,                  3,  false },
        { "advapi32.dll", "StartServiceCtrlDispatcherA",     HandleStartServiceCtrlDispatcherA,     1,  false },
        { "advapi32.dll", "StartServiceCtrlDispatcherW",     HandleStartServiceCtrlDispatcherW,     1,  false },
        { "advapi32.dll", "RegisterServiceCtrlHandlerExA",   HandleRegisterServiceCtrlHandlerExA,   3,  false },
        { "advapi32.dll", "RegisterServiceCtrlHandlerExW",   HandleRegisterServiceCtrlHandlerExW,   3,  false },
        { "advapi32.dll", "SetServiceStatus",                HandleSetServiceStatus,                2,  false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Advapi32
