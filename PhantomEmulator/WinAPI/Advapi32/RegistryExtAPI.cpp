/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RegistryExtAPI.cpp — Advapi32 advanced registry API handler implementations
 *
 * Covers RegQueryInfoKeyA/W, RegSaveKeyA/W, RegLoadKeyA/W,
 * RegUnLoadKeyA/W, RegNotifyChangeKeyValue, RegRestoreKeyA/W,
 * RegOpenKeyA/W, RegConnectRegistryA/W, RegGetValueA/W,
 * RegCopyTreeA/W, RegDeleteTreeA/W, RegDeleteKeyValueA/W.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma warning(disable : 4834)
#include "RegistryExtAPI.hpp"
#include "../APIDispatcher.hpp"

namespace Phantom::WinAPI::Advapi32 {

static constexpr uint32_t ERROR_SUCCESS           = 0;
static constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
static constexpr uint32_t ERROR_NOT_SUPPORTED     = 50;

// ============================================================================
// RegQueryInfoKeyA/W — return zeroed key metadata
// ============================================================================

static bool RegQueryInfoKeyImpl(APIContext& ctx, bool /*isWide*/) {
    GuestAddress lpcSubKeys       = ctx.GetArgPtr(2);
    GuestAddress lpcMaxSubKeyLen  = ctx.GetArgPtr(3);
    GuestAddress lpcMaxClassLen   = ctx.GetArgPtr(4);
    GuestAddress lpcValues        = ctx.GetArgPtr(5);
    GuestAddress lpcMaxValueNameLen = ctx.GetArgPtr(6);
    GuestAddress lpcMaxValueLen   = ctx.GetArgPtr(7);
    GuestAddress lpcbSecurityDesc = ctx.GetArgPtr(8);
    GuestAddress lpftLastWriteTime = ctx.GetArgPtr(9);

    if (lpcSubKeys)         ctx.Memory().WriteU32(lpcSubKeys, 0);
    if (lpcMaxSubKeyLen)    ctx.Memory().WriteU32(lpcMaxSubKeyLen, 0);
    if (lpcMaxClassLen)     ctx.Memory().WriteU32(lpcMaxClassLen, 0);
    if (lpcValues)          ctx.Memory().WriteU32(lpcValues, 0);
    if (lpcMaxValueNameLen) ctx.Memory().WriteU32(lpcMaxValueNameLen, 0);
    if (lpcMaxValueLen)     ctx.Memory().WriteU32(lpcMaxValueLen, 0);
    if (lpcbSecurityDesc)   ctx.Memory().WriteU32(lpcbSecurityDesc, 0);
    if (lpftLastWriteTime)  ctx.Memory().WriteU64(lpftLastWriteTime, 0);

    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

bool HandleRegQueryInfoKeyA(APIContext& ctx) { return RegQueryInfoKeyImpl(ctx, false); }
bool HandleRegQueryInfoKeyW(APIContext& ctx) { return RegQueryInfoKeyImpl(ctx, true); }

// ============================================================================
// RegSaveKeyA/W — no-op (hive export suppressed in emulation)
// ============================================================================

bool HandleRegSaveKeyA(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}
bool HandleRegSaveKeyW(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// RegLoadKeyA/W — no-op
// ============================================================================

bool HandleRegLoadKeyA(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}
bool HandleRegLoadKeyW(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// RegUnLoadKeyA/W — no-op
// ============================================================================

bool HandleRegUnLoadKeyA(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}
bool HandleRegUnLoadKeyW(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// RegNotifyChangeKeyValue — no-op (always succeeds, no actual notification)
// ============================================================================

bool HandleRegNotifyChangeKeyValue(APIContext& ctx) {
    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// RegRestoreKeyA/W — no-op
// ============================================================================

bool HandleRegRestoreKeyA(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}
bool HandleRegRestoreKeyW(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// RegOpenKeyA/W — forward to RegOpenKeyEx with default access
// ============================================================================

bool HandleRegOpenKeyA(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}
bool HandleRegOpenKeyW(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// RegConnectRegistryA/W — remote registry not supported in emulation
// ============================================================================

bool HandleRegConnectRegistryA(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}
bool HandleRegConnectRegistryW(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// RegGetValueA/W — simplified version returning not-found
// ============================================================================

bool HandleRegGetValueA(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}
bool HandleRegGetValueW(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// RegCopyTreeA/W — no-op
// ============================================================================

bool HandleRegCopyTreeA(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}
bool HandleRegCopyTreeW(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// RegDeleteTreeA/W — no-op
// ============================================================================

bool HandleRegDeleteTreeA(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}
bool HandleRegDeleteTreeW(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// RegDeleteKeyValueA/W — no-op
// ============================================================================

bool HandleRegDeleteKeyValueA(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}
bool HandleRegDeleteKeyValueW(APIContext& ctx) {
    ctx.SetReturn32(ERROR_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterRegistryExtAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "advapi32.dll", "RegQueryInfoKeyA",         HandleRegQueryInfoKeyA,         11, false },
        { "advapi32.dll", "RegQueryInfoKeyW",         HandleRegQueryInfoKeyW,         11, false },
        { "advapi32.dll", "RegSaveKeyA",              HandleRegSaveKeyA,              3,  false },
        { "advapi32.dll", "RegSaveKeyW",              HandleRegSaveKeyW,              3,  false },
        { "advapi32.dll", "RegLoadKeyA",              HandleRegLoadKeyA,              3,  false },
        { "advapi32.dll", "RegLoadKeyW",              HandleRegLoadKeyW,              3,  false },
        { "advapi32.dll", "RegUnLoadKeyA",            HandleRegUnLoadKeyA,            2,  false },
        { "advapi32.dll", "RegUnLoadKeyW",            HandleRegUnLoadKeyW,            2,  false },
        { "advapi32.dll", "RegNotifyChangeKeyValue",  HandleRegNotifyChangeKeyValue,  6,  false },
        { "advapi32.dll", "RegRestoreKeyA",           HandleRegRestoreKeyA,           3,  false },
        { "advapi32.dll", "RegRestoreKeyW",           HandleRegRestoreKeyW,           3,  false },
        { "advapi32.dll", "RegOpenKeyA",              HandleRegOpenKeyA,              3,  false },
        { "advapi32.dll", "RegOpenKeyW",              HandleRegOpenKeyW,              3,  false },
        { "advapi32.dll", "RegConnectRegistryA",      HandleRegConnectRegistryA,      3,  false },
        { "advapi32.dll", "RegConnectRegistryW",      HandleRegConnectRegistryW,      3,  false },
        { "advapi32.dll", "RegGetValueA",             HandleRegGetValueA,             8,  false },
        { "advapi32.dll", "RegGetValueW",             HandleRegGetValueW,             8,  false },
        { "advapi32.dll", "RegCopyTreeA",             HandleRegCopyTreeA,             3,  false },
        { "advapi32.dll", "RegCopyTreeW",             HandleRegCopyTreeW,             3,  false },
        { "advapi32.dll", "RegDeleteTreeA",           HandleRegDeleteTreeA,           2,  false },
        { "advapi32.dll", "RegDeleteTreeW",           HandleRegDeleteTreeW,           2,  false },
        { "advapi32.dll", "RegDeleteKeyValueA",       HandleRegDeleteKeyValueA,       3,  false },
        { "advapi32.dll", "RegDeleteKeyValueW",       HandleRegDeleteKeyValueW,       3,  false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Advapi32
