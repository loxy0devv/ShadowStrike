/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * SharedIpcDispatcher — command handlers that every product tier exposes
 * through the native Named Pipe IPC channel.
 *
 * Security model:
 *   - Every handler (except AuthHandshake) checks IsClientAuthenticated()
 *     using the caller's IpcAuthToken before executing.
 *   - All destructive commands (Kill, Isolate, Block) additionally verify
 *     the caller's Windows token integrity level is >= High.
 *   - No plaintext secrets pass through any handler; JSON payloads are
 *     depth/node validated before field extraction.
 *
 * Tier scope:
 *   This dispatcher installs all handlers in the 300–499 and 540–559 command
 *   ranges that are available in ALL tiers (Home, EDR, XDR). EDR- and
 *   XDR-specific handlers (500–539) live in their respective dispatchers.
 *
 * Usage:
 *   SharedIpcDispatcher::Instance().Install(ServiceCommunicator::Instance());
 */

#pragma once

#include <memory>

namespace ShadowStrike::Service { class ServiceCommunicator; }

namespace ShadowStrike::Products::Shared {

class SharedIpcDispatcher final {
public:
    [[nodiscard]] static SharedIpcDispatcher& Instance();

    /// Install all shared command handlers into @p svc.
    void Install(Service::ServiceCommunicator& svc);

    /// Replace all installed handlers with no-ops (call before Stop()).
    void Uninstall(Service::ServiceCommunicator& svc);

    SharedIpcDispatcher(const SharedIpcDispatcher&)            = delete;
    SharedIpcDispatcher& operator=(const SharedIpcDispatcher&) = delete;

private:
    SharedIpcDispatcher();
    ~SharedIpcDispatcher();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::Products::Shared
