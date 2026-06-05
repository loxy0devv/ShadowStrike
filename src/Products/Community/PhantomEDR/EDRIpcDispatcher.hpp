/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * EDRIpcDispatcher — installs EDR-specific IPC command handlers (500–519).
 * Requires SharedIpcDispatcher to be installed first.
 *
 * Commands handled here are gated by FeatureCategory::ForensicsAdvanced.
 * Any command requiring EDR tier sends an error if the feature is not enabled.
 */
#pragma once
#include <memory>
namespace ShadowStrike::Service { class ServiceCommunicator; }
namespace ShadowStrike::Products::PhantomEDR {

class EDRIpcDispatcher final {
public:
    [[nodiscard]] static EDRIpcDispatcher& Instance();
    void Install(Service::ServiceCommunicator& svc);
    void Uninstall(Service::ServiceCommunicator& svc);
    EDRIpcDispatcher(const EDRIpcDispatcher&) = delete;
    EDRIpcDispatcher& operator=(const EDRIpcDispatcher&) = delete;
private:
    EDRIpcDispatcher();
    ~EDRIpcDispatcher();
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR
