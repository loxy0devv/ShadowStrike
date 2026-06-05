/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "pch.h"
#include "TierSelector.hpp"

#include "PhantomCore/Service/ProductExtensions.hpp"
#include "PhantomCore/Config/ProductTier.hpp"
#include "PhantomCore/Config/ConfigManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "Products/Community/PhantomHome/HomeProductOrchestrator.hpp"
#include "Products/Community/PhantomEDR/EDRProductOrchestrator.hpp"
#include "Products/Community/PhantomXDR/XDRProductOrchestrator.hpp"
#include "Products/Community/PhantomXDR/XDRProductEntry.hpp"

#include <format>

namespace ShadowStrike::Products::Shared {

using ShadowStrike::Utils::Logger;
using ShadowStrike::Service::ProductExtensions;
using ShadowStrike::Config::ProductTierManager;
using ShadowStrike::Config::ProductTier;
using ShadowStrike::Config::FeatureCategory;

static constexpr std::string_view kLog = "[TierSelector]";

TierSelector& TierSelector::Instance() noexcept {
    static TierSelector s;
    return s;
}

bool TierSelector::Select() noexcept {
    try {
        // Step 1: compile-time identity (set by vcxproj preprocessor)
        ProductMode requested = DetectCompiletimeMode();
        m_result.reason = std::format("compile-time={}", ToString(requested));

        // Step 2: runtime config override
        ProductMode cfgOverride = ReadConfigOverride();
        if (cfgOverride != ProductMode::Unknown && cfgOverride > requested) {
            requested = cfgOverride;
            m_result.reason += std::format("+config={}", ToString(requested));
        }

        // Step 3: enforce license floor — cannot activate features above license tier
        ProductMode final = ApplyLicenseFloor(requested);
        if (final != requested) {
            m_result.reason += std::format("+license-floor={}", ToString(final));
        }

        m_result.mode = final;
        m_result.productName = std::string(ToString(final));

        Logger::Info("{} Selected product mode: {} ({})",
                     kLog, m_result.productName, m_result.reason);

        // Step 4: register the tier's orchestrator as the ProductExtensions callback
        if (!RegisterCallbacks(final)) {
            Logger::Error("{} Failed to register callbacks for mode {}", kLog, m_result.productName);
            return false;
        }

        m_result.selected = true;
        return true;

    } catch (const std::exception& e) {
        Logger::Error("{} Exception during selection: {}", kLog, e.what());
        return false;
    } catch (...) {
        Logger::Error("{} Unknown exception during selection", kLog);
        return false;
    }
}

ProductMode TierSelector::DetectCompiletimeMode() const noexcept {
#if defined(SS_PRODUCT_XDR)
    return ProductMode::XDR;
#elif defined(SS_PRODUCT_EDR)
    return ProductMode::EDR;
#elif defined(SS_PRODUCT_HOME)
    return ProductMode::Home;
#else
    // Default: if no product macro defined, treat as Home (safest default)
    return ProductMode::Home;
#endif
}

ProductMode TierSelector::ReadConfigOverride() const noexcept {
    try {
        auto& cfg = Config::ConfigManager::Instance();
        std::wstring mode = cfg.GetValue<std::wstring>(L"Product/Mode", L"");
        if (mode == L"XDR") return ProductMode::XDR;
        if (mode == L"EDR") return ProductMode::EDR;
        if (mode == L"Home") return ProductMode::Home;
    } catch (...) {}
    return ProductMode::Unknown;
}

ProductMode TierSelector::ApplyLicenseFloor(ProductMode requested) const noexcept {
    try {
        auto& tm = ProductTierManager::Instance();
        // XDR requires Enterprise tier
        if (requested == ProductMode::XDR &&
            !tm.IsFeatureEnabled(FeatureCategory::XDRCorrelation)) {
            Logger::Warn("{} License does not permit XDR — downgrading to EDR", kLog);
            requested = ProductMode::EDR;
        }
        // EDR requires at minimum Professional tier features
        if (requested == ProductMode::EDR &&
            !tm.IsFeatureEnabled(FeatureCategory::ForensicsAdvanced)) {
            Logger::Warn("{} License does not permit full EDR — running Home mode", kLog);
            requested = ProductMode::Home;
        }
    } catch (...) {}
    return requested;
}

bool TierSelector::RegisterCallbacks(ProductMode mode) noexcept {
    auto& ext = ProductExtensions::Instance();

    switch (mode) {
        case ProductMode::Home: {
            ext.SetProductEntry(
                "PhantomHome",
                []() noexcept -> bool {
                    try {
                        auto& orch = ::ShadowStrike::Products::Home::HomeProductOrchestrator::Instance();
                        return orch.Initialize() && orch.Start();
                    } catch (...) { return false; }
                },
                []() noexcept {
                    try {
                        ::ShadowStrike::Products::Home::HomeProductOrchestrator::Instance().Shutdown();
                    } catch (...) {}
                });
            return true;
        }

        case ProductMode::EDR: {
            ext.SetProductEntry(
                "PhantomEDR",
                []() noexcept -> bool {
                    try {
                        return ::ShadowStrike::Products::PhantomEDR::RegisterEDRModules();
                    } catch (...) { return false; }
                },
                []() noexcept {
                    try {
                        ::ShadowStrike::Products::PhantomEDR::EDRProductOrchestrator::Instance().Shutdown();
                    } catch (...) {}
                });
            return true;
        }

        case ProductMode::XDR: {
            ext.SetProductEntry(
                "PhantomXDR",
                []() noexcept -> bool {
                    try {
                        return ::ShadowStrike::Products::PhantomXDR::BootXDRProduct();
                    } catch (...) { return false; }
                },
                []() noexcept {
                    try {
                        ::ShadowStrike::Products::PhantomXDR::ShutdownXDRProduct();
                    } catch (...) {}
                });
            return true;
        }

        default:
            Logger::Error("{} Unknown product mode — cannot register callbacks", kLog);
            return false;
    }
}

} // namespace ShadowStrike::Products::Shared
