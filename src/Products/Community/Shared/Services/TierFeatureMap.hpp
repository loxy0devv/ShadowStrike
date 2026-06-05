/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * TierFeatureMap — compile-time table of which features are active per tier.
 *
 * This table is the single source of truth for what each product mode
 * can and cannot do. It is evaluated at startup to populate
 * ProductTierManager's pre-computed boolean array.
 *
 * Column semantics:
 *   Home    — PhantomHome (consumer endpoint, single user, local GUI)
 *   EDR     — PhantomEDR (enterprise endpoint, fleet, remote response)
 *   XDR     — PhantomXDR (extended: cross-domain, SIEM/SOAR, identity)
 *
 * A feature marked false in a tier is gated by ProductTierManager::IsFeatureEnabled.
 * The REST API, config manager, and product orchestrators all call this gate.
 * Never bypass it with direct capability checks.
 */

#pragma once

#include "PhantomCore/Config/ProductTier.hpp"
#include "Products/Community/Shared/TierBoot/TierSelector.hpp"

#include <array>
#include <initializer_list>

namespace ShadowStrike::Products::Shared {

using ShadowStrike::Config::FeatureCategory;
using ShadowStrike::Config::ProductTier;

/// One row per FeatureCategory.
struct FeatureRow {
    FeatureCategory category;
    bool    home;   ///< Enabled in PhantomHome
    bool    edr;    ///< Enabled in PhantomEDR
    bool    xdr;    ///< Enabled in PhantomXDR (superset of EDR)
    const char* displayName;
    const char* description;
};

/// The master feature availability table.
/// Order matches FeatureCategory enum — keep in sync.
inline constexpr std::array<FeatureRow, 18> kTierFeatureMap{{
    // Category                   Home   EDR    XDR    Name                  Description
    { FeatureCategory::Core,              true,  true,  true,  "Core Protection",       "Real-time scan, behavioral analysis, AI inference" },
    { FeatureCategory::HomeProtection,    true,  false, false, "Home Protection",        "Banking, email, USB, IoT, privacy, gaming safeguards" },
    { FeatureCategory::ForensicsBasic,    true,  true,  true,  "Basic Forensics",        "Timeline, artifact extraction, process tree" },
    { FeatureCategory::ForensicsAdvanced, false, true,  true,  "Advanced Forensics",     "Memory dump, network capture, full evidence collection" },
    { FeatureCategory::ThreatIntel,       true,  true,  true,  "Threat Intelligence",    "Public threat feeds, basic IOC matching" },
    { FeatureCategory::ThreatIntelAdvanced, false, true, true, "Advanced Threat Intel",  "Priority feeds, ATT&CK enrichment, advanced IOC management" },
    { FeatureCategory::Dashboard,         true,  true,  true,  "Local Dashboard",        "Localhost REST API and web dashboard" },
    { FeatureCategory::CloudConsole,      false, true,  true,  "Cloud Console",          "Remote management console, fleet telemetry" },
    { FeatureCategory::FleetManagement,   false, true,  true,  "Fleet Management",       "Multi-endpoint management, policy deployment" },
    { FeatureCategory::RemoteActions,     false, true,  true,  "Remote Actions",         "Remote scan, quarantine, isolate, response" },
    { FeatureCategory::SIEMIntegration,   false, false, true,  "SIEM Integration",       "Splunk, Elastic, Microsoft Sentinel, QRadar connectors" },
    { FeatureCategory::SOARIntegration,   false, false, true,  "SOAR Integration",       "Playbook triggers, enrichment pipelines, automated response" },
    { FeatureCategory::ComplianceReporting, false, false, true, "Compliance Reporting",  "PCI-DSS, HIPAA, SOC2, ISO27001, NIST templates" },
    { FeatureCategory::CustomRules,       false, true,  true,  "Custom Detection Rules", "Native rule editor, Sigma import, custom rule testing" },
    { FeatureCategory::RBAC,              false, false, true,  "RBAC + SSO",             "Role-based access control, SAML/OIDC SSO" },
    { FeatureCategory::XDRCorrelation,    false, false, true,  "XDR Correlation",        "Cross-domain storylines, multi-source attack chain" },
    { FeatureCategory::CloudTelemetry,    false, false, true,  "Cloud Telemetry",        "Cloud workload telemetry aggregation" },
    { FeatureCategory::KernelProtection,  true,  true,  true,  "Kernel Protection",      "Signed minifilter driver, kernel-mode detection" },
}};

/// Apply the feature map for a given product mode to a ProductTierManager.
/// Called during TierSelector::Select() after the manager is initialized.
inline void ApplyTierFeatureMap(ProductMode mode) {
    auto& tm = ShadowStrike::Config::ProductTierManager::Instance();
    for (const auto& row : kTierFeatureMap) {
        bool enabled = false;
        switch (mode) {
            case ProductMode::Home: enabled = row.home; break;
            case ProductMode::EDR:  enabled = row.edr;  break;
            case ProductMode::XDR:  enabled = row.xdr;  break;
            default: enabled = false; break;
        }
        tm.SetFeatureOverride(row.category, enabled);
    }
}

/// Returns the minimal ProductTier constant that corresponds to a ProductMode.
/// Used to initialize ProductTierManager's license tier level.
inline constexpr ProductTier ModeToLicenseTier(ProductMode mode) noexcept {
    switch (mode) {
        case ProductMode::Home: return ProductTier::Community;
        case ProductMode::EDR:  return ProductTier::Professional;
        case ProductMode::XDR:  return ProductTier::Enterprise;
        default:                return ProductTier::Community;
    }
}

} // namespace ShadowStrike::Products::Shared
