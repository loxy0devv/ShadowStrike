/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * TierSelector — determines which product mode (Home / EDR / XDR) to activate
 * at service startup, then registers the correct ProductExtensions callback.
 *
 * Decision order:
 *   1. Compile-time binary identity (SS_PRODUCT_HOME / SS_PRODUCT_EDR / SS_PRODUCT_XDR
 *      preprocessor constants set by the vcxproj per binary)
 *   2. Runtime override via the "Product/Mode" config key (allows field upgrade without
 *      binary swap — EDR key unlocks XDR features on an EDR binary)
 *   3. License file tier floor (Community licenses cannot run XDR)
 *
 * After selection, TierSelector calls ProductExtensions::SetProductEntry() with
 * the appropriate orchestrator init/shutdown callbacks, then optionally starts the
 * REST API server at the tier-appropriate endpoint set.
 *
 * Thread-safety: Select() must be called once from the main thread before any other
 * threads are created. All other methods are read-only after selection.
 */

#pragma once

#include <string>
#include <string_view>

namespace ShadowStrike {
namespace Products {
namespace Shared {

enum class ProductMode : uint8_t {
    Unknown = 0,
    Home    = 1,   ///< PhantomHome — consumer endpoint, local UI
    EDR     = 2,   ///< PhantomEDR — enterprise endpoint detection & response
    XDR     = 3,   ///< PhantomXDR — extended detection & response, fleet-level
};

struct TierSelectionResult {
    ProductMode mode      = ProductMode::Unknown;
    bool        selected  = false;
    std::string productName;
    std::string reason;     ///< Why this mode was chosen (for boot trace)
};

class TierSelector {
public:
    [[nodiscard]] static TierSelector& Instance() noexcept;

    /// Detect the correct product mode and register ProductExtensions callbacks.
    /// Must be called before AntivirusService::Initialize().
    /// @return false if no valid tier could be determined (service should abort).
    [[nodiscard]] bool Select() noexcept;

    [[nodiscard]] ProductMode GetMode() const noexcept { return m_result.mode; }
    [[nodiscard]] std::string_view GetProductName() const noexcept { return m_result.productName; }
    [[nodiscard]] bool IsSelected() const noexcept { return m_result.selected; }
    [[nodiscard]] const TierSelectionResult& Result() const noexcept { return m_result; }

    TierSelector(const TierSelector&)            = delete;
    TierSelector& operator=(const TierSelector&) = delete;

private:
    TierSelector()  = default;
    ~TierSelector() = default;

    [[nodiscard]] ProductMode DetectCompiletimeMode() const noexcept;
    [[nodiscard]] ProductMode ReadConfigOverride() const noexcept;
    [[nodiscard]] ProductMode ApplyLicenseFloor(ProductMode requested) const noexcept;
    bool RegisterCallbacks(ProductMode mode) noexcept;

    TierSelectionResult m_result;
};

/// Convenience: returns human-readable name for a ProductMode.
[[nodiscard]] constexpr std::string_view ToString(ProductMode m) noexcept {
    switch (m) {
        case ProductMode::Home: return "PhantomHome";
        case ProductMode::EDR:  return "PhantomEDR";
        case ProductMode::XDR:  return "PhantomXDR";
        default:                return "Unknown";
    }
}

} // namespace Shared
} // namespace Products
} // namespace ShadowStrike
