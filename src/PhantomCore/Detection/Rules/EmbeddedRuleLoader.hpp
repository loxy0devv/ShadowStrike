/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * EmbeddedRuleLoader — loads rule corpora compiled into the binary by
 * tools/bake_rules.ps1.  The blob is XOR-obfuscated; the key lives in
 * RulesBlobKey.hpp which is not exported in any public header.
 */

#pragma once

#include "RuleImporter.hpp"
#include "RuleStore.hpp"

#include <cstddef>

namespace ShadowStrike::Detection {

/// Load all embedded rule corpora into store.
/// Returns the total number of rules successfully loaded.
/// Returns 0 if no blob is compiled in (dev / clean build).
size_t LoadEmbeddedRules(RuleStore& store, ImportResult* result = nullptr);

} // namespace ShadowStrike::Detection
