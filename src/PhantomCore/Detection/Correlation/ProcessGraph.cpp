/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"
#include "ProcessGraph.hpp"

#include <algorithm>

namespace ShadowStrike {
namespace Detection {

namespace {
std::string lower(const std::wstring& w) {
    std::string s;
    s.reserve(w.size());
    for (auto c : w) s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c & 0xFF))));
    return s;
}

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

constexpr size_t kMaxTailBuffer = 256;

void pushBounded(std::vector<std::wstring>& v, std::wstring s, size_t cap = kMaxTailBuffer) {
    v.push_back(std::move(s));
    if (v.size() > cap) v.erase(v.begin(), v.begin() + (v.size() - cap));
}
void pushBounded(std::vector<std::string>& v, std::string s, size_t cap = kMaxTailBuffer) {
    v.push_back(std::move(s));
    if (v.size() > cap) v.erase(v.begin(), v.begin() + (v.size() - cap));
}
} // anon

ProcessGraph::ProcessGraph() = default;
ProcessGraph::~ProcessGraph() = default;

void ProcessGraph::OnProcessStart(uint32_t pid, uint32_t parentPid,
                                  std::wstring image, std::string commandLine,
                                  std::string userSid, std::string integrity,
                                  std::chrono::system_clock::time_point at) {
    if (pid == 0) return;
    std::unique_lock lock(m_mutex);
    auto& n = m_nodes[pid];
    n.pid = pid;
    n.parentPid = parentPid;
    n.imagePath = image;
    auto last = image.find_last_of(L"\\/");
    auto base = (last == std::wstring::npos) ? image : image.substr(last + 1);
    n.imageNameLower = lower(base);
    n.commandLine = std::move(commandLine);
    n.userSid = std::move(userSid);
    n.integrityLevel = std::move(integrity);
    n.created = at;
    n.creationToken = m_creationCounter.fetch_add(1, std::memory_order_relaxed);

    if (parentPid != 0) {
        auto it = m_nodes.find(parentPid);
        if (it != m_nodes.end()) it->second.childPids.push_back(pid);
    }
}

void ProcessGraph::OnProcessExit(uint32_t pid,
                                 std::chrono::system_clock::time_point at) {
    if (pid == 0) return;
    std::unique_lock lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return;
    it->second.terminated = at;
}

void ProcessGraph::OnImageLoad(uint32_t pid, std::wstring image, bool /*signedImg*/) {
    if (pid == 0) return;
    std::unique_lock lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return;
    pushBounded(it->second.loadedImages, std::move(image));
}

void ProcessGraph::OnNetworkEndpoint(uint32_t pid, std::string endpoint) {
    if (pid == 0) return;
    std::unique_lock lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return;
    pushBounded(it->second.networkEndpoints, std::move(endpoint));
}

void ProcessGraph::OnFileWrite(uint32_t pid, std::wstring path) {
    if (pid == 0) return;
    std::unique_lock lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return;
    pushBounded(it->second.fileWrites, std::move(path));
}

void ProcessGraph::OnRegistryWrite(uint32_t pid, std::string key) {
    if (pid == 0) return;
    std::unique_lock lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return;
    pushBounded(it->second.registryWrites, std::move(key));
}

void ProcessGraph::OnApiSeen(uint32_t pid, std::string api) {
    if (pid == 0) return;
    std::unique_lock lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return;
    pushBounded(it->second.observedApis, lower(std::move(api)));
}

void ProcessGraph::OnSignerInfo(uint32_t pid, std::string subject, bool trusted) {
    if (pid == 0) return;
    std::unique_lock lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return;
    it->second.signerSubject = std::move(subject);
    it->second.trustedSigner = trusted;
    it->second.signed_ = !it->second.signerSubject.empty();
}

void ProcessGraph::ApplyMatch(uint32_t pid, const RuleMatch& match) {
    if (pid == 0 || match.rule == nullptr) return;
    std::unique_lock lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return;
    auto& n = it->second;
    n.matchedRuleCount += 1;
    n.matchedRules.push_back(match.rule->id);
    if (match.rule->severity > n.worstSeverity) n.worstSeverity = match.rule->severity;
    n.cumulativeScore = std::min(100.0f, n.cumulativeScore + match.score * 5.0f);
    for (const auto& a : match.attack) n.attack.push_back(a);
}

std::optional<ProcessNode> ProcessGraph::Get(uint32_t pid) const {
    std::shared_lock lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return std::nullopt;
    return it->second;
}

std::vector<ProcessNode> ProcessGraph::Children(uint32_t pid) const {
    std::shared_lock lock(m_mutex);
    std::vector<ProcessNode> out;
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return out;
    for (auto c : it->second.childPids) {
        auto cit = m_nodes.find(c);
        if (cit != m_nodes.end()) out.push_back(cit->second);
    }
    return out;
}

std::vector<ProcessNode> ProcessGraph::AncestryChain(uint32_t pid) const {
    std::shared_lock lock(m_mutex);
    std::vector<ProcessNode> out;
    uint32_t cur = pid;
    while (cur != 0) {
        auto it = m_nodes.find(cur);
        if (it == m_nodes.end()) break;
        out.push_back(it->second);
        cur = it->second.parentPid;
        if (out.size() > 32) break;  // sanity
    }
    return out;
}

std::vector<uint32_t> ProcessGraph::Descendants(uint32_t pid) const {
    std::shared_lock lock(m_mutex);
    std::vector<uint32_t> out;
    std::vector<uint32_t> stack{pid};
    while (!stack.empty()) {
        uint32_t cur = stack.back(); stack.pop_back();
        auto it = m_nodes.find(cur);
        if (it == m_nodes.end()) continue;
        for (auto c : it->second.childPids) {
            out.push_back(c);
            stack.push_back(c);
            if (out.size() > 8192) return out; // sanity
        }
    }
    return out;
}

size_t ProcessGraph::Size() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_nodes.size();
}

std::vector<ProcessNode> ProcessGraph::Snapshot() const {
    std::shared_lock lock(m_mutex);
    std::vector<ProcessNode> out;
    out.reserve(m_nodes.size());
    for (const auto& kv : m_nodes) out.push_back(kv.second);
    return out;
}

size_t ProcessGraph::Reap(std::chrono::seconds age) {
    auto now = std::chrono::system_clock::now();
    std::unique_lock lock(m_mutex);
    size_t removed = 0;
    for (auto it = m_nodes.begin(); it != m_nodes.end(); ) {
        if (it->second.terminated.has_value() &&
            (now - *it->second.terminated) > age) {
            it = m_nodes.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

float ProcessGraph::Score(uint32_t pid) const {
    std::shared_lock lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return 0.0f;
    float s = it->second.cumulativeScore;
    if (it->second.trustedSigner) s *= 0.7f;
    if (it->second.signed_ && !it->second.trustedSigner) s += 4.0f;
    return std::clamp(s, 0.0f, 100.0f);
}

} // namespace Detection
} // namespace ShadowStrike
