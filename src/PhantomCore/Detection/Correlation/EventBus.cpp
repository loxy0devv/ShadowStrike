/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"
#include "EventBus.hpp"

namespace ShadowStrike {
namespace Detection {

EventBus::EventBus(size_t capacity) : m_capacity(capacity) {}

EventBus::~EventBus() {
    Stop();
}

void EventBus::Start(EventSink sink) {
    bool expected = false;
    if (!m_running.compare_exchange_strong(expected, true)) return;
    m_sink = std::move(sink);
    m_thread = std::thread(&EventBus::DrainLoop, this);
}

void EventBus::Stop() {
    if (!m_running.exchange(false)) return;
    m_cv.notify_all();
    if (m_thread.joinable()) m_thread.join();
}

bool EventBus::Push(DetectionEvent ev) noexcept {
    {
        std::lock_guard<std::mutex> g(m_mutex);
        if (m_queue.size() >= m_capacity) {
            m_dropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        m_queue.push(std::move(ev));
        m_pushed.fetch_add(1, std::memory_order_relaxed);
    }
    m_cv.notify_one();
    return true;
}

EventBus::Stats EventBus::GetStats() const noexcept {
    Stats s;
    s.pushed    = m_pushed.load(std::memory_order_relaxed);
    s.dropped   = m_dropped.load(std::memory_order_relaxed);
    s.delivered = m_delivered.load(std::memory_order_relaxed);
    std::lock_guard<std::mutex> g(const_cast<std::mutex&>(m_mutex));
    s.inFlight  = m_queue.size();
    return s;
}

void EventBus::DrainLoop() {
    while (true) {
        DetectionEvent ev;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [&]{ return !m_queue.empty() || !m_running.load(); });
            if (!m_running.load() && m_queue.empty()) return;
            ev = std::move(m_queue.front());
            m_queue.pop();
        }
        try {
            if (m_sink) m_sink(std::move(ev));
        } catch (...) {
            // Sink errors must not kill the drain loop.
        }
        m_delivered.fetch_add(1, std::memory_order_relaxed);
    }
}

} // namespace Detection
} // namespace ShadowStrike
