/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * EventBus — non-blocking MPSC-ish event queue between producers
 * (PhantomSensor.sys, user-mode probes, AMSI, WFP filter) and the
 * Correlator.
 *
 * Implementation: a bounded ring buffer with a single drain thread that
 * pumps events into a Correlator. We tolerate event loss on overflow by
 * incrementing m_dropped — losing telemetry is better than blocking the
 * sensor and creating user-visible stalls.
 */

#pragma once

#include "../Rules/PhantomRule.hpp"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

namespace ShadowStrike {
namespace Detection {

using EventSink = std::function<void(DetectionEvent)>;

class EventBus {
public:
    explicit EventBus(size_t capacity = 65536);
    ~EventBus();

    /// Start the drain thread. Idempotent.
    void Start(EventSink sink);

    /// Stop the drain thread. Pending events are dropped.
    void Stop();

    /// Push an event. Returns false if the queue is full (event dropped).
    bool Push(DetectionEvent ev) noexcept;

    /// Statistics
    struct Stats {
        uint64_t pushed   = 0;
        uint64_t dropped  = 0;
        uint64_t delivered= 0;
        size_t   inFlight = 0;
    };
    [[nodiscard]] Stats GetStats() const noexcept;

private:
    void DrainLoop();

    const size_t                  m_capacity;
    EventSink                     m_sink;
    std::queue<DetectionEvent>    m_queue;
    std::mutex                    m_mutex;
    std::condition_variable       m_cv;
    std::atomic<bool>             m_running{false};
    std::thread                   m_thread;

    std::atomic<uint64_t>         m_pushed{0};
    std::atomic<uint64_t>         m_dropped{0};
    std::atomic<uint64_t>         m_delivered{0};
};

} // namespace Detection
} // namespace ShadowStrike
