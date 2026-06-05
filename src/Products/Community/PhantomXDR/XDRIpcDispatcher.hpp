/*
 * ShadowStrike — XDR IPC dispatcher (commands 520–539).
 * Requires EDRIpcDispatcher and SharedIpcDispatcher installed first.
 * All handlers gated by FeatureCategory::XDRCorrelation.
 */
#pragma once
#include <memory>
namespace ShadowStrike::Service { class ServiceCommunicator; }
namespace ShadowStrike::Products::PhantomXDR {

class XDRIpcDispatcher final {
public:
    [[nodiscard]] static XDRIpcDispatcher& Instance();
    void Install(Service::ServiceCommunicator& svc);
    void Uninstall(Service::ServiceCommunicator& svc);
    XDRIpcDispatcher(const XDRIpcDispatcher&) = delete;
    XDRIpcDispatcher& operator=(const XDRIpcDispatcher&) = delete;
private:
    XDRIpcDispatcher();
    ~XDRIpcDispatcher();
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR
