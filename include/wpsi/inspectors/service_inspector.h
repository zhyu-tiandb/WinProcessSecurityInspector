#pragma once

#include <optional>
#include <string>
#include <vector>

#include <Windows.h>
#include <winsvc.h>

#include "wpsi/common/result.h"
#include "wpsi/core/context.h"

namespace wpsi {

class ServiceInspector {
public:
    Result<std::optional<ServiceInfo>> inspectByPid(DWORD pid) const {
        Result<std::optional<ServiceInfo>> result;
        SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (manager == nullptr) {
            result.partial = true;
            result.error = {ErrorCode::AccessDenied, GetLastError(), "OpenSCManagerW failed"};
            return result;
        }

        DWORD bytesNeeded = 0;
        DWORD count = 0;
        DWORD resume = 0;
        EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            nullptr, 0, &bytesNeeded, &count, &resume, nullptr);
        if (bytesNeeded == 0) {
            CloseServiceHandle(manager);
            return result;
        }

        std::vector<unsigned char> buffer(bytesNeeded);
        if (!EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                buffer.data(), static_cast<DWORD>(buffer.size()), &bytesNeeded, &count, &resume, nullptr)) {
            result.partial = true;
            result.error = {ErrorCode::ApiFailed, GetLastError(), "EnumServicesStatusExW failed"};
            CloseServiceHandle(manager);
            return result;
        }

        const auto* services = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for (DWORD i = 0; i < count; ++i) {
            if (services[i].ServiceStatusProcess.dwProcessId == pid) {
                ServiceInfo info;
                info.serviceName = services[i].lpServiceName ? services[i].lpServiceName : L"";
                info.displayName.value = services[i].lpDisplayName ? services[i].lpDisplayName : L"";
                info.displayName.available = true;
                info.state.value = service_state_name(services[i].ServiceStatusProcess.dwCurrentState);
                info.state.available = true;
                info.startedByScm.value = true;
                info.startedByScm.available = true;
                result.value = info;
                break;
            }
        }
        CloseServiceHandle(manager);
        return result;
    }

private:
    static std::wstring service_state_name(DWORD state) {
        switch (state) {
        case SERVICE_STOPPED: return L"Stopped";
        case SERVICE_START_PENDING: return L"Start Pending";
        case SERVICE_STOP_PENDING: return L"Stop Pending";
        case SERVICE_RUNNING: return L"Running";
        case SERVICE_CONTINUE_PENDING: return L"Continue Pending";
        case SERVICE_PAUSE_PENDING: return L"Pause Pending";
        case SERVICE_PAUSED: return L"Paused";
        default: return L"Unknown";
        }
    }
};

} // namespace wpsi
