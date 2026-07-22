#pragma once

#include <array>
#include <vector>

#include <Windows.h>

#include "wpsi/common/result.h"
#include "wpsi/core/context.h"

namespace wpsi {

class WindowInspector {
public:
    Result<std::vector<WindowInfo>> enumerateTopLevelWindows() const {
        Result<std::vector<WindowInfo>> result;
        EnumWindows(
            [](HWND hwnd, LPARAM lparam) -> BOOL {
                auto* windows = reinterpret_cast<std::vector<WindowInfo>*>(lparam);
                windows->push_back(read_window(hwnd));
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&result.value));
        return result;
    }

    Result<std::vector<WindowInfo>> enumerateWindowsForPid(DWORD pid) const {
        auto all = enumerateTopLevelWindows();
        if (!all.ok) {
            return all;
        }
        std::vector<WindowInfo> filtered;
        for (const auto& window : all.value) {
            if (window.ownerPid == pid) {
                filtered.push_back(window);
            }
        }
        all.value = std::move(filtered);
        return all;
    }

    Result<FieldValue<HWND>> foregroundWindow() const {
        Result<FieldValue<HWND>> result;
        const auto hwnd = GetForegroundWindow();
        if (hwnd == nullptr) {
            result.partial = true;
            result.value.error = {ErrorCode::ApiFailed, GetLastError(), "GetForegroundWindow returned null"};
            return result;
        }
        result.value.value = hwnd;
        result.value.available = true;
        return result;
    }

private:
    static WindowInfo read_window(HWND hwnd) {
        WindowInfo info;
        info.hwnd = hwnd;
        info.ownerThreadId = GetWindowThreadProcessId(hwnd, &info.ownerPid);

        std::array<wchar_t, 512> title {};
        const int titleLength = GetWindowTextW(hwnd, title.data(), static_cast<int>(title.size()));
        if (titleLength > 0) {
            info.title.assign(title.data(), static_cast<size_t>(titleLength));
        }

        std::array<wchar_t, 256> className {};
        const int classLength = GetClassNameW(hwnd, className.data(), static_cast<int>(className.size()));
        if (classLength > 0) {
            info.className.assign(className.data(), static_cast<size_t>(classLength));
        }

        info.visible = IsWindowVisible(hwnd) != FALSE;
        info.minimized = IsIconic(hwnd) != FALSE;
        info.foreground = hwnd == GetForegroundWindow();
        info.toolWindow = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) != 0;
        info.hasOwnerWindow = GetWindow(hwnd, GW_OWNER) != nullptr;
        return info;
    }
};

} // namespace wpsi
