#pragma once

#include <array>
#include <string>

#include <Windows.h>

#include "wpsi/common/result.h"
#include "wpsi/common/win_handle.h"
#include "wpsi/core/context.h"

namespace wpsi {

inline FieldValue<std::wstring> user_object_name(HANDLE handle) {
    FieldValue<std::wstring> value;
    DWORD needed = 0;
    GetUserObjectInformationW(handle, UOI_NAME, nullptr, 0, &needed);
    if (needed == 0) {
        value.error = {ErrorCode::ApiFailed, GetLastError(), "GetUserObjectInformationW size failed"};
        return value;
    }
    std::wstring buffer(needed / sizeof(wchar_t), L'\0');
    if (!GetUserObjectInformationW(handle, UOI_NAME, buffer.data(), needed, &needed)) {
        value.error = {ErrorCode::ApiFailed, GetLastError(), "GetUserObjectInformationW failed"};
        return value;
    }
    while (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }
    value.value = std::move(buffer);
    value.available = true;
    return value;
}

class DesktopInspector {
public:
    Result<DesktopInfo> inspectCurrentThread() const {
        Result<DesktopInfo> result;
        const auto station = GetProcessWindowStation();
        if (station != nullptr) {
            result.value.windowStation = user_object_name(station);
            result.partial = result.partial || !result.value.windowStation.available;
        }

        const auto threadDesktop = GetThreadDesktop(GetCurrentThreadId());
        if (threadDesktop != nullptr) {
            result.value.threadDesktop = user_object_name(threadDesktop);
            result.value.desktop = result.value.threadDesktop;
            result.partial = result.partial || !result.value.threadDesktop.available;
        }

        WinHandle inputDesktop(OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS));
        if (inputDesktop.valid()) {
            result.value.inputDesktop = user_object_name(inputDesktop.get());
            result.partial = result.partial || !result.value.inputDesktop.available;
        } else {
            result.value.inputDesktop.error = {ErrorCode::AccessDenied, GetLastError(), "OpenInputDesktop failed"};
            result.partial = true;
        }
        return result;
    }

    Result<FieldValue<std::wstring>> queryWindowDesktop(HWND hwnd) const {
        Result<FieldValue<std::wstring>> result;
        const DWORD threadId = GetWindowThreadProcessId(hwnd, nullptr);
        if (threadId == 0) {
            result.ok = false;
            result.error = {ErrorCode::ApiFailed, GetLastError(), "GetWindowThreadProcessId failed"};
            return result;
        }
        const auto desktop = GetThreadDesktop(threadId);
        if (desktop == nullptr) {
            result.ok = false;
            result.error = {ErrorCode::AccessDenied, GetLastError(), "GetThreadDesktop failed"};
            return result;
        }
        result.value = user_object_name(desktop);
        result.partial = !result.value.available;
        return result;
    }
};

} // namespace wpsi
