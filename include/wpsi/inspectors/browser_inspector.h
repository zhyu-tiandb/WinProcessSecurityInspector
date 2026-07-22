#pragma once

#include <string>

#include "wpsi/core/context.h"
#include "wpsi/common/string_utils.h"

namespace wpsi {

inline BrowserProcessRole detectBrowserRole(std::wstring_view processName, std::wstring_view commandLine) {
    const auto process = lower_copy(std::wstring(processName));
    const auto command = lower_copy(std::wstring(commandLine));

    if (process.find(L"crashreporter.exe") != std::wstring::npos ||
        command.find(L"-crashreport") != std::wstring::npos ||
        process.find(L"crashpad") != std::wstring::npos ||
        command.find(L"crashpad-handler") != std::wstring::npos) {
        return BrowserProcessRole::CrashHandler;
    }

    if (process.find(L"firefox.exe") != std::wstring::npos) {
        if (command.find(L"--type=gpu") != std::wstring::npos) {
            return BrowserProcessRole::GpuProcess;
        }
        if (command.find(L"-contentproc") != std::wstring::npos) {
            return BrowserProcessRole::Renderer;
        }
        return BrowserProcessRole::Main;
    }

    if (command.find(L"--type=renderer") != std::wstring::npos) {
        return BrowserProcessRole::Renderer;
    }
    if (command.find(L"--type=gpu-process") != std::wstring::npos) {
        return BrowserProcessRole::GpuProcess;
    }
    if (command.find(L"--type=utility") != std::wstring::npos) {
        if (command.find(L"network.mojom.networkservice") != std::wstring::npos) {
            return BrowserProcessRole::NetworkService;
        }
        return BrowserProcessRole::Utility;
    }
    if (process.find(L"chrome.exe") != std::wstring::npos ||
        process.find(L"msedge.exe") != std::wstring::npos) {
        return BrowserProcessRole::Main;
    }

    return BrowserProcessRole::Unknown;
}

} // namespace wpsi
