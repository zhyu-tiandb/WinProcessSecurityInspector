#pragma once

#include <string>
#include <vector>

#include "wpsi/core/context.h"
#include "wpsi/common/string_utils.h"
#include "wpsi/inspectors/process_inspector.h"
#include "wpsi/inspectors/window_inspector.h"

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

inline BrowserKind detectBrowserKind(std::wstring_view processName) {
    const auto process = lower_copy(std::wstring(processName));
    if (process.find(L"chrome.exe") != std::wstring::npos) {
        return BrowserKind::Chrome;
    }
    if (process.find(L"msedge.exe") != std::wstring::npos) {
        return BrowserKind::Edge;
    }
    if (process.find(L"firefox.exe") != std::wstring::npos) {
        return BrowserKind::Firefox;
    }
    return BrowserKind::Unknown;
}

class BrowserInspector {
public:
    Result<BrowserProcessContext> inspect(DWORD inputPid) const {
        if (inputPid == 0) {
            inputPid = GetCurrentProcessId();
        }

        Result<BrowserProcessContext> result;
        result.value.inputPid = inputPid;

        const auto process = processInspector_.inspect(inputPid);
        if (!process.ok) {
            result.ok = false;
            result.error = process.error;
            return result;
        }

        result.value.browserKind = detectBrowserKind(process.value.processName);
        const auto commandLine = process.value.commandLine.available ? process.value.commandLine.value : L"";
        result.value.role = detectBrowserRole(process.value.processName, commandLine);
        result.value.relatedProcessIds.push_back(inputPid);

        DWORD mainPid = inputPid;
        if (result.value.role != BrowserProcessRole::Main) {
            const auto chain = processInspector_.parentChainOf(inputPid);
            for (const auto parentPid : chain.value) {
                const auto parent = processInspector_.inspect(parentPid);
                if (!parent.ok) {
                    continue;
                }
                if (detectBrowserKind(parent.value.processName) == result.value.browserKind &&
                    detectBrowserRole(parent.value.processName,
                        parent.value.commandLine.available ? parent.value.commandLine.value : L"") ==
                        BrowserProcessRole::Main) {
                    mainPid = parentPid;
                    break;
                }
            }
            result.partial = result.partial || chain.partial;
        }

        result.value.mainProcessPid.value = mainPid;
        result.value.mainProcessPid.available = true;

        const auto windows = windowInspector_.enumerateWindowsForPid(mainPid);
        if (windows.ok) {
            for (const auto& window : windows.value) {
                if (window.visible && !window.toolWindow) {
                    result.value.candidateWindows.push_back(window);
                }
            }
            if (!result.value.candidateWindows.empty()) {
                result.value.topLevelWindow.value = result.value.candidateWindows.front().hwnd;
                result.value.topLevelWindow.available = true;
            }
        } else {
            result.partial = true;
        }

        return result;
    }

private:
    ProcessInspector processInspector_;
    WindowInspector windowInspector_;
};

} // namespace wpsi
