#pragma once

#include <array>
#include <cwctype>
#include <string>
#include <vector>

#include <Windows.h>
#include <TlHelp32.h>

#include "wpsi/common/result.h"
#include "wpsi/common/win_handle.h"
#include "wpsi/core/context.h"

namespace wpsi {

inline std::wstring priority_class_name(DWORD priorityClass) {
    switch (priorityClass) {
    case IDLE_PRIORITY_CLASS:
        return L"Idle";
    case BELOW_NORMAL_PRIORITY_CLASS:
        return L"Below Normal";
    case NORMAL_PRIORITY_CLASS:
        return L"Normal";
    case ABOVE_NORMAL_PRIORITY_CLASS:
        return L"Above Normal";
    case HIGH_PRIORITY_CLASS:
        return L"High";
    case REALTIME_PRIORITY_CLASS:
        return L"Realtime";
    default:
        return L"Unknown";
    }
}

inline FieldValue<TimePoint> filetime_to_time_point(const FILETIME& fileTime) {
    ULARGE_INTEGER value {};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;

    // FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01.
    constexpr unsigned long long epochDifference100Ns = 116444736000000000ULL;
    FieldValue<TimePoint> result;
    if (value.QuadPart < epochDifference100Ns) {
        result.error = {ErrorCode::ApiFailed, 0, "FILETIME is before Unix epoch"};
        return result;
    }

    const auto unix100Ns = value.QuadPart - epochDifference100Ns;
    result.value = TimePoint(std::chrono::duration_cast<TimePoint::duration>(
        std::chrono::duration<unsigned long long, std::ratio<1, 10000000>>(unix100Ns)));
    result.available = true;
    return result;
}

class ProcessInspector {
public:
    Result<std::vector<DWORD>> findByName(std::wstring_view processName) const {
        Result<std::vector<DWORD>> result;
        const auto wanted = lower_copy_local(std::wstring(processName));

        WinHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot.valid()) {
            result.ok = false;
            result.error = {ErrorCode::ApiFailed, GetLastError(), "CreateToolhelp32Snapshot failed"};
            return result;
        }

        PROCESSENTRY32W entry {};
        entry.dwSize = sizeof(entry);
        if (!Process32FirstW(snapshot.get(), &entry)) {
            result.ok = false;
            result.error = {ErrorCode::ApiFailed, GetLastError(), "Process32FirstW failed"};
            return result;
        }

        do {
            if (lower_copy_local(entry.szExeFile) == wanted) {
                result.value.push_back(entry.th32ProcessID);
            }
        } while (Process32NextW(snapshot.get(), &entry));

        return result;
    }

    Result<ProcessInfo> inspect(DWORD pid) const {
        Result<ProcessInfo> result;
        result.value.pid = pid;
        fill_snapshot_fields(pid, result.value, result);

        WinHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!process.valid()) {
            result.ok = false;
            result.error = {ErrorCode::AccessDenied, GetLastError(), "OpenProcess failed"};
            return result;
        }

        std::array<wchar_t, 32768> path {};
        DWORD pathSize = static_cast<DWORD>(path.size());
        if (QueryFullProcessImageNameW(process.get(), 0, path.data(), &pathSize)) {
            result.value.executablePath.value.assign(path.data(), pathSize);
            result.value.executablePath.available = true;
            const auto slash = result.value.executablePath.value.find_last_of(L"\\/");
            result.value.processName = slash == std::wstring::npos
                ? result.value.executablePath.value
                : result.value.executablePath.value.substr(slash + 1);
        } else {
            result.partial = true;
            result.value.executablePath.error = {ErrorCode::ApiFailed, GetLastError(), "QueryFullProcessImageNameW failed"};
        }

        if (pid == GetCurrentProcessId()) {
            result.value.commandLine.value = GetCommandLineW();
            result.value.commandLine.available = true;
        }

        fill_architecture(process.get(), result.value);

        FILETIME createTime {};
        FILETIME exitTime {};
        FILETIME kernelTime {};
        FILETIME userTime {};
        if (GetProcessTimes(process.get(), &createTime, &exitTime, &kernelTime, &userTime)) {
            result.value.startTime = filetime_to_time_point(createTime);
        } else {
            result.partial = true;
            result.value.startTime.error = {ErrorCode::ApiFailed, GetLastError(), "GetProcessTimes failed"};
        }

        const DWORD priority = GetPriorityClass(process.get());
        if (priority != 0) {
            result.value.priorityClassName.value = priority_class_name(priority);
            result.value.priorityClassName.available = true;
        } else {
            result.partial = true;
            result.value.priorityClassName.error = {ErrorCode::ApiFailed, GetLastError(), "GetPriorityClass failed"};
        }

        DWORD handleCount = 0;
        if (GetProcessHandleCount(process.get(), &handleCount)) {
            result.value.handleCount.value = handleCount;
            result.value.handleCount.available = true;
        }

        BOOL inJob = FALSE;
        if (IsProcessInJob(process.get(), nullptr, &inJob)) {
            result.value.inJobObject.value = inJob != FALSE;
            result.value.inJobObject.available = true;
        }

        DWORD sessionId = 0;
        if (ProcessIdToSessionId(pid, &sessionId)) {
            result.value.sessionId = sessionId;
        }

        return result;
    }

private:
    static std::wstring lower_copy_local(std::wstring value) {
        for (auto& ch : value) {
            ch = static_cast<wchar_t>(::towlower(ch));
        }
        return value;
    }

    static void fill_snapshot_fields(DWORD pid, ProcessInfo& info, Result<ProcessInfo>& result) {
        WinHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot.valid()) {
            result.partial = true;
            return;
        }

        PROCESSENTRY32W entry {};
        entry.dwSize = sizeof(entry);
        if (!Process32FirstW(snapshot.get(), &entry)) {
            result.partial = true;
            return;
        }

        do {
            if (entry.th32ProcessID == pid) {
                info.parentPid = entry.th32ParentProcessID;
                info.processName = entry.szExeFile;
                info.threadCount.value = entry.cntThreads;
                info.threadCount.available = true;
                return;
            }
        } while (Process32NextW(snapshot.get(), &entry));

        result.partial = true;
    }

    static void fill_architecture(HANDLE process, ProcessInfo& info) {
        USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (IsWow64Process2(process, &processMachine, &nativeMachine)) {
            if (processMachine == IMAGE_FILE_MACHINE_I386) {
                info.architecture = ProcessArchitecture::X86;
                return;
            }
            if (processMachine == IMAGE_FILE_MACHINE_ARM64) {
                info.architecture = ProcessArchitecture::Arm64;
                return;
            }
            if (processMachine == IMAGE_FILE_MACHINE_AMD64) {
                info.architecture = ProcessArchitecture::X64;
                return;
            }

            switch (nativeMachine) {
            case IMAGE_FILE_MACHINE_I386:
                info.architecture = ProcessArchitecture::X86;
                break;
            case IMAGE_FILE_MACHINE_AMD64:
                info.architecture = ProcessArchitecture::X64;
                break;
            case IMAGE_FILE_MACHINE_ARM64:
                info.architecture = ProcessArchitecture::Arm64;
                break;
            default:
                info.architecture = ProcessArchitecture::Unknown;
                break;
            }
        }
    }
};

} // namespace wpsi
