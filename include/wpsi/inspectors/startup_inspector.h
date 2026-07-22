#pragma once

#include <string>
#include <vector>

#include <Windows.h>

#include "wpsi/common/result.h"
#include "wpsi/common/string_utils.h"
#include "wpsi/core/context.h"

namespace wpsi {

class StartupInspector {
public:
    Result<std::vector<StartupSourceInfo>> inspect(std::wstring_view executablePath) const {
        Result<std::vector<StartupSourceInfo>> result;
        read_run_key(HKEY_CURRENT_USER, L"HKCU Run", executablePath, result.value);
        read_run_key(HKEY_CURRENT_USER, L"HKCU RunOnce", executablePath, result.value,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        read_run_key(HKEY_LOCAL_MACHINE, L"HKLM Run", executablePath, result.value);
        read_run_key(HKEY_LOCAL_MACHINE, L"HKLM RunOnce", executablePath, result.value,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        return result;
    }

private:
    static void read_run_key(
        HKEY root,
        std::wstring_view sourceType,
        std::wstring_view executablePath,
        std::vector<StartupSourceInfo>& output,
        const wchar_t* subkey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run") {
        HKEY key = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
            return;
        }

        const auto wanted = lower_copy(std::wstring(executablePath));
        for (DWORD index = 0;; ++index) {
            wchar_t name[512] {};
            wchar_t value[4096] {};
            DWORD nameSize = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
            DWORD valueBytes = sizeof(value);
            DWORD type = 0;
            const auto status = RegEnumValueW(
                key, index, name, &nameSize, nullptr, &type, reinterpret_cast<LPBYTE>(value), &valueBytes);
            if (status == ERROR_NO_MORE_ITEMS) {
                break;
            }
            if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
                continue;
            }
            std::wstring command(value, value + (valueBytes / sizeof(wchar_t)));
            while (!command.empty() && command.back() == L'\0') {
                command.pop_back();
            }
            if (lower_copy(command).find(wanted) != std::wstring::npos ||
                (!wanted.empty() && lower_copy(command).find(lower_copy(file_name(wanted))) != std::wstring::npos)) {
                StartupSourceInfo info;
                info.sourceType = sourceType;
                info.name.assign(name, nameSize);
                info.command = std::move(command);
                output.push_back(std::move(info));
            }
        }
        RegCloseKey(key);
    }

    static std::wstring file_name(std::wstring_view path) {
        const auto pos = path.find_last_of(L"\\/");
        if (pos == std::wstring::npos) {
            return std::wstring(path);
        }
        return std::wstring(path.substr(pos + 1));
    }
};

} // namespace wpsi
