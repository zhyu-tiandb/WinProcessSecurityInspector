#pragma once

#include <string>
#include <vector>

#include <Windows.h>

#include "wpsi/common/result.h"
#include "wpsi/common/string_utils.h"
#include "wpsi/core/context.h"

namespace wpsi {

class CompatibilityInspector {
public:
    Result<std::vector<std::wstring>> inspectLayers(std::wstring_view executablePath) const {
        Result<std::vector<std::wstring>> result;
        read_layers(HKEY_CURRENT_USER, executablePath, result.value);
        read_layers(HKEY_LOCAL_MACHINE, executablePath, result.value);
        return result;
    }

private:
    static void read_layers(HKEY root, std::wstring_view executablePath, std::vector<std::wstring>& layers) {
        HKEY key = nullptr;
        const auto status = RegOpenKeyExW(
            root,
            L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &key);
        if (status != ERROR_SUCCESS) {
            return;
        }

        DWORD type = 0;
        DWORD bytes = 0;
        const std::wstring path(executablePath);
        if (RegQueryValueExW(key, path.c_str(), nullptr, &type, nullptr, &bytes) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ) && bytes > sizeof(wchar_t)) {
            std::wstring value(bytes / sizeof(wchar_t), L'\0');
            if (RegQueryValueExW(key, path.c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(value.data()), &bytes) ==
                ERROR_SUCCESS) {
                while (!value.empty() && value.back() == L'\0') {
                    value.pop_back();
                }
                layers.push_back(value);
            }
        }
        RegCloseKey(key);
    }
};

} // namespace wpsi
