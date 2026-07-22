#pragma once

#include <algorithm>
#include <cctype>
#include <string>

#include <Windows.h>

#include "wpsi/common/result.h"
#include "wpsi/common/string_utils.h"
#include "wpsi/core/context.h"

namespace wpsi {

class ManifestInspector {
public:
    Result<ManifestInfo> inspect(std::wstring_view executablePath) const {
        Result<ManifestInfo> result;
        HMODULE module = LoadLibraryExW(std::wstring(executablePath).c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
        if (module == nullptr) {
            result.partial = true;
            return result;
        }

        HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(24));
        if (resource == nullptr) {
            FreeLibrary(module);
            return result;
        }
        const auto loaded = LoadResource(module, resource);
        const auto size = SizeofResource(module, resource);
        const auto* bytes = static_cast<const char*>(LockResource(loaded));
        if (bytes != nullptr && size > 0) {
            std::string manifest(bytes, bytes + size);
            auto lowered = manifest;
            std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            read_attribute(manifest, lowered, "requestedexecutionlevel", "level", result.value.requestedExecutionLevel);
            FieldValue<std::wstring> uiAccessText;
            read_attribute(manifest, lowered, "requestedexecutionlevel", "uiaccess", uiAccessText);
            if (uiAccessText.available) {
                result.value.uiAccess.available = true;
                result.value.uiAccess.value = lower_copy(uiAccessText.value) == L"true";
            }
        }
        FreeLibrary(module);
        return result;
    }

private:
    static void read_attribute(
        const std::string& original,
        const std::string& lowered,
        const std::string& element,
        const std::string& attribute,
        FieldValue<std::wstring>& output) {
        const auto elementPos = lowered.find(element);
        if (elementPos == std::string::npos) {
            return;
        }
        const auto attrPos = lowered.find(attribute + "=", elementPos);
        if (attrPos == std::string::npos) {
            return;
        }
        const auto quotePos = original.find_first_of("\"'", attrPos + attribute.size() + 1);
        if (quotePos == std::string::npos) {
            return;
        }
        const char quote = original[quotePos];
        const auto endPos = original.find(quote, quotePos + 1);
        if (endPos == std::string::npos) {
            return;
        }
        const auto value = original.substr(quotePos + 1, endPos - quotePos - 1);
        output.value.assign(value.begin(), value.end());
        output.available = true;
    }
};

} // namespace wpsi
