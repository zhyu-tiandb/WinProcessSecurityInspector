#pragma once

#include <algorithm>
#include <codecvt>
#include <cwctype>
#include <locale>
#include <sstream>
#include <string>
#include <vector>

namespace wpsi {

inline std::string to_utf8(const std::wstring& value) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(value);
}

inline std::wstring lower_copy(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    return value;
}

inline bool is_sensitive_name(const std::wstring& name) {
    const auto lowered = lower_copy(name);
    static const wchar_t* needles[] = {
        L"password", L"passwd", L"pwd", L"secret", L"token", L"cookie", L"key", L"credential", L"auth"
    };
    for (const auto* needle : needles) {
        if (lowered.find(needle) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

inline bool is_partial_sensitive_name(const std::wstring& name) {
    const auto lowered = lower_copy(name);
    return lowered.find(L"session") != std::wstring::npos ||
        lowered.find(L"sid") != std::wstring::npos ||
        lowered.find(L"luid") != std::wstring::npos;
}

inline std::vector<std::wstring> split_command_line_simple(std::wstring_view commandLine) {
    std::wistringstream stream{std::wstring(commandLine)};
    std::vector<std::wstring> tokens;
    std::wstring token;
    while (stream >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

inline std::wstring partially_redact(std::wstring_view value) {
    std::wstring result(value.substr(0, std::min<size_t>(4, value.size())));
    result += L"***";
    return result;
}

inline std::wstring redactSid(std::wstring_view sid) {
    return partially_redact(sid);
}

inline std::wstring redactCommandLine(std::wstring_view commandLine) {
    auto tokens = split_command_line_simple(commandLine);
    for (size_t i = 0; i < tokens.size(); ++i) {
        auto& token = tokens[i];
        const auto equals = token.find(L'=');
        const auto name = equals == std::wstring::npos ? token : token.substr(0, equals);

        if (is_sensitive_name(name)) {
            if (equals == std::wstring::npos) {
                if (i + 1 < tokens.size()) {
                    tokens[i + 1] = L"***";
                }
            } else {
                token = token.substr(0, equals + 1) + L"***";
            }
        } else if (is_partial_sensitive_name(name)) {
            if (equals == std::wstring::npos) {
                if (i + 1 < tokens.size()) {
                    tokens[i + 1] = partially_redact(tokens[i + 1]);
                }
            } else {
                token = token.substr(0, equals + 1) + partially_redact(token.substr(equals + 1));
            }
        }
    }

    std::wstring result;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i != 0) {
            result += L' ';
        }
        result += tokens[i];
    }
    return result;
}

} // namespace wpsi
