#pragma once

#include <memory>
#include <string>
#include <vector>

#include <Windows.h>
#include <sddl.h>

#include "wpsi/common/result.h"
#include "wpsi/common/win_handle.h"
#include "wpsi/core/context.h"

namespace wpsi {

inline IntegrityLevel integrity_from_rid(DWORD rid) {
    if (rid < SECURITY_MANDATORY_LOW_RID) {
        return IntegrityLevel::Untrusted;
    }
    if (rid < SECURITY_MANDATORY_MEDIUM_RID) {
        return IntegrityLevel::Low;
    }
    if (rid < SECURITY_MANDATORY_MEDIUM_RID + 0x100) {
        return IntegrityLevel::Medium;
    }
    if (rid < SECURITY_MANDATORY_HIGH_RID) {
        return IntegrityLevel::MediumPlus;
    }
    if (rid < SECURITY_MANDATORY_SYSTEM_RID) {
        return IntegrityLevel::High;
    }
    if (rid == SECURITY_MANDATORY_SYSTEM_RID) {
        return IntegrityLevel::System;
    }
    return IntegrityLevel::ProtectedProcess;
}

inline ElevationType map_elevation_type(TOKEN_ELEVATION_TYPE type) {
    switch (type) {
    case TokenElevationTypeDefault:
        return ElevationType::Default;
    case TokenElevationTypeFull:
        return ElevationType::Full;
    case TokenElevationTypeLimited:
        return ElevationType::Limited;
    default:
        return ElevationType::Unknown;
    }
}

template <typename T>
inline bool query_token_value(HANDLE token, TOKEN_INFORMATION_CLASS infoClass, T& value) {
    DWORD size = sizeof(T);
    return GetTokenInformation(token, infoClass, &value, size, &size) != FALSE;
}

inline std::vector<unsigned char> query_token_buffer(HANDLE token, TOKEN_INFORMATION_CLASS infoClass) {
    DWORD size = 0;
    GetTokenInformation(token, infoClass, nullptr, 0, &size);
    std::vector<unsigned char> buffer(size);
    if (size == 0 || !GetTokenInformation(token, infoClass, buffer.data(), size, &size)) {
        buffer.clear();
    }
    return buffer;
}

inline FieldValue<std::wstring> sid_to_string(PSID sid) {
    FieldValue<std::wstring> result;
    LPWSTR text = nullptr;
    if (ConvertSidToStringSidW(sid, &text)) {
        result.value = text;
        result.available = true;
        LocalFree(text);
    } else {
        result.error = {ErrorCode::ApiFailed, GetLastError(), "ConvertSidToStringSidW failed"};
    }
    return result;
}

class TokenInspector {
public:
    Result<TokenInfo> inspect(DWORD pid, bool includePrivileges) const {
        Result<TokenInfo> result;

        WinHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!process.valid()) {
            result.ok = false;
            result.error = {ErrorCode::AccessDenied, GetLastError(), "OpenProcess failed"};
            return result;
        }

        HANDLE rawToken = nullptr;
        if (!OpenProcessToken(process.get(), TOKEN_QUERY, &rawToken)) {
            result.ok = false;
            result.error = {ErrorCode::AccessDenied, GetLastError(), "OpenProcessToken failed"};
            return result;
        }
        WinHandle token(rawToken);

        read_user_sid(token.get(), result.value, result);
        read_integrity(token.get(), result.value, result);
        read_elevation(token.get(), result.value, result);
        read_app_container(token.get(), result.value, result);
        read_ui_access(token.get(), result.value, result);
        if (includePrivileges) {
            read_privileges(token.get(), result.value, result);
        }

        return result;
    }

private:
    static void read_user_sid(HANDLE token, TokenInfo& info, Result<TokenInfo>& result) {
        auto buffer = query_token_buffer(token, TokenUser);
        if (buffer.empty()) {
            result.partial = true;
            info.userSid.error = {ErrorCode::ApiFailed, GetLastError(), "TokenUser query failed"};
            return;
        }

        const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(buffer.data());
        info.userSid = sid_to_string(tokenUser->User.Sid);
    }

    static void read_integrity(HANDLE token, TokenInfo& info, Result<TokenInfo>& result) {
        auto buffer = query_token_buffer(token, TokenIntegrityLevel);
        if (buffer.empty()) {
            result.partial = true;
            info.integrityLevel.error = {ErrorCode::ApiFailed, GetLastError(), "TokenIntegrityLevel query failed"};
            return;
        }

        const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
        const DWORD subAuthorityCount = *GetSidSubAuthorityCount(label->Label.Sid);
        const DWORD rid = *GetSidSubAuthority(label->Label.Sid, subAuthorityCount - 1);
        info.integrityRid.value = rid;
        info.integrityRid.available = true;
        info.integrityLevel.value = integrity_from_rid(rid);
        info.integrityLevel.available = true;
    }

    static void read_elevation(HANDLE token, TokenInfo& info, Result<TokenInfo>& result) {
        TOKEN_ELEVATION elevation {};
        if (query_token_value(token, TokenElevation, elevation)) {
            info.elevated.value = elevation.TokenIsElevated != 0;
            info.elevated.available = true;
        } else {
            result.partial = true;
            info.elevated.error = {ErrorCode::ApiFailed, GetLastError(), "TokenElevation query failed"};
        }

        TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
        if (query_token_value(token, TokenElevationType, elevationType)) {
            info.elevationType.value = map_elevation_type(elevationType);
            info.elevationType.available = true;
        } else {
            result.partial = true;
            info.elevationType.error = {ErrorCode::ApiFailed, GetLastError(), "TokenElevationType query failed"};
        }
    }

    static void read_app_container(HANDLE token, TokenInfo& info, Result<TokenInfo>& result) {
        DWORD isAppContainer = 0;
        if (query_token_value(token, TokenIsAppContainer, isAppContainer)) {
            info.appContainer.value = isAppContainer != 0;
            info.appContainer.available = true;
        } else {
            result.partial = true;
            info.appContainer.error = {ErrorCode::ApiFailed, GetLastError(), "TokenIsAppContainer query failed"};
        }
    }

    static void read_ui_access(HANDLE token, TokenInfo& info, Result<TokenInfo>& result) {
        DWORD uiAccess = 0;
        if (query_token_value(token, TokenUIAccess, uiAccess)) {
            info.uiAccess.value = uiAccess != 0;
            info.uiAccess.available = true;
        } else {
            result.partial = true;
            info.uiAccess.error = {ErrorCode::ApiFailed, GetLastError(), "TokenUIAccess query failed"};
        }
    }

    static void read_privileges(HANDLE token, TokenInfo& info, Result<TokenInfo>& result) {
        auto buffer = query_token_buffer(token, TokenPrivileges);
        if (buffer.empty()) {
            result.partial = true;
            return;
        }

        const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
        for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
            const auto attributes = privileges->Privileges[i].Attributes;
            PrivilegeInfo privilege;
            privilege.present = true;
            if ((attributes & SE_PRIVILEGE_REMOVED) != 0) {
                privilege.state = PrivilegeState::Removed;
            } else if ((attributes & SE_PRIVILEGE_ENABLED) != 0) {
                privilege.state = PrivilegeState::Enabled;
            } else {
                privilege.state = PrivilegeState::Disabled;
            }
            info.privileges.push_back(privilege);
        }
    }
};

} // namespace wpsi
