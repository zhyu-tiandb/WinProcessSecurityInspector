#pragma once

#include <string>

#include <Windows.h>
#include <Softpub.h>
#include <WinTrust.h>

#include "wpsi/common/result.h"
#include "wpsi/core/context.h"

namespace wpsi {

class SignatureInspector {
public:
    Result<SignatureInfo> inspect(std::wstring_view executablePath) const {
        Result<SignatureInfo> result;
        WINTRUST_FILE_INFO fileInfo {};
        fileInfo.cbStruct = sizeof(fileInfo);
        const std::wstring path(executablePath);
        fileInfo.pcwszFilePath = path.c_str();

        WINTRUST_DATA trustData {};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.pFile = &fileInfo;

        GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG status = WinVerifyTrust(nullptr, &policy, &trustData);

        result.value.signedFile.available = true;
        result.value.valid.available = true;
        result.value.valid.value = status == ERROR_SUCCESS;
        result.value.signedFile.value = status != TRUST_E_NOSIGNATURE;

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policy, &trustData);
        return result;
    }
};

} // namespace wpsi
