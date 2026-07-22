#pragma once

#include <Windows.h>

#include "wpsi/common/result.h"
#include "wpsi/core/context.h"

namespace wpsi {

class SessionInspector {
public:
    Result<SessionInfo> inspect(DWORD pid, DWORD processSessionId) const {
        Result<SessionInfo> result;
        result.value.processSessionId = processSessionId;
        result.value.sessionZero = processSessionId == 0;

        DWORD apiSessionId = 0;
        if (ProcessIdToSessionId(pid, &apiSessionId)) {
            result.value.processSessionId = apiSessionId;
            result.value.sessionZero = apiSessionId == 0;
        } else {
            result.partial = true;
            result.error = {ErrorCode::PartialData, GetLastError(), "ProcessIdToSessionId failed"};
        }

        result.value.activeConsoleSessionId.value = WTSGetActiveConsoleSessionId();
        result.value.activeConsoleSessionId.available = true;
        return result;
    }
};

} // namespace wpsi
