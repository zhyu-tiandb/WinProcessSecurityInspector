#pragma once

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "wpsi/core/context.h"

namespace wpsi {

struct DiagnosisContext {
    std::optional<ProcessSecurityContext> source;
    std::optional<ProcessSecurityContext> target;
    std::optional<BrowserProcessContext> browser;
};

class RuleEngine {
public:
    std::vector<RuleResult> evaluate(const DiagnosisContext& context) const {
        std::vector<RuleResult> results;
        if (!context.source || !context.target) {
            return results;
        }

        const auto comparison = compare(*context.source, *context.target);

        if (comparison.sourceIntegrityLowerThanTarget) {
            results.push_back({"R001", DiagnosisSeverity::Warning,
                "Integrity level barrier",
                "Source integrity level is lower than target integrity level.",
                "Run both processes at compatible integrity levels or use IPC."});
        }

        if (!comparison.sameSession) {
            results.push_back({"R002", DiagnosisSeverity::Error,
                "Session mismatch",
                "Source and target processes are in different sessions.",
                "Use a user-session agent or service-to-user IPC."});
        }

        if (!comparison.sameUserSid) {
            results.push_back({"R003", DiagnosisSeverity::Error,
                "User SID mismatch",
                "Source and target processes run under different user SIDs.",
                "Confirm the browser belongs to the intended interactive user."});
        }

        if (comparison.targetAppContainer) {
            results.push_back({"R011", DiagnosisSeverity::Warning,
                "Target AppContainer",
                "Target process is running inside an AppContainer.",
                "Treat window messages and input automation as potentially restricted."});
        }

        if (!comparison.sourceUIAccess && comparison.sourceIntegrityLowerThanTarget) {
            results.push_back({"R012", DiagnosisSeverity::Warning,
                "Missing UIAccess",
                "Source has no UIAccess while its integrity level is lower than target.",
                "UIAccess cannot mitigate the UIPI barrier for this source process."});
        }

        return results;
    }

    ComparisonResult compare(const ProcessSecurityContext& source, const ProcessSecurityContext& target) const {
        ComparisonResult result;
        result.sourcePid = source.process.pid;
        result.targetPid = target.process.pid;
        result.sameSession = source.session.processSessionId == target.session.processSessionId;
        result.sameUserSid =
            source.token.userSid.available &&
            target.token.userSid.available &&
            source.token.userSid.value == target.token.userSid.value;
        result.sameWindowStation =
            source.desktop.windowStation.available &&
            target.desktop.windowStation.available &&
            source.desktop.windowStation.value == target.desktop.windowStation.value;
        result.sameDesktop =
            source.desktop.desktop.available &&
            target.desktop.desktop.available &&
            source.desktop.desktop.value == target.desktop.desktop.value;
        result.sourceIntegrityLowerThanTarget =
            rank(source.token.integrityLevel) < rank(target.token.integrityLevel);
        result.sourceAppContainer = source.token.appContainer.available && source.token.appContainer.value;
        result.targetAppContainer = target.token.appContainer.available && target.token.appContainer.value;
        result.sourceUIAccess = source.token.uiAccess.available && source.token.uiAccess.value;
        result.targetUIAccess = target.token.uiAccess.available && target.token.uiAccess.value;
        return result;
    }

    DiagnosisSeverity overallSeverity(const std::vector<RuleResult>& results) const {
        DiagnosisSeverity severity = DiagnosisSeverity::Info;
        for (const auto& result : results) {
            if (severity_rank(result.severity) > severity_rank(severity)) {
                severity = result.severity;
            }
        }
        return severity;
    }

private:
    static int rank(const FieldValue<IntegrityLevel>& level) {
        if (!level.available) {
            return 0;
        }

        switch (level.value) {
        case IntegrityLevel::Untrusted:
            return 1;
        case IntegrityLevel::Low:
            return 2;
        case IntegrityLevel::Medium:
            return 3;
        case IntegrityLevel::MediumPlus:
            return 4;
        case IntegrityLevel::High:
            return 5;
        case IntegrityLevel::System:
            return 6;
        case IntegrityLevel::ProtectedProcess:
            return 7;
        case IntegrityLevel::Unknown:
        default:
            return 0;
        }
    }

    static int severity_rank(DiagnosisSeverity severity) {
        switch (severity) {
        case DiagnosisSeverity::Info:
            return 0;
        case DiagnosisSeverity::Notice:
            return 1;
        case DiagnosisSeverity::Warning:
            return 2;
        case DiagnosisSeverity::Error:
            return 3;
        case DiagnosisSeverity::Critical:
            return 4;
        default:
            return 0;
        }
    }
};

} // namespace wpsi
