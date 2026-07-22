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

        const bool sourceService =
            context.source->session.sessionZero ||
            context.source->session.processSessionId == 0 ||
            context.source->process.serviceName.available ||
            context.source->service.has_value();
        const auto targetName = lower_ascii(context.target->process.processName);
        const bool targetBrowser =
            targetName == "chrome.exe" || targetName == "msedge.exe" || targetName == "firefox.exe";
        if (sourceService && targetBrowser && context.source->session.processSessionId != context.target->session.processSessionId) {
            results.push_back({"R004", DiagnosisSeverity::Critical,
                "Session 0 service desktop isolation",
                "A service/session-0 source is targeting a user-session browser.",
                "Do not directly operate user desktop windows from a service; use a user-session agent or IPC."});
        }

        if (context.browser && context.browser->mainProcessPid.available &&
            context.browser->inputPid != 0 && context.browser->inputPid != context.browser->mainProcessPid.value) {
            results.push_back({"R005", DiagnosisSeverity::Warning,
                "Browser child process PID",
                "Input PID is not the browser main process.",
                "Use the resolved browser main process PID and top-level window for desktop interaction."});
        }

        if (context.browser && context.browser->mainProcessPid.available &&
            context.browser->candidateWindows.empty()) {
            results.push_back({"R006", DiagnosisSeverity::Warning,
                "No visible browser top-level window",
                "No visible top-level window was found for the resolved browser main process.",
                "Continue locating the browser instance through parent process or foreground window evidence."});
        }

        if (!context.source->compatibilityLayers.empty() || !context.target->compatibilityLayers.empty()) {
            results.push_back({"R009", DiagnosisSeverity::Notice,
                "AppCompat compatibility layer",
                "At least one process has AppCompat compatibility layers configured.",
                "Check RUNASADMIN/RUNASINVOKER and other layer overrides before diagnosing UAC behavior."});
        }

        if (context.source->desktop.desktop.available && context.target->desktop.desktop.available &&
            context.source->desktop.desktop.value != context.target->desktop.desktop.value) {
            results.push_back({"R010", DiagnosisSeverity::Critical,
                "Desktop mismatch",
                "Source and target are associated with different desktops.",
                "Do not rely on direct window interaction across desktop boundaries."});
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

    static std::string lower_ascii(std::wstring_view text) {
        std::string value;
        value.reserve(text.size());
        for (const auto ch : text) {
            char out = static_cast<char>(ch >= L'A' && ch <= L'Z' ? ch - L'A' + L'a' : ch);
            value.push_back(out);
        }
        return value;
    }
};

} // namespace wpsi
