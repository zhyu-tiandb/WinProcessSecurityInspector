#pragma once

#include <sstream>

#include "wpsi/common/string_utils.h"
#include "wpsi/report/json_exporter.h"

namespace wpsi {

inline std::string exportDiagnosisReportMarkdown(const DiagnosisReport& report) {
    std::ostringstream out;
    out << "# WPSI Diagnosis Report\n\n";
    out << "- Overall Severity: " << severity_name(report.overallSeverity) << "\n";
    out << "- Process Count: " << report.processes.size() << "\n\n";

    out << "## Processes\n\n";
    for (const auto& process : report.processes) {
        out << "### " << to_utf8(process.process.processName) << " (" << process.process.pid << ")\n\n";
        out << "- Session ID: " << process.session.processSessionId << "\n";
        if (process.process.executablePath.available) {
            out << "- Path: `" << to_utf8(process.process.executablePath.value) << "`\n";
        }
        if (process.token.userSid.available) {
            out << "- User SID: `" << to_utf8(redactSid(process.token.userSid.value)) << "`\n";
        }
        if (process.desktop.desktop.available) {
            out << "- Desktop: `" << to_utf8(process.desktop.desktop.value) << "`\n";
        }
        if (!process.compatibilityLayers.empty()) {
            out << "- AppCompat: `" << to_utf8(process.compatibilityLayers.front()) << "`\n";
        }
        if (process.service.has_value()) {
            out << "- Service: `" << to_utf8(process.service->serviceName) << "`\n";
        }
        out << "\n";
    }

    if (report.browser.inputPid != 0 || report.browser.mainProcessPid.available) {
        out << "## Browser\n\n";
        out << "- Input PID: " << report.browser.inputPid << "\n";
        out << "- Role: " << browser_role_name(report.browser.role) << "\n";
        if (report.browser.mainProcessPid.available) {
            out << "- Main PID: " << report.browser.mainProcessPid.value << "\n";
        }
        out << "- Candidate Windows: " << report.browser.candidateWindows.size() << "\n\n";
    }

    out << "## Diagnosis\n\n";
    if (report.ruleResults.empty()) {
        out << "No diagnosis rules matched.\n";
    }
    for (const auto& rule : report.ruleResults) {
        out << "- **" << rule.ruleId << " [" << severity_name(rule.severity) << "]** "
            << rule.title << ": " << rule.evidence << " Recommendation: " << rule.recommendation << "\n";
    }
    return out.str();
}

} // namespace wpsi
