#pragma once

#include <sstream>
#include <string>

#include "wpsi/common/string_utils.h"
#include "wpsi/core/context.h"

namespace wpsi {

inline const char* severity_name(DiagnosisSeverity severity) {
    switch (severity) {
    case DiagnosisSeverity::Info:
        return "INFO";
    case DiagnosisSeverity::Notice:
        return "NOTICE";
    case DiagnosisSeverity::Warning:
        return "WARNING";
    case DiagnosisSeverity::Error:
        return "ERROR";
    case DiagnosisSeverity::Critical:
        return "CRITICAL";
    default:
        return "INFO";
    }
}

inline std::string json_escape(std::string_view value) {
    std::string result;
    for (char ch : value) {
        switch (ch) {
        case '\\':
            result += "\\\\";
            break;
        case '"':
            result += "\\\"";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        default:
            result += ch;
            break;
        }
    }
    return result;
}

inline std::string json_string(const std::wstring& value) {
    return "\"" + json_escape(to_utf8(value)) + "\"";
}

inline std::string json_string(std::string_view value) {
    return "\"" + json_escape(value) + "\"";
}

inline std::string exportDiagnosisReportJson(const DiagnosisReport& report, bool redactSensitiveData = true) {
    std::ostringstream out;
    out << "{";
    out << "\"summary\":{\"overallSeverity\":\"" << severity_name(report.overallSeverity) << "\"},";

    out << "\"processes\":[";
    for (size_t i = 0; i < report.processes.size(); ++i) {
        const auto& process = report.processes[i];
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"pid\":" << process.process.pid << ",";
        out << "\"sessionId\":" << process.session.processSessionId;
        if (process.process.processName.size() > 0) {
            out << ",\"name\":" << json_string(process.process.processName);
        }
        if (process.process.executablePath.available) {
            out << ",\"path\":" << json_string(process.process.executablePath.value);
        }
        if (process.token.userSid.available) {
            const auto sid = redactSensitiveData ? redactSid(process.token.userSid.value) : process.token.userSid.value;
            out << ",\"userSid\":" << json_string(sid);
        }
        if (process.token.integrityLevel.available) {
            out << ",\"integrityLevel\":" << static_cast<int>(process.token.integrityLevel.value);
        }
        if (process.token.elevated.available) {
            out << ",\"elevated\":" << (process.token.elevated.value ? "true" : "false");
        }
        out << "}";
    }
    out << "],";

    out << "\"diagnosis\":[";
    for (size_t i = 0; i < report.ruleResults.size(); ++i) {
        const auto& rule = report.ruleResults[i];
        if (i != 0) {
            out << ",";
        }
        out << "{";
        out << "\"ruleId\":" << json_string(rule.ruleId) << ",";
        out << "\"severity\":\"" << severity_name(rule.severity) << "\",";
        out << "\"title\":" << json_string(rule.title) << ",";
        out << "\"evidence\":" << json_string(rule.evidence) << ",";
        out << "\"recommendation\":" << json_string(rule.recommendation);
        out << "}";
    }
    out << "]";

    if (report.comparison.has_value()) {
        const auto& comparison = *report.comparison;
        out << ",\"comparison\":{";
        out << "\"sourcePid\":" << comparison.sourcePid << ",";
        out << "\"targetPid\":" << comparison.targetPid << ",";
        out << "\"sameSession\":" << (comparison.sameSession ? "true" : "false") << ",";
        out << "\"sameUserSid\":" << (comparison.sameUserSid ? "true" : "false") << ",";
        out << "\"sourceIntegrityLowerThanTarget\":"
            << (comparison.sourceIntegrityLowerThanTarget ? "true" : "false");
        out << "}";
    }

    out << "}";
    return out.str();
}

} // namespace wpsi
