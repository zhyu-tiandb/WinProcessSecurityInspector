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

inline const char* browser_role_name(BrowserProcessRole role) {
    switch (role) {
    case BrowserProcessRole::Main: return "Main";
    case BrowserProcessRole::Renderer: return "Renderer";
    case BrowserProcessRole::NetworkService: return "NetworkService";
    case BrowserProcessRole::GpuProcess: return "GpuProcess";
    case BrowserProcessRole::Utility: return "Utility";
    case BrowserProcessRole::CrashHandler: return "CrashHandler";
    case BrowserProcessRole::Extension: return "Extension";
    default: return "Unknown";
    }
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
        if (process.desktop.windowStation.available) {
            out << ",\"windowStation\":" << json_string(process.desktop.windowStation.value);
        }
        if (process.desktop.desktop.available) {
            out << ",\"desktop\":" << json_string(process.desktop.desktop.value);
        }
        if (!process.compatibilityLayers.empty()) {
            out << ",\"compatibilityLayers\":[";
            for (size_t j = 0; j < process.compatibilityLayers.size(); ++j) {
                if (j != 0) {
                    out << ",";
                }
                out << json_string(process.compatibilityLayers[j]);
            }
            out << "]";
        }
        if (process.service.has_value()) {
            out << ",\"service\":{\"name\":" << json_string(process.service->serviceName);
            if (process.service->displayName.available) {
                out << ",\"displayName\":" << json_string(process.service->displayName.value);
            }
            if (process.service->state.available) {
                out << ",\"state\":" << json_string(process.service->state.value);
            }
            out << "}";
        }
        if (process.manifest.requestedExecutionLevel.available || process.manifest.uiAccess.available) {
            out << ",\"manifest\":{";
            bool wroteManifestField = false;
            if (process.manifest.requestedExecutionLevel.available) {
                out << "\"requestedExecutionLevel\":" << json_string(process.manifest.requestedExecutionLevel.value);
                wroteManifestField = true;
            }
            if (process.manifest.uiAccess.available) {
                if (wroteManifestField) {
                    out << ",";
                }
                out << "\"uiAccess\":" << (process.manifest.uiAccess.value ? "true" : "false");
            }
            out << "}";
        }
        if (process.signature.signedFile.available) {
            out << ",\"signature\":{\"signed\":" << (process.signature.signedFile.value ? "true" : "false");
            if (process.signature.valid.available) {
                out << ",\"valid\":" << (process.signature.valid.value ? "true" : "false");
            }
            out << "}";
        }
        if (!process.startupSources.empty()) {
            out << ",\"startupSources\":[";
            for (size_t j = 0; j < process.startupSources.size(); ++j) {
                if (j != 0) {
                    out << ",";
                }
                out << "{\"type\":" << json_string(process.startupSources[j].sourceType)
                    << ",\"name\":" << json_string(process.startupSources[j].name)
                    << ",\"command\":" << json_string(redactCommandLine(process.startupSources[j].command)) << "}";
            }
            out << "]";
        }
        if (!process.windows.empty()) {
            out << ",\"windows\":[";
            for (size_t j = 0; j < process.windows.size(); ++j) {
                const auto& window = process.windows[j];
                if (j != 0) {
                    out << ",";
                }
                out << "{\"hwnd\":\"0x" << std::hex << reinterpret_cast<uintptr_t>(window.hwnd) << std::dec << "\",";
                out << "\"ownerPid\":" << window.ownerPid << ",";
                out << "\"title\":" << json_string(window.title) << ",";
                out << "\"className\":" << json_string(window.className) << ",";
                out << "\"visible\":" << (window.visible ? "true" : "false") << "}";
            }
            out << "]";
        }
        out << "}";
    }
    out << "],";

    out << "\"browser\":{";
    out << "\"inputPid\":" << report.browser.inputPid << ",";
    out << "\"role\":\"" << browser_role_name(report.browser.role) << "\"";
    if (report.browser.mainProcessPid.available) {
        out << ",\"mainProcessPid\":" << report.browser.mainProcessPid.value;
    }
    out << ",\"candidateWindowCount\":" << report.browser.candidateWindows.size();
    out << "},";

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
