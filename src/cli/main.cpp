#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <Windows.h>

#include "wpsi/common/string_utils.h"
#include "wpsi/diagnosis/rule_engine.h"
#include "wpsi/inspectors/process_inspector.h"
#include "wpsi/inspectors/session_inspector.h"
#include "wpsi/inspectors/token_inspector.h"
#include "wpsi/report/json_exporter.h"

namespace {

std::wstring integrity_name(wpsi::IntegrityLevel level) {
    switch (level) {
    case wpsi::IntegrityLevel::Untrusted:
        return L"Untrusted";
    case wpsi::IntegrityLevel::Low:
        return L"Low";
    case wpsi::IntegrityLevel::Medium:
        return L"Medium";
    case wpsi::IntegrityLevel::MediumPlus:
        return L"Medium Plus";
    case wpsi::IntegrityLevel::High:
        return L"High";
    case wpsi::IntegrityLevel::System:
        return L"System";
    case wpsi::IntegrityLevel::ProtectedProcess:
        return L"Protected Process";
    case wpsi::IntegrityLevel::Unknown:
    default:
        return L"Unknown";
    }
}

std::wstring elevation_name(wpsi::ElevationType type) {
    switch (type) {
    case wpsi::ElevationType::Default:
        return L"Default";
    case wpsi::ElevationType::Full:
        return L"Full";
    case wpsi::ElevationType::Limited:
        return L"Limited";
    case wpsi::ElevationType::Unknown:
    default:
        return L"Unknown";
    }
}

void print_help() {
    std::cout
        << "wpsi inspect [--pid <pid>] [--format text|json] [--output <path>]\n"
        << "wpsi compare --pid <pid1> --pid <pid2> [--format text|json] [--output <path>]\n"
        << "wpsi --help\n";
}

bool parse_pid(const char* text, DWORD& pid) {
    try {
        const auto parsed = std::stoul(text);
        if (parsed > 0xFFFFFFFFul) {
            return false;
        }
        pid = static_cast<DWORD>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool write_output_file(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    file << content;
    return static_cast<bool>(file);
}

struct CapturedProcess {
    wpsi::ProcessSecurityContext context;
    bool ok = false;
    bool partial = false;
    unsigned long error = 0;
};

CapturedProcess capture_process(DWORD pid) {
    wpsi::ProcessInspector processInspector;
    wpsi::SessionInspector sessionInspector;
    wpsi::TokenInspector tokenInspector;

    CapturedProcess captured;
    const auto process = processInspector.inspect(pid);
    if (!process.ok) {
        captured.error = process.error.win32Error;
        return captured;
    }

    const auto session = sessionInspector.inspect(pid, process.value.sessionId);
    const auto token = tokenInspector.inspect(pid, false);
    captured.context.process = process.value;
    captured.context.session = session.value;
    if (token.ok) {
        captured.context.token = token.value;
    }
    captured.ok = true;
    captured.partial = process.partial || session.partial || token.partial || !token.ok;
    return captured;
}

int inspect_process(DWORD pid, bool json, const std::string& outputPath) {
    const auto captured = capture_process(pid);
    if (!captured.ok) {
        std::cerr << "Failed to inspect process. Win32 error: " << captured.error << '\n';
        return 2;
    }

    const auto& process = captured.context.process;
    const auto& session = captured.context.session;
    const auto& token = captured.context.token;

    if (json) {
        wpsi::DiagnosisReport report;
        report.processes.push_back(captured.context);
        const auto payload = wpsi::exportDiagnosisReportJson(report) + "\n";
        if (!outputPath.empty()) {
            return write_output_file(outputPath, payload) ? 0 : 3;
        }
        std::cout << payload;
        return 0;
    }

    std::wcout << L"[Process]\n";
    std::wcout << L"PID : " << process.pid << L"\n";
    std::wcout << L"Name : " << process.processName << L"\n";
    if (process.executablePath.available) {
        std::wcout << L"Path : " << process.executablePath.value << L"\n";
    }
    std::wcout << L"Session ID : " << session.processSessionId << L"\n";
    if (process.priorityClassName.available) {
        std::wcout << L"Priority Class : " << process.priorityClassName.value << L"\n";
    }

    std::wcout << L"\n[Token]\n";
    if (token.userSid.available) {
        std::wcout << L"User SID : " << token.userSid.value << L"\n";
    }
    if (token.integrityLevel.available) {
        std::wcout << L"Integrity Level : " << integrity_name(token.integrityLevel.value) << L"\n";
    }
    if (token.integrityRid.available) {
        std::wcout << L"Integrity RID : 0x" << std::hex << token.integrityRid.value << std::dec << L"\n";
    }
    if (token.elevated.available) {
        std::wcout << L"Elevated : " << (token.elevated.value ? L"Yes" : L"No") << L"\n";
    }
    if (token.elevationType.available) {
        std::wcout << L"Elevation Type : " << elevation_name(token.elevationType.value) << L"\n";
    }

    if (captured.partial) {
        std::wcout << L"\n[Notice]\nPartial data returned. Run as administrator for more complete results.\n";
    }

    return 0;
}

int inspect_by_name(const std::wstring& name, bool json, const std::string& outputPath) {
    wpsi::ProcessInspector processInspector;
    const auto matches = processInspector.findByName(name);
    if (!matches.ok) {
        std::cerr << "Failed to enumerate processes. Win32 error: " << matches.error.win32Error << '\n';
        return 4;
    }
    if (matches.value.empty()) {
        std::cerr << "No process matched the requested name\n";
        return 2;
    }

    wpsi::DiagnosisReport report;
    for (const auto pid : matches.value) {
        const auto captured = capture_process(pid);
        if (captured.ok) {
            report.processes.push_back(captured.context);
        }
    }

    if (json) {
        const auto payload = wpsi::exportDiagnosisReportJson(report) + "\n";
        if (!outputPath.empty()) {
            return write_output_file(outputPath, payload) ? 0 : 3;
        }
        std::cout << payload;
        return 0;
    }

    for (const auto& process : report.processes) {
        std::wcout << L"[Process]\n";
        std::wcout << L"PID : " << process.process.pid << L"\n";
        std::wcout << L"Name : " << process.process.processName << L"\n\n";
    }

    return report.processes.empty() ? 2 : 0;
}

int compare_processes(DWORD sourcePid, DWORD targetPid, bool json, const std::string& outputPath) {
    const auto source = capture_process(sourcePid);
    const auto target = capture_process(targetPid);
    if (!source.ok || !target.ok) {
        std::cerr << "Failed to inspect one or more processes\n";
        return 2;
    }

    wpsi::DiagnosisContext context;
    context.source = source.context;
    context.target = target.context;

    wpsi::RuleEngine engine;
    wpsi::DiagnosisReport report;
    report.processes.push_back(source.context);
    report.processes.push_back(target.context);
    report.comparison = engine.compare(source.context, target.context);
    report.ruleResults = engine.evaluate(context);
    report.overallSeverity = engine.overallSeverity(report.ruleResults);

    if (json) {
        const auto payload = wpsi::exportDiagnosisReportJson(report) + "\n";
        if (!outputPath.empty()) {
            return write_output_file(outputPath, payload) ? 0 : 3;
        }
        std::cout << payload;
        return 0;
    }

    const auto& comparison = *report.comparison;
    std::wcout << L"[Comparison]\n";
    std::wcout << L"Source PID : " << comparison.sourcePid << L"\n";
    std::wcout << L"Target PID : " << comparison.targetPid << L"\n";
    std::wcout << L"Same Session : " << (comparison.sameSession ? L"Yes" : L"No") << L"\n";
    std::wcout << L"Same User SID : " << (comparison.sameUserSid ? L"Yes" : L"No") << L"\n";
    std::wcout << L"Source IL Lower Than Target : "
               << (comparison.sourceIntegrityLowerThanTarget ? L"Yes" : L"No") << L"\n";

    if (!report.ruleResults.empty()) {
        std::wcout << L"\n[Diagnosis]\n";
        for (const auto& rule : report.ruleResults) {
            std::cout << rule.ruleId << " : " << rule.title << "\n";
        }
    }

    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc <= 1 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        print_help();
        return argc <= 1 ? 1 : 0;
    }

    const std::string command = argv[1];
    if (command != "inspect" && command != "compare") {
        print_help();
        return 1;
    }

    DWORD pid = GetCurrentProcessId();
    DWORD secondPid = 0;
    bool json = false;
    std::string outputPath;
    std::wstring processName;
    std::vector<DWORD> pids;
    for (int i = 2; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--pid") {
            if (i + 1 >= argc || !parse_pid(argv[i + 1], pid)) {
                std::cerr << "Invalid --pid value\n";
                return 1;
            }
            if (pid == 0) {
                pid = GetCurrentProcessId();
            }
            pids.push_back(pid);
            ++i;
        } else if (argument == "--format") {
            if (i + 1 >= argc) {
                std::cerr << "Missing --format value\n";
                return 1;
            }
            const std::string format = argv[++i];
            if (format == "json") {
                json = true;
            } else if (format == "text") {
                json = false;
            } else {
                std::cerr << "Unsupported format: " << format << '\n';
                return 1;
            }
        } else if (argument == "--output") {
            if (i + 1 >= argc) {
                std::cerr << "Missing --output value\n";
                return 1;
            }
            outputPath = argv[++i];
        } else if (argument == "--name") {
            if (i + 1 >= argc) {
                std::cerr << "Missing --name value\n";
                return 1;
            }
            const std::string rawName = argv[++i];
            processName.assign(rawName.begin(), rawName.end());
        } else {
            std::cerr << "Unknown argument: " << argument << '\n';
            return 1;
        }
    }

    if (command == "compare") {
        if (pids.size() < 2) {
            std::cerr << "compare requires two --pid values\n";
            return 1;
        }
        return compare_processes(pids[0], pids[1], json, outputPath);
    }

    if (!pids.empty()) {
        pid = pids[0];
    }
    if (!processName.empty()) {
        return inspect_by_name(processName, json, outputPath);
    }
    return inspect_process(pid, json, outputPath);
}
