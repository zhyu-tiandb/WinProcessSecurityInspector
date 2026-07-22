#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <Windows.h>

#include "wpsi/common/string_utils.h"
#include "wpsi/diagnosis/rule_engine.h"
#include "wpsi/inspectors/browser_inspector.h"
#include "wpsi/inspectors/compatibility_inspector.h"
#include "wpsi/inspectors/desktop_inspector.h"
#include "wpsi/inspectors/manifest_inspector.h"
#include "wpsi/inspectors/process_inspector.h"
#include "wpsi/inspectors/service_inspector.h"
#include "wpsi/inspectors/signature_inspector.h"
#include "wpsi/inspectors/startup_inspector.h"
#include "wpsi/inspectors/session_inspector.h"
#include "wpsi/inspectors/token_inspector.h"
#include "wpsi/inspectors/window_inspector.h"
#include "wpsi/report/html_exporter.h"
#include "wpsi/report/json_exporter.h"
#include "wpsi/report/markdown_exporter.h"

namespace {

enum class OutputFormat {
    Text,
    Json,
    Markdown,
    Html
};

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
        << "wpsi inspect [--pid <pid>] [--name <process>] [--format text|json|markdown|html] [--output <path>]\n"
        << "wpsi compare --pid <pid1> --pid <pid2> [--format text|json|markdown|html] [--output <path>]\n"
        << "wpsi browser --network-pid <pid> [--format text|json|markdown|html] [--output <path>]\n"
        << "wpsi windows --pid <pid>\n"
        << "wpsi tree --pid <pid>\n"
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

std::string export_report(const wpsi::DiagnosisReport& report, OutputFormat format) {
    switch (format) {
    case OutputFormat::Json:
        return wpsi::exportDiagnosisReportJson(report) + "\n";
    case OutputFormat::Markdown:
        return wpsi::exportDiagnosisReportMarkdown(report) + "\n";
    case OutputFormat::Html:
        return wpsi::exportDiagnosisReportHtml(report) + "\n";
    case OutputFormat::Text:
    default:
        return {};
    }
}

struct CapturedProcess {
    wpsi::ProcessSecurityContext context;
    bool ok = false;
    bool partial = false;
    unsigned long error = 0;
};

struct ProcessSelector {
    bool hasPid = false;
    DWORD pid = 0;
    std::wstring name;
};

CapturedProcess capture_process(DWORD pid) {
    wpsi::ProcessInspector processInspector;
    wpsi::SessionInspector sessionInspector;
    wpsi::TokenInspector tokenInspector;
    wpsi::DesktopInspector desktopInspector;
    wpsi::WindowInspector windowInspector;
    wpsi::CompatibilityInspector compatibilityInspector;
    wpsi::ManifestInspector manifestInspector;
    wpsi::ServiceInspector serviceInspector;
    wpsi::SignatureInspector signatureInspector;
    wpsi::StartupInspector startupInspector;

    CapturedProcess captured;
    const auto process = processInspector.inspect(pid);
    if (!process.ok) {
        captured.error = process.error.win32Error;
        return captured;
    }

    const auto session = sessionInspector.inspect(pid, process.value.sessionId);
    const auto token = tokenInspector.inspect(pid, true);
    const auto desktop = desktopInspector.inspectCurrentThread();
    const auto windows = windowInspector.enumerateWindowsForPid(pid);
    const auto service = serviceInspector.inspectByPid(pid);
    captured.context.process = process.value;
    captured.context.session = session.value;
    captured.context.desktop = desktop.value;
    if (windows.ok) {
        captured.context.windows = windows.value;
    }
    if (service.ok && service.value.has_value()) {
        captured.context.service = service.value;
        captured.context.process.serviceName.value = service.value->serviceName;
        captured.context.process.serviceName.available = true;
    }
    if (process.value.executablePath.available) {
        const auto layers = compatibilityInspector.inspectLayers(process.value.executablePath.value);
        if (layers.ok) {
            captured.context.compatibilityLayers = layers.value;
        }
        const auto manifest = manifestInspector.inspect(process.value.executablePath.value);
        if (manifest.ok) {
            captured.context.manifest = manifest.value;
        }
        const auto signature = signatureInspector.inspect(process.value.executablePath.value);
        if (signature.ok) {
            captured.context.signature = signature.value;
        }
        const auto startupSources = startupInspector.inspect(process.value.executablePath.value);
        if (startupSources.ok) {
            captured.context.startupSources = startupSources.value;
        }
    }
    if (token.ok) {
        captured.context.token = token.value;
    }
    captured.ok = true;
    captured.partial =
        process.partial || session.partial || token.partial || desktop.partial ||
        !token.ok || !windows.ok || service.partial;
    return captured;
}

bool resolve_selector(const ProcessSelector& selector, DWORD& pid) {
    if (selector.hasPid) {
        pid = selector.pid == 0 ? GetCurrentProcessId() : selector.pid;
        return true;
    }

    wpsi::ProcessInspector processInspector;
    const auto matches = processInspector.findByName(selector.name);
    if (!matches.ok || matches.value.empty()) {
        return false;
    }

    for (const auto candidatePid : matches.value) {
        const auto captured = capture_process(candidatePid);
        if (captured.ok) {
            pid = candidatePid;
            return true;
        }
    }
    return false;
}

void print_process_text(const CapturedProcess& captured) {
    const auto& process = captured.context.process;
    const auto& session = captured.context.session;
    const auto& token = captured.context.token;

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
    if (captured.context.desktop.windowStation.available) {
        std::wcout << L"Window Station : " << captured.context.desktop.windowStation.value << L"\n";
    }
    if (captured.context.desktop.desktop.available) {
        std::wcout << L"Desktop : " << captured.context.desktop.desktop.value << L"\n";
    }
    if (captured.context.service.has_value()) {
        std::wcout << L"Service : " << captured.context.service->serviceName << L"\n";
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
    if (token.uiAccess.available) {
        std::wcout << L"UIAccess : " << (token.uiAccess.value ? L"Yes" : L"No") << L"\n";
    }
    if (token.appContainer.available) {
        std::wcout << L"AppContainer : " << (token.appContainer.value ? L"Yes" : L"No") << L"\n";
    }

    if (!captured.context.compatibilityLayers.empty()) {
        std::wcout << L"\n[Compatibility]\n";
        for (const auto& layer : captured.context.compatibilityLayers) {
            std::wcout << L"Layer : " << layer << L"\n";
        }
    }

    if (captured.context.manifest.requestedExecutionLevel.available || captured.context.manifest.uiAccess.available) {
        std::wcout << L"\n[Manifest]\n";
        if (captured.context.manifest.requestedExecutionLevel.available) {
            std::wcout << L"Requested Execution Level : "
                       << captured.context.manifest.requestedExecutionLevel.value << L"\n";
        }
        if (captured.context.manifest.uiAccess.available) {
            std::wcout << L"Manifest UIAccess : "
                       << (captured.context.manifest.uiAccess.value ? L"true" : L"false") << L"\n";
        }
    }

    if (captured.context.signature.signedFile.available) {
        std::wcout << L"\n[Signature]\n";
        std::wcout << L"Signed : " << (captured.context.signature.signedFile.value ? L"Yes" : L"No") << L"\n";
        if (captured.context.signature.valid.available) {
            std::wcout << L"Valid : " << (captured.context.signature.valid.value ? L"Yes" : L"No") << L"\n";
        }
    }

    if (!captured.context.startupSources.empty()) {
        std::wcout << L"\n[Startup]\n";
        for (const auto& source : captured.context.startupSources) {
            std::wcout << source.sourceType << L" : " << source.name << L"\n";
        }
    }

    if (!captured.context.windows.empty()) {
        std::wcout << L"\n[Windows]\n";
        for (const auto& window : captured.context.windows) {
            std::wcout << L"HWND : 0x" << std::hex << reinterpret_cast<uintptr_t>(window.hwnd) << std::dec
                       << L" Visible : " << (window.visible ? L"Yes" : L"No")
                       << L" Title : " << window.title << L"\n";
        }
    }

    if (captured.partial) {
        std::wcout << L"\n[Notice]\nPartial data returned. Run as administrator for more complete results.\n";
    }
}

int write_report_or_stdout(const wpsi::DiagnosisReport& report, OutputFormat format, const std::string& outputPath) {
    const auto payload = export_report(report, format);
    if (!outputPath.empty()) {
        return write_output_file(outputPath, payload) ? 0 : 3;
    }
    std::cout << payload;
    return 0;
}

int inspect_process(DWORD pid, OutputFormat format, const std::string& outputPath) {
    const auto captured = capture_process(pid);
    if (!captured.ok) {
        std::cerr << "Failed to inspect process. Win32 error: " << captured.error << '\n';
        return 2;
    }

    if (format != OutputFormat::Text) {
        wpsi::DiagnosisReport report;
        report.processes.push_back(captured.context);
        return write_report_or_stdout(report, format, outputPath);
    }

    print_process_text(captured);
    return 0;
}

int inspect_by_name(const std::wstring& name, OutputFormat format, const std::string& outputPath) {
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
    std::vector<CapturedProcess> capturedProcesses;
    for (const auto pid : matches.value) {
        const auto captured = capture_process(pid);
        if (captured.ok) {
            capturedProcesses.push_back(captured);
            report.processes.push_back(captured.context);
        }
    }

    if (format != OutputFormat::Text) {
        return write_report_or_stdout(report, format, outputPath);
    }

    for (size_t i = 0; i < capturedProcesses.size(); ++i) {
        if (i > 0) {
            std::wcout << L"\n";
        }
        print_process_text(capturedProcesses[i]);
        std::wcout << L"\n";
    }

    return report.processes.empty() ? 2 : 0;
}

int compare_processes(DWORD sourcePid, DWORD targetPid, OutputFormat format, const std::string& outputPath) {
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

    if (format != OutputFormat::Text) {
        return write_report_or_stdout(report, format, outputPath);
    }

    const auto& comparison = *report.comparison;
    std::wcout << L"[Comparison]\n";
    std::wcout << L"Source PID : " << comparison.sourcePid << L"\n";
    std::wcout << L"Source Name : " << source.context.process.processName << L"\n";
    std::wcout << L"Target PID : " << comparison.targetPid << L"\n";
    std::wcout << L"Target Name : " << target.context.process.processName << L"\n";
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

int browser_process(DWORD networkPid, OutputFormat format, const std::string& outputPath) {
    wpsi::BrowserInspector browserInspector;
    const auto browser = browserInspector.inspect(networkPid);
    if (!browser.ok) {
        std::cerr << "Failed to inspect browser process. Win32 error: " << browser.error.win32Error << '\n';
        return 2;
    }

    wpsi::DiagnosisReport report;
    report.browser = browser.value;
    if (browser.value.mainProcessPid.available) {
        const auto captured = capture_process(browser.value.mainProcessPid.value);
        if (captured.ok) {
            report.processes.push_back(captured.context);
            wpsi::DiagnosisContext context;
            context.source = capture_process(GetCurrentProcessId()).context;
            context.target = captured.context;
            context.browser = browser.value;
            wpsi::RuleEngine engine;
            report.comparison = engine.compare(*context.source, *context.target);
            report.ruleResults = engine.evaluate(context);
            report.overallSeverity = engine.overallSeverity(report.ruleResults);
        }
    }

    if (format != OutputFormat::Text) {
        return write_report_or_stdout(report, format, outputPath);
    }

    std::wcout << L"[Browser]\n";
    std::wcout << L"Input PID : " << browser.value.inputPid << L"\n";
    if (browser.value.mainProcessPid.available) {
        std::wcout << L"Main PID : " << browser.value.mainProcessPid.value << L"\n";
    }
    std::cout << "Role : " << wpsi::browser_role_name(browser.value.role) << "\n";
    std::wcout << L"Candidate Windows : " << browser.value.candidateWindows.size() << L"\n";
    return 0;
}

int windows_for_process(DWORD pid) {
    wpsi::WindowInspector inspector;
    const auto windows = inspector.enumerateWindowsForPid(pid);
    if (!windows.ok) {
        std::cerr << "Failed to enumerate windows\n";
        return 4;
    }
    std::wcout << L"[Windows]\n";
    for (const auto& window : windows.value) {
        std::wcout << L"HWND : 0x" << std::hex << reinterpret_cast<uintptr_t>(window.hwnd) << std::dec
                   << L" PID : " << window.ownerPid
                   << L" Visible : " << (window.visible ? L"Yes" : L"No")
                   << L" Class : " << window.className
                   << L" Title : " << window.title << L"\n";
    }
    return 0;
}

int process_tree(DWORD pid) {
    wpsi::ProcessInspector inspector;
    const auto parents = inspector.parentChainOf(pid);
    const auto children = inspector.childrenOf(pid);
    std::wcout << L"[Tree]\n";
    std::wcout << L"PID : " << pid << L"\n";
    std::wcout << L"Parents :";
    for (const auto parent : parents.value) {
        std::wcout << L" " << parent;
    }
    std::wcout << L"\nChildren :";
    for (const auto child : children.value) {
        std::wcout << L" " << child;
    }
    std::wcout << L"\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc <= 1 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        print_help();
        return argc <= 1 ? 1 : 0;
    }

    const std::string command = argv[1];
    if (command != "inspect" && command != "compare" && command != "browser" &&
        command != "windows" && command != "tree") {
        print_help();
        return 1;
    }

    DWORD pid = GetCurrentProcessId();
    DWORD networkPid = 0;
    OutputFormat format = OutputFormat::Text;
    std::string outputPath;
    std::wstring processName;
    std::vector<DWORD> pids;
    std::vector<ProcessSelector> compareSelectors;
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
            compareSelectors.push_back({true, pid, L""});
            ++i;
        } else if (argument == "--format") {
            if (i + 1 >= argc) {
                std::cerr << "Missing --format value\n";
                return 1;
            }
            const std::string requestedFormat = argv[++i];
            if (requestedFormat == "json") {
                format = OutputFormat::Json;
            } else if (requestedFormat == "text") {
                format = OutputFormat::Text;
            } else if (requestedFormat == "markdown") {
                format = OutputFormat::Markdown;
            } else if (requestedFormat == "html") {
                format = OutputFormat::Html;
            } else {
                std::cerr << "Unsupported format: " << requestedFormat << '\n';
                return 1;
            }
        } else if (argument == "--network-pid") {
            if (i + 1 >= argc || !parse_pid(argv[i + 1], networkPid)) {
                std::cerr << "Invalid --network-pid value\n";
                return 1;
            }
            if (networkPid == 0) {
                networkPid = GetCurrentProcessId();
            }
            ++i;
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
            std::wstring name(rawName.begin(), rawName.end());
            if (command == "compare") {
                compareSelectors.push_back({false, 0, name});
            } else {
                processName = std::move(name);
            }
        } else {
            std::cerr << "Unknown argument: " << argument << '\n';
            return 1;
        }
    }

    if (command == "compare") {
        if (compareSelectors.size() < 2) {
            std::cerr << "compare requires two process selectors\n";
            return 1;
        }
        DWORD sourcePid = 0;
        DWORD targetPid = 0;
        if (!resolve_selector(compareSelectors[0], sourcePid) ||
            !resolve_selector(compareSelectors[1], targetPid)) {
            std::cerr << "Failed to resolve one or more compare targets\n";
            return 2;
        }
        return compare_processes(sourcePid, targetPid, format, outputPath);
    }

    if (command == "browser") {
        if (networkPid == 0) {
            networkPid = pid;
        }
        return browser_process(networkPid, format, outputPath);
    }

    if (!pids.empty()) {
        pid = pids[0];
    }
    if (command == "windows") {
        return windows_for_process(pid);
    }
    if (command == "tree") {
        return process_tree(pid);
    }
    if (!processName.empty()) {
        return inspect_by_name(processName, format, outputPath);
    }
    return inspect_process(pid, format, outputPath);
}
