#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "wpsi/core/context.h"
#include "wpsi/diagnosis/rule_engine.h"
#include "wpsi/inspectors/browser_inspector.h"
#include "wpsi/common/string_utils.h"
#include "wpsi/report/json_exporter.h"

namespace {

int failures = 0;

void expect_true(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void expect_eq(const std::string& actual, const std::string& expected, const char* message) {
    if (actual != expected) {
        std::cerr << "FAIL: " << message << "\n  expected: " << expected << "\n  actual:   " << actual << '\n';
        ++failures;
    }
}

wpsi::ProcessSecurityContext make_process(
    unsigned long pid,
    unsigned long session_id,
    std::wstring user_sid,
    wpsi::IntegrityLevel integrity,
    bool ui_access,
    bool app_container) {
    wpsi::ProcessSecurityContext context;
    context.process.pid = pid;
    context.session.processSessionId = session_id;
    context.token.userSid.available = true;
    context.token.userSid.value = std::move(user_sid);
    context.token.integrityLevel.available = true;
    context.token.integrityLevel.value = integrity;
    context.token.uiAccess.available = true;
    context.token.uiAccess.value = ui_access;
    context.token.appContainer.available = true;
    context.token.appContainer.value = app_container;
    return context;
}

bool has_rule(const std::vector<wpsi::RuleResult>& results, const std::string& id) {
    for (const auto& result : results) {
        if (result.ruleId == id) {
            return true;
        }
    }
    return false;
}

void test_rule_engine_detects_phase2_phase3_risks() {
    auto source = make_process(10, 0, L"S-1-5-18", wpsi::IntegrityLevel::System, false, false);
    auto target = make_process(20, 1, L"S-1-5-21-user-a", wpsi::IntegrityLevel::Medium, false, false);
    source.session.sessionZero = true;
    source.process.serviceName.available = true;
    source.process.serviceName.value = L"WpsiTestService";
    target.process.processName = L"chrome.exe";
    target.desktop.desktop.available = true;
    target.desktop.desktop.value = L"Default";
    source.desktop.desktop.available = true;
    source.desktop.desktop.value = L"Service-0x0-3e7$";

    wpsi::BrowserProcessContext browser;
    browser.inputPid = 21;
    browser.mainProcessPid.available = true;
    browser.mainProcessPid.value = 20;
    browser.role = wpsi::BrowserProcessRole::NetworkService;

    wpsi::DiagnosisContext diagnosis_context;
    diagnosis_context.source = source;
    diagnosis_context.target = target;
    diagnosis_context.browser = browser;

    wpsi::RuleEngine engine;
    const auto results = engine.evaluate(diagnosis_context);

    expect_true(has_rule(results, "R004"), "Session 0 service to browser should produce R004");
    expect_true(has_rule(results, "R005"), "browser child input pid should produce R005");
    expect_true(has_rule(results, "R006"), "browser without candidate window should produce R006");
    expect_true(has_rule(results, "R010"), "desktop mismatch should produce R010");
}

void test_rule_engine_detects_appcompat_layer() {
    auto process = make_process(30, 1, L"S-1-5-21-user-a", wpsi::IntegrityLevel::Medium, false, false);
    process.compatibilityLayers.push_back(L"RUNASADMIN");

    wpsi::DiagnosisContext diagnosis_context;
    diagnosis_context.source = process;
    diagnosis_context.target = process;

    wpsi::RuleEngine engine;
    const auto results = engine.evaluate(diagnosis_context);

    expect_true(has_rule(results, "R009"), "AppCompat layer should produce R009");
}

void test_rule_engine_detects_phase1_risks() {
    auto source = make_process(100, 1, L"S-1-5-21-user-a", wpsi::IntegrityLevel::Medium, false, false);
    auto target = make_process(200, 2, L"S-1-5-21-user-b", wpsi::IntegrityLevel::High, false, true);

    wpsi::DiagnosisContext diagnosis_context;
    diagnosis_context.source = source;
    diagnosis_context.target = target;

    wpsi::RuleEngine engine;
    const auto results = engine.evaluate(diagnosis_context);

    expect_true(has_rule(results, "R001"), "medium source to high target should produce R001");
    expect_true(has_rule(results, "R002"), "different sessions should produce R002");
    expect_true(has_rule(results, "R003"), "different user SIDs should produce R003");
    expect_true(has_rule(results, "R011"), "AppContainer target should produce R011");
    expect_true(has_rule(results, "R012"), "missing UIAccess with lower source IL should produce R012");
    expect_true(engine.overallSeverity(results) == wpsi::DiagnosisSeverity::Error,
        "overall severity should be the highest rule severity");
}

void test_command_line_redaction_hides_sensitive_values() {
    const auto redacted = wpsi::to_utf8(wpsi::redactCommandLine(
        L"app.exe --user alice --password=secret --token abc123 --sid S-1-5-21-9999"));

    expect_true(redacted.find("secret") == std::string::npos, "password value should be hidden");
    expect_true(redacted.find("abc123") == std::string::npos, "token value should be hidden");
    expect_true(redacted.find("--password=***") != std::string::npos, "password flag should remain with hidden value");
    expect_true(redacted.find("--token ***") != std::string::npos, "space separated token value should be hidden");
    expect_true(redacted.find("--sid S-1-***") != std::string::npos, "sid value should be partially redacted");
}

void test_browser_role_detection_from_command_line() {
    expect_true(
        wpsi::detectBrowserRole(L"chrome.exe", L"chrome.exe --type=renderer") == wpsi::BrowserProcessRole::Renderer,
        "Chrome renderer command line should be renderer");
    expect_true(
        wpsi::detectBrowserRole(L"msedge.exe", L"msedge.exe --type=utility --utility-sub-type=network.mojom.NetworkService") ==
            wpsi::BrowserProcessRole::NetworkService,
        "Edge network utility command line should be network service");
    expect_true(
        wpsi::detectBrowserRole(L"firefox.exe", L"firefox.exe -contentproc -parentBuildID 202607") ==
            wpsi::BrowserProcessRole::Renderer,
        "Firefox content process command line should be renderer");
    expect_true(
        wpsi::detectBrowserRole(L"crashreporter.exe", L"crashreporter.exe -crashreport") ==
            wpsi::BrowserProcessRole::CrashHandler,
        "Firefox crashreporter should be crash handler");
}

void test_json_exporter_outputs_process_and_rules() {
    wpsi::DiagnosisReport report;
    report.processes.push_back(make_process(
        100, 1, L"S-1-5-21-user-a", wpsi::IntegrityLevel::Medium, false, false));
    report.ruleResults.push_back({"R001", wpsi::DiagnosisSeverity::Warning, "IL", "evidence", "recommendation"});
    report.overallSeverity = wpsi::DiagnosisSeverity::Warning;

    const auto json = wpsi::exportDiagnosisReportJson(report);

    expect_true(json.find("\"overallSeverity\":\"WARNING\"") != std::string::npos,
        "JSON should include overall severity");
    expect_true(json.find("\"pid\":100") != std::string::npos,
        "JSON should include process pid");
    expect_true(json.find("\"userSid\":\"S-1-***\"") != std::string::npos,
        "JSON should redact SID by default");
    expect_true(json.find("\"ruleId\":\"R001\"") != std::string::npos,
        "JSON should include rule id");
}

} // namespace

int main() {
    test_rule_engine_detects_phase1_risks();
    test_rule_engine_detects_phase2_phase3_risks();
    test_rule_engine_detects_appcompat_layer();
    test_command_line_redaction_hides_sensitive_values();
    test_browser_role_detection_from_command_line();
    test_json_exporter_outputs_process_and_rules();

    if (failures != 0) {
        std::cerr << failures << " test failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "All phase1 core tests passed\n";
    return EXIT_SUCCESS;
}
