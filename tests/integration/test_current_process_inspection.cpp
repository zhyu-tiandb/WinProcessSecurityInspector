#include <cstdlib>
#include <iostream>

#include <Windows.h>

#include "wpsi/inspectors/process_inspector.h"
#include "wpsi/inspectors/session_inspector.h"
#include "wpsi/inspectors/token_inspector.h"

namespace {

int failures = 0;

void expect_true(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void test_current_process_basic_inspection() {
    const DWORD current_pid = GetCurrentProcessId();

    wpsi::ProcessInspector process_inspector;
    const auto process = process_inspector.inspect(current_pid);

    expect_true(process.ok, "current process inspection should succeed");
    expect_true(process.value.pid == current_pid, "process pid should match current pid");
    expect_true(process.value.parentPid != 0, "current process parent pid should be populated");
    expect_true(process.value.executablePath.available, "current process executable path should be available");
    expect_true(process.value.commandLine.available, "current process command line should be available");
    expect_true(process.value.startTime.available, "current process start time should be available");
    expect_true(process.value.architecture != wpsi::ProcessArchitecture::Unknown, "current process architecture should be available");
    expect_true(process.value.priorityClassName.available, "current process priority class should be available");
    expect_true(process.value.threadCount.available, "current process thread count should be available");
}

void test_find_current_process_by_name() {
    const DWORD current_pid = GetCurrentProcessId();
    wpsi::ProcessInspector process_inspector;
    const auto process = process_inspector.inspect(current_pid);
    expect_true(process.ok, "current process inspection should succeed before name lookup");

    const auto matches = process_inspector.findByName(process.value.processName);
    expect_true(matches.ok, "findByName should succeed for current process name");

    bool found = false;
    for (const auto pid : matches.value) {
        if (pid == current_pid) {
            found = true;
        }
    }
    expect_true(found, "findByName should include current process pid");
}

void test_current_process_session_inspection() {
    const DWORD current_pid = GetCurrentProcessId();
    DWORD expected_session = 0;
    expect_true(ProcessIdToSessionId(current_pid, &expected_session) != 0, "Windows should return current process session");

    wpsi::SessionInspector session_inspector;
    const auto session = session_inspector.inspect(current_pid, expected_session);

    expect_true(session.ok, "current process session inspection should succeed");
    expect_true(session.value.processSessionId == expected_session, "process session id should match Windows API");
}

void test_current_process_token_inspection() {
    wpsi::TokenInspector token_inspector;
    const auto token = token_inspector.inspect(GetCurrentProcessId(), false);

    expect_true(token.ok, "current process token inspection should succeed");
    expect_true(token.value.userSid.available, "current process user SID should be available");
    expect_true(token.value.integrityLevel.available, "current process integrity level should be available");
    expect_true(token.value.integrityRid.available, "current process integrity RID should be available");
    expect_true(token.value.elevated.available, "current process elevation should be available");
    expect_true(token.value.elevationType.available, "current process elevation type should be available");
}

} // namespace

int main() {
    test_current_process_basic_inspection();
    test_find_current_process_by_name();
    test_current_process_session_inspection();
    test_current_process_token_inspection();

    if (failures != 0) {
        std::cerr << failures << " integration failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "Current process inspection tests passed\n";
    return EXIT_SUCCESS;
}
