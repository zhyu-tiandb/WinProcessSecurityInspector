#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include <Windows.h>

#include "wpsi/common/result.h"

namespace wpsi {

using TimePoint = std::chrono::system_clock::time_point;

enum class ProcessArchitecture {
    Unknown,
    X86,
    X64,
    Arm64
};

enum class IntegrityLevel {
    Unknown,
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    ProtectedProcess
};

enum class ElevationType {
    Unknown,
    Default,
    Full,
    Limited
};

enum class PrivilegeState {
    Unknown,
    Enabled,
    Disabled,
    Removed
};

enum class BrowserKind {
    Unknown,
    Chrome,
    Edge,
    Firefox
};

enum class BrowserProcessRole {
    Unknown,
    Main,
    Renderer,
    NetworkService,
    GpuProcess,
    Utility,
    CrashHandler,
    Extension
};

enum class DiagnosisSeverity {
    Info,
    Notice,
    Warning,
    Error,
    Critical
};

struct ProcessInfo {
    DWORD pid = 0;
    DWORD parentPid = 0;
    std::wstring processName;
    FieldValue<std::wstring> executablePath;
    FieldValue<std::wstring> commandLine;
    FieldValue<TimePoint> startTime;
    ProcessArchitecture architecture = ProcessArchitecture::Unknown;
    DWORD sessionId = 0;
    FieldValue<std::wstring> priorityClassName;
    FieldValue<DWORD> threadCount;
    FieldValue<DWORD> handleCount;
    FieldValue<bool> inJobObject;
    FieldValue<std::wstring> serviceName;
};

struct PrivilegeInfo {
    std::wstring name;
    bool present = false;
    PrivilegeState state = PrivilegeState::Unknown;
};

struct TokenInfo {
    FieldValue<std::wstring> userName;
    FieldValue<std::wstring> domain;
    FieldValue<std::wstring> userSid;
    FieldValue<std::wstring> logonSid;
    FieldValue<unsigned long long> authenticationId;
    FieldValue<bool> localSystem;
    FieldValue<bool> localService;
    FieldValue<bool> networkService;
    FieldValue<bool> interactiveUser;
    FieldValue<std::wstring> tokenType;
    FieldValue<IntegrityLevel> integrityLevel;
    FieldValue<DWORD> integrityRid;
    FieldValue<bool> elevated;
    FieldValue<ElevationType> elevationType;
    FieldValue<bool> hasLinkedToken;
    FieldValue<IntegrityLevel> linkedTokenIntegrityLevel;
    FieldValue<bool> administratorMember;
    FieldValue<bool> administratorEnabled;
    FieldValue<bool> administratorDenyOnly;
    FieldValue<bool> uiAccess;
    FieldValue<bool> appContainer;
    FieldValue<std::wstring> appContainerSid;
    std::vector<std::wstring> capabilitySids;
    std::vector<PrivilegeInfo> privileges;
};

struct SessionInfo {
    DWORD processSessionId = 0;
    FieldValue<DWORD> activeConsoleSessionId;
    FieldValue<DWORD> interactiveUserSessionId;
    FieldValue<std::wstring> sessionState;
    FieldValue<std::wstring> sessionUser;
    FieldValue<bool> locked;
    bool sessionZero = false;
};

struct DesktopInfo {
    FieldValue<std::wstring> windowStation;
    FieldValue<std::wstring> desktop;
    FieldValue<std::wstring> threadDesktop;
    FieldValue<std::wstring> inputDesktop;
};

struct WindowInfo {
    HWND hwnd = nullptr;
    DWORD ownerPid = 0;
    DWORD ownerThreadId = 0;
    std::wstring title;
    std::wstring className;
    bool visible = false;
    bool minimized = false;
    bool foreground = false;
    bool toolWindow = false;
    bool hasOwnerWindow = false;
    FieldValue<std::wstring> desktop;
};

struct BrowserProcessContext {
    DWORD inputPid = 0;
    BrowserKind browserKind = BrowserKind::Unknown;
    BrowserProcessRole role = BrowserProcessRole::Unknown;
    FieldValue<DWORD> mainProcessPid;
    FieldValue<HWND> topLevelWindow;
    FieldValue<std::wstring> profilePath;
    std::vector<DWORD> relatedProcessIds;
    std::vector<WindowInfo> candidateWindows;
};

struct ProcessSecurityContext {
    ProcessInfo process;
    TokenInfo token;
    SessionInfo session;
    DesktopInfo desktop;
    std::vector<WindowInfo> windows;
};

struct ComparisonResult {
    DWORD sourcePid = 0;
    DWORD targetPid = 0;
    bool sameSession = false;
    bool sameUserSid = false;
    bool sameWindowStation = false;
    bool sameDesktop = false;
    bool sourceIntegrityLowerThanTarget = false;
    bool sourceAppContainer = false;
    bool targetAppContainer = false;
    bool sourceUIAccess = false;
    bool targetUIAccess = false;
};

struct RuleResult {
    std::string ruleId;
    DiagnosisSeverity severity = DiagnosisSeverity::Info;
    std::string title;
    std::string evidence;
    std::string recommendation;
};

struct DiagnosisReport {
    std::vector<ProcessSecurityContext> processes;
    BrowserProcessContext browser;
    std::optional<ComparisonResult> comparison;
    std::vector<RuleResult> ruleResults;
    DiagnosisSeverity overallSeverity = DiagnosisSeverity::Info;
};

} // namespace wpsi
