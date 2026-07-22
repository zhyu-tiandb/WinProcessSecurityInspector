# Windows 进程安全上下文与桌面会话诊断工具详细设计

## 1. 文档范围

本文档在以下文档基础上细化实现方案：

- `docs/requirements/software-requirements-specification.md`
- `docs/design/overview-design.md`
- `docs/review/requirements-and-design-review.md`

详细设计覆盖核心库、Inspector、诊断规则、CLI、报告导出、错误降级、线程模型、测试策略和分阶段落地方式。本文档不包含 Qt GUI 的像素级界面设计，GUI 详细设计在产品化阶段单独展开。

## 2. 设计目标

1. 核心采集逻辑可作为独立库复用。
2. CLI、GUI、`xianc2` 集成层共享同一套数据模型和诊断规则。
3. Windows API 调用集中在平台适配层，便于 mock 和测试。
4. 普通用户模式下尽量返回部分结果，不因权限不足导致整次失败。
5. 输出模型稳定，便于 JSON、Markdown、HTML 和日志复用。
6. 第一阶段可快速落地，后续浏览器专项和完整诊断能自然扩展。

## 3. 目标文件结构

### 3.1 公共头文件

```text
include/wpsi/
├─ common/
│  ├─ com_context.h
│  ├─ logger.h
│  ├─ result.h
│  ├─ string_utils.h
│  ├─ time_utils.h
│  └─ win_handle.h
├─ core/
│  ├─ context.h
│  ├─ inspection_options.h
│  └─ inspection_service.h
├─ inspectors/
│  ├─ process_inspector.h
│  ├─ token_inspector.h
│  ├─ session_inspector.h
│  ├─ desktop_inspector.h
│  ├─ window_inspector.h
│  ├─ browser_inspector.h
│  ├─ compatibility_inspector.h
│  ├─ manifest_inspector.h
│  ├─ signature_inspector.h
│  ├─ service_inspector.h
│  └─ startup_inspector.h
├─ diagnosis/
│  ├─ diagnosis_context.h
│  ├─ rule_engine.h
│  └─ rule_config.h
└─ report/
   ├─ export_format.h
   ├─ report_exporter.h
   ├─ text_exporter.h
   ├─ json_exporter.h
   ├─ markdown_exporter.h
   └─ html_exporter.h
```

### 3.2 源文件

```text
src/
├─ common/
│  ├─ com_context.cpp
│  ├─ logger.cpp
│  ├─ string_utils.cpp
│  ├─ time_utils.cpp
│  └─ win_handle.cpp
├─ core/
│  ├─ context.cpp
│  └─ inspection_service.cpp
├─ inspectors/
│  ├─ process/process_inspector.cpp
│  ├─ token/token_inspector.cpp
│  ├─ session/session_inspector.cpp
│  ├─ desktop/desktop_inspector.cpp
│  ├─ window/window_inspector.cpp
│  ├─ browser/browser_inspector.cpp
│  ├─ compatibility/compatibility_inspector.cpp
│  ├─ manifest/manifest_inspector.cpp
│  ├─ signature/signature_inspector.cpp
│  ├─ service/service_inspector.cpp
│  └─ startup/startup_inspector.cpp
├─ diagnosis/
│  ├─ rule_engine.cpp
│  ├─ rule_config.cpp
│  └─ rules.cpp
├─ report/
│  ├─ text_exporter.cpp
│  ├─ json_exporter.cpp
│  ├─ markdown_exporter.cpp
│  └─ html_exporter.cpp
├─ cli/
│  ├─ main.cpp
│  ├─ command_line.cpp
│  └─ commands.cpp
└─ integration/
   └─ xianc2/
      └─ wpsi_xianc2_api.cpp
```

### 3.3 测试文件

```text
tests/
├─ unit/
│  ├─ test_rule_engine.cpp
│  ├─ test_browser_role_detection.cpp
│  ├─ test_redaction.cpp
│  ├─ test_json_exporter.cpp
│  └─ test_process_tree.cpp
├─ integration/
│  ├─ test_current_process_inspection.cpp
│  ├─ test_uac_elevation.cpp
│  ├─ test_session0_service.cpp
│  └─ test_browser_pid_resolution.cpp
└─ fixtures/
   ├─ chrome_network_service_snapshot.json
   ├─ edge_renderer_snapshot.json
   ├─ firefox_contentproc_snapshot.json
   ├─ medium_to_high_uipi_snapshot.json
   └─ session_mismatch_snapshot.json
```

## 4. 公共基础设施设计

### 4.1 结果包装

文件：`include/wpsi/common/result.h`

所有 Inspector 返回结构化结果，不通过异常表达常规权限失败。

```cpp
namespace wpsi {

enum class ErrorCode {
    Ok,
    InvalidArgument,
    ProcessNotFound,
    AccessDenied,
    PartialData,
    ApiFailed,
    Timeout,
    Unsupported,
    InternalError
};

struct ErrorInfo {
    ErrorCode code = ErrorCode::Ok;
    unsigned long win32Error = 0;
    std::string message;
};

template <typename T>
struct Result {
    T value {};
    ErrorInfo error {};
    bool ok = true;
    bool partial = false;
};

template <typename T>
struct FieldValue {
    T value {};
    bool available = false;
    ErrorInfo error {};
};

} // namespace wpsi
```

约定：

- 目标 PID 不存在时，`Result.ok = false`。
- 单个字段读取失败时，`Result.ok = true`、`Result.partial = true`，字段 `available = false`。
- 权限不足使用 `ErrorCode::AccessDenied`，不做自动提权。

### 4.2 Windows 句柄 RAII

文件：`include/wpsi/common/win_handle.h`

```cpp
namespace wpsi {

class WinHandle {
public:
    WinHandle() noexcept;
    explicit WinHandle(HANDLE handle) noexcept;
    ~WinHandle();

    WinHandle(const WinHandle&) = delete;
    WinHandle& operator=(const WinHandle&) = delete;
    WinHandle(WinHandle&& other) noexcept;
    WinHandle& operator=(WinHandle&& other) noexcept;

    HANDLE get() const noexcept;
    HANDLE release() noexcept;
    bool valid() const noexcept;
    void reset(HANDLE handle = nullptr) noexcept;

private:
    HANDLE handle_;
};

} // namespace wpsi
```

句柄关闭规则：

- `nullptr` 和 `INVALID_HANDLE_VALUE` 均视为无效。
- 不在析构中抛异常。
- 所有 `OpenProcess`、`OpenProcessToken`、`OpenWindowStation` 等返回值必须立即包进 `WinHandle` 或专用 RAII 类型。

### 4.3 字符串与时间

内部统一使用 `std::wstring` 保存 Windows 原生文本。导出 JSON、Markdown、HTML 时转换为 UTF-8。

时间字段使用：

```cpp
using TimePoint = std::chrono::system_clock::time_point;
```

导出格式采用 ISO 8601 本地时间字符串，并保留原始 FILETIME 转换失败状态。

## 5. 核心模型设计

文件：`include/wpsi/core/context.h`

### 5.1 枚举

```cpp
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
```

### 5.2 进程模型

```cpp
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
```

### 5.3 Token 模型

```cpp
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
```

### 5.4 Session、Desktop、Window 模型

```cpp
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
```

### 5.5 浏览器模型

```cpp
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
```

### 5.6 诊断聚合模型

```cpp
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
```

`DiagnosisReport.comparison` 是报告快照字段，由 `InspectionService` 或 `RuleEngine` 基于 `source` 和 `target` 统一计算后写入。规则引擎不得信任外部传入的 ComparisonResult 覆盖源数据，避免出现 source / target 与 comparison 不一致的诊断结果。

## 6. 采集选项与服务门面

文件：`include/wpsi/core/inspection_options.h`

```cpp
struct InspectionOptions {
    bool includeToken = true;
    bool includePrivileges = false;
    bool includeWindows = false;
    bool includeChildren = false;
    bool includeDesktop = false;
    bool includeCompatibility = false;
    bool includeSignature = false;
    bool includeService = false;
    std::chrono::milliseconds inspectorTimeout {3000};
};
```

文件：`include/wpsi/core/inspection_service.h`

```cpp
class InspectionService {
public:
    Result<ProcessSecurityContext> inspectProcess(
        DWORD pid,
        const InspectionOptions& options) const;

    Result<std::vector<ProcessSecurityContext>> inspectByName(
        std::wstring_view processName,
        const InspectionOptions& options) const;

    Result<ComparisonResult> compareProcesses(
        DWORD sourcePid,
        DWORD targetPid,
        const InspectionOptions& options) const;

    Result<BrowserProcessContext> inspectBrowserProcess(
        DWORD networkPid,
        const InspectionOptions& options) const;

    Result<DiagnosisReport> diagnoseInteraction(
        DWORD sourcePid,
        DWORD targetPid,
        const InspectionOptions& options) const;
};
```

调度规则：

- `inspectProcess` 第一阶段启用 process、token、session、priority。
- `compareProcesses` 自动启用满足对比需要的字段。
- `inspectBrowserProcess` 第二阶段启用 process tree、window、browser role。
- `diagnoseInteraction` 聚合 source、target/browser main 和规则引擎。

核心 API 默认返回原始采集数据，便于 `xianc2` 等可信调用方继续分析。脱敏仅发生在报告导出、日志写入和诊断包生成边界。

## 7. Inspector 详细设计

### 7.1 ProcessInspector

文件：

- `include/wpsi/inspectors/process_inspector.h`
- `src/inspectors/process/process_inspector.cpp`

接口：

```cpp
class ProcessInspector {
public:
    Result<ProcessInfo> inspect(DWORD pid) const;
    Result<std::vector<DWORD>> findByName(std::wstring_view processName) const;
    Result<std::vector<ProcessInfo>> snapshotProcesses() const;
    Result<std::vector<DWORD>> childrenOf(DWORD pid) const;
    Result<std::vector<DWORD>> parentChainOf(DWORD pid) const;
};
```

主要 API：

- `CreateToolhelp32Snapshot`
- `Process32FirstW`
- `Process32NextW`
- `OpenProcess`
- `QueryFullProcessImageNameW`
- `GetProcessTimes`
- `GetPriorityClass`
- `GetProcessHandleCount`
- `IsProcessInJob`
- `IsWow64Process2`
- `NtQueryInformationProcess`，仅作为命令行读取的后备路径

实现要点：

- 枚举快照中保存 PID、Parent PID、进程名。
- 查询进程路径优先使用 `QueryFullProcessImageNameW`。
- 启动时间优先使用文档化 API `GetProcessTimes`。
- 命令行读取失败时返回部分结果，不阻断诊断。
- 父 PID 复用判断依赖父子进程 `startTime`，父进程启动时间晚于子进程时标记为疑似复用。
- 单个进程基础诊断目标耗时不超过 200 毫秒；WMI 不参与第一阶段 ProcessInspector。

`NtQueryInformationProcess` 属于未文档化接口，不作为启动时间来源。仅当文档化 API 无法获取命令行时，用它读取 PEB 命令行作为后备；跨 Windows 版本、WOW64 和 ARM64 模拟层下结构差异导致读取失败时，应返回部分结果并说明命令行不可读。

### 7.2 TokenInspector

文件：

- `include/wpsi/inspectors/token_inspector.h`
- `src/inspectors/token/token_inspector.cpp`

接口：

```cpp
class TokenInspector {
public:
    Result<TokenInfo> inspect(DWORD pid, bool includePrivileges) const;
};
```

主要 API：

- `OpenProcess`
- `OpenProcessToken`
- `GetTokenInformation`
- `LookupAccountSidW`
- `ConvertSidToStringSidW`
- `CheckTokenMembership`

Token 查询项：

- `TokenUser`
- `TokenGroups`
- `TokenStatistics`
- `TokenType`
- `TokenIntegrityLevel`
- `TokenElevation`
- `TokenElevationType`
- `TokenLinkedToken`
- `TokenPrivileges`
- `TokenUIAccess`
- `TokenIsAppContainer`
- `TokenAppContainerSid`
- `TokenCapabilities`

Integrity RID 映射：

| RID 范围 | 结果 |
| --- | --- |
| `< SECURITY_MANDATORY_LOW_RID` | Untrusted |
| `SECURITY_MANDATORY_LOW_RID` | Low |
| `SECURITY_MANDATORY_MEDIUM_RID` | Medium |
| `SECURITY_MANDATORY_MEDIUM_PLUS_RID` | MediumPlus |
| `SECURITY_MANDATORY_HIGH_RID` | High |
| `SECURITY_MANDATORY_SYSTEM_RID` | System |
| 高于 System 或受保护进程特殊返回 | ProtectedProcess |

管理员判断：

- `administratorMember` 表示 Token Groups 中存在 Administrators SID。
- `administratorEnabled` 表示 SID 属性包含 enabled。
- `administratorDenyOnly` 表示 SID 属性包含 deny-only。
- 不使用 `IsUserAnAdmin()` 作为最终判断。

特权状态映射：

| 条件 | `present` | `state` |
| --- | --- | --- |
| 目标特权未出现在 `TokenPrivileges` 中 | `false` | `Unknown` |
| `Attributes & SE_PRIVILEGE_REMOVED` | `true` | `Removed` |
| `Attributes & SE_PRIVILEGE_ENABLED` | `true` | `Enabled` |
| 出现在 `TokenPrivileges` 中但未 Enabled / Removed | `true` | `Disabled` |

如果同时出现 `SE_PRIVILEGE_ENABLED` 和 `SE_PRIVILEGE_REMOVED`，按 `Removed` 处理，并在字段错误信息中记录矛盾属性。

### 7.3 SessionInspector

接口：

```cpp
class SessionInspector {
public:
    Result<SessionInfo> inspect(DWORD pid, DWORD processSessionId) const;
};
```

主要 API：

- `ProcessIdToSessionId`
- `WTSGetActiveConsoleSessionId`
- `WTSEnumerateSessionsW`
- `WTSQuerySessionInformationW`

锁屏判断：

- 优先尝试 WTS session 状态。
- 无法可靠判断时 `locked.available = false`。

异常判定不在 Inspector 内完成，由 RuleEngine 根据 Session 与目标操作上下文判断。

### 7.4 DesktopInspector

接口：

```cpp
class DesktopInspector {
public:
    Result<DesktopInfo> inspectCurrentThread() const;
    Result<FieldValue<std::wstring>> queryWindowDesktop(HWND hwnd) const;
};
```

主要 API：

- `GetProcessWindowStation`
- `GetThreadDesktop`
- `GetCurrentThreadId`
- `OpenInputDesktop`
- `GetUserObjectInformationW`

限制：

- Windows 不提供直接读取任意进程当前 Desktop 的稳定公开 API。
- 对远程进程 Desktop 的判断以其窗口 Desktop 和当前线程/Desktop 信息为主。
- 无窗口进程的 Desktop 字段可能不可用，应返回部分结果。
- 当桌面锁定、快速用户切换或当前进程缺少 UIAccess 时，`OpenInputDesktop` 可能返回 `NULL` 且错误为 `ERROR_ACCESS_DENIED`。此时 `inputDesktop.available = false`，并在证据中提示可能由锁屏或 UIAccess 限制造成。

### 7.5 WindowInspector

接口：

```cpp
class WindowInspector {
public:
    Result<std::vector<WindowInfo>> enumerateTopLevelWindows() const;
    Result<std::vector<WindowInfo>> enumerateWindowsForPid(DWORD pid) const;
    Result<FieldValue<HWND>> foregroundWindow() const;
};
```

主要 API：

- `EnumWindows`
- `GetWindowThreadProcessId`
- `GetWindowTextW`
- `GetClassNameW`
- `IsWindowVisible`
- `IsIconic`
- `GetForegroundWindow`
- `GetWindowLongPtrW`
- `GetWindow`

顶层窗口过滤：

- `WS_EX_TOOLWINDOW` 默认为工具窗口。
- 有 Owner Window 的窗口不作为主顶层窗口，但仍保留在列表。
- 浏览器主窗口候选优先级：可见 -> 非最小化 -> 无 Owner -> 标题非空 -> 前台窗口。

窗口枚举限制：

- `EnumWindows` 只能枚举调用线程当前 Window Station / Desktop 上的顶层窗口。
- 目标进程位于其他 Session、其他 Window Station 或其他 Desktop 时，枚举结果可能为空或不完整。
- 这种空结果代表 Windows 桌面隔离限制，不应直接等同于目标进程没有窗口；RuleEngine 应结合 Session 和 Desktop 结果输出更准确的解释。

### 7.6 BrowserInspector

接口：

```cpp
class BrowserInspector {
public:
    Result<BrowserProcessContext> inspect(DWORD inputPid) const;
};
```

依赖：

- `ProcessInspector`
- `WindowInspector`

Chrome / Edge 角色识别：

| 参数 | 角色 |
| --- | --- |
| 无 `--type=` | Main |
| `--type=renderer` | Renderer |
| `--type=utility` + `network.mojom.NetworkService` | NetworkService |
| `--type=gpu-process` | GpuProcess |
| `--type=utility` | Utility |
| `crashpad-handler` 或 crash handler 进程名 | CrashHandler |

Firefox 角色识别：

| 参数 | 角色 |
| --- | --- |
| 无 `-contentproc` | Main |
| `-contentproc` | Renderer |
| `--type=gpu` | GpuProcess |
| `-contentproc` + sandbox 相关参数 | Utility 或 Renderer，无法确定时为 Unknown |
| `crashreporter.exe` 或命令行包含 `-crashreport` | CrashHandler |

主进程查找：

1. 如果输入 PID 已是主进程，直接返回。
2. 沿父链向上查找同浏览器进程名且符合主进程特征的进程。
3. 如果父链断裂，使用同 Session、同 User SID、同 Profile 路径、启动时间接近的进程作为候选。
4. 枚举顶层窗口，选择 owner PID 与主进程或同实例进程匹配的窗口。

### 7.7 CompatibilityInspector

接口：

```cpp
class CompatibilityInspector {
public:
    Result<std::vector<std::wstring>> inspectLayers(std::wstring_view executablePath) const;
};
```

读取路径：

- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`

匹配方式：

- 按完整路径精确匹配。
- 大小写不敏感。
- 未命中返回空列表，不视为错误。

### 7.8 ManifestInspector

接口：

```cpp
struct ManifestInfo {
    FieldValue<std::wstring> requestedExecutionLevel;
    FieldValue<bool> uiAccess;
};

class ManifestInspector {
public:
    Result<ManifestInfo> inspect(std::wstring_view executablePath) const;
};
```

实现路径：

- 优先使用资源 API 读取 RT_MANIFEST。
- 解析 XML 中 `requestedExecutionLevel` 和 `uiAccess`。
- 无 Manifest 返回 `available = false`，不视为错误。

### 7.9 SignatureInspector

接口：

```cpp
struct SignatureInfo {
    FieldValue<bool> signedFile;
    FieldValue<bool> valid;
    FieldValue<std::wstring> signer;
    FieldValue<std::wstring> issuer;
    FieldValue<std::wstring> timestamp;
    FieldValue<std::wstring> sha256;
};

class SignatureInspector {
public:
    Result<SignatureInfo> inspect(std::wstring_view executablePath) const;
};
```

主要 API：

- `WinVerifyTrust`
- CryptoAPI 证书读取接口
- BCrypt 或 CryptoAPI 计算 SHA-256

验签可能较慢，默认不进入第一阶段基础采集。

调用 `WinVerifyTrust` 时必须设置 `WTD_UI_NONE`，禁止弹出任何证书对话框。验签失败时静默返回签名状态为“无法验证”，并记录 Win32 错误码。

### 7.10 ServiceInspector

接口：

```cpp
struct ServiceInfo {
    std::wstring serviceName;
    FieldValue<std::wstring> displayName;
    FieldValue<std::wstring> startType;
    FieldValue<std::wstring> accountName;
    FieldValue<std::wstring> serviceType;
    FieldValue<bool> interactiveDesktopAllowed;
    FieldValue<std::wstring> state;
    FieldValue<bool> delayedAutoStart;
    FieldValue<bool> startedByScm;
};

class ServiceInspector {
public:
    Result<std::optional<ServiceInfo>> inspectByPid(DWORD pid) const;
};
```

实现路径：

- 优先使用 SCM API 枚举服务状态并匹配 PID。
- 需要扩展信息时再使用 WMI。
- WMI 超时或不可用时返回 SCM 可获得字段。

### 7.11 StartupInspector

接口：

```cpp
struct StartupSourceInfo {
    std::wstring sourceType;
    std::wstring name;
    std::wstring command;
    std::map<std::wstring, std::wstring> properties;
};

class StartupInspector {
public:
    Result<std::vector<StartupSourceInfo>> inspect(std::wstring_view executablePath) const;
};
```

来源：

- HKCU Run / RunOnce。
- HKLM Run / RunOnce。
- Startup 文件夹。
- Task Scheduler COM。
- ServiceInspector 结果。
- 父进程推断。

## 8. 诊断规则引擎详细设计

文件：

- `include/wpsi/diagnosis/rule_engine.h`
- `src/diagnosis/rule_engine.cpp`
- `src/diagnosis/rules.cpp`

### 8.1 输入输出

```cpp
struct DiagnosisContext {
    std::optional<ProcessSecurityContext> source;
    std::optional<ProcessSecurityContext> target;
    std::optional<BrowserProcessContext> browser;
};

class RuleEngine {
public:
    explicit RuleEngine(RuleConfig config);
    std::vector<RuleResult> evaluate(const DiagnosisContext& context) const;
    ComparisonResult compare(const ProcessSecurityContext& source,
                             const ProcessSecurityContext& target) const;
    DiagnosisSeverity overallSeverity(const std::vector<RuleResult>& results) const;
};
```

### 8.2 规则配置

文件：`config/diagnosis-rules.json`

```json
{
  "version": 1,
  "rules": [
    {
      "id": "R001",
      "severity": "WARNING",
      "enabled": true,
      "description": "Source process integrity level is lower than target process integrity level."
    }
  ]
}
```

加载失败策略：

- 配置文件不存在：使用内置默认规则。
- JSON 格式错误：记录日志，使用内置默认规则。
- 单条规则未知：忽略该规则并记录日志。
- severity 非法：使用该规则内置默认等级。

### 8.3 首批规则

| ID | 条件 | 等级 | 建议 |
| --- | --- | --- | --- |
| R001 | source IL < target IL | WARNING | 以相同或更高完整性级别启动调用方，或改用受支持 IPC |
| R002 | source SessionId != target SessionId | ERROR | 使用用户 Session Agent 或服务到用户进程 IPC |
| R003 | source User SID != target User SID | ERROR | 确认目标浏览器属于当前交互用户 |
| R004 | source 是 Session 0 服务且 target 是用户浏览器 | CRITICAL | 服务不要直接操作桌面窗口 |
| R005 | 输入浏览器 PID 为子进程 | WARNING | 使用识别出的浏览器主进程和顶层窗口 |
| R006 | 目标进程无可见顶层窗口 | WARNING | 沿父进程或同实例主进程继续定位 |
| R007 | Medium/Limited 且涉及管理员能力 | WARNING | 管理员能力移到服务或提升进程中执行 |
| R008 | Priority < Normal | NOTICE | 关注高负载延迟，不作为权限问题处理 |
| R009 | 命中 AppCompat 兼容层 | NOTICE | 检查 RUNASADMIN/RUNASINVOKER 等覆盖行为 |
| R010 | Window Station 或 Desktop 不同 | CRITICAL | 不进行直接窗口交互，改用同桌面代理 |
| R011 | target 是 AppContainer | WARNING | 目标进程受 AppContainer 隔离，窗口消息和输入可能受限 |
| R012 | source 无 UIAccess 且 source IL < target IL | WARNING | 结合 R001 输出 UIAccess 缺失证据，默认与 R001 合并展示 |

R012 是 R001 的补充规则。默认报告中若 R001 和 R012 同时命中，应合并为一条 UIPI/UIAccess 风险结论，保留两个规则 ID，避免重复告警。

## 9. 报告导出详细设计

### 9.1 导出接口

```cpp
enum class ExportFormat {
    Text,
    Json,
    Markdown,
    Html
};

class ReportExporter {
public:
    virtual ~ReportExporter() = default;
    virtual Result<std::string> exportReport(const DiagnosisReport& report) const = 0;
};
```

### 9.2 JSON 输出

JSON 字段命名使用 lowerCamelCase。

示例结构：

```json
{
  "summary": {
    "overallSeverity": "WARNING",
    "generatedAt": "2026-07-21T16:00:00+08:00"
  },
  "processes": [],
  "browser": {},
  "comparison": {},
  "diagnosis": []
}
```

敏感字段在进入 exporter 后由 exporter 生成脱敏副本，核心采集结果保持原始数据。

脱敏执行层：

- 核心 API 返回原始数据。
- `ReportExporter` 根据 `ExportOptions.redactSensitiveData` 生成脱敏副本后输出。
- 日志写入统一调用脱敏工具函数。
- 现场诊断包默认强制脱敏，除非调用方显式传入内部调试选项。

```cpp
struct ExportOptions {
    bool redactSensitiveData = true;
    bool includeUnavailableFields = true;
};
```

### 9.3 文本输出

文本输出用于控制台，按以下顺序：

1. Summary。
2. Process。
3. Browser。
4. Comparison。
5. Diagnosis。
6. Recommendation。

### 9.4 Markdown / HTML

Markdown 和 HTML 属于第三、第四阶段能力。HTML 不嵌入外部网络资源，便于现场归档。

## 10. CLI 详细设计

### 10.1 命令模型

```cpp
enum class CommandKind {
    Inspect,
    Compare,
    Browser,
    Sessions,
    Windows,
    Tree,
    Export,
    Help
};

struct CommandLineOptions {
    CommandKind command = CommandKind::Help;
    std::vector<DWORD> pids;
    std::wstring processName;
    DWORD networkPid = 0;
    ExportFormat format = ExportFormat::Text;
    std::wstring outputPath;
    InspectionOptions inspection;
};
```

### 10.2 参数规则

- `inspect` 未指定 PID 或 name 时，进入当前环境诊断模式。
- `inspect --pid <pid>` 诊断单个 PID。
- `inspect --name <name>` 诊断匹配进程名的全部进程。
- `compare` 至少需要两个 PID。
- `browser --network-pid <pid>` 必须提供 PID。
- `--format` 默认 text。
- `--output` 为空时输出到 stdout。

### 10.3 退出码

| 退出码 | 含义 |
| --- | --- |
| 0 | 命令执行成功，可能包含 WARNING/ERROR 诊断结论 |
| 1 | 参数错误 |
| 2 | 目标进程不存在 |
| 3 | 输出文件写入失败 |
| 4 | 内部错误 |

诊断发现 ERROR/CRITICAL 不改变进程退出码，因为它是工具的正常诊断结果。

## 11. 错误处理与降级

### 11.1 权限不足

权限不足时：

- 保留基础进程信息。
- 对不可用字段填充 `available = false`。
- 报告中输出“建议以管理员身份重新运行以获得完整结果”。
- 不自动请求 UAC 提升。

### 11.2 目标进程退出

目标进程在采集过程中退出：

- 已采集字段保留。
- 后续字段标记 `ProcessNotFound`。
- 诊断报告标记为 partial。

### 11.3 超时

超时适用于 WMI、Task Scheduler COM、签名验证等可能阻塞模块。

- 第一阶段基础采集不依赖超时等待型 API。
- 单项超时默认 3 秒。
- 超时后跳过该 Inspector，保留错误信息。

## 12. 脱敏设计

文件：`include/wpsi/common/string_utils.h`

```cpp
std::wstring redactCommandLine(std::wstring_view commandLine);
std::wstring redactSid(std::wstring_view sid);
std::wstring redactPath(std::wstring_view path);
```

命令行脱敏规则：

- 参数名包含 `password`、`passwd`、`pwd`、`secret`、`token`、`cookie`、`key`、`credential`、`auth` 时，隐藏对应值。
- 参数名包含 `session`、`sid`、`luid` 时，保留前 4 个字符。
- 解析失败时隐藏完整参数值。

路径脱敏规则：

- 用户目录中的用户名可替换为 `%USERPROFILE%`。
- Program Files 路径默认保留。

## 13. COM 与线程模型

### 13.1 核心库线程安全

- Inspector 对象无共享可变状态。
- `InspectionService` 可重入。
- 配置加载结果为只读对象，可由多个线程共享。
- 日志库使用线程安全 sink。

日志抽象：

文件：`include/wpsi/common/logger.h`

```cpp
class Logger {
public:
    virtual ~Logger() = default;
    virtual void debug(std::string_view message) = 0;
    virtual void info(std::string_view message) = 0;
    virtual void warn(std::string_view message) = 0;
    virtual void error(std::string_view message) = 0;
};
```

默认实现可封装 `spdlog`，核心模块依赖 `Logger` 接口而不是直接依赖第三方日志 API。

### 13.2 COM Worker

COM 相关 Inspector 包括：

- Task Scheduler 查询。
- WMI 查询。

设计：

- 提供 `ComExecutionContext`。
- 默认在调用线程尝试 `CoInitializeEx(nullptr, COINIT_MULTITHREADED)`。
- 如果返回 `RPC_E_CHANGED_MODE`，切换到专用 COM Worker 线程执行。
- Worker 线程初始化 MTA，执行任务后返回结果。

文件：`include/wpsi/common/com_context.h`

```cpp
class ComExecutionContext {
public:
    Result<void> initializeMta();
    Result<void> runOnComWorker(std::function<Result<void>()> task);
};
```

`runOnComWorker` 的具体实现可在 Phase 3 引入 Task Scheduler 或 WMI 前完成。Phase 1 不依赖 COM。

## 14. 阶段落地范围

### 14.1 Phase 1

实现文件：

- common result / handle / string / time。
- core context / options / service。
- ProcessInspector。
- TokenInspector 的基础 Token、IL、Elevation。
- SessionInspector 的 SessionId。
- RuleEngine 的 R001、R002、R003、R008。
- TextExporter、JsonExporter。
- CLI inspect、compare。

不实现：

- DesktopInspector。
- BrowserInspector。
- GUI。
- COM/WMI。
- Signature、Manifest、AppCompat。

### 14.2 Phase 2

新增：

- WindowInspector。
- BrowserInspector。
- RuleEngine 的 R005、R006。
- CLI browser、windows、tree。

### 14.3 Phase 3

新增：

- DesktopInspector。
- CompatibilityInspector。
- ManifestInspector。
- SignatureInspector。
- ServiceInspector。
- StartupInspector。
- RuleEngine 的 R004、R007、R009、R010、R011、R012。
- MarkdownExporter、HTMLExporter。

### 14.4 Phase 4

新增：

- Qt GUI。
- xianc2 集成封装。
- 现场诊断包。
- GUI 测试与人工验收清单。

## 15. 测试详细设计

### 15.1 单元测试

规则引擎测试：

- Medium -> High 命中 R001。
- Session 不同命中 R002。
- User SID 不同命中 R003。
- 多规则命中时 overallSeverity 取最高等级。

浏览器识别测试：

- Chrome `--utility-sub-type=network.mojom.NetworkService` 识别为 NetworkService。
- Chrome 无 `--type=` 识别为 Main。
- Firefox `-contentproc` 识别为 Renderer。

脱敏测试：

- `--password=abc` 输出 `--password=***`。
- `--token abc` 输出 `--token ***`。
- `--sid S-1-5-21-xxxx` 输出前 4 字符加 `***`。

### 15.2 集成测试

Windows 测试机执行：

- 当前进程 inspect。
- 普通启动和管理员启动 UAC 差异。
- Below Normal 优先级识别。
- Chrome / Edge / Firefox 浏览器 PID 识别。
- AppCompat 测试程序兼容层读取。

### 15.3 人工验收

需要人工或受控环境验证：

- Session 0 服务操作用户浏览器风险。
- 不同用户 SID。
- 不同 Desktop。
- Qt GUI 页面行为。

## 16. 依赖与构建

### 16.1 CMake 目标

```text
wpsi_core       静态库，核心模型、Inspector、规则、报告
wpsi_cli        命令行可执行文件
wpsi_gui        Qt GUI，可选
wpsi_tests      单元测试和集成测试
```

### 16.2 Windows 库

预计链接：

- `Advapi32`
- `User32`
- `Wtsapi32`
- `Psapi`
- `Shell32`
- `Shlwapi`
- `Wintrust`
- `Crypt32`
- `Taskschd`
- `Comsuppw`
- `Ole32`
- `OleAut32`

### 16.3 第三方依赖

第一阶段尽量不引入重型依赖。

- JSON：可使用 `nlohmann/json` 或项目既有 JSON 库。
- 日志：可使用 `spdlog` 或项目既有日志库。
- 测试：推荐 GoogleTest。

若项目需要保持最小依赖，JSON 和日志可先用轻量内部实现，后续替换。

## 17. 详细设计验收

本文档满足以下条件后，可进入实现计划：

1. Phase 1 文件边界清晰。
2. 核心数据模型字段覆盖 SRS Phase 1 和后续扩展点。
3. Inspector 接口可独立 mock。
4. RuleEngine 输入输出稳定。
5. CLI 行为、退出码和输出路径明确。
6. 错误降级、脱敏、线程模型和测试策略可执行。
