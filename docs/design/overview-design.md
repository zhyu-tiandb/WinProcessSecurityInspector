# Windows 进程安全上下文与桌面会话诊断工具概要设计

## 1. 项目定位

Windows 进程安全上下文与桌面会话诊断工具，工程名 `WinProcessSecurityInspector`，简称 `WPSI`。

本工具用于采集并对比 Windows 进程的安全上下文、桌面会话、窗口归属、浏览器多进程关系和启动来源，自动识别可能导致桌面交互失败、UIPI 阻断、Session 隔离、浏览器 PID 误判和权限不足的问题。

工具需要同时满足三类使用方式：

- 独立命令行工具：用于现场快速诊断和导出报告。
- Qt 图形界面工具：用于可视化查看进程、Token、Session、窗口和诊断结论。
- 可集成库：供 `xianc2` 或其他组件直接调用核心诊断能力。

## 2. 总体架构

项目采用“核心库 + 应用入口 + 集成适配”的分层架构。

```text
CLI / GUI / xianc2 integration
        |
        v
Diagnosis service facade
        |
        v
Inspectors + diagnosis engine + report exporter
        |
        v
Windows API / WMI / registry / service manager / task scheduler
```

### 2.1 核心库

核心库负责所有平台诊断能力，包含：

- 进程基础信息采集。
- Token、完整性级别、UAC、管理员 SID、特权、UIAccess、AppContainer 采集。
- Session、Window Station、Desktop、窗口枚举采集。
- 浏览器主进程和子进程角色识别。
- AppCompat、Manifest、签名、服务、启动来源采集。
- 诊断规则执行。
- 报告模型生成和导出。

核心库不得依赖 CLI 或 GUI。

### 2.2 CLI

CLI 提供现场诊断入口，支持需求中的命令：

- `wpsi inspect`
- `wpsi inspect --pid <pid>`
- `wpsi inspect --name <process>`
- `wpsi compare --pid <pid1> --pid <pid2>`
- `wpsi browser --network-pid <pid>`
- `wpsi sessions`
- `wpsi windows --pid <pid>`
- `wpsi tree --pid <pid>`
- `wpsi export --format json|markdown|html`

第一阶段优先实现 `inspect`、`compare`、文本输出和 JSON 输出。

### 2.3 GUI

GUI 默认保持 Qt 5 兼容，以满足现有 `xianc2` 项目集成约束。若后续建设独立 GUI 产品形态，可评估 Qt 6.5 LTS 或更高版本，但不得破坏核心库和 Qt 5 调用方的兼容性。

GUI 作为核心库的可视化调用方。主要视图包括：

- 进程列表。
- 进程详情页签。
- 多进程对比视图。
- 浏览器诊断视图。
- 自动诊断结论视图。
- 报告导出入口。

GUI 不直接调用底层 Windows API，避免采集逻辑分散。

### 2.4 xianc2 集成层

`src/integration/xianc2` 封装面向 `xianc2` 的轻量接口，屏蔽内部模型细节。

建议接口：

```cpp
ProcessSecurityContext inspect_process(DWORD pid);
BrowserProcessContext inspect_browser_process(DWORD pid);
ComparisonResult compare_processes(DWORD sourcePid, DWORD targetPid);
DiagnosisReport diagnose_interaction(DWORD sourcePid, DWORD targetPid);
```

## 3. 核心数据结构

概要设计阶段先定义模块间稳定契约，具体字段类型可在详细设计中细化为强类型枚举、`std::optional` 或结果包装类型。

```cpp
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

enum class DiagnosisSeverity {
    Info,
    Notice,
    Warning,
    Error,
    Critical
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

struct FieldStatus {
    bool available;
    unsigned long errorCode;
    std::string message;
};

struct ProcessInfo {
    unsigned long pid;
    unsigned long parentPid;
    std::wstring name;
    std::wstring executablePath;
    std::wstring commandLine;
    std::chrono::system_clock::time_point startTime;
    std::wstring architecture;
    unsigned long sessionId;
    std::wstring priorityClassName;
    unsigned long threadCount;
    unsigned long handleCount;
    bool inJobObject;
    std::wstring serviceName;
};

struct TokenInfo {
    std::wstring userName;
    std::wstring domain;
    std::wstring userSid;
    std::wstring logonSid;
    unsigned long long authenticationId;
    IntegrityLevel integrityLevel;
    unsigned long integrityRid;
    bool elevated;
    ElevationType elevationType;
    bool hasLinkedToken;
    IntegrityLevel linkedTokenIntegrityLevel;
    bool administratorMember;
    bool administratorEnabled;
    bool administratorDenyOnly;
    bool uiAccess;
    bool appContainer;
    std::vector<std::wstring> privilegeNames;
};

struct DesktopInfo {
    std::wstring windowStation;
    std::wstring desktop;
    std::wstring threadDesktop;
    std::wstring inputDesktop;
};

struct WindowInfo {
    unsigned long long hwnd;
    unsigned long ownerPid;
    unsigned long ownerThreadId;
    std::wstring title;
    std::wstring className;
    bool visible;
    bool minimized;
    bool foreground;
    bool toolWindow;
    bool hasOwnerWindow;
    std::wstring desktop;
};

struct BrowserProcessContext {
    unsigned long inputPid;
    BrowserProcessRole role;
    unsigned long mainProcessPid;
    unsigned long long topLevelWindowHwnd;
    std::wstring browserName;
    std::wstring profilePath;
};

struct ProcessSecurityContext {
    ProcessInfo process;
    TokenInfo token;
    DesktopInfo desktop;
    std::vector<WindowInfo> windows;
};

struct RuleResult {
    std::string ruleId;
    DiagnosisSeverity severity;
    std::string title;
    std::string evidence;
    std::string recommendation;
};

struct ComparisonResult {
    unsigned long sourcePid;
    unsigned long targetPid;
    bool sameSession;
    bool sameUserSid;
    bool sameWindowStation;
    bool sameDesktop;
    bool sourceIntegrityLowerThanTarget;
    bool sourceAppContainer;
    bool targetAppContainer;
    bool sourceUIAccess;
    bool targetUIAccess;
};

struct DiagnosisReport {
    ProcessSecurityContext source;
    ProcessSecurityContext target;
    std::vector<RuleResult> ruleResults;
    DiagnosisSeverity overallSeverity;
};
```

## 4. 项目目录树

```text
WinProcessSecurityInspector/
├─ CMakeLists.txt
├─ README.md
├─ docs/
│  ├─ requirements/
│  ├─ design/
│  │  └─ overview-design.md
│  ├─ api/
│  └─ test-cases/
├─ include/
│  └─ wpsi/
│     ├─ core/
│     ├─ inspectors/
│     ├─ diagnosis/
│     ├─ report/
│     └─ common/
├─ src/
│  ├─ core/
│  ├─ inspectors/
│  │  ├─ process/
│  │  ├─ token/
│  │  ├─ session/
│  │  ├─ desktop/
│  │  ├─ window/
│  │  ├─ browser/
│  │  ├─ compatibility/
│  │  ├─ manifest/
│  │  ├─ signature/
│  │  ├─ service/
│  │  └─ startup/
│  ├─ diagnosis/
│  ├─ report/
│  ├─ cli/
│  ├─ gui/
│  └─ integration/
│     └─ xianc2/
├─ tests/
│  ├─ unit/
│  ├─ integration/
│  └─ fixtures/
├─ tools/
│  ├─ scripts/
│  └─ packaging/
├─ examples/
│  ├─ cli/
│  └─ xianc2/
├─ config/
│  └─ diagnosis-rules.json
└─ output/
   ├─ reports/
   └─ logs/
```

## 5. 模块职责

### 5.1 `src/core`

提供统一调度、上下文对象、错误模型和公共服务门面。

职责：

- 根据 CLI/GUI/API 请求组织采集流程。
- 聚合多个 Inspector 的输出。
- 控制超时、权限不足降级和敏感信息脱敏。
- 对外提供稳定接口。

### 5.2 `src/inspectors/process`

采集进程基础信息：

- 进程名、PID、Parent PID。
- 可执行路径、命令行、启动时间。
- 架构、Session ID、优先级、线程数、句柄数。
- Job Object 归属。
- 服务名关联。

### 5.3 `src/inspectors/token`

采集进程 Token 信息：

- User SID、Logon SID、Authentication ID。
- Token Type。
- Integrity Level 和 RID。
- Elevation、Elevation Type、Linked Token。
- Administrators SID 是否存在、启用或 Deny-Only。
- Token Privileges。
- UIAccess。
- AppContainer SID 和 Capability SID。

### 5.4 `src/inspectors/session`

采集 Session 信息：

- 进程 Session ID。
- 当前活动控制台 Session。
- 当前交互用户 Session。
- Session 状态、用户、锁定状态。
- 是否为 Session 0。

### 5.5 `src/inspectors/desktop`

采集桌面交互环境：

- Window Station。
- Desktop。
- 当前线程 Desktop。
- 当前输入 Desktop。
- 目标窗口 Desktop。

### 5.6 `src/inspectors/window`

枚举和分析窗口：

- HWND、标题、窗口类。
- 可见、最小化、前台状态。
- 所属 PID 和线程。
- Owner Window、Tool Window。
- 目标进程是否存在可见顶层窗口。

### 5.7 `src/inspectors/browser`

识别浏览器多进程关系：

- Chrome、Edge、Firefox 主进程。
- Renderer、Network Service、GPU Process、Utility、Crash Handler、Extension Process。
- 根据父子关系、命令行、User Data Directory、Session、User SID 和顶层窗口定位同一浏览器实例。
- Chrome / Edge 优先识别 `--type=renderer`、`--type=utility`、`--type=gpu-process`、`--utility-sub-type=network.mojom.NetworkService` 等参数。
- Firefox 优先识别 `-contentproc`、`--type=gpu`、`-sandbox`、`-parentBuildID` 等参数，并结合父子关系、Profile 路径和顶层窗口判断主进程。
- 浏览器识别优先级为：进程名匹配 -> 命令行参数匹配 -> 父子关系 -> 顶层窗口 -> User SID / Session / Profile 归属。

### 5.8 `src/inspectors/compatibility`

读取 AppCompat 注册表：

- `RUNASADMIN`
- `RUNASINVOKER`
- `RunAsHighest`
- `RunAsRevoke`
- `WINXPSP3`
- `DISABLETHEMES`
- `HIGHDPIAWARE`

### 5.9 `src/inspectors/manifest`

读取 EXE Manifest：

- `requestedExecutionLevel`
- `uiAccess`

### 5.10 `src/inspectors/signature`

采集 Authenticode 签名和文件可信信息：

- 是否签名。
- 签名是否有效。
- 签名者、证书颁发者、时间戳。
- 文件哈希。

### 5.11 `src/inspectors/service`

识别进程是否属于 Windows Service，并采集：

- 服务名、显示名。
- 启动类型、服务账户。
- Service Type、状态。
- 是否允许交互桌面。
- 是否延迟启动、是否由 SCM 启动。

### 5.12 `src/inspectors/startup`

识别启动来源：

- Run / RunOnce 注册表。
- Startup 文件夹。
- 任务计划程序。
- Windows Service。
- 父进程。
- ShellExecute runas。

### 5.13 `src/diagnosis`

执行自动诊断规则，输出 `INFO`、`NOTICE`、`WARNING`、`ERROR`、`CRITICAL` 五级结论。

规则引擎接口：

```cpp
struct DiagnosisContext {
    ProcessSecurityContext source;
    ProcessSecurityContext target;
    BrowserProcessContext browser;
};

std::vector<RuleResult> evaluate_rules(const DiagnosisContext& context);
DiagnosisReport diagnose_interaction(const DiagnosisContext& context);
```

首批规则映射：

| 规则 ID | 规则 | 默认等级 |
| --- | --- | --- |
| R001 | 调用方完整性级别低于目标进程 | WARNING |
| R002 | Session 不一致 | ERROR |
| R003 | User SID 不一致 | ERROR |
| R004 | 服务进程位于 Session 0 且尝试操作用户 Session 浏览器 | CRITICAL |
| R005 | 输入 PID 是浏览器子进程 | WARNING |
| R006 | 目标 PID 无可见顶层窗口 | WARNING |
| R007 | Medium / Limited 进程涉及管理员能力 | WARNING |
| R008 | 进程优先级低于 Normal | NOTICE |
| R009 | 存在 AppCompat 兼容性层 | NOTICE |
| R010 | Window Station 或 Desktop 不一致 | CRITICAL |
| R011 | 目标进程为 AppContainer | WARNING |
| R012 | 调用方无 UIAccess 且调用方完整性级别低于目标进程 | WARNING |

多条规则同时命中时，`DiagnosisReport.overallSeverity` 取最高等级。每条规则应保留证据字段和建议字段，便于报告追溯。

R012 默认与 R001 合并展示为一条 UIPI/UIAccess 风险结论，避免重复告警。

规则配置文件为 `config/diagnosis-rules.json`。配置支持规则启用/禁用、默认等级覆盖和说明文字覆盖。配置文件只影响诊断输出，不改变底层采集行为。

### 5.14 `src/report`

负责报告导出：

- Console text。
- JSON。
- Markdown。
- HTML。
- 日志文件。

第一阶段实现 Console text 和 JSON。

## 6. 核心数据流

### 6.1 单进程诊断

```text
输入 PID 或进程名
  -> ProcessInspector
  -> TokenInspector
  -> SessionInspector
  -> DesktopInspector
  -> WindowInspector
  -> DiagnosisEngine
  -> ReportExporter
```

### 6.2 多进程对比

```text
输入 source PID 和 target PID
  -> 分别采集 ProcessSecurityContext
  -> ComparisonEngine 对比 IL / Session / User SID / Desktop / UIAccess / AppContainer
  -> DiagnosisEngine 生成风险结论
  -> ReportExporter 输出
```

### 6.3 浏览器访问诊断

```text
输入 WFP network PID
  -> BrowserInspector 判断角色
  -> 沿父进程链查找浏览器主进程
  -> WindowInspector 查找同实例顶层窗口
  -> 采集调用方和浏览器主进程安全上下文
  -> DiagnosisEngine 判断 UIPI / Session / Desktop / User SID 风险
  -> ReportExporter 输出
```

## 7. 错误处理与降级策略

工具默认不要求管理员权限。遇到权限不足时，应返回部分结果并标记字段状态。

错误处理原则：

- 采集失败不得导致整次诊断失败，除非目标进程不存在。
- 每个字段保留 `available`、`value`、`errorCode`、`message`。
- 对 SYSTEM、其他用户、受保护进程等读取失败场景给出明确提示。
- 报告中说明“建议以管理员身份重新运行以获得完整结果”。
- 敏感命令行参数默认脱敏。

## 8. 并发与线程模型

核心库默认采用同步接口，调用方可在外层线程池或 GUI Worker 线程中并发调度。

线程安全约束：

- 核心库公开的无状态诊断函数应设计为可重入。
- Inspector 不保存跨请求可变全局状态；共享缓存必须使用锁或只读初始化。
- `EnumWindows`、`GetTokenInformation`、`OpenProcessToken` 等同步 API 在调用线程执行。
- GUI 不得在 UI 线程执行全系统扫描、WMI 查询、签名验证等可能阻塞操作。
- 核心库不保证可在信号处理函数或进程崩溃回调中安全调用。

## 9. Windows API 依赖与 COM 初始化

底层依赖按 Inspector 隔离，单个依赖失败不应阻断整次诊断。

| 模块 | 主要依赖 | 降级策略 |
| --- | --- | --- |
| process | Toolhelp、PSAPI、NtQueryInformationProcess | 返回可获得字段，命令行不可读时标记权限不足 |
| token | OpenProcessToken、GetTokenInformation | Token 不可读时保留进程基础信息 |
| session | WTS API | Session 详情不可读时保留 SessionId |
| window | EnumWindows、GetWindowThreadProcessId | 无窗口时返回空列表 |
| service | SCM API，必要时 WMI | SCM 不可用时跳过服务详情 |
| startup | Registry、Task Scheduler COM | COM 初始化失败时跳过任务计划来源 |
| signature | WinVerifyTrust | 验签失败时返回签名状态未知 |

COM 调用默认使用 `COINIT_MULTITHREADED`。如 Qt GUI 或第三方宿主已初始化不同 COM Apartment，集成层应检测 `RPC_E_CHANGED_MODE` 并在专用工作线程中执行 COM 相关 Inspector。

WMI 和任务计划程序查询默认单项超时不超过 3 秒。超时后返回部分结果，并在报告中标记降级原因。

## 10. 测试策略

测试分为三层：

- 单元测试：验证规则引擎、浏览器角色识别、脱敏、报告导出等纯逻辑。
- 集成测试：在 Windows 测试机上验证真实进程、Token、Session、窗口和服务采集。
- 端到端测试：通过 CLI 构造普通启动、管理员启动、Session 0、浏览器子进程和 AppCompat 场景。

Windows API 通过接口抽象层或依赖注入进行 mock。核心规则不直接依赖真实 Windows API 返回值，而依赖 `ProcessSecurityContext`、`BrowserProcessContext` 等快照模型。

`tests/fixtures/` 用于保存脱敏后的进程树快照、Token 快照、窗口列表快照和浏览器命令行样本。无法访问真实 Windows API 的 CI 环境至少运行纯逻辑单元测试；完整集成测试在 Windows 环境中执行。

GUI 测试使用 Qt Test 覆盖模型和 Widget 级交互。跨窗口自动化可作为产品化阶段选项，无法自动化的场景进入人工验收清单。

## 11. 日志策略

日志用于定位工具自身问题，不替代诊断报告。

- 推荐使用 `spdlog` 或项目既有日志库。
- 日志级别映射为 trace、debug、info、warn、error、critical。
- 默认日志级别为 info，`--verbose` 可提升到 debug。
- 日志文件采用大小滚动策略，单文件建议不超过 10 MB，默认保留 5 个历史文件。
- 日志和报告共享脱敏规则，不输出密码、Token、Cookie、认证密钥。

## 12. 安全设计

工具只读取诊断信息，不执行会改变系统安全状态的操作。

限制：

- 不修改 Token。
- 不提升目标进程权限。
- 不注入目标进程。
- 不绕过 UIPI。
- 不关闭安全软件。
- 不修改 UAC 设置。
- 不修改兼容性注册表。
- 不输出密码、Token、Cookie、认证密钥。

## 13. 输出报告结构

报告默认包含：

1. 系统概况。
2. 当前交互用户。
3. 活动 Session。
4. 目标进程列表。
5. 每个进程的安全上下文。
6. 进程树。
7. 浏览器进程角色识别。
8. 顶层窗口列表。
9. 权限差异对比。
10. 自动诊断结论。
11. 风险等级。
12. 修复建议。

## 14. 分阶段实现计划

### 第一阶段：最小可用版本

实现：

- PID、进程名、路径。
- Parent PID。
- User SID。
- SessionId。
- Integrity Level。
- Elevation。
- Elevation Type。
- Priority Class。
- 进程对比。
- 文本和 JSON 输出。

目标：覆盖“开机自启动异常、管理员启动正常、基础权限差异定位”的主要场景。

### 第二阶段：浏览器专项

实现：

- Chrome / Edge 子进程角色识别。
- 浏览器主进程查找。
- 顶层窗口定位。
- 当前前台窗口。
- UIPI 和 Session 自动判断。

目标：覆盖 WFP PID 不是浏览器主进程、认证页无法弹出或刷新、无法控制浏览器窗口等场景。

### 第三阶段：完整诊断

实现：

- Window Station。
- Desktop。
- UIAccess。
- AppContainer。
- Token Privileges。
- Job Object。
- Manifest。
- AppCompat。
- 服务和任务计划来源。

目标：形成完整现场诊断证据链。

### 第四阶段：产品化

实现：

- Qt 图形界面。
- HTML 报告。
- xianc2 集成。
- 一键采集现场诊断包。
- 诊断规则配置化。
- 日志脱敏。

## 15. 验收映射

第一阶段验收：

- 能正确输出指定进程的 PID、Parent PID、User SID、SessionId。
- 能正确识别 Medium / Limited 与 High / Full。
- 能输出 Integrity Level、Elevation、Elevation Type、Priority Class。
- 能比较两个进程的 IL、SessionId、User SID。
- 能输出文本和 JSON。

第二阶段验收：

- 输入 Chrome Network Service PID 后，能找到浏览器主进程和顶层窗口。
- 能识别浏览器子进程角色。
- 能输出 UIPI、Session、User SID 风险判断。

第三阶段验收：

- 能识别 Session 0 服务进程。
- 能识别不同 Window Station / Desktop。
- 能读取 AppCompat、Manifest、UIAccess、Privileges、Job Object。

第四阶段验收：

- GUI 可展示进程列表、详情、对比视图和诊断结论。
- 同一次诊断可导出 JSON、Markdown、HTML。
- xianc2 能通过库接口调用诊断能力。
