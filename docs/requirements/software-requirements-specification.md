# Windows 进程安全上下文与桌面会话诊断工具需求规格说明

## 1. 文档目的

本文档根据《Windows 进程安全上下文与桌面会话诊断工具需求说明》整理形成，用于指导 `WinProcessSecurityInspector` 的架构设计、开发拆分、测试验收和后续集成。

## 2. 工具概述

工具名称：Windows 进程安全上下文与桌面会话诊断工具

建议工程名：`WinProcessSecurityInspector`

简称：`WPSI`

本工具用于采集、对比并诊断 Windows 进程的安全上下文、桌面会话、窗口归属、进程启动关系和浏览器多进程关系，帮助定位以下问题：

- 开机自启动后功能异常。
- 手工以管理员身份运行后功能恢复。
- 无法控制浏览器窗口。
- `SendInput`、`SetForegroundWindow`、窗口消息操作失败。
- 服务进程无法弹出用户可见窗口。
- WFP 获取到的浏览器 PID 不是浏览器主进程。
- 浏览器认证页面无法打开或无法刷新。
- 不同用户或不同 Session 之间 IPC、窗口交互失败。
- 程序权限不足但现场无法快速定位。

## 3. 建设目标

工具应实现以下目标：

1. 采集指定进程的完整安全上下文。
2. 对比当前应用、访问控制程序、交互用户和目标浏览器之间的权限差异。
3. 识别浏览器主进程、子进程和顶层窗口之间的关系。
4. 判断进程是否具备桌面交互条件。
5. 自动生成明确的风险、异常和修复建议。
6. 支持命令行、图形界面和文件导出。
7. 能够作为独立诊断工具使用，也能作为库集成到 `xianc2` 中。
8. 为现场问题提供可复现、可对比、可归档的诊断证据。

## 4. 适用对象

工具主要面向以下进程或输入来源：

- `xianc2.exe`
- `fjAccessControl.exe`
- Windows Service
- `explorer.exe`
- `chrome.exe`
- `msedge.exe`
- `firefox.exe`
- 其他受控浏览器
- WFP 事件中获得的源进程
- 用户指定的任意 PID 或进程名称

## 5. 运行模式需求

### 5.1 当前环境诊断模式

命令示例：

```text
wpsi.exe inspect
```

工具应自动分析当前登录用户及相关进程，包括：

- 当前诊断工具进程。
- `explorer.exe`。
- `xianc2.exe`。
- `fjAccessControl.exe`。
- 主流浏览器进程。
- 当前前台窗口所属进程。

### 5.2 指定进程诊断模式

命令示例：

```text
wpsi.exe inspect --pid 4520
wpsi.exe inspect --name chrome.exe
```

工具应支持按 PID 或进程名诊断，并支持同时指定多个进程。

```text
wpsi.exe compare --pid 4520 --pid 6688
```

### 5.3 浏览器访问诊断模式

命令示例：

```text
wpsi.exe browser --network-pid 9824
```

输入 WFP 获取到的浏览器 PID 后，工具应自动完成：

1. 获取进程信息。
2. 判断是否为浏览器子进程。
3. 沿父进程链向上查找浏览器主进程。
4. 查找同一浏览器实例的顶层窗口。
5. 获取当前前台窗口。
6. 对比调用进程与浏览器主进程的权限。
7. 判断是否可能被 UIPI、Session 或桌面隔离阻断。

## 6. 功能需求

### 6.1 进程基础信息采集

对每个目标进程至少采集：

| 字段 | 说明 |
| --- | --- |
| Process Name | 进程名称 |
| PID | 当前进程 ID |
| Parent PID | 父进程 ID |
| Executable Path | 可执行文件完整路径 |
| Command Line | 启动命令行 |
| Process Start Time | 进程启动时间 |
| Architecture | x86、x64、ARM64 |
| Session ID | 所属 Session |
| Priority Class | 基本优先级 |
| Thread Count | 线程数量 |
| Handle Count | 句柄数量 |
| Is In Job | 是否处于 Job Object |
| Service Name | 如属于服务，显示服务名称 |

### 6.2 用户身份信息采集

对进程 Token 至少采集：

| 字段 | 说明 |
| --- | --- |
| User Name | 用户名 |
| Domain | 用户域 |
| User SID | 用户 SID |
| Logon SID | 登录会话 SID |
| Authentication ID | 登录认证 LUID |
| Is LocalSystem | 是否为 SYSTEM |
| Is LocalService | 是否为 LocalService |
| Is NetworkService | 是否为 NetworkService |
| Is Interactive User | 是否为交互登录用户 |
| Token Type | Primary 或 Impersonation |

典型 SID 应识别为可读名称：

| SID | 名称 |
| --- | --- |
| `S-1-5-18` | LocalSystem |
| `S-1-5-19` | LocalService |
| `S-1-5-20` | NetworkService |

### 6.3 Integrity Level 检测

工具必须读取 `TokenIntegrityLevel`，并输出原始 RID 和可读名称。

完整性级别映射：

- Untrusted
- Low
- Medium
- Medium Plus
- High
- System
- Protected Process

输出示例：

```text
Integrity Level : Medium
Integrity RID   : 0x00002000
```

### 6.4 UAC 和 Elevation 检测

工具必须采集：

- `TokenElevation`
- `TokenElevationType`
- `TokenLinkedToken`

输出字段：

| 字段 | 说明 |
| --- | --- |
| Elevated | 当前是否已提升 |
| Elevation Type | Default、Full、Limited |
| Has Linked Token | 是否存在关联 Token |
| Linked Token IL | 关联 Token 的完整性级别 |
| UAC Split Token | 是否为管理员拆分令牌 |

### 6.5 管理员权限检测

工具应区分：

- 用户是否属于 Administrators 组。
- 当前 Token 中管理员 SID 是否启用。
- 管理员 SID 是否为 Deny-Only。
- 当前进程是否实际以管理员权限运行。

不得仅依赖 `IsUserAnAdmin()` 判断管理员权限。

### 6.6 Token 特权检测

工具应读取进程 Token 中的特权列表，并标识每项状态：

- Present
- Enabled
- Disabled
- Removed

重点关注：

- `SeDebugPrivilege`
- `SeImpersonatePrivilege`
- `SeTcbPrivilege`
- `SeAssignPrimaryTokenPrivilege`
- `SeIncreaseQuotaPrivilege`
- `SeLoadDriverPrivilege`
- `SeCreateGlobalPrivilege`
- `SeSecurityPrivilege`
- `SeTakeOwnershipPrivilege`
- `SeShutdownPrivilege`

### 6.7 UIAccess 检测

工具应读取 `TokenUIAccess`，并输出：

```text
UIAccess : Yes / No
```

同时检查：

- 程序是否位于受信任目录。
- EXE 是否有数字签名。
- Manifest 是否声明 `uiAccess="true"`。

工具只做检测，不自动修改。

### 6.8 AppContainer 检测

工具应读取：

- `TokenIsAppContainer`
- `TokenAppContainerSid`
- `TokenCapabilities`

输出：

- 是否为 AppContainer。
- AppContainer SID。
- Capability SID。
- 是否为浏览器沙箱子进程。

### 6.9 Session 检测

工具必须采集：

- Process SessionId。
- 当前活动控制台 Session。
- 当前交互用户 Session。
- Session 状态。
- Session 用户。
- Session 是否锁定。
- 是否为 Session 0。

以下组合场景应标为严重异常：

- 服务进程位于 Session 0，且尝试直接操作用户 Session 中的浏览器窗口。
- 浏览器进程位于非交互用户 Session，导致用户不可见或无法进行正常桌面交互。

说明：服务进程位于 Session 0、浏览器位于交互用户 Session 本身是 Windows 的正常行为，不应单独判定为异常。

### 6.10 Window Station 和 Desktop 检测

工具应获取：

- 进程关联的 Window Station。
- 进程关联的 Desktop。
- 当前线程 Desktop。
- 目标窗口 Desktop。
- 当前输入 Desktop。

应识别不同 Window Station 或 Desktop 导致的桌面交互不可用问题。

### 6.11 进程优先级检测

工具应采集：

- `GetPriorityClass`
- `GetThreadPriority`

优先级映射：

- Idle
- Below Normal
- Normal
- Above Normal
- High
- Realtime

同时检查：

- 是否调用后台模式。
- 是否由父进程继承。
- 是否由任务计划程序设置。
- 是否处于资源限制 Job Object。

优先级低可能导致高负载下响应延迟，但不应被误判为 UAC 或 Integrity Level 权限问题。

### 6.12 Job Object 检测

工具应检测：

- `IsProcessInJob`
- `QueryInformationJobObject`

采集内容：

- 是否加入 Job Object。
- CPU 限制。
- 内存限制。
- 活跃进程限制。
- UI 限制。
- Kill-on-job-close。
- 优先级限制。

### 6.13 进程父子关系分析

工具必须构建进程树，支持：

- 向上追溯父进程。
- 向下列出子进程。
- 显示启动时间。
- 判断父 PID 是否已被复用。
- 显示每个进程的命令行参数。

### 6.14 浏览器主进程识别

针对 Chrome、Edge、Firefox，工具应识别：

- 主进程。
- Renderer。
- Network Service。
- GPU Process。
- Utility Process。
- Crash Handler。
- Extension Process。

识别依据包括：

- 进程名。
- 父子关系。
- 命令行参数。
- 顶层窗口。
- 创建时间。
- User Data Directory。
- Session。
- User SID。

Chrome / Edge 子进程常见参数：

- `--type=renderer`
- `--type=utility`
- `--type=gpu-process`
- `--utility-sub-type=network.mojom.NetworkService`

主进程通常不带 `--type=` 参数。

Firefox 子进程识别应单独处理。常见依据包括：

| 维度 | Firefox 识别特征 |
| --- | --- |
| 主进程 | `firefox.exe`，通常无 `-contentproc` 参数，可能带 `--parent` |
| 内容子进程 | `firefox.exe` 且命令行包含 `-contentproc` |
| GPU 或沙箱子进程 | 命令行可能包含 `--type=gpu`、`-contentproc`、`-sandbox` |
| 同实例判断 | 父子关系、启动时间、用户 SID、Session、Profile 路径、顶层窗口 |

浏览器识别优先级应为：进程名匹配 -> 命令行参数匹配 -> 父子关系 -> 顶层窗口 -> User SID / Session / Profile 归属。

### 6.15 顶层窗口检测

工具应枚举目标进程相关窗口：

- HWND。
- 窗口标题。
- Window Class。
- 可见状态。
- 最小化状态。
- 是否前台窗口。
- 所属 PID。
- 所属线程。
- 窗口 Desktop。
- 是否为 Tool Window。
- 是否有 Owner Window。

工具应判断：

- 目标 PID 是否存在可见顶层窗口。
- WFP PID 是否只是无窗口的浏览器子进程。
- 浏览器主进程是否拥有窗口。
- 当前前台浏览器窗口属于哪个 PID。

### 6.16 前台交互能力判断

工具应综合判断当前进程是否有能力：

- 找到目标浏览器窗口。
- 切换前台窗口。
- 调用 `SendInput`。
- 发送窗口消息。
- 操作剪贴板。
- 在目标桌面显示 UI。

判断规则至少包括：

1. Session 是否相同。
2. User SID 是否相同。
3. Window Station 是否相同。
4. Desktop 是否相同。
5. 调用方 IL 是否低于目标 IL。
6. 目标是否为 AppContainer。
7. 调用方是否具有 UIAccess。
8. 是否存在前台切换限制。
9. 是否为服务 Session。
10. 是否存在 UIPI 限制。

### 6.17 UIPI 风险判断

工具应自动比较调用方与目标进程的 Integrity Level。

典型判断：

- 调用方 Medium，目标 High：输出高风险，窗口消息、自动化控制或 `SendInput` 可能受 UIPI 限制。
- 调用方 High，目标 Medium：未发现由完整性级别导致的单向 UIPI 阻断。

最终操作是否成功仍受前台窗口策略和目标程序行为影响。

### 6.18 AppCompat 配置检测

工具应检查以下注册表：

- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`

识别：

- `RUNASADMIN`
- `RUNASINVOKER`
- `RunAsHighest`
- `RunAsRevoke`
- `WINXPSP3`
- `DISABLETHEMES`
- `HIGHDPIAWARE`

工具应显示目标 EXE 是否受到兼容层影响，并解释潜在影响。

### 6.19 Manifest 检测

工具应读取 EXE Manifest，识别：

- `requestedExecutionLevel`
- `uiAccess`

支持的执行级别：

- `asInvoker`
- `highestAvailable`
- `requireAdministrator`

### 6.20 可执行文件签名检测

工具应采集：

- 是否有 Authenticode 签名。
- 签名是否有效。
- 签名者。
- 证书颁发者。
- 时间戳。
- 文件哈希。

该能力用于辅助判断 UIAccess、企业安全策略和文件可信性。

### 6.21 服务信息检测

当进程属于 Windows Service 时，工具应输出：

- 服务名称。
- Display Name。
- 启动类型。
- 服务账户。
- Service Type。
- 是否允许交互桌面。
- 服务 Session。
- 服务状态。
- 是否延迟启动。
- 是否由 SCM 启动。

### 6.22 自启动来源检测

工具应尽量识别进程启动来源：

- 注册表 Run。
- 注册表 RunOnce。
- Startup 文件夹。
- 任务计划程序。
- Windows Service。
- 安装程序启动器。
- 父进程。
- 用户手工启动。
- `ShellExecute runas`。

重点检测注册表路径：

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`

任务计划程序需输出：

- 任务名称。
- Run Level。
- Logon Type。
- Priority。
- 是否仅用户登录时运行。
- 是否使用最高权限运行。

## 7. 自动诊断规则需求

工具至少实现以下规则：

| 编号 | 规则 | 结论 |
| --- | --- | --- |
| R001 | `xianc2 IL < browser IL` | 可能受到 UIPI 限制 |
| R002 | `xianc2 SessionId != browser SessionId` | 无法可靠进行直接桌面交互 |
| R003 | `xianc2 User SID != browser User SID` | 属于不同用户安全上下文，应通过用户态 Agent 或 IPC 协作 |
| R004 | `process SessionId == 0` | 服务进程不应直接弹出用户界面或控制浏览器 |
| R005 | 目标 PID 为浏览器子进程 | 该 PID 不是浏览器主进程，不能直接用于顶层窗口定位 |
| R006 | 目标 PID 未发现可见顶层窗口 | 应继续向父进程或同实例主进程查找 |
| R007 | Medium / Limited 进程涉及管理员能力 | 存在权限不足风险 |
| R008 | 进程优先级低于 Normal | 可能造成高负载下处理延迟，但不是权限问题 |
| R009 | 存在 AppCompat 兼容性层 | 输出覆盖行为和潜在影响 |
| R010 | 调用方 Desktop 与目标 Desktop 不同 | 无法直接进行可靠窗口交互 |
| R011 | 目标进程为 AppContainer | 目标受 AppContainer 隔离，窗口消息和输入可能受限 |
| R012 | 调用方无 UIAccess 且调用方完整性级别低于目标进程 | 缺少 UIAccess 时，前台窗口切换和 `SendInput` 可能受 UIPI 限制 |

## 8. 诊断等级需求

诊断项分为五级：

| 等级 | 含义 |
| --- | --- |
| INFO | 信息项，无异常 |
| NOTICE | 值得关注，但不一定影响功能 |
| WARNING | 可能造成功能异常 |
| ERROR | 已发现明确不兼容条件 |
| CRITICAL | 无法进行目标操作 |

## 9. 输出格式需求

工具应支持以下格式：

- 控制台文本。
- JSON。
- Markdown。
- HTML。
- 日志文件。

命令示例：

```text
wpsi.exe inspect --format json --output result.json
wpsi.exe compare xianc2.exe chrome.exe --format markdown
```

JSON 应适合集成到 `xianc2` 日志或远程诊断平台。

## 10. 推荐报告结构

报告应包含：

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

## 11. 图形界面需求

### 11.1 进程列表

显示字段：

- 名称。
- PID。
- 用户。
- Session。
- Integrity Level。
- Elevation。
- 架构。
- 优先级。

支持排序、筛选和刷新。

### 11.2 进程详情

按页签展示：

- General。
- Token。
- Privileges。
- Session。
- Desktop。
- Windows。
- Parent Tree。
- Browser Role。
- Compatibility。
- Signature。
- Diagnosis。

### 11.3 对比视图

允许选择两个或多个进程进行对比，并突出差异项。

重点对比：

- Integrity Level。
- Session。
- User SID。
- Window Station。
- Desktop。
- Elevation。
- UIAccess。

### 11.4 诊断结论

显示：

- 结论。
- 风险等级。
- 证据。
- 可能影响。
- 建议处理方式。

## 12. 命令行接口需求

建议命令：

```text
wpsi inspect
wpsi inspect --pid <pid>
wpsi inspect --name <process>
wpsi compare --pid <pid1> --pid <pid2>
wpsi browser --network-pid <pid>
wpsi sessions
wpsi windows --pid <pid>
wpsi tree --pid <pid>
wpsi export --format json
```

支持参数：

- `--pid`
- `--name`
- `--all`
- `--browser`
- `--include-children`
- `--include-windows`
- `--include-token`
- `--include-privileges`
- `--format`
- `--output`
- `--verbose`

## 13. 集成接口需求

工具核心能力应封装为独立静态库或动态库。

建议模块：

- `process_inspector`
- `token_inspector`
- `session_inspector`
- `desktop_inspector`
- `window_inspector`
- `browser_inspector`
- `compatibility_inspector`
- `diagnosis_engine`
- `report_exporter`

建议接口：

```cpp
ProcessSecurityContext inspect_process(DWORD pid);
BrowserProcessContext inspect_browser_process(DWORD pid);
ComparisonResult compare_processes(DWORD sourcePid, DWORD targetPid);
DiagnosisReport diagnose_interaction(DWORD sourcePid, DWORD targetPid);
```

供 `xianc2` 调用示例：

```cpp
auto report = diagnose_interaction(
    GetCurrentProcessId(),
    browser_pid);
```

## 14. 权限需求

工具普通模式应以普通用户运行，并尽量获取同一用户进程信息。

以下情况可能需要管理员权限：

- 查询其他用户进程。
- 查询 SYSTEM 进程。
- 获取受保护进程 Token。
- 获取完整命令行。
- 读取服务配置。
- 读取部分任务计划。
- 启用 `SeDebugPrivilege`。

工具不得默认要求管理员权限。权限不足时应提示：

```text
部分进程信息无法读取。建议以管理员身份重新运行以获得完整结果。
```

## 15. 安全需求

工具必须满足：

1. 只读取信息，不修改 Token。
2. 不提升目标进程权限。
3. 不注入目标进程。
4. 不绕过 UIPI。
5. 不关闭安全软件。
6. 不修改 UAC 设置。
7. 不修改兼容性注册表。
8. 导出报告时默认隐藏敏感命令行参数。
9. 用户 SID、用户名和路径支持脱敏。
10. 日志中不得输出密码、Token、Cookie、认证密钥。

敏感命令行参数脱敏规则：

- 参数名包含 `password`、`passwd`、`pwd`、`secret`、`token`、`cookie`、`key`、`credential`、`auth` 时，对应值替换为 `***`。
- 参数名包含 `session`、`sid`、`luid` 时，保留前 4 个字符并追加 `***`。
- 无法可靠识别参数边界时，应隐藏完整参数值，并在报告中标记为已脱敏。

## 16. 兼容性需求

工具应支持：

- Windows 10 x64。
- Windows 11 x64。
- 普通用户。
- 管理员用户。
- UAC 开启和关闭环境。
- 多用户登录。
- 远程桌面 Session。
- Chrome。
- Edge。
- Firefox。
- Qt 5 / C++20 项目集成。

跨架构兼容性要求：

- 推荐发布 x64 原生版本，用于 Windows 10/11 x64 环境。
- 如需 32 位版本，应明确标记其读取 64 位进程命令行、PEB 和部分模块信息时可能受限。
- 进程架构检测应优先使用 `IsWow64Process2`，并区分 x86、x64、ARM64 及模拟层。
- 跨架构读取命令行时，应考虑 WOW64 下 PEB 结构差异；无法可靠读取时返回部分结果和明确提示。

GUI 技术栈要求：

- 默认保持 Qt 5 兼容，以满足现有 `xianc2` 集成约束。
- 新独立 GUI 可评估 Qt 6.5 LTS 或更高版本，但不得破坏 Qt 5 集成目标。

## 17. 性能需求

性能指标：

- 单进程基础诊断不超过 200 毫秒。
- 全系统进程扫描不超过 3 秒。
- 浏览器进程树识别不超过 1 秒。
- 不应持续占用高 CPU。
- 默认不进行周期性监控。
- 实时监控模式刷新周期不低于 1 秒。
- 工具退出后不得残留后台进程。

异常路径超时要求：

- `OpenProcess`、`OpenProcessToken` 等同步 API 失败后应立即返回，不应重试等待超过 100 毫秒。
- WMI、任务计划程序、签名验证等可能阻塞的 Inspector 应设置独立超时，默认单项不超过 3 秒。
- 目标进程退出、访问被拒绝或系统服务不可用时，应返回部分结果，不应阻塞整次诊断。

## 18. 验收标准

### 18.1 基础采集验收

工具能够正确输出指定进程的：

- PID。
- Parent PID。
- User SID。
- SessionId。
- Integrity Level。
- Elevation。
- Elevation Type。
- UIAccess。
- Priority Class。
- Window Station。
- Desktop。

说明：Window Station 和 Desktop 采集属于第三阶段完整诊断能力，对应第 19.3 节。第一阶段验收以 PID、Parent PID、User SID、SessionId、Integrity Level、Elevation、Elevation Type、Priority Class 和基础对比输出为准。

### 18.2 UAC 场景验收

同一程序分别通过普通启动和管理员启动，工具应正确识别：

- Medium + Limited。
- High + Full。

### 18.3 Session 0 验收

对 Windows Service 应识别：

- `SessionId = 0`
- `User = SYSTEM`

并提示不能直接操作用户浏览器。

### 18.4 浏览器多进程验收

输入 Chrome Network Service PID，工具应找到：

- 子进程角色。
- Chrome 主进程。
- 主窗口 HWND。
- 主进程权限信息。

### 18.5 UIPI 验收

构造诊断工具为 Medium、目标进程为 High 的场景，工具应输出 UIPI 风险提示。

### 18.6 用户不一致验收

两个不同用户启动进程时，工具应识别 User SID 不同。

### 18.7 Desktop 不一致验收

服务桌面与用户桌面不一致时，工具应输出明确错误。

### 18.8 优先级验收

将进程设置为 Below Normal 后，工具应正确显示，并区分其与权限问题。

### 18.9 AppCompat 验收

为测试程序配置：

- `RUNASADMIN`
- `RUNASINVOKER`
- `RunAsRevoke`

工具应正确读取并解释。

### 18.10 报告导出验收

同一次诊断能够导出：

- JSON。
- Markdown。
- HTML。

## 19. 开发优先级

### 19.1 第一阶段：最小可用版本

实现：

- PID 和进程路径。
- Parent PID。
- User SID。
- SessionId。
- Integrity Level。
- Elevation。
- Elevation Type。
- Priority Class。
- 进程对比。
- 文本和 JSON 输出。

### 19.2 第二阶段：浏览器专项

实现：

- Chrome / Edge 子进程角色识别。
- 浏览器主进程查找。
- 顶层窗口定位。
- 当前前台窗口。
- UIPI 和 Session 自动判断。

### 19.3 第三阶段：完整诊断

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

### 19.4 第四阶段：产品化

实现：

- Qt 图形界面。
- HTML 报告。
- `xianc2` 集成。
- 一键采集现场诊断包。
- 诊断规则配置化。
- 日志脱敏。

## 20. 最小问题闭环范围

本节描述覆盖现场核心问题所需的最小闭环能力，范围跨越第一至第三阶段。各阶段实际交付内容以第 19 节为准。

最小问题闭环应覆盖：

1. 当前 `xianc2` 的安全上下文。
2. `fjAccessControl` 的安全上下文。
3. `explorer.exe` 的安全上下文。
4. WFP 获取到的浏览器 PID。
5. 浏览器主进程 PID。
6. 浏览器窗口 PID。
7. Integrity Level 对比。
8. Elevation 对比。
9. SessionId 对比。
10. User SID 对比。
11. Window Station 和 Desktop 对比。
12. 自动生成是否存在 UIPI 或 Session 隔离问题的结论。

该最小版本应覆盖大部分现场问题：

- 开机自启动异常。
- 管理员启动正常。
- 无法弹认证页。
- 无法控制浏览器。
- WFP PID 不对应浏览器窗口。
