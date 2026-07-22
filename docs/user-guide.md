# WPSI 命令行使用说明

`wpsi_cli.exe` 用于采集 Windows 进程安全上下文、Session、窗口、浏览器主进程关系和进程树信息，帮助定位权限、UIPI、Session 隔离、浏览器 PID 误判等问题。

建议在测试机使用 Release 产物：

```powershell
build\Release\wpsi_cli.exe
```

不要使用 Debug 产物作为测试机发布包，否则可能依赖 Visual Studio 调试运行库。

## 1. 基础 inspect

```powershell
wpsi_cli.exe inspect
```

作用：

- 诊断当前 `wpsi_cli.exe` 自身进程。
- 用于快速确认工具在当前用户、当前 Session 下能采集哪些字段。

典型输出包括：

- PID
- Process Name
- Executable Path
- Session ID
- Priority Class
- User SID
- Integrity Level
- Elevation
- UIAccess
- AppContainer
- Desktop / Window Station
- Signature / Manifest / Startup 信息，如果可获取

适用场景：

- 验证工具能正常运行。
- 确认当前命令行是否普通权限或管理员权限。
- 对比不同启动方式下工具自身权限差异。

## 2. 按 PID inspect

```powershell
wpsi_cli.exe inspect --pid 1234
```

作用：

- 诊断指定 PID 的单个进程。

示例：

```powershell
wpsi_cli.exe inspect --pid 4520
```

重点看：

- `Session ID`：目标进程是否位于当前交互用户 Session。
- `Integrity Level`：目标是否为 Medium、High、System 等。
- `Elevated` / `Elevation Type`：目标是否已提升。
- `UIAccess`：是否具备跨 IL 辅助访问能力。
- `AppContainer`：是否处于 AppContainer 隔离。
- `[Windows]`：该 PID 是否有可见顶层窗口。
- `[Notice] Partial data returned`：说明部分字段因权限不足或系统限制不可读。

常见判断：

- 如果目标是管理员运行，普通权限工具可能只能读取部分信息。
- 如果目标是服务或 SYSTEM 进程，普通用户模式下 token、服务配置等字段可能不完整。

## 3. 按进程名 inspect

```powershell
wpsi_cli.exe inspect --name xianc2.exe
```

作用：

- 按进程名查找所有匹配进程，并逐个输出诊断信息。

示例：

```powershell
wpsi_cli.exe inspect --name xianc2.exe
wpsi_cli.exe inspect --name chrome.exe
wpsi_cli.exe inspect --name fjAccessControl.exe
```

注意：

- 进程名需要包含 `.exe`。
- 如果同名进程有多个，会输出多个进程块。
- 如果进程不存在，会输出：

```text
No process matched the requested name
```

适用场景：

- 不知道 PID，只知道进程名。
- 现场快速查看 `xianc2.exe`、`chrome.exe`、`msedge.exe`、`firefox.exe` 的权限状态。

## 4. 进程对比 compare

```powershell
wpsi_cli.exe compare --pid 1234 --pid 5678
```

作用：

- 对比两个进程的安全上下文差异。

示例：

```powershell
wpsi_cli.exe compare --pid 4520 --pid 6688
```

输出示例：

```text
[Comparison]
Source PID : 4520
Source Name : xianc2.exe
Target PID : 6688
Target Name : chrome.exe
Same Session : Yes
Same User SID : Yes
Source IL Lower Than Target : No
```

字段说明：

- `Source PID / Source Name`：发起操作的一方，例如 `xianc2.exe`。
- `Target PID / Target Name`：被操作的一方，例如 `chrome.exe`。
- `Same Session`：是否处于同一个 Windows Session。
- `Same User SID`：是否属于同一个用户安全上下文。
- `Source IL Lower Than Target`：Source 的完整性级别是否低于 Target。

重点解释：

```text
Source IL Lower Than Target : Yes
```

表示 Source 完整性级别低于 Target，可能触发 UIPI 限制。典型表现包括：

- 发窗口消息失败。
- `SendInput` 不生效。
- 无法控制浏览器窗口。
- 无法可靠切换前台窗口。

也支持按进程名对比：

```powershell
wpsi_cli.exe compare --name xianc2.exe --name chrome.exe
wpsi_cli.exe compare --name xianc2.exe --pid 5678
wpsi_cli.exe compare --pid 1234 --name chrome.exe
```

如果进程名匹配多个实例，会选择第一个可采集成功的进程，并在输出中显示实际参与对比的 PID 和进程名。

## 5. 浏览器专项 browser

```powershell
wpsi_cli.exe browser --network-pid 9824
```

作用：

- 诊断浏览器相关 PID。
- 适合处理 WFP、网络过滤、访问控制模块拿到的浏览器 PID。
- 判断输入 PID 是浏览器主进程、Renderer、Network Service、GPU、Utility 还是 Crash Handler。
- 尝试沿父进程链定位浏览器主进程。
- 尝试定位浏览器主窗口。

示例：

```powershell
wpsi_cli.exe browser --network-pid 9824
```

典型输出：

```text
[Browser]
Input PID : 9824
Main PID : 6688
Role : NetworkService
Candidate Windows : 1
```

字段说明：

- `Input PID`：输入的 PID，通常来自 WFP 或其他模块。
- `Main PID`：工具推断出的浏览器主进程 PID。
- `Role`：输入 PID 的浏览器角色。
- `Candidate Windows`：候选浏览器顶层窗口数量。

重要说明：

- Chrome / Edge 的网络 PID 常常不是主窗口 PID。
- 如果 `Role` 是 `NetworkService`、`Renderer`、`Utility`，通常不应直接用该 PID 查找窗口。
- 应优先使用 `Main PID` 和候选顶层窗口继续诊断。

关于 Tab 标题：

- Win32 窗口标题通常只能拿到当前活动 Tab 的标题，例如：

```text
172.16.99.173 - Google Chrome
```

- Chrome 的每个 Tab 不是独立 Win32 子窗口，不能通过 `EnumWindows/GetWindowText` 直接枚举所有 Tab 标题。
- 如果要获取所有 Tab 标题，需要 Chrome DevTools Protocol、UI Automation、扩展或浏览器内部接口。

## 6. 窗口枚举 windows

```powershell
wpsi_cli.exe windows --pid 1234
```

作用：

- 枚举指定 PID 拥有的顶层窗口。

示例：

```powershell
wpsi_cli.exe windows --pid 6688
```

典型输出：

```text
[Windows]
HWND : 0x405b2 PID : 6688 Visible : Yes Class : Chrome_WidgetWin_1 Title : 172.16.99.173 - Google Chrome
HWND : 0x40566 PID : 6688 Visible : No Class : MSCTFIME UI Title : MSCTFIME UI
HWND : 0x705ae PID : 6688 Visible : No Class : IME Title : Default IME
```

字段说明：

- `HWND`：窗口句柄。
- `PID`：窗口归属进程。
- `Visible`：窗口是否可见。
- `Class`：窗口类名。
- `Title`：Win32 窗口标题。

注意：

- 可见窗口才通常代表用户能看到的主窗口。
- `MSCTFIME UI`、`Default IME` 多数是输入法或系统辅助窗口，不是浏览器 Tab。
- Chrome/Edge/Firefox 的 Tab 不一定对应独立 HWND。

## 7. 进程树 tree

```powershell
wpsi_cli.exe tree --pid 1234
```

作用：

- 查看指定进程的父进程链和直接子进程。

示例：

```powershell
wpsi_cli.exe tree --pid 9824
```

典型输出：

```text
[Tree]
PID : 9824
Parents : 6688 1234 888
Children : 10020 10088
```

字段说明：

- `PID`：目标进程。
- `Parents`：从当前进程向上追溯的父进程链。
- `Children`：当前进程的直接子进程。

适用场景：

- 判断 WFP PID 是否只是浏览器子进程。
- 沿父进程链查找 Chrome / Edge / Firefox 主进程。
- 分析 `xianc2.exe` 是否由计划任务、服务、启动器或 explorer 间接启动。

注意：

- Windows PID 可能复用，父进程链是当前快照结果。
- 如果父进程已经退出，父链可能不完整。

## 8. 输出格式

默认输出文本：

```powershell
wpsi_cli.exe inspect --name xianc2.exe
```

JSON：

```powershell
wpsi_cli.exe inspect --name xianc2.exe --format json
wpsi_cli.exe inspect --name xianc2.exe --format json --output result.json
```

Markdown：

```powershell
wpsi_cli.exe inspect --name xianc2.exe --format markdown --output result.md
```

HTML：

```powershell
wpsi_cli.exe inspect --name xianc2.exe --format html --output result.html
```

建议：

- 给现场人员看：使用默认文本或 HTML。
- 给程序集成或日志平台：使用 JSON。
- 给问题报告归档：使用 Markdown 或 HTML。

## 9. 常见问题

### 9.1 为什么提示 partial data?

表示部分字段无法读取，但工具仍返回了可获得的数据。常见原因：

- 当前用户权限不足。
- 目标进程是 SYSTEM 或管理员进程。
- 目标进程退出。
- Windows 不允许跨 Session 或跨 Desktop 读取某些信息。

### 9.2 为什么按进程名找不到?

确认：

- 进程确实正在运行。
- 名称包含 `.exe`。
- 没有输错大小写或路径。这里只需要进程名，不需要完整路径。

### 9.3 为什么 Chrome 只能看到一个标题?

Win32 窗口标题通常只反映当前活动 Tab。后台 Tab 不是独立 HWND，不能通过当前窗口枚举方式直接读取。

### 9.4 compare 应该怎么选 Source 和 Target?

建议：

- Source：发起操作的一方，例如 `xianc2.exe`、`fjAccessControl.exe`。
- Target：被操作的一方，例如 `chrome.exe`、`msedge.exe`、`firefox.exe`。

例如：

```powershell
wpsi_cli.exe compare --name xianc2.exe --name chrome.exe
```

如果输出：

```text
Same Session : No
```

说明两者不在同一 Session，直接桌面交互通常不可靠。

如果输出：

```text
Source IL Lower Than Target : Yes
```

说明 Source 权限完整性低于 Target，可能被 UIPI 阻断。
