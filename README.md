# WinProcessSecurityInspector

Windows 进程安全上下文与桌面会话诊断工具。

本项目用于诊断 Windows 进程之间的安全上下文、Session、Window Station、Desktop、浏览器多进程关系和桌面交互风险，辅助定位开机自启动异常、管理员启动后恢复正常、无法控制浏览器窗口、WFP PID 不对应浏览器主窗口等问题。

## 当前进度

已完成：

- Phase 1：基础进程、Token、Session、优先级、文本/JSON 输出、`inspect`、`compare`。
- Phase 2：窗口枚举、进程树、浏览器角色识别、浏览器主进程定位、`browser`、`windows`、`tree`。
- Phase 3：Desktop、AppCompat、Manifest、签名状态、服务 PID 关联、注册表 Run/RunOnce 启动来源、Markdown/HTML 输出、R004/R005/R006/R009/R010/R011/R012。

仍留在后续深化：

- Task Scheduler COM 启动来源细节。
- Authenticode 证书链详细字段、签名者、颁发者、时间戳和 SHA-256。
- Qt GUI 和 xianc2 集成封装。

## 常用命令

```powershell
wpsi_cli.exe inspect
wpsi_cli.exe inspect --pid 1234
wpsi_cli.exe inspect --name xianc2.exe
wpsi_cli.exe compare --pid 1234 --pid 5678
wpsi_cli.exe browser --network-pid 9824
wpsi_cli.exe windows --pid 1234
wpsi_cli.exe tree --pid 1234
```

导出报告：

```powershell
wpsi_cli.exe inspect --format json --output result.json
wpsi_cli.exe inspect --format markdown --output result.md
wpsi_cli.exe inspect --format html --output result.html
```

测试机建议使用 Release 产物：

```powershell
build\Release\wpsi_cli.exe
```

不要把 Debug 产物作为测试机发布包，否则可能依赖 Visual Studio 调试运行库。
