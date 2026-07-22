# WinProcessSecurityInspector

Windows 进程安全上下文与桌面会话诊断工具。

本项目用于诊断 Windows 进程之间的安全上下文、Session、Window Station、Desktop、浏览器多进程关系和桌面交互风险，帮助定位开机自启动异常、管理员启动后恢复正常、无法控制浏览器窗口、WFP PID 不对应浏览器主窗口等问题。

当前阶段已建立通用项目目录树，并完成概要设计文档：

- `docs/design/overview-design.md`

后续建议按以下阶段推进：

1. 最小可用 CLI 和核心库。
2. 浏览器专项诊断。
3. 完整 Token / Session / Desktop / AppCompat 诊断。
4. Qt GUI、HTML 报告和 xianc2 集成。
