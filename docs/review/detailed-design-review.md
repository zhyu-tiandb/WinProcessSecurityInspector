# Windows 进程安全上下文与桌面会话诊断工具 —— 详细设计审查报告

| 项目 | 内容 |
|------|------|
| **审查日期** | 2026-07-22 |
| **审查对象** | `docs/design/detailed-design.md`（1234 行 / 17 章） |
| **基准文档** | SRS、概设（修订版）、首轮审查/复审报告 |
| **审查性质** | 详细设计阶段审查，重点关注概设承接、模型一致性、API 正确性、阶段可实施性 |
| **审查结论** | **有条件通过** — 文档质量高，发现 2 项需修正、5 项需澄清、4 项建议 |

---

## 1. 概设审查反馈的落实情况

上一轮概设审查遗留 4 项建议（见复审报告 §3.3），检查结果：

| 建议 | 落实情况 | 验证 |
|------|---------|------|
| `ProcessInfo` 补充 `startTime` | ✅ **已落实** | 详细设计 §5.2 `ProcessInfo` 包含 `FieldValue<TimePoint> startTime` |
| `ProcessSecurityContext` 与 `BrowserProcessContext` 的拆分方式 | ✅ **已落实** | 保持拆开：`DiagnosisReport` 中 `processes[]` 与 `browser` 分离，`DiagnosisContext` 使用 `optional<>` 组合 |
| COM Apartment 检测和 Worker 线程模式 | ✅ **已落实** | 详细设计 §13.2 给出了 `ComExecutionContext` 策略和 `RPC_E_CHANGED_MODE` 回退方案 |
| 诊断规则配置 JSON Schema | ✅ **已落实** | 详细设计 §8.2 给出了规则配置 JSON 示例，含 version / id / severity / enabled / description |

**概设反馈全部闭环。**

---

## 2. 结构完整性评价

| 维度 | 评级 | 说明 |
|------|------|------|
| 头文件结构 | ✅ 完整 | 54 个头文件路径，命名清晰，按 common / core / inspectors / diagnosis / report 分层 |
| 源文件结构 | ✅ 完整 | 38 个 `.cpp` 文件，与头文件一一对应 |
| 测试文件结构 | ✅ 完整 | 9 个测试文件，分 unit / integration / fixtures 三层 |
| 核心模型定义 | ✅ 完整 | 8 个枚举 + 12 个结构体，字段覆盖 SRS 全部采集项 |
| Inspector 接口 | ✅ 完整 | 11 个 Inspector 全部有签名定义 |
| 规则引擎接口 | ✅ 完整 | 输入（DiagnosisContext）+ 输出（RuleResult[]）+ R001-R010 完整定义 |
| 导出接口 | ⚠️ 基本完整 | Text/JSON 完整，Markdown/HTML 仅声明了存在 |
| COM/线程模型 | ✅ 完整 | 有独立章节（§13） |
| 测试策略 | ✅ 完整 | 多层 + 用例举例 + CI 分级 |
| 日志 | ⚠️ 基本完整 | 选择了 spdlog 但没有对应头文件路径声明 |

---

## 3. 需修正项

### 3.1 🔴 R001-R010 遗漏 AppContainer 和 UIAccess 诊断维度

| 条目 | 内容 |
|------|------|
| **位置** | `§8.3` 首批规则表、`§5.6` `ComparisonResult` |
| **问题** | SRS §6.16（前台交互能力判断）要求诊断规则**至少包括** 10 项判断，其中第 6 项"目标是否为 AppContainer"和第 7 项"调用方是否具有 UIAccess"在 R001-R010 中**完全未被覆盖**。 |
| **证据** | |

SRS §6.16 的 10 项规则 vs 当前的 R001-R010 覆盖情况：

| SRS 项目 | R00x 覆盖 | 备注 |
|----------|-----------|------|
| 1. Session 是否相同 | R002 ✅ | |
| 2. User SID 是否相同 | R003 ✅ | |
| 3. Window Station 是否相同 | R010 ✅ | |
| 4. Desktop 是否相同 | R010 ✅ | |
| 5. 调用方 IL 是否低于目标 IL | R001 ✅ | |
| **6. 目标是否为 AppContainer** | **❌ 未覆盖** | **需要新增规则或增强 R010** |
| **7. 调用方是否具有 UIAccess** | **❌ 未覆盖** | **需要新增规则或增强 R001** |
| 8. 是否存在前台切换限制 | R001/R002 ⚠️ | 间接覆盖 |
| 9. 是否为服务 Session | R004 ✅ | |
| 10. 是否存在 UIPI 限制 | R001 ⚠️ | 部分覆盖（UIPI ≠ IL 单向比较） |

**影响**：
- AppContainer 进程（如 Edge 沙箱、UWP 应用）是现场诊断的常见目标，缺少此规则将导致诊断报告遗漏风险
- UIAccess 差异是判定 "能否控制前台窗口" 的关键输入

**建议**：
1. 在 `ComparisonResult` 中补充 `sourceAppContainer`、`targetAppContainer`、`sourceUIAccess`、`targetUIAccess` 字段
2. 新增两条规则（或合并到 R001/R010）：

   | 规则 ID | 条件 | 默认等级 | 说明 |
   |---------|------|---------|------|
   | R011 | 目标进程是 AppContainer 且调用方不是 | WARNING | AppContainer 进程受额外隔离限制，窗口消息和输入可能被阻断 |
   | R012 | 调用方无 UIAccess 且目标 IL > 调用方 IL | WARNING | 缺少 UIAccess 时，前台窗口切换和 SendInput 可能受限 |
   
   或精简合并后调整 R001 描述："调用方 IL 低于目标 IL，或缺少 UIAccess，或目标为 AppContainer"

---

### 3.2 🔴 `PrivilegeState` 四态映射规则未定义

| 条目 | 内容 |
|------|------|
| **位置** | `§5.3` `PrivilegeInfo`、`§7.2` TokenInspector |
| **问题** | 定义了 `PrivilegeState` 枚举（Present / Enabled / Disabled / Removed），但未说明如何从 `LUID_AND_ATTRIBUTES` 属性标志映射到这四态 |

**缺失的映射规则**：

```cpp
// 需要补充的映射逻辑（伪代码）：
SE_PRIVILEGE_ENABLED            → Enabled
SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_REMOVED  // 矛盾组合，不应发生
仅在 Present 中未 Enabled       → Disabled
SE_PRIVILEGE_REMOVED            → Removed
```

**影响**：实现者需要自行推导映射规则，可能导致实现不统一。

**建议**：
- 在 §7.2 中补充 `LUID_AND_ATTRIBUTES.Attributes` → `PrivilegeState` 的映射表
- 明确 `SE_PRIVILEGE_REMOVED` 的检测方式（`(Attributes & SE_PRIVILEGE_REMOVED) != 0`）

---

## 4. 需澄清项

### 4.1 🟡 窗口枚举跨 Desktop / Session 的限制未说明

| 条目 | 内容 |
|------|------|
| **位置** | `§7.5` WindowInspector |
| **问题** | `EnumWindows` 枚举的是**调用线程当前 Desktop** 上的顶层窗口。诊断工具无法枚举其他 Session 或其他 Window Station 中的窗口，这在多用户或服务场景下是关键限制，但文档未提及 |

**影响**：
- 当诊断工具位于 Session 1，目标窗口位于 Session 2 时，`EnumWindows` 返回空列表 → WindowInspector 报告 "无可见顶层窗口"
- 实现者可能误以为工具能发现所有 Session 的窗口

**建议**：在 §7.5 或 §11（错误处理）中说明：
> `EnumWindows` 受调用线程的 Window Station 和 Desktop 约束。如目标进程位于不同 Session、不同 Window Station 或不同 Desktop，窗口枚举将返回空列表或部分结果。此限制不是缺陷，而是 Windows 安全隔离的正常行为。

---

### 4.2 🟡 脱敏执行层不明确

| 条目 | 内容 |
|------|------|
| **位置** | `§6` `InspectionOptions.redactSensitiveData` vs `§9.2` "敏感字段在进入 exporter 前统一脱敏" |
| **问题** | 两个地方对脱敏执行层的描述不一致 |

**矛盾点**：
- `InspectionOptions` 中 `redactSensitiveData = true` 默认启用 → 暗示脱敏发生在 `InspectionService` 层
- §9.2 "敏感字段在进入 exporter 前统一脱敏" → 暗示脱敏发生在 ReportExporter 层

**影响**：
- 如果 `redactSensitiveData = true` 但在源码层脱敏，那么通过 `xianc2` 集成（API 模式）获取的 `ProcessSecurityContext` 也是脱敏后的，这可能不是调用方期望的
- 如果仅在 exporter 脱敏，`InspectionOptions` 中的 `redactSensitiveData` 就不应出现在服务层接口

**建议**：
- 统一策略：**在 ReportExporter 层脱敏**，核心 API 返回原始数据
- `InspectionOptions` 中移除 `redactSensitiveData`，改为在导出选项中控制
- 或者在 §12 中明确声明脱敏层级

---

### 4.3 🟡 `OpenInputDesktop` 在锁屏/UIAccess 场景的可用性

| 条目 | 内容 |
|------|------|
| **位置** | `§7.4` DesktopInspector |
| **问题** | `OpenInputDesktop` 在 Windows Vista 之后的设计中，当桌面锁定时可能对非 UIAccess 进程返回 `NULL`（`ERROR_ACCESS_DENIED`）。文档未提及此限制 |

**影响**：在锁屏或快速用户切换（FUS）场景下，DesktopInspector 可能无法获取 `inputDesktop` 信息，且不会明确告知用户是因为锁屏而非工具缺陷。

**建议**：
- 在 §7.4 中补充：
  > 当桌面锁定或当前进程无 UIAccess 时，`OpenInputDesktop` 可能返回 `NULL`。此时 `inputDesktop` 标记为 `available=false`，并在证据中提示可能是锁屏或 UIAccess 限制。

---

### 4.4 🟡 `NtQueryInformationProcess` 作为未文档化 API 的风险

| 条目 | 内容 |
|------|------|
| **位置** | `§7.1` ProcessInspector |
| **问题** | 文档将 `NtQueryInformationProcess` 作为命令行和启动时间的扩展读取手段。该 API 是**未文档化的内核态接口**，不同 Windows 版本间 `PROCESS_BASIC_INFORMATION` 和 `PEB` 结构存在差异，且可能被 PatchGuard 或后续版本变更影响 |

**建议**：
- 明确优先使用 `GetProcessTimes`（稳定文档化 API）获取启动时间
- 仅将 `NtQueryInformationProcess` 作为命令行读取的回退路径
- 添加版本兼容性说明：
  > `NtQueryInformationProcess` 为未文档化 API，结构定义在不同 Windows 版本间可能变化。优先使用文档化 API；仅当文档化 API 不足以获取所需信息（如命令行）时，使用 NtQueryInformationProcess 作为后备。

---

### 4.5 🟡 `WinVerifyTrust` 的 UI 抑制

| 条目 | 内容 |
|------|------|
| **位置** | `§7.9` SignatureInspector |
| **问题** | `WinVerifyTrust` 默认可能弹出 UI 对话框（如证书链构建失败时的重试对话框），这在 CLI 无头模式或远程诊断场景下是不可接受的 |

**建议**：
- 明确要求使用 `WTD_UI_NONE` 标志调用 `WinVerifyTrust`
- 添加说明：
  > 调用 `WinVerifyTrust` 时必须设置 `WTD_UI_NONE`，禁止弹出任何证书对话框。验签失败时静默返回签名状态为"无法验证"。

---

## 5. 优化建议

### 5.1 📌 `ComExecutionContext` 定义未出现在文件树和接口中

| 条目 | 内容 |
|------|------|
| **位置** | `§13.2` 提及 `ComExecutionContext`，但 `§3` 文件树和 `§5` 接口中均未出现 |
| **影响** | 实现者看不到这个重要抽象的定义 |
| **建议** | 在 §3.1 文件树中添加 `include/wpsi/common/com_context.h`，或在 §13.2 中给出该类型的完整签名 |

### 5.2 📌 `DiagnosisContext` 与 `ComparisonResult` 的冗余设计

| 条目 | 内容 |
|------|------|
| **位置** | `§8.1` vs `§5.6` |
| **问题** | `DiagnosisContext` 包含 `optional<ComparisonResult>`，而 `ComparisonResult` 是从 `source` 和 `target` 的 `ProcessSecurityContext` 推导的。这产生了数据冗余：规则引擎收到一致的两组数据可能导致矛盾 |
| **建议** | 移除 `DiagnosisContext.comparison`，改为在规则引擎内复用 `evaluate()` 内部的计算结果，或在 `ComparisonResult` 明确标注为"缓存字段，应与 source/target 一致" |

### 5.3 📌 日志头文件路径未出现在文件树

| 条目 | 内容 |
|------|------|
| **位置** | `§3.1` 文件树 vs `§11` 日志策略 |
| **问题** | §11 选择了 spdlog，但文件树中没有任何日志相关头文件路径（如 `include/wpsi/common/logger.h` 或 `include/wpsi/common/log.h`） |
| **建议** | 补充日志抽象接口头文件路径，或明确说明直接使用 spdlog API（不封装自有接口） |

### 5.4 📌 浏览器 CrashHandler 在 Firefox 角色表中缺失

| 条目 | 内容 |
|------|------|
| **位置** | `§7.6` Firefox 角色表 |
| **问题** | Chrome/Edge 角色表包含 CrashHandler，Firefox 角色表没有对应项。Firefox 的崩溃处理由 `crashreporter.exe` 子进程处理，与主进程命令行不同 |
| **建议** | 补充 Firefox CrashHandler 识别：`crashreporter.exe` 进程名匹配，或命令行包含 `-crashreport` 参数 |

---

## 6. 阶段边界检查

### 6.1 Phase 1 可实现性评估

```
Phase 1 交付物：
├─ common/     → result, win_handle, string_utils, time_utils
├─ core/       → context, options, inspection_service
├─ inspectors/
│  ├─ process/       → ProcessInspector       ✅
│  ├─ token/         → TokenInspector         ⚠️ 仅基础 Token/IL/Elevation
│  └─ session/       → SessionInspector       ⚠️ 仅 SessionId
├─ diagnosis/  → RuleEngine (R001/R002/R003/R008)
├─ report/     → TextExporter, JsonExporter
└─ cli/        → inspect, compare
```

**评估结论**：Phase 1 范围合理，可独立交付。

**依赖检查**：
| 规则 | 依赖的 Inspector | Phase | 可实施性 |
|------|-----------------|-------|---------|
| R001 (IL 对比) | TokenInspector | Phase 1 ✅ | TokenInspector 基础版已包含 IL |
| R002 (Session 对比) | SessionInspector | Phase 1 ✅ | Phase 1 包含 SessionId 采集 |
| R003 (User SID 对比) | TokenInspector | Phase 1 ✅ | UserSid 是基础采集项 |
| R008 (优先级) | ProcessInspector | Phase 1 ✅ | GetPriorityClass 是基础采集 |

### 6.2 Phase 2 边界

```
Phase 2 新增：
├─ inspectors/window/       → WindowInspector
├─ inspectors/browser/      → BrowserInspector
├─ RuleEngine R005/R006
└─ CLI browser / windows / tree
```

**评估结论**：合理。BrowserInspector 依赖于 WindowInspector（查找顶层窗口），同属一个 Phase 是正确的。

### 6.3 Phase 3 边界

```
Phase 3 新增：
├─ DesktopInspector + Compatibility/Manifest/Signature/Service/Startup
├─ RuleEngine R004/R007/R009/R010
├─ MarkdownExporter + HTMLExporter
```

**关键依赖链**：
- R004（Session 0 服务 + 浏览器）→ ServiceInspector + BrowserInspector → **正确**（Service Phase 3, Browser Phase 2）
- R007（Medium/Limited + 管理员）→ TokenInspector → **正确**（Phase 1）
- R009（AppCompat）→ CompatibilityInspector → **正确**（Phase 3）
- R010（Desktop 不一致）→ DesktopInspector → **正确**（Phase 3）

**评估结论**：合理，无循环依赖。

---

## 7. 技术正确性专项检查

### 7.1 Windows API 选型

| Inspector | API | 评估 |
|-----------|-----|------|
| Process | `CreateToolhelp32Snapshot` | ✅ 推荐，普通用户可用 |
| Process | `QueryFullProcessImageNameW` | ✅ `PROCESS_QUERY_LIMITED_INFORMATION` 即可 |
| Token | `OpenProcessToken` | ✅ |
| Token | `CheckTokenMembership` | ✅ 不需要句柄，比 `OpenToken` 更稳健 |
| Session | `WTSEnumerateSessionsW` | ✅ 本地查询无特殊权限要求 |
| Desktop | `OpenInputDesktop` | ⚠️ 见 §4.3，需补充锁屏说明 |
| Window | `EnumWindows` | ⚠️ 见 §4.1，跨 Desktop 限制需说明 |
| Signature | `WinVerifyTrust` | ⚠️ 见 §4.5，需指定 `WTD_UI_NONE` |
| Manifest | `RT_MANIFEST` 资源读取 | ✅ 标准方案 |
| Service | `OpenSCManager` + WMI | ✅ SCM 优先，WMI 作为扩展 |

### 7.2 跨架构兼容性

| 场景 | 评估 |
|------|------|
| `IsWow64Process2` 的使用 | ✅ §7.1 正确引用，可区分 x86/x64/ARM64/模拟层 |
| WOW64 下 PEB 命令行读取 | ✅ §7.1 正确说明可能失败时返回部分结果 |
| x64 原生构建为推荐 | ✅ SRS 已做要求 |

### 7.3 构建依赖

| 依赖 | 评估 |
|------|------|
| `Advapi32` / `User32` / `Wtsapi32` | ✅ Windows 标准库 |
| `Wintrust` + `Crypt32` | ✅ 签名验证所需 |
| `Taskschd` / `Comsuppw` / `Ole32` / `OleAut32` | ✅ COM 所需 |
| `nlohmann/json` | ✅ 合理 |
| `spdlog` | ✅ 合理 |
| GoogleTest | ✅ 行业标准 |

---

## 8. 与概设的一致性检查

| 概设承诺 | 详细设计承接 | 状态 |
|---------|-------------|------|
| 模块间数据结构定义 | §5 定义了完整 struct/enum | ✅ |
| 规则引擎接口签名 | §8.1 定义 `RuleEngine` 类和 `evaluate()` | ✅ |
| R001-R010 映射表 | §8.3 完整映射，含等级和建议 | ✅ |
| 线程安全模型 | §13 明确：无状态 + 可重入 + COM Worker | ✅ |
| 测试策略三层 | §15 完整 | ✅ |
| COM 初始化模型 | §13.2 MTA + RPC_E_CHANGED_MODE 回退 | ✅ |
| 日志策略 | §11 spdlog + 5 级 + 滚动 10MB×5 | ✅ |
| 脱敏规则 | §12 三函数 + 参数/路径/SID | ✅ |
| 集成层接口 | §6 `InspectionService` 匹配概设 4 个 API | ✅ |
| `config/diagnosis-rules.json` | §8.2 JSON 示例 + 加载失败策略 | ✅ |

**一致性检查结论**：详细设计与概设完全对齐，概设所有承诺均在详细设计中落地。

---

## 9. 审查总结

### 9.1 问题汇总

| 编号 | 类别 | 严重度 | 简述 | 位置 |
|------|------|--------|------|------|
| 3.1 | 遗漏 | 🔴 **需修正** | R001-R010 未覆盖 AppContainer 和 UIAccess 诊断维度 | §8.3, §5.6 |
| 3.2 | 模糊 | 🔴 **需修正** | `PrivilegeState` 四态映射规则未定义 | §5.3, §7.2 |
| 4.1 | 缺失 | 🟡 需澄清 | 窗口枚举跨 Desktop/Session 限制未说明 | §7.5 |
| 4.2 | 矛盾 | 🟡 需澄清 | 脱敏层不明确（`InspectionOptions` vs Export） | §6, §9.2 |
| 4.3 | 缺失 | 🟡 需澄清 | `OpenInputDesktop` 锁屏/UIAccess 限制未说明 | §7.4 |
| 4.4 | 风险 | 🟡 需澄清 | `NtQueryInformationProcess` 未文档化 API 风险 | §7.1 |
| 4.5 | 缺失 | 🟡 需澄清 | `WinVerifyTrust` UI 抑制未说明 | §7.9 |
| 5.1 | 遗漏 | 📌 建议 | `ComExecutionContext` 定义未出现在文件树 | §13.2 |
| 5.2 | 冗余 | 📌 建议 | `DiagnosisContext.comparison` 冗余设计 | §8.1 vs §5.6 |
| 5.3 | 遗漏 | 📌 建议 | 日志头文件路径未出现在文件树 | §3.1 vs §11 |
| 5.4 | 遗漏 | 📌 建议 | Firefox CrashHandler 角色表缺失 | §7.6 |

### 9.2 按优先级排序

| 优先级 | 编号 | 处理要求 |
|--------|------|---------|
| **P0 — 开工前必须修正** | 3.1, 3.2 | 补充 R011/R012 规则定义、补充 PrivilegeState 映射规则 |
| **P1 — 进入 Phase 1 实现前补充** | 4.2, 4.4 | 统一脱敏层策略、明确 NtQueryInformationProcess 为后备方案 |
| **P2 — Phase 1 实现中关注** | 4.1, 4.3, 4.5 | 在对应 Inspector 中补充限制说明 |
| **P3 — 实现前完善即可** | 5.1, 5.2, 5.3, 5.4 | 补充 ComExecutionContext、日志头文件，整理冗余 |

### 9.3 总体结论

| 维度 | 评分 | 说明 |
|------|------|------|
| 结构完整性 | ★★★★★ | 1234 行/17 章，覆盖全面 |
| 概设对齐度 | ★★★★★ | 概设所有承诺全部落地 |
| 模型一致性 | ★★★★☆ | 1 处冗余、1 处遗漏字段 |
| API 正确性 | ★★★★☆ | 2 处需补充限制说明 |
| 可实施性 | ★★★★★ | Phase 1 边界清晰无阻塞 |
| 可测试性 | ★★★★★ | §15 给出了具体用例 |
| **综合** | **★★★★☆** | **2 项 P0 修正后即可进入实现** |

### 9.4 建议的行动顺序

```
修正 P0（3.1, 3.2）
  ↓
澄清 P1（4.2, 4.4）
  ↓
进入 Phase 1 实现，同时在实现中标注 P2 限制
  ↓
Phase 1 收尾前补充 P3 完善项
```

---

## 10. 附录：核心模型覆盖追溯

### 10.1 SRS §6 功能需求 × 核心模型字段

| SRS 功能节 | 核心模型字段 | 状态 |
|-----------|-------------|------|
| §6.1 进程基础信息 | `ProcessInfo` 全字段 | ✅ |
| §6.2 用户身份信息 | `TokenInfo.userName/domain/userSid/logonSid/...` | ✅ |
| §6.3 Integrity Level | `TokenInfo.integrityLevel/integrityRid` | ✅ |
| §6.4 UAC/Elevation | `TokenInfo.elevated/elevationType/hasLinkedToken/...` | ✅ |
| §6.5 管理员权限 | `TokenInfo.administratorMember/enabled/DenyOnly` | ✅ |
| §6.6 Token 特权 | `TokenInfo.privileges[]` + `PrivilegeInfo` | ⚠️ 缺四态映射规则 |
| §6.7 UIAccess | `TokenInfo.uiAccess` + `ManifestInfo.uiAccess` | ✅ |
| §6.8 AppContainer | `TokenInfo.appContainer/appContainerSid/capabilitySids` | ✅ |
| §6.9 Session | `SessionInfo` 全字段 | ✅ |
| §6.10 Window Station/Desktop | `DesktopInfo` 全字段 | ✅ |
| §6.11 优先级 | `ProcessInfo.priorityClassName` + `GetThreadPriority` | ✅ |
| §6.12 Job Object | `ProcessInfo.inJobObject` + `QueryInformationJobObject` | ⚠️ 字段在 ProcessInfo 但 JobObject 详细字段未扩展 |
| §6.13 进程树 | `ProcessInspector.childrenOf/parentChainOf` | ✅ |
| §6.14 浏览器识别 | `BrowserProcessContext` + 角色表 | ✅ |
| §6.15 顶层窗口 | `WindowInfo` 全字段 | ✅ |
| §6.16 前台交互判断 | 综合规则 R001-R010 | ⚠️ 缺 AppContainer/UIAccess 维度 |
| §6.18 AppCompat | `CompatibilityInspector` | ✅ |
| §6.19 Manifest | `ManifestInspector` | ✅ |
| §6.20 签名 | `SignatureInspector` | ✅ |
| §6.21 服务 | `ServiceInspector` | ✅ |
| §6.22 启动来源 | `StartupInspector` | ✅ |

### 10.2 Phase 边界 × Inspector 交付

| Inspector | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|-----------|---------|---------|---------|---------|
| ProcessInspector | ✅ 完整 | — | — | — |
| TokenInspector | ✅ 基础版 | — | 🐾 扩展特权 | — |
| SessionInspector | ✅ SessionId | — | 🐾 全量 | — |
| DesktopInspector | — | — | ✅ | — |
| WindowInspector | — | ✅ | — | — |
| BrowserInspector | — | ✅ | — | — |
| CompatibilityInspector | — | — | ✅ | — |
| ManifestInspector | — | — | ✅ | — |
| SignatureInspector | — | — | ✅ | — |
| ServiceInspector | — | — | ✅ | — |
| StartupInspector | — | — | ✅ | — |
| GUI | — | — | — | ✅ |

---

*审查人：Claude Code (deepseek-chat)*
*审查日期：2026-07-22*
