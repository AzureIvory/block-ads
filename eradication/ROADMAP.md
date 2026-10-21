# 根除流程路线图

按顺序推进，每项完成后记录测试场景、结果和提交。当前已有共享 artifact 归属记录及部分操作日志，但正式状态机、自动崩溃恢复和持续验证尚未实现。先把前六项验证扎实，再扩展检测范围。

当前优先级已按实际用途调整：优先推进删除后的独立验证、重生观察、失败状态及只读结果展示。现有恢复功能保留，额外的恢复能力和自动回滚扩展暂缓，不再作为这些后续工作的前置条件；操作日志及崩溃后避免误删的检查仍继续保留。

## 1. HitEvent / integration correctness

当前进度：`tests/` 中的可控子进程、模拟 ETW 属性、身份拒绝、双 PID 共享文件及恢复归属测试已通过。真实 Kernel Process ETW provider 测试在 Windows workflow 上通过，覆盖真实进程事件、HitEvent 和 case 的一对一追溯；本机非管理员会话仍无法启动 ETW session。加载 DLL 的进程在隔离、恢复、重启后再次命中并产生新 case；尚待原 `fuck` 日志的系统级回归和真实 PID 复用压力。

### 1.1 Event correctness：ETW / startup scan → HitEvent

- [x] 使用隔离目录与可控测试进程，分别触发启动扫描和 ETW，核对事件的 PID、父 PID、创建时间、镜像路径、文件 identity、规则、来源和时间戳。
- [x] 定义“唯一”的边界：同一次原始命中产生一条带 ID 的 HitEvent；20 秒进程 gate 与同 ID 入队去重分别测试，多个 PID 命中同一文件保留不同事件。
- [ ] 核对原有 kill/日志与 HitEvent 严格一对一，且原流程行为不变。
- [x] 覆盖排队前退出、创建时间缺失、模拟 PID 复用后的创建时间不符、镜像路径或文件 identity 变化。真实 PID 复用压力测试仍包含在上一条真实 ETW 验收中。
- [ ] 评估 ETW 事件到 `procHit` 身份快照之间的窗口：当前事件没有可比较的创建时间，原始 `fuck` 路径仍按既有行为执行。通过真实命中测试记录这个边界，再设计不改变原拦截语义的处理。

### 1.2 Remediation correctness：HitEvent → 处置

- [x] 同 ID HitEvent 在单次运行中只入队一次；已退出进程通过创建时间校验，不产生第二次文件修改。跨重启队列恢复留待第 3 项。
- [x] 多个 PID 命中同一文件时，每个命中保留独立 case，artifact 与持久化项只实际处置一次；并发排队、共享归属与恢复后进程重启重新命中均有测试。
- [x] 测试分别断言 HitEvent 数量、case 数量和实际文件隔离次数；对同 ID 重复提交及不同 PID 命中同一文件分别断言。
- [x] 持久化 artifact ownership：多个 case 引用同一隔离记录；关联 case 先释放引用，owner 在其他引用释放后才能恢复。恢复后共享记录与 owner case 一起更新。
- [x] 稳定 `artifact_id` 使用 `SHA256 + 规范化原路径 + 文件 identity`；哈希尚不可用时用路径与文件 identity 查找已隔离记录。同路径被替换、同内容但不同文件 identity 不合并。

## 2. Quarantine + restore round-trip

当前进度：真实 EXE 已完成隔离、恢复及重新启动验证；命中进程加载无签名 DLL 后自动隔离并恢复 EXE/DLL 的测试也在 Windows workflow 上通过。Run/RunOnce 与 Task Scheduler 的真实往返测试在 Windows workflow 上通过，Startup `.lnk` 在隔离目录内完成真实快捷方式往返测试。

- [x] 真实隔离 EXE/DLL，恢复原路径、哈希和可执行状态；共享 artifact 的恢复归属、真实加载 DLL 的自动隔离及进程重启均通过测试。
- [x] 验证原路径已被其他文件占用时拒绝覆盖，包括相同哈希占位文件和检查后竞态；重复隔离与重复恢复通过共享归属和恢复测试验证。
- [x] 分别验证 Run/RunOnce、任务 XML、Startup `.lnk` 的备份与恢复；快捷方式保留 target、arguments、working directory 和原始二进制 metadata。
- [x] 在 [ROUND_TRIP.md](ROUND_TRIP.md) 记录各步骤 crash 后可能观察到的状态与当前不能自动恢复的窗口，作为第 3 项 journal 的输入。

## 3. Crash semantics / Action Journal

当前进度：`quarantine_copy`、`quarantine_hash_verify`、`quarantine_publish`、`delete_original`、`record_ownership`、`remove_persistence`、`restore_copy`、`restore_hash_verify`、`restore_file`、`restore_ownership`、`restore_persistence`、共享引用增减和最终 case 提交均已按 intent 与独立结果文件记录操作 ID、关联身份、前置条件、结果、错误和时间。新日志在同一 case 内还有持久化顺序号；跨进程写入使用 Windows 文件锁分配，读取时拒绝缺号、重复号或 intent/结果不一致。隔离副本和恢复文件均使用不可覆盖的移动。文件操作的 intent 另存预期哈希、文件 identity、隔离路径和临时路径；Run/Task/Startup 的删除 intent 记录精确位置，文件型持久化项还记录备份哈希；case 更新记录新旧快照哈希。启动时只读核对未决操作、缺少最终 case 的 plan、孤立共享引用、已提交但未发布的恢复副本，以及已提交恢复动作与旧 case 状态的冲突；同一路径的新命中保留 case，暂停新的自动处置。被占用文件现在使用 Restart Manager 枚举占用者，仅在进程创建时间、镜像路径和文件 identity 均匹配原命中 EXE 时终止该进程，再重试删除；仍被占用则登记重启删除并保持 `pending_reboot`。子进程测试已覆盖隔离和恢复副本复制、哈希校验、发布、原件删除、Run/Task/Startup 删除、共享引用增减和最终 case 提交的三个崩溃边界；Run/Task 的真实删除边界测试已在 Windows workflow 上通过。当前不自动重试或回滚未决 journal。

- [ ] 为每个 destructive step 定义 `落盘 intent → 执行动作 → 验证结果 → 落盘 committed state`；已覆盖隔离与恢复副本的复制、哈希、发布、原件删除、持久化删除、共享引用和 case 提交。Run/RunOnce 恢复核对值内容及注册表类型；Startup 恢复核对备份和目标哈希，以不覆盖目标的移动发布；Task 恢复核对任务名与系统 Tasks 路径，以禁止写共享的临时 XML 快照注册，再比较完整 XML（触发器、主体、设置、所有动作及参数均保留，仅忽略编码、命名空间前缀、属性顺序、注释和元素间缩进）。恢复 intent 记录精确持久化身份、关联文件、值类型或备份哈希，失败原因写入 case；跳过动作仍需记录。文件内容在发布前同步，JSON 用临时文件与原子替换写入。
- [ ] 持久化按序操作日志，记录操作 ID、case/artifact 引用、动作、前置条件、结果、错误和时间。关键动作与严格顺序号已记录，仍需覆盖跳过动作。
- [x] 在复制、哈希校验、删除原件、清除持久化项、写入 committed state 之前和之后分别注入崩溃。文件、Run/Task/Startup、共享引用和最终 case 提交均覆盖三个日志边界。
- [ ] 启动时从 intent、journal、case、备份与隔离副本重建进度；目前已只读核对文件、归属记录、缺失的最终 case 与滞后的恢复状态，暂停同路径新的自动处置。Run/Startup/Task 恢复关联 intent 中的值类型或备份哈希，区分未观察到、观察到但未提交及冲突；恢复已提交而 case 持久化项仍为旧状态时要求人工检查。Startup 的三个崩溃边界和备份/目标替换测试已在本机通过；Run 恢复的崩溃与类型冲突测试已在隔离 Windows workflow 通过。Task 完整 XML、三个恢复崩溃边界、备份变更、占位任务及位置拒绝测试已接入同一 workflow；仍需决定安全继续、回滚或人工处理的完整规则。
- [x] 被占用文件先识别并终止身份匹配的占用进程，再重试删除；仍被占用时可登记 reboot-delete，单独记录 `pending_reboot`，重启后验证前不能记为已删除。登记失败仍为 `pending`，待重启 case 暂不允许恢复。
- [ ] 在重启后核对排队删除是否真正执行；恢复前安全取消尚未执行的排队删除，并防止路径被替换后误删。（按当前优先级暂缓。）

## 4. Task / Service 失败与恢复

- [ ] 计划任务覆盖引号、参数、`%ENV%`、`cmd /c`、`powershell -File`，以及不应匹配的参数或名称；在真实 Task Scheduler 中验证 XML round-trip。
- [ ] 注入备份失败、删除失败、删除后验证失败，验证 journal、case 与恢复行为；覆盖多个 case 关联同一任务。
- [ ] Service 继续只扫描和备份，保持 `experimental_review`，不自动 disable 或 delete。
- [ ] 如将来考虑服务处置，先完成 SCM round-trip：start type、delayed auto start、dependencies、service account、failure actions、description、SID type、required privileges、trigger start、binary path 及当前运行状态；注册表导出本身不足以证明可恢复。

## 5. Formal case + artifact state machine

- [ ] 明确并持久化 case 流程：`Detected → Contained → EvidenceCollected → Quarantined → PersistenceRemoved → PendingVerification → Verified → RestoreAvailable`。
- [ ] 分别定义 case、共享 artifact、持久化项及 remediation ownership 的状态与转移；部分失败进入 `PartialFailure`，延迟删除进入 `PendingReboot`。
- [ ] 每次转移引用对应的 Action Journal 记录，定义前置条件、落盘时机、重试与恢复规则；最终状态不能替代操作历史。
- [ ] 任一失败、未验证删除或未完成恢复都不能计为成功；为 GUI 和诊断提供可解释的状态来源。

## 6. Post-clean verification

- [x] 在处置后立即核对实际隔离/共享关联的原 EXE/DLL 不存在、命中进程已退出、相同镜像路径没有再次运行、已移除的 Run/Task/Startup 未重新占位；服务继续只记录 `experimental_review`。每项检查有独立 intent/result 与 case 中的 operation 引用、时间、范围和证据；无法读取为 `unknown`，日志失败不能记为通过。发现残留/重新占位记为 `partial_failure`（待重启删除仍优先保留 `pending_reboot`），单次通过仍保持 `pending_verification` 并标明需要观察和重启核对。不因同哈希文件、不同类型 Run 值或无关任务占位而再次删除；是否由原软件重建仍需进一步归因。
- [ ] 设置有界观察窗口，检查文件、进程和持久化项是否重生；核心已启用后台 10 秒窗口、1 秒采样，等待不占用清理互斥锁。记录采样时间、operation 引用、进程 PID/父 PID/创建时间、首次残留证据与最大采样间隔；最终样本必须在窗口截止后开始。采样间隔超过配置的两倍、读取或日志失败均不能算完整观察，关闭时记录中断。观察后仍需重启核对；采样之间的瞬时重生可能漏过，updater/watchdog/helper 的进一步归因尚待补充。仅凭一次文件不存在不能进入 `Verified`。
- [ ] 在许可且具备可归因数据时观察 payload 下载或重新释放迹象；网络活动本身不能单独证明与命中软件有关。
- [ ] 重启后再次验证文件、进程和持久化项；若无法自动完成，case 保持 `pending_verification` 并明确需要人工复查。
- [ ] 将每次验证的范围、时间、结果和证据写入 Action Journal；即时核对已落盘，仍需覆盖有界观察及重启验证。全部必要检查通过后才转入 `Verified`，复现则进入 `PartialFailure` 或新一轮有归属的处置。

## 7. GUI read-only API

- [ ] 提供稳定的只读 case、artifact 和 journal API；先展示进度、证据、失败原因和恢复可用性，再设计 GUI 恢复操作。
- [ ] GUI 与主分支改动合并后接入，避免让界面直接推断 JSON 文件中的临时实现细节。

## 8. 扩展持久化类型

- [ ] 前七项稳定后再评估 WMI、Winlogon、IFEO、COM 等。每新增一种类型，都先设计准确关联、完整备份、恢复、失败测试和 journal 操作。
