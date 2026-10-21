# 测试

所有 Go 测试都放在本目录。普通测试使用隔离的工作区临时目录和可控的测试子进程，不运行主程序的全局扫描，也不触碰系统计划任务或服务。

```powershell
go test ./...
go test -race ./tests
```

真实 Kernel Process ETW provider 测试需要从管理员 PowerShell 单独运行：

```powershell
$env:BLOCK_ADS_TEST_LIVE_ETW = '1'
go test ./tests -run '^TestLiveKernelProcessETW$' -count=1 -v
```

该测试使用独立的临时 ETW session 名称和测试子进程。普通权限下 `StartTraceW` 会返回 `Access is denied`，这不代表模拟 ETW 属性解析测试失败。

`codex/removal` 每次推送也会运行 `.github/workflows/removal-p1.yml`，在 Windows runner 上执行普通测试及真实 ETW 测试。只有真实 ETW 运行通过后，路线图第 1.1 项才算完成。

Run/RunOnce 和 Task Scheduler 的真实往返测试会修改执行机器的当前用户启动项及计划任务，只在隔离的 Windows runner 上开启，并由测试清理临时条目：

```powershell
$env:BLOCK_ADS_TEST_REAL_PERSISTENCE = '1'
go test ./tests -run '^(TestRegistryRunAndRunOnceRoundTrip|TestScheduledTaskRoundTrip)$' -count=1 -v
```

同一隔离 runner 还执行 `TestRunRestoreChecksValueTypeAndCrashBoundaries`，验证 Run 恢复的三个崩溃边界、`REG_EXPAND_SZ` 保留及同内容不同类型/二进制占位值拒绝覆盖。普通测试中的 `TestCrashAtStartupRestoreBoundaries`、`TestStartupRestoreRefusesChangedInputs`、`TestStartupRestoreRecoveryDetectsConflicts` 和 `TestStartupRestoreCommitsVerifiedEvidence` 使用隔离目录验证快捷方式恢复，不触碰真实 Startup 目录。

`TestTaskXMLMatchesCompleteDefinition` 和 `TestTaskXMLRejectsIncompleteOrAmbiguousDefinitions` 在普通测试中验证完整 XML 比较、UTF-16 与命名空间前缀、参数空格保留、配置差异和损坏输入；不访问系统任务。`TestTaskRestoreVerificationAndCrashBoundaries` 仅由上述隔离 runner 开启，覆盖真实任务完整 XML 恢复、三个崩溃边界、恢复后配置被更改、备份变化、占位任务不覆盖及任务位置校验。

真实加载 DLL 的测试需要 Windows C 编译器 `gcc`，会在隔离目录编译一个无签名测试 DLL，让可控子进程加载，再验证 EXE/DLL 隔离、恢复和重启后的重新命中：

```powershell
$env:BLOCK_ADS_TEST_LIVE_DLL = '1'
go test ./tests -run '^TestLoadedDLLQuarantineAndRestore$' -count=1 -v
```
