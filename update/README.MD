# 更新发布工具

生成 update.json / sync.json。

## 图形界面（推荐）

直接运行（无参数）即弹出 GUI：

    go run .
    # 或编译后双击 exe

填表 → 点「生成」即可。URL 基址、输出目录已内置默认值。

默认目录为「程序所在目录/update」，输出写回程序所在目录。

## 命令行（自动化场景用）

带参数走命令行：

    go run . -version 1.2 -notes "1.2版本\n优化UI"

常用参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| -version | (必填) | 版本号，如 1.2 |
| -notes | "" | 更新说明，支持 \n |
| -msupported | 0 | 最低支持版本 |
| -mandatory | false | 强制更新 |
| -run | "" | 更新后运行的文件，逗号分隔，如 UI.exe |
| -base | 程序所在目录 | 输出目录 |
| -updateDir | update | 待发布的源文件目录 |
| -fileBase1 | https://api.ttraw.com/block-ads/update/ | 下载基址1 |
| -fileBase2 | https://raw.githubusercontent.com/.../update/update/ | 下载基址2 |

完整示例（URL 用默认，可不传）：

    go run . -version 1.2 -msupported 1.0 -notes "1.2版本\n优化UI"
    go run . -version 1.2 -run "UI.exe"
