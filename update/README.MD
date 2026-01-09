生成 JSON
go run manifest_gen.go -version 1.2 -msupported 1.0 -mandatory=false ^
  -notes "更新说明，支持\n换行" ^
  -fileBase1 https://raw.githubusercontent.com/AzureIvory/block-ads/refs/heads/main/update/update -fileBase2 https://api.ttraw.com/block-ads/update


指定更新后要运行的文件（run=true）：
go run manifest_gen.go -version 1.2 -run "UI.exe"
