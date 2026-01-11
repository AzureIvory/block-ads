go run createjson.go -version 1.2 -msupported 1.0 -mandatory=false ^
  -notes "1.2版本\n优化UI\n新增同步/更新功能\n新增上传数据功能" ^
  -fileBase1 https://api.ttraw.com/block-ads/update -fileBase2 https://raw.githubusercontent.com/AzureIvory/block-ads/refs/heads/main/update/update


指定更新后要运行的文件（run=true）：
go run createjson -version 1.2 -run "UI.exe"
