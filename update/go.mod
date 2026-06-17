module createjson

go 1.25.0

// 本地 winui（代理 7890 当前不可达，暂用本地源码；网络恢复后可换回 GitHub require）。
replace github.com/AzureIvory/winui => J:/项目/winui

require github.com/AzureIvory/winui v0.0.0-20260617123449-806b6891370c

require (
	golang.org/x/image v0.39.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
)
