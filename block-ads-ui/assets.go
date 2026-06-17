//go:build windows

package main

import _ "embed"

//go:embed assets/Enlarge.png
var assetEnlarge []byte

//go:embed assets/Minimize.png
var assetMinimize []byte

//go:embed assets/Guard.png
var assetGuard []byte

//go:embed assets/GitHub.png
var assetGitHub []byte

//go:embed assets/start.png
var assetStart []byte

//go:embed assets/enable.png
var assetEnable []byte

//go:embed assets/disabled.png
var assetDisabled []byte

//go:embed assets/icon.png
var assetIconPNG []byte

//go:embed assets/wait.gif
var assetWaitGIF []byte

//go:embed icon.ico
var assetIconICO []byte

// assetImage 按名字取出已内嵌的 PNG 字节并解码为 core.Image。
func assetImage(name string) []byte {
	switch name {
	case "Enlarge.png":
		return assetEnlarge
	case "Minimize.png":
		return assetMinimize
	case "Guard.png":
		return assetGuard
	case "GitHub.png":
		return assetGitHub
	case "start.png":
		return assetStart
	case "enable.png":
		return assetEnable
	case "disabled.png":
		return assetDisabled
	case "icon.png":
		return assetIconPNG
	}
	return nil
}
