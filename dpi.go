//go:build windows

package main

import "syscall"

// EnableDPIAwareness 尽早设置进程DPI感知，避免高分屏下被系统位图拉伸导致模糊。
// Win10+ 优先尝试 Per-Monitor V2；Win7/8 回退到 SetProcessDPIAware。
func EnableDPIAwareness() {
	// SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
	if procSetProcessDpiAwarenessContext.Find() == nil {
		// -4 == DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
		const perMonitorAwareV2 = ^uintptr(3) // (DPI_AWARENESS_CONTEXT)-4
			_, _, _ = procSetProcessDpiAwarenessContext.Call(perMonitorAwareV2)
		return
	}
	// SetProcessDPIAware() (Win7可用)
	if procSetProcessDPIAware.Find() == nil {
		_, _, _ = procSetProcessDPIAware.Call()
	}
}

// dpiForHwnd 取窗口DPI（Win10+），否则回退系统DPI（Win7/8）。
func dpiForHwnd(hwnd syscall.Handle) uint32 {
	if hwnd != 0 && procGetDpiForWindow.Find() == nil {
		ret, _, _ := procGetDpiForWindow.Call(uintptr(hwnd))
		if ret != 0 {
			return uint32(ret)
		}
	}
	return systemDPI()
}

// systemDPI 获取系统DPI（Win7可用）。
func systemDPI() uint32 {
	if procGetDpiForSystem.Find() == nil {
		ret, _, _ := procGetDpiForSystem.Call()
		if ret != 0 {
			return uint32(ret)
		}
	}

	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return 96
	}
	const LOGPIXELSX = 88
	dpi, _, _ := procGetDeviceCaps.Call(hdc, LOGPIXELSX)
	procReleaseDC.Call(0, hdc)

	if dpi == 0 {
		return 96
	}
	return uint32(dpi)
}

// mulDivDPI 用于点字号换算：-MulDiv(pt, dpi, 72)。
func mulDivDPI(n, num, den int32) int32 { return int32(int64(n) * int64(num) / int64(den)) }

var (
	user32DPI                         = syscall.NewLazyDLL("user32.dll")
	gdi32DPI                          = syscall.NewLazyDLL("gdi32.dll")
	procSetProcessDpiAwarenessContext = user32DPI.NewProc("SetProcessDpiAwarenessContext")
	procSetProcessDPIAware            = user32DPI.NewProc("SetProcessDPIAware")
	procGetDpiForWindow               = user32DPI.NewProc("GetDpiForWindow")
	procGetDpiForSystem               = user32DPI.NewProc("GetDpiForSystem")

	procGetDC         = user32DPI.NewProc("GetDC")
	procReleaseDC     = user32DPI.NewProc("ReleaseDC")
	procGetDeviceCaps = gdi32DPI.NewProc("GetDeviceCaps")
)
