//go:build windows

package main

import (
	"strings"
	"syscall"
	"unsafe"

	"github.com/AzureIvory/winui/core"
	"golang.org/x/sys/windows"
)

// 右键菜单项 ID。
const (
	logCtxMenuUninstall = 1001
	logCtxMenuDelete    = 1002
)

var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	procCreatePopupMenu = user32.NewProc("CreatePopupMenu")
	procAppendMenuW     = user32.NewProc("AppendMenuW")
	procTrackPopupMenu  = user32.NewProc("TrackPopupMenu")
	procDestroyMenu     = user32.NewProc("DestroyMenu")
	procGetCursorPos    = user32.NewProc("GetCursorPos")
	procClientToScreen  = user32.NewProc("ClientToScreen")
)

const (
	mfString      = 0x00000000
	mfByPosition  = 0x00000400
	tpmLeftAlign  = 0x0000
	tpmTopAlign   = 0x0000
	tpmRetCmd     = 0x0100 // 返回菜单项 ID 而非 BOOL
	tpmLeftButton = 0x0000
	tpmNoNotify   = 0x0080
)

type point struct {
	X, Y int32
}

// showLogCtxMenu 在光标处弹出原生右键菜单（尝试卸载 / 强制删除）。
// 在 UI 线程调用：TrackPopupMenu 自带模态消息循环，会阻塞直到用户选择或取消。
func (u *nativeUI) showLogCtxMenu() {
	row, ok := u.currentLogRow()
	if !ok || strings.TrimSpace(row.Path) == "" {
		u.showMessage("当前记录没有可操作的路径。", true)
		return
	}

	hmenu, _, _ := procCreatePopupMenu.Call()
	if hmenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hmenu)

	rm, _ := syscall.UTF16PtrFromString("尝试卸载")
	del, _ := syscall.UTF16PtrFromString("强制删除")
	procAppendMenuW.Call(hmenu, mfString, uintptr(logCtxMenuUninstall), uintptr(unsafe.Pointer(rm)))
	procAppendMenuW.Call(hmenu, mfString, uintptr(logCtxMenuDelete), uintptr(unsafe.Pointer(del)))

	// 光标位置（屏幕坐标），用于定位菜单。
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	hwnd := uintptr(0)
	if u.app != nil {
		hwnd = uintptr(u.app.Handle())
	}
	cmd, _, _ := procTrackPopupMenu.Call(
		hmenu,
		uintptr(tpmLeftAlign|tpmTopAlign|tpmRetCmd|tpmLeftButton|tpmNoNotify),
		uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0,
	)
	switch int32(cmd) {
	case logCtxMenuUninstall:
		u.tryRemoveSelectedLog()
	case logCtxMenuDelete:
		u.forceDeleteSelectedLog()
	}
}

// 保留 core 引用以备未来在菜单中绘制图标等扩展。
var _ = core.Point{}
