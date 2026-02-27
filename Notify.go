package main

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// NotifyConfig 配置参数
// Icon/TitleIcon 支持：
//   - syscall.Handle(HICON)：推荐(比如 SHGetFileInfoW)
//   - []byte：.ico 文件内容
//   - string：.ico 文件路径
//
// 注意：窗口关闭时会 DestroyIcon 释放句柄。
type NotifyConfig struct {
	Title      string
	TitleIcon  interface{}
	Message    string
	SubMessage string
	Icon       interface{}
	LeftColor  uint32
	Timeout    int

	OnIgnore    func() // 不再提示（全局关闭弹窗）
	OnWhitelist func() // 加入白名单
	OnBodyClick func() // 点击正文
}

// ShowNotification 显示通知入口
func ShowNotification(cfg NotifyConfig) {
	if cfg.LeftColor == 0 {
		cfg.LeftColor = 0x2F2FD3 // 默认红色(BGR)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 // 默认10秒
	}
	createWindow(cfg)
}

var (
	windowStore = make(map[syscall.Handle]*windowState)
	storeMutex  sync.RWMutex
)

type windowState struct {
	config *NotifyConfig

	// 资源缓存
	hFontBold  syscall.Handle
	hFontReg   syscall.Handle
	hFontSml   syscall.Handle
	hTitleIcon syscall.Handle
	hMainIcon  syscall.Handle

	// 区域检测
	rectBody      RECT
	rectIgnore    RECT
	rectWhitelist RECT
	rectDismiss   RECT
	rectClose     RECT

	// 状态
	isHoveringBody bool
	isTracking     bool
}

func registerWindow(hwnd syscall.Handle, state *windowState) {
	storeMutex.Lock()
	windowStore[hwnd] = state
	storeMutex.Unlock()
}

func unregisterWindow(hwnd syscall.Handle) {
	storeMutex.Lock()
	delete(windowStore, hwnd)
	storeMutex.Unlock()
}

func getWindowState(hwnd syscall.Handle) *windowState {
	storeMutex.RLock()
	s := windowStore[hwnd]
	storeMutex.RUnlock()
	return s
}

func createWindow(cfg NotifyConfig) {
	// 每个窗口独立消息循环：必须锁 OS 线程
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInstance := GetModuleHandle(nil)
	className := syscall.StringToUTF16Ptr("GoNotify_" + fmt.Sprint(time.Now().UnixNano()))

	var wc WNDCLASSEX
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.Style = CS_HREDRAW | CS_VREDRAW | CS_DROPSHADOW
	wc.LpfnWndProc = syscall.NewCallback(WndProc)
	wc.HInstance = hInstance
	wc.HbrBackground = 0 // 自行绘制背景，防止闪烁
	wc.LpszClassName = className
	wc.HCursor = LoadCursor(0, IDC_ARROW)

	RegisterClassEx(&wc)

	w, h := 380, 165
	scrW := GetSystemMetrics(SM_CXSCREEN)
	scrH := GetSystemMetrics(SM_CYSCREEN)
	x := int32(scrW) - int32(w) - 20
	y := int32(scrH) - int32(h) - 60

	hwnd := CreateWindowEx(
		WS_EX_TOPMOST|WS_EX_TOOLWINDOW,
		className,
		syscall.StringToUTF16Ptr(cfg.Title),
		WS_POPUP,
		x, y, int32(w), int32(h),
		0, 0, hInstance, nil,
	)
	if hwnd == 0 {
		return
	}

	state := &windowState{
		config:     &cfg,
		hFontBold:  createFont("Microsoft YaHei UI", 13, 700),
		hFontReg:   createFont("Microsoft YaHei UI", 16, 400),
		hFontSml:   createFont("Microsoft YaHei UI", 11, 400),
		hTitleIcon: loadIcon(cfg.TitleIcon),
		hMainIcon:  loadIcon(cfg.Icon),
	}
	registerWindow(hwnd, state)

	// 圆角
	rgn := CreateRoundRectRgn(0, 0, int32(w)+1, int32(h)+1, 8, 8)
	SetWindowRgn(hwnd, rgn, true)
	DeleteObject(HGDIOBJ(rgn))

	if cfg.Timeout > 0 {
		SetTimer(hwnd, 1, uint32(cfg.Timeout*1000), 0)
	}

	// 动画进场
	AnimateWindow(hwnd, 200, AW_SLIDE|AW_VER_NEGATIVE|AW_ACTIVATE)
	UpdateWindow(hwnd)

	var msg MSG
	for GetMessage(&msg, 0, 0, 0) > 0 {
		TranslateMessage(&msg)
		DispatchMessage(&msg)
	}
}

func WndProc(hwnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	state := getWindowState(hwnd)
	if state == nil && msg != WM_CREATE {
		return DefWindowProc(hwnd, msg, wParam, lParam)
	}

	switch msg {
	case WM_ERASEBKGND:
		return 1 // 防止闪烁

	case WM_PRINTCLIENT:
		hdc := syscall.Handle(wParam)
		drawDoubleBuffered(hdc, hwnd, state)
		return 0

	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc := BeginPaint(hwnd, &ps)
		drawDoubleBuffered(hdc, hwnd, state)
		EndPaint(hwnd, &ps)
		return 0

	case WM_MOUSEMOVE:
		x := int32(int16(LOWORD(uint32(lParam))))
		y := int32(int16(HIWORD(uint32(lParam))))

		if !state.isTracking {
			var tme TRACKMOUSEEVENT
			tme.CbSize = uint32(unsafe.Sizeof(tme))
			tme.DwFlags = TME_LEAVE
			tme.HwndTrack = hwnd
			TrackMouseEvent(&tme)
			state.isTracking = true
		}

		isOverBody := ptInRect(POINT{x, y}, state.rectBody)
		if isOverBody != state.isHoveringBody {
			state.isHoveringBody = isOverBody
			InvalidateRect(hwnd, &state.rectBody, 0)
		}

		if state.config.Timeout > 0 {
			SetTimer(hwnd, 1, uint32(state.config.Timeout*1000), 0)
		}
		return 0

	case WM_MOUSELEAVE:
		state.isTracking = false
		state.isHoveringBody = false
		InvalidateRect(hwnd, nil, 0)
		return 0

	case WM_SETCURSOR:
		if syscall.Handle(wParam) == hwnd {
			var p POINT
			GetCursorPos(&p)
			ScreenToClient(hwnd, &p)

			isClickable := ptInRect(p, state.rectClose) ||
				ptInRect(p, state.rectIgnore) ||
				ptInRect(p, state.rectWhitelist) ||
				ptInRect(p, state.rectDismiss) ||
				ptInRect(p, state.rectBody)

			if isClickable {
				SetCursor(LoadCursor(0, IDC_HAND))
			} else {
				SetCursor(LoadCursor(0, IDC_ARROW))
			}
			return 1
		}
		return DefWindowProc(hwnd, msg, wParam, lParam)

	case WM_LBUTTONUP:
		x := int32(int16(LOWORD(uint32(lParam))))
		y := int32(int16(HIWORD(uint32(lParam))))
		handleClicks(hwnd, state, x, y)
		return 0

	case WM_TIMER:
		if wParam == 1 {
			KillTimer(hwnd, 1)
			AnimateWindow(hwnd, 200, AW_HIDE|AW_BLEND)
			procDestroyWindow.Call(uintptr(hwnd))
		}
		return 0

	case WM_DESTROY:
		DeleteObject(HGDIOBJ(state.hFontBold))
		DeleteObject(HGDIOBJ(state.hFontReg))
		DeleteObject(HGDIOBJ(state.hFontSml))

		// 图标释放：避免重复释放
		if state.hTitleIcon != 0 {
			DestroyIcon(state.hTitleIcon)
		}
		if state.hMainIcon != 0 && state.hMainIcon != state.hTitleIcon {
			DestroyIcon(state.hMainIcon)
		}

		unregisterWindow(hwnd)
		PostQuitMessage(0)
		return 0
	}
	return DefWindowProc(hwnd, msg, wParam, lParam)
}

// 双缓冲绘制入口
func drawDoubleBuffered(destDC syscall.Handle, hwnd syscall.Handle, state *windowState) {
	var rect RECT
	GetClientRect(hwnd, &rect)
	w, h := rect.Right, rect.Bottom

	memDC := CreateCompatibleDC(destDC)
	memBitmap := CreateCompatibleBitmap(destDC, w, h)
	oldBitmap := SelectObject(memDC, HGDIOBJ(memBitmap))

	drawUI(memDC, w, h, state)
	BitBlt(destDC, 0, 0, w, h, memDC, 0, 0, SRCCOPY)

	SelectObject(memDC, oldBitmap)
	DeleteObject(HGDIOBJ(memBitmap))
	DeleteDC(memDC)
}

// 实际绘制逻辑
func drawUI(hdc syscall.Handle, w, h int32, state *windowState) {
	cfg := state.config
	SetBkMode(hdc, TRANSPARENT)

	// 底层彩条背景
	brushBase := CreateSolidBrush(cfg.LeftColor)
	rectBase := RECT{0, 0, w, h}
	FillRect(hdc, &rectBase, brushBase)
	DeleteObject(HGDIOBJ(brushBase))

	// 内容层白色偏移 6px
	brushWhite := CreateSolidBrush(0xFFFFFF)
	rectContent := RECT{6, 0, w, h}
	FillRect(hdc, &rectContent, brushWhite)
	DeleteObject(HGDIOBJ(brushWhite))

	// 头部
	if state.hTitleIcon != 0 {
		DrawIconEx(hdc, 18, 10, state.hTitleIcon, 16, 16, 0, 0, DI_NORMAL)
	}

	SelectObject(hdc, HGDIOBJ(state.hFontBold))
	SetTextColor(hdc, cfg.LeftColor)
	rectTitle := RECT{42, 0, w - 40, 36}
	DrawText(hdc, cfg.Title, &rectTitle, DT_SINGLELINE|DT_VCENTER)

	SelectObject(hdc, HGDIOBJ(state.hFontReg))
	SetTextColor(hdc, 0x888888)
	state.rectClose = RECT{w - 40, 0, w, 36}
	DrawText(hdc, "×", &state.rectClose, DT_CENTER|DT_VCENTER|DT_SINGLELINE)

	// 正文区 hover
	state.rectBody = RECT{6, 36, w, 125}
	bodyColor := uint32(0xF9F9F9)
	if state.isHoveringBody {
		bodyColor = 0xECECEC
	}
	brushBody := CreateSolidBrush(bodyColor)
	FillRect(hdc, &state.rectBody, brushBody)
	DeleteObject(HGDIOBJ(brushBody))

	// 图标底块
	brushIconBox := CreateSolidBrush(0xEBEBEB)
	rectIconBox := RECT{24, 52, 64, 92}
	FillRect(hdc, &rectIconBox, brushIconBox)
	DeleteObject(HGDIOBJ(brushIconBox))
	if state.hMainIcon != 0 {
		DrawIconEx(hdc, 28, 56, state.hMainIcon, 32, 32, 0, 0, DI_NORMAL)
	}

	SelectObject(hdc, HGDIOBJ(state.hFontBold))
	SetTextColor(hdc, 0x222222)
	rectMsg := RECT{76, 50, w - 20, 72}
	DrawText(hdc, cfg.Message, &rectMsg, DT_SINGLELINE|DT_VCENTER|DT_PATH_ELLIPSIS)

	SelectObject(hdc, HGDIOBJ(state.hFontSml))
	SetTextColor(hdc, 0x666666)
	rectSub := RECT{76, 74, w - 20, 110}
	DrawText(hdc, cfg.SubMessage, &rectSub, DT_WORDBREAK|DT_PATH_ELLIPSIS)

	// 底部按钮
	drawLine(hdc, 6, 125, int(w), 125, 0xEAEAEA)
	SelectObject(hdc, HGDIOBJ(state.hFontSml))

	btnBlue := uint32(0xD77800) // BGR

	SetTextColor(hdc, 0x999999)
	state.rectIgnore = RECT{18, 125, 110, 165}
	DrawText(hdc, "不再提示", &state.rectIgnore, DT_SINGLELINE|DT_VCENTER)

	SetTextColor(hdc, btnBlue)
	state.rectWhitelist = RECT{120, 125, 220, 165}
	DrawText(hdc, "加入白名单", &state.rectWhitelist, DT_SINGLELINE|DT_VCENTER)

	SetTextColor(hdc, 0x999999)
	state.rectDismiss = RECT{w - 80, 125, w - 20, 165}
	DrawText(hdc, "知道了", &state.rectDismiss, DT_RIGHT|DT_VCENTER|DT_SINGLELINE)
}

func handleClicks(hwnd syscall.Handle, state *windowState, x, y int32) {
	pt := POINT{x, y}
	cfg := state.config

	if ptInRect(pt, state.rectClose) {
		AnimateWindow(hwnd, 150, AW_HIDE|AW_BLEND)
		procDestroyWindow.Call(uintptr(hwnd))
		return
	}
	if ptInRect(pt, state.rectIgnore) {
		if cfg.OnIgnore != nil {
			cfg.OnIgnore()
		}
		procDestroyWindow.Call(uintptr(hwnd))
		return
	}
	if ptInRect(pt, state.rectWhitelist) {
		if cfg.OnWhitelist != nil {
			cfg.OnWhitelist()
		}
		procDestroyWindow.Call(uintptr(hwnd))
		return
	}
	if ptInRect(pt, state.rectDismiss) {
		procDestroyWindow.Call(uintptr(hwnd))
		return
	}
	if ptInRect(pt, state.rectBody) {
		if cfg.OnBodyClick != nil {
			cfg.OnBodyClick()
		}
		procDestroyWindow.Call(uintptr(hwnd))
	}
}

func ptInRect(pt POINT, r RECT) bool {
	return pt.X >= r.Left && pt.X <= r.Right && pt.Y >= r.Top && pt.Y <= r.Bottom
}

const (
	// Class Styles
	CS_VREDRAW    = 0x0001
	CS_HREDRAW    = 0x0002
	CS_DROPSHADOW = 0x00020000

	// Window Styles
	WS_POPUP         = 0x80000000
	WS_EX_TOPMOST    = 0x00000008
	WS_EX_TOOLWINDOW = 0x00000080

	// Messages
	WM_CREATE      = 0x0001
	WM_DESTROY     = 0x0002
	WM_PAINT       = 0x000F
	WM_ERASEBKGND  = 0x0014
	WM_SETCURSOR   = 0x0020
	WM_TIMER       = 0x0113
	WM_MOUSEMOVE   = 0x0200
	WM_LBUTTONUP   = 0x0202
	WM_MOUSELEAVE  = 0x02A3
	WM_PRINTCLIENT = 0x0318

	// System Metrics
	SM_CXSCREEN = 0
	SM_CYSCREEN = 1

	// Animation
	AW_SLIDE        = 0x00040000
	AW_ACTIVATE     = 0x00020000
	AW_BLEND        = 0x00080000
	AW_HIDE         = 0x00010000
	AW_VER_NEGATIVE = 0x00000008

	// Text format
	DT_CENTER        = 0x01
	DT_RIGHT         = 0x02
	DT_VCENTER       = 0x04
	DT_SINGLELINE    = 0x20
	DT_WORDBREAK     = 0x10
	DT_PATH_ELLIPSIS = 0x4000

	// GDI
	TRANSPARENT = 1
	SRCCOPY     = 0x00CC0020

	// Resources
	IDC_ARROW = 32512
	IDC_HAND  = 32649
	DI_NORMAL = 0x0003
	TME_LEAVE = 0x00000002
)

type WNDCLASSEX struct {
	CbSize, Style                            uint32
	LpfnWndProc                              uintptr
	CbClsExtra, CbWndExtra                   int32
	HInstance, HIcon, HCursor, HbrBackground syscall.Handle
	LpszMenuName, LpszClassName              *uint16
	HIconSm                                  syscall.Handle
}

type MSG struct {
	Hwnd           syscall.Handle
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Pt             POINT
}

type POINT struct{ X, Y int32 }

type RECT struct{ Left, Top, Right, Bottom int32 }

type PAINTSTRUCT struct {
	Hdc                  syscall.Handle
	FErase               int32
	RcPaint              RECT
	FRestore, FIncUpdate int32
	RgbReserved          [32]byte
}

type HBRUSH syscall.Handle

type HGDIOBJ syscall.Handle

type TRACKMOUSEEVENT struct {
	CbSize      uint32
	DwFlags     uint32
	HwndTrack   syscall.Handle
	DwHoverTime uint32
}

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procSetWindowRgn     = user32.NewProc("SetWindowRgn")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procLoadCursorW      = user32.NewProc("LoadCursorW")
	procLoadImageW       = user32.NewProc("LoadImageW")
	procBeginPaint       = user32.NewProc("BeginPaint")
	procEndPaint         = user32.NewProc("EndPaint")
	procFillRect         = user32.NewProc("FillRect")
	procDrawTextW        = user32.NewProc("DrawTextW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procDrawIconEx       = user32.NewProc("DrawIconEx")
	procGetClientRect    = user32.NewProc("GetClientRect")
	procSetTimer         = user32.NewProc("SetTimer")
	procKillTimer        = user32.NewProc("KillTimer")
	procAnimateWindow    = user32.NewProc("AnimateWindow")
	procTrackMouseEvent  = user32.NewProc("TrackMouseEvent")
	procInvalidateRect   = user32.NewProc("InvalidateRect")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procScreenToClient   = user32.NewProc("ScreenToClient")
	procSetCursor        = user32.NewProc("SetCursor")
	procDestroyIcon      = user32.NewProc("DestroyIcon")

	procCreateSolidBrush         = gdi32.NewProc("CreateSolidBrush")
	procCreateRoundRectRgn       = gdi32.NewProc("CreateRoundRectRgn")
	procCreateFontW              = gdi32.NewProc("CreateFontW")
	procSelectObject             = gdi32.NewProc("SelectObject")
	procDeleteObject             = gdi32.NewProc("DeleteObject")
	procSetBkMode                = gdi32.NewProc("SetBkMode")
	procSetTextColor             = gdi32.NewProc("SetTextColor")
	procCreatePen                = gdi32.NewProc("CreatePen")
	procMoveToEx                 = gdi32.NewProc("MoveToEx")
	procLineTo                   = gdi32.NewProc("LineTo")
	procCreateIconFromResourceEx = user32.NewProc("CreateIconFromResourceEx")

	// 双缓冲
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
)

func GetModuleHandle(name *uint16) syscall.Handle {
	ret, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(name)))
	return syscall.Handle(ret)
}

func RegisterClassEx(wc *WNDCLASSEX) uint16 {
	ret, _, _ := procRegisterClassExW.Call(uintptr(unsafe.Pointer(wc)))
	return uint16(ret)
}

func CreateWindowEx(exStyle uint32, cn *uint16, wn *uint16, style uint32, x, y, w, h int32, p, m, i syscall.Handle, param unsafe.Pointer) syscall.Handle {
	ret, _, _ := procCreateWindowExW.Call(
		uintptr(exStyle),
		uintptr(unsafe.Pointer(cn)),
		uintptr(unsafe.Pointer(wn)),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(p), uintptr(m), uintptr(i),
		uintptr(param),
	)
	return syscall.Handle(ret)
}

func UpdateWindow(hwnd syscall.Handle) { procUpdateWindow.Call(uintptr(hwnd)) }

func GetMessage(msg *MSG, hwnd syscall.Handle, min, max uint32) int32 {
	ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(msg)), uintptr(hwnd), uintptr(min), uintptr(max))
	return int32(ret)
}

func TranslateMessage(msg *MSG) { procTranslateMessage.Call(uintptr(unsafe.Pointer(msg))) }

func DispatchMessage(msg *MSG) { procDispatchMessageW.Call(uintptr(unsafe.Pointer(msg))) }

func DefWindowProc(hwnd syscall.Handle, msg uint32, w, l uintptr) uintptr {
	ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), w, l)
	return ret
}

func PostQuitMessage(exitCode int32) { procPostQuitMessage.Call(uintptr(exitCode)) }

func GetSystemMetrics(index int32) int32 {
	ret, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int32(ret)
}

func CreateRoundRectRgn(x1, y1, x2, y2, w, h int32) syscall.Handle {
	ret, _, _ := procCreateRoundRectRgn.Call(uintptr(x1), uintptr(y1), uintptr(x2), uintptr(y2), uintptr(w), uintptr(h))
	return syscall.Handle(ret)
}

func SetWindowRgn(hwnd, hrgn syscall.Handle, redraw bool) {
	procSetWindowRgn.Call(uintptr(hwnd), uintptr(hrgn), uintptr(1))
}

func BeginPaint(hwnd syscall.Handle, ps *PAINTSTRUCT) syscall.Handle {
	ret, _, _ := procBeginPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(ps)))
	return syscall.Handle(ret)
}

func EndPaint(hwnd syscall.Handle, ps *PAINTSTRUCT) {
	procEndPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(ps)))
}

func CreateSolidBrush(color uint32) HBRUSH {
	ret, _, _ := procCreateSolidBrush.Call(uintptr(color))
	return HBRUSH(ret)
}

func FillRect(hdc syscall.Handle, r *RECT, hbr HBRUSH) {
	procFillRect.Call(uintptr(hdc), uintptr(unsafe.Pointer(r)), uintptr(hbr))
}

func DeleteObject(obj HGDIOBJ) { procDeleteObject.Call(uintptr(obj)) }

func SelectObject(hdc syscall.Handle, obj HGDIOBJ) HGDIOBJ {
	ret, _, _ := procSelectObject.Call(uintptr(hdc), uintptr(obj))
	return HGDIOBJ(ret)
}

func SetBkMode(hdc syscall.Handle, mode int32) { procSetBkMode.Call(uintptr(hdc), uintptr(mode)) }

func SetTextColor(hdc syscall.Handle, color uint32) {
	procSetTextColor.Call(uintptr(hdc), uintptr(color))
}

func DrawText(hdc syscall.Handle, text string, rect *RECT, format uint32) {
	ptr, _ := syscall.UTF16PtrFromString(text)
	procDrawTextW.Call(uintptr(hdc), uintptr(unsafe.Pointer(ptr)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(rect)), uintptr(format))
}

func LoadCursor(inst syscall.Handle, id uintptr) syscall.Handle {
	ret, _, _ := procLoadCursorW.Call(uintptr(inst), id)
	return syscall.Handle(ret)
}

func DrawIconEx(hdc syscall.Handle, x, y int32, hIcon syscall.Handle, w, h int32, step, brush, flags uint32) {
	procDrawIconEx.Call(uintptr(hdc), uintptr(x), uintptr(y), uintptr(hIcon), uintptr(w), uintptr(h), uintptr(step), uintptr(brush), uintptr(flags))
}

func GetClientRect(hwnd syscall.Handle, rect *RECT) {
	procGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(rect)))
}

func SetTimer(hwnd syscall.Handle, id uintptr, timeout uint32, proc uintptr) {
	procSetTimer.Call(uintptr(hwnd), id, uintptr(timeout), proc)
}

func KillTimer(hwnd syscall.Handle, id uintptr) { procKillTimer.Call(uintptr(hwnd), id) }

func AnimateWindow(hwnd syscall.Handle, time uint32, flags uint32) {
	procAnimateWindow.Call(uintptr(hwnd), uintptr(time), uintptr(flags))
}

func TrackMouseEvent(tme *TRACKMOUSEEVENT) { procTrackMouseEvent.Call(uintptr(unsafe.Pointer(tme))) }

func InvalidateRect(hwnd syscall.Handle, rect *RECT, erase int32) {
	procInvalidateRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(rect)), uintptr(erase))
}

func GetCursorPos(pt *POINT) { procGetCursorPos.Call(uintptr(unsafe.Pointer(pt))) }

func ScreenToClient(hwnd syscall.Handle, pt *POINT) {
	procScreenToClient.Call(uintptr(hwnd), uintptr(unsafe.Pointer(pt)))
}

func SetCursor(hCursor syscall.Handle) { procSetCursor.Call(uintptr(hCursor)) }

func DestroyIcon(h syscall.Handle) {
	if h != 0 {
		procDestroyIcon.Call(uintptr(h))
	}
}

func CreateCompatibleDC(hdc syscall.Handle) syscall.Handle {
	ret, _, _ := procCreateCompatibleDC.Call(uintptr(hdc))
	return syscall.Handle(ret)
}

func CreateCompatibleBitmap(hdc syscall.Handle, w, h int32) syscall.Handle {
	ret, _, _ := procCreateCompatibleBitmap.Call(uintptr(hdc), uintptr(w), uintptr(h))
	return syscall.Handle(ret)
}

func BitBlt(dest syscall.Handle, x, y, w, h int32, src syscall.Handle, x1, y1 int32, rop uint32) {
	procBitBlt.Call(uintptr(dest), uintptr(x), uintptr(y), uintptr(w), uintptr(h), uintptr(src), uintptr(x1), uintptr(y1), uintptr(rop))
}

func DeleteDC(hdc syscall.Handle) { procDeleteDC.Call(uintptr(hdc)) }

func LOWORD(dw uint32) uint16 { return uint16(dw & 0xFFFF) }

func HIWORD(dw uint32) uint16 { return uint16((dw >> 16) & 0xFFFF) }

func loadIcon(input interface{}) syscall.Handle {
	if input == nil {
		return 0
	}
	switch v := input.(type) {
	case syscall.Handle:
		return v
	case uintptr:
		return syscall.Handle(v)
	case string:
		p, _ := syscall.UTF16PtrFromString(v)
		// IMAGE_ICON=1, LR_LOADFROMFILE=0x10, LR_DEFAULTSIZE=0x40
		h, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(p)), 1, 0, 0, 0x10|0x40)
		return syscall.Handle(h)
	case []byte:
		return loadIconFromBytes(v)
	}
	return 0
}

func loadIconFromBytes(data []byte) syscall.Handle {
	if len(data) < 22 {
		return 0
	}
	size := binary.LittleEndian.Uint32(data[14:18])
	offset := binary.LittleEndian.Uint32(data[18:22])
	if uint32(len(data)) < offset+size {
		return 0
	}
	iconData := data[offset : offset+size]
	ret, _, _ := procCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&iconData[0])),
		uintptr(size),
		1,
		0x00030000,
		0, 0, 0,
	)
	return syscall.Handle(ret)
}

func createFont(face string, size, weight int32) syscall.Handle {
	h := -mulDiv(size, 96, 72)
	f, _ := syscall.UTF16PtrFromString(face)
	ret, _, _ := procCreateFontW.Call(
		uintptr(h),
		0, 0, 0,
		uintptr(weight),
		0, 0, 0,
		1, 0, 0, 5, 0,
		uintptr(unsafe.Pointer(f)),
	)
	return syscall.Handle(ret)
}

func mulDiv(n, num, den int32) int32 { return int32(int64(n) * int64(num) / int64(den)) }

func drawLine(hdc syscall.Handle, x1, y1, x2, y2 int, color uint32) {
	pen, _, _ := procCreatePen.Call(0, 1, uintptr(color))
	old := SelectObject(hdc, HGDIOBJ(pen))
	procMoveToEx.Call(uintptr(hdc), uintptr(x1), uintptr(y1), 0)
	procLineTo.Call(uintptr(hdc), uintptr(x2), uintptr(y2))
	SelectObject(hdc, old)
	DeleteObject(HGDIOBJ(pen))
}
