package main

import (
	"syscall"
	"unsafe"
)

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procShowWindow       = user32.NewProc("ShowWindow")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
)

type (
	HWND      = syscall.Handle
	HINSTANCE = syscall.Handle
)

type POINT struct {
	X, Y int32
}

type MSG struct {
	Hwnd     HWND
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       POINT
	LPrivate uint32
}

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     HINSTANCE
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

// 消息回调
func wndProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	const WM_DESTROY = 0x0002

	switch msg {
	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	default:
		ret, _, _ := procDefWindowProcW.Call(
			hwnd,
			uintptr(msg),
			wparam,
			lparam,
		)
		return ret
	}
}

func main() {

	hInst, _, _ := procGetModuleHandleW.Call(0)
	hInstance := HINSTANCE(hInst)

	className, _ := syscall.UTF16PtrFromString("CabinetWClass")
	title, _ := syscall.UTF16PtrFromString("控制面板")

	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         0,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     hInstance,
		LpszClassName: className,
	}
	ret, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if ret == 0 {
		panic(err)
	}

	const (
		WS_EX_TOOLWINDOW = 0x00000080
		WS_POPUP         = 0x80000000
		SW_HIDE          = 0
	)

	hwnd, _, err2 := procCreateWindowExW.Call(
		WS_EX_TOOLWINDOW,                   //exStyle
		uintptr(unsafe.Pointer(className)), //lpClassName
		uintptr(unsafe.Pointer(title)),     //lpWindowName
		WS_POPUP,                           //dwStyle
		0, 0, 0, 0,                         //x,y,w,h
		0, 0, //hWndParent,hMenu
		uintptr(hInstance), //hInstance
		0,                  //lpParam
	)
	if hwnd == 0 {
		panic(err2)
	}

	procShowWindow.Call(hwnd, SW_HIDE)

	//消息循环
	var msg MSG
	for {
		r, _, _ := procGetMessageW.Call(
			uintptr(unsafe.Pointer(&msg)),
			0, 0, 0,
		)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}
