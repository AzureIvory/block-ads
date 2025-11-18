package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	reg "golang.org/x/sys/windows/registry"
)

// 删除文件相关
var (
	procDeleteFileW = modKernel32.NewProc("DeleteFileW")
)

// 进程相关
const (
	th32csSnapProcess = 0x00000002
	processTerminate  = 0x0001
)

var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modKernel32.NewProc("Process32NextW")
	procOpenProcess              = modKernel32.NewProc("OpenProcess")
	procTerminateProcess         = modKernel32.NewProc("TerminateProcess")
)

// PROCESSENTRY32 结构
type processEntry32 struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [260]uint16
}

func Kill(exeName string) error {
	exeName = strings.TrimSpace(exeName)
	if exeName == "" {
		return fmt.Errorf("空字符")
	}
	exeName = filepath.Base(exeName)
	if err := Killcmd(exeName); err == nil {
		return nil
	}
	if err := Killapi(exeName); err == nil {
		return nil
	}
	if err := Killos(exeName); err == nil {
		return nil
	}

	return fmt.Errorf("failed to kill %s by all methods", exeName)
}

func Killcmd(exeName string) error {
	cmd := exec.Command("taskkill", "/IM", exeName, "/F")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	return cmd.Run()
}

func Killapi(exeName string) error {
	pids, err := find(exeName)
	if err != nil {
		return err
	}
	if len(pids) == 0 {
		return fmt.Errorf("no process found: %s", exeName)
	}

	var lastErr error
	for _, pid := range pids {
		h, _, e := procOpenProcess.Call(
			uintptr(processTerminate),
			uintptr(0),
			uintptr(uint32(pid)),
		)
		if h == 0 {
			lastErr = fmt.Errorf("OpenProcess %d: %v", pid, e)
			continue
		}
		_, _, e2 := procTerminateProcess.Call(h, uintptr(1))
		syscall.CloseHandle(syscall.Handle(h))
		if e2 != syscall.Errno(0) && e2 != nil {
			lastErr = fmt.Errorf("TerminateProcess %d: %v", pid, e2)
		}
	}
	return lastErr
}

func Killos(exeName string) error {
	pids, err := find(exeName)
	if err != nil {
		return err
	}
	if len(pids) == 0 {
		return fmt.Errorf("no process found: %s", exeName)
	}

	var lastErr error
	for _, pid := range pids {
		p, err := os.FindProcess(pid)
		if err != nil {
			lastErr = err
			continue
		}
		if err = p.Kill(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// 查找进程
func find(exeName string) ([]int, error) {
	target := strings.ToLower(exeName)

	snap, _, err := procCreateToolhelp32Snapshot.Call(
		uintptr(th32csSnapProcess),
		0,
	)
	const invalidHandle = ^uintptr(0)
	if snap == invalidHandle {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var pe processEntry32
	pe.DwSize = uint32(unsafe.Sizeof(pe))

	ret, _, err := procProcess32FirstW.Call(
		snap,
		uintptr(unsafe.Pointer(&pe)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("Process32FirstW: %v", err)
	}

	var pids []int
	for {
		name := u16_str(pe.SzExeFile[:])
		if strings.EqualFold(name, target) {
			pids = append(pids, int(pe.Th32ProcessID))
		}

		ret, _, _ = procProcess32NextW.Call(
			snap,
			uintptr(unsafe.Pointer(&pe)),
		)
		if ret == 0 {
			break
		}
	}
	return pids, nil
}

// 进程是否存在
func HasProc(exeName string) bool {
	pids, err := find(exeName)
	if err != nil {
		return false
	}
	return len(pids) > 0
}

func u16_str(u []uint16) string {
	n := 0
	for n < len(u) && u[n] != 0 {
		n++
	}
	return string(utf16.Decode(u[:n]))
}

func Del(path string) error {
	if path == "" {
		return fmt.Errorf("空字符")
	}
	if err := os.Remove(path); err == nil {
		return nil
	}
	if err := delapi(path); err == nil {
		return nil
	}
	if err := delcmd(path); err == nil {
		return nil
	}
	return fmt.Errorf("failed to delete file: %s", path)
}

func delapi(path string) error {
	p16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	r, _, e := procDeleteFileW.Call(uintptr(unsafe.Pointer(p16)))
	if r == 0 {
		if e != nil && e != syscall.Errno(0) {
			return e
		}
		return fmt.Errorf("DeleteFileW failed")
	}
	return nil
}

func delcmd(path string) error {
	cmd := exec.Command("cmd", "/C", "del", "/F", "/Q", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	return cmd.Run()
}

// 简单判断系统是否有WebView2
func HasWV2() bool {
	const gu = `{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`

	// 检测WebView2注册表
	if chkKey_pv(reg.LOCAL_MACHINE, `SOFTWARE\Microsoft\EdgeUpdate\Clients\`+gu) ||
		chkKey_pv(reg.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\`+gu) ||
		chkKey_pv(reg.CURRENT_USER, `SOFTWARE\Microsoft\EdgeUpdate\Clients\`+gu) {
		return true
	}

	msg := "缺少运行库 WebView2，是否安装？\n\n" +
		"是：安装运行库\n" +
		"否：退出\n" +
		"取消：继续运行"
	cap := "提示"

	u32 := syscall.NewLazyDLL("user32.dll")
	mb := u32.NewProc("MessageBoxW")

	tPtr, _ := syscall.UTF16PtrFromString(msg)
	cPtr, _ := syscall.UTF16PtrFromString(cap)

	// MB_YESNOCANCEL(0x3) | MB_ICONWARNING(0x30)
	ret, _, _ := mb.Call(
		0,
		uintptr(unsafe.Pointer(tPtr)),
		uintptr(unsafe.Pointer(cPtr)),
		uintptr(0x00000003|0x00000030),
	)

	switch ret {
	case 6: //是
		dir, err := os.Getwd()
		if err != nil {
			os.Exit(0)
			return false
		}
		p := filepath.Join(dir, "MicrosoftEdgeWebview2Setup.exe")
		cmd := exec.Command(p)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}
		_ = cmd.Start()
		os.Exit(0)
		return false

	case 7: // 否
		os.Exit(0)
		return false

	case 2: // 跳过
		return true

	default:
		// 调用失败跳过
		return true
	}
}

// 检查指定键是否且是否有“pv”
func chkKey_pv(root reg.Key, sub string) bool {
	k, err := reg.OpenKey(root, sub, reg.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	if _, _, err = k.GetStringValue("pv"); err == nil {
		return true
	}
	return false
}
