package utils

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	reg "golang.org/x/sys/windows/registry"
)

const (
	// 进程相关
	th32csSnapProcess = 0x00000002
	processTerminate  = 0x0001

	shmNameLocal  = "block-ads-unins"         // 共享内存名（同会话）
	shmNameGlobal = "Global\\block-ads-unins" // 跨会话共享内存名
	shmSize       = 4096                      // 4KB就够用了
	pageReadWrite = 0x04                      // PAGE_READWRITE
	fileMapWrite  = 0x0002                    // FILE_MAP_WRITE
	fileMapRead   = 0x0004                    // FILE_MAP_READ
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modKernel32.NewProc("Process32NextW")
	procOpenProcess              = modKernel32.NewProc("OpenProcess")
	procTerminateProcess         = modKernel32.NewProc("TerminateProcess")

	// 删除文件相关
	procDeleteFileW = modKernel32.NewProc("DeleteFileW")

	// 共享内存相关
	procCreateFileMappingW = modKernel32.NewProc("CreateFileMappingW")
	procOpenFileMappingW   = modKernel32.NewProc("OpenFileMappingW")
	procMapViewOfFile      = modKernel32.NewProc("MapViewOfFile")
	procUnmapViewOfFile    = modKernel32.NewProc("UnmapViewOfFile")
)

// 写共享内存锁
var shmMu sync.Mutex

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

// 把卸载程序文件名写入共享内存，供 block-ads.exe 读取并临时放行
// 约定：共享内存中存的是 UTF-8 文本，按换行符分隔多个文件名
func addUnWithName(name, shmName string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("空卸载名")
	}
	if strings.ContainsAny(name, "\r\n") {
		return fmt.Errorf("卸载名包含非法字符")
	}

	shmMu.Lock()
	defer shmMu.Unlock()

	nm, err := syscall.UTF16PtrFromString(shmName)
	if err != nil {
		return err
	}

	// 先尝试打开已有的文件映射
	h, _, e := procOpenFileMappingW.Call(
		uintptr(fileMapRead|fileMapWrite),
		0,
		uintptr(unsafe.Pointer(nm)),
	)
	if h == 0 {
		// 没有就创建新的共享内存（基于系统分页文件）
		h, _, e = procCreateFileMappingW.Call(
			uintptr(syscall.InvalidHandle), // 使用系统分页文件
			0,
			uintptr(pageReadWrite),
			0,
			uintptr(shmSize),
			uintptr(unsafe.Pointer(nm)),
		)
		if h == 0 {
			if e != nil && e != syscall.Errno(0) {
				return fmt.Errorf("CreateFileMappingW: %v", e)
			}
			return fmt.Errorf("CreateFileMappingW 失败")
		}
	}
	defer syscall.CloseHandle(syscall.Handle(h))

	// 映射视图
	addr, _, e2 := procMapViewOfFile.Call(
		h,
		uintptr(fileMapRead|fileMapWrite),
		0,
		0,
		uintptr(shmSize),
	)
	if addr == 0 {
		if e2 != nil && e2 != syscall.Errno(0) {
			return fmt.Errorf("MapViewOfFile: %v", e2)
		}
		return fmt.Errorf("MapViewOfFile 失败")
	}
	defer procUnmapViewOfFile.Call(addr)

	buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), shmSize)

	// 读现有内容（到第一个 0 字节为止）
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}

	cur := ""
	if end > 0 {
		cur = string(buf[:end])
	}

	// 用 map 去重
	set := make(map[string]struct{})
	if cur != "" {
		for _, ln := range strings.Split(cur, "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			set[ln] = struct{}{}
		}
	}
	set[name] = struct{}{} // 加入本次的卸载器文件名

	// 重新拼成字符串
	var sb strings.Builder
	first := true
	for k := range set {
		if !first {
			sb.WriteByte('\n')
		}
		sb.WriteString(k)
		first = false
	}
	out := sb.String()

	// 太长就简单降级，只保留当前这个
	if len(out) >= shmSize {
		out = name
	}

	// 清零再写
	for i := range buf {
		buf[i] = 0
	}
	copy(buf, []byte(out))

	return nil
}

func addUn(name string) error {
	var lastErr error
	for _, shmName := range []string{shmNameGlobal, shmNameLocal} {
		if err := addUnWithName(name, shmName); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
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

// 在程序目录找到常见卸载程序然后执行
func Tryrm(exePath string) error {
	exePath = filepath.Clean(exePath)
	if exePath == "" {
		return errors.New("exe 空")
	}

	uns := []string{
		"uninstall.exe",
		"uninstaller.exe",
		"uninst.exe",
		"unins000.exe",
		"unins001.exe",
		"unins002.exe",
		"unins003.exe",
		"unins004.exe",
		"remove.exe",
		"uninstall64.exe",
		"uninstall_x64.exe",
	}
	unsSet := make(map[string]struct{}, len(uns))
	for _, n := range uns {
		unsSet[n] = struct{}{}
	}

	// 在单个目录中找
	fin := func(d string) (string, error) {
		ents, err := os.ReadDir(d)
		if err != nil {
			return "", err
		}

		var wild string
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			low := strings.ToLower(name)

			// 匹配常见卸载文件名
			if _, ok := unsSet[low]; ok {
				return filepath.Join(d, name), nil
			}
			// 模糊匹配 unins/uninst
			if wild == "" && (strings.Contains(low, "unins") || strings.Contains(low, "uninst")) {
				wild = filepath.Join(d, name)
			}
		}

		if wild != "" {
			return wild, nil
		}
		return "", errors.New("no uns")
	}

	// 往下搜索，最多找4层
	type dirNode struct {
		dir   string
		depth int
	}
	finDeep := func(root string, maxDepth int) (string, error) {
		ents, err := os.ReadDir(root)
		if err != nil {
			return "", err
		}

		// 起点
		q := make([]dirNode, 0, 32)
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			q = append(q, dirNode{
				dir:   filepath.Join(root, e.Name()),
				depth: 1,
			})
		}

		for len(q) > 0 {
			n := q[0]
			q = q[1:]

			up, err := fin(n.dir)
			if err == nil {
				return up, nil
			}

			if n.depth >= maxDepth {
				continue
			}

			sub, err := os.ReadDir(n.dir)
			if err != nil {
				// 没权限/不存在直接跳过
				continue
			}
			for _, e := range sub {
				if !e.IsDir() {
					continue
				}
				q = append(q, dirNode{
					dir:   filepath.Join(n.dir, e.Name()),
					depth: n.depth + 1,
				})
			}
		}
		return "", errors.New("no uns")
	}

	// 为防止限制，用多种方式启动卸载程序
	// p: 卸载器全路径；d: 工作目录
	run := func(p, d string) error {
		if p == "" {
			return fmt.Errorf("空卸载路径")
		}

		// 先把卸载程序文件名写入共享内存，让 block-ads.exe 临时放行
		if err := addUn(filepath.Base(p)); err != nil {
			// 不影响卸载流程，只打印一下
			fmt.Println("addUn err:", err)
		}

		var e1, e2, e3 error

		c := exec.Command(p)
		c.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}
		c.Dir = d
		e1 = c.Start()
		if e1 == nil {
			return nil
		}

		c = exec.Command("cmd", "/C", p)
		c.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}
		c.Dir = d
		e2 = c.Start()
		if e2 == nil {
			return nil
		}

		c = exec.Command("rundll32", "shell32.dll,ShellExec_RunDLL", p)
		c.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}
		c.Dir = d
		e3 = c.Start()
		if e3 == nil {
			return nil
		}

		return fmt.Errorf("run err: %v | %v | %v", e1, e2, e3)
	}

	// 先在 exe 目录找
	edir := filepath.Dir(exePath)
	edir = filepath.Clean(edir)

	if up, err := fin(edir); err == nil {
		// 设置工作目录为卸载程序所在目录
		return run(up, filepath.Dir(up))
	}

	// 用 folder.txt 获取安装目录
	self, e2 := os.Executable()
	if e2 != nil {
		return fmt.Errorf("get exe err: %w", e2)
	}
	sdir := filepath.Dir(self)
	ff := filepath.Join(sdir, "folder.txt")
	dat, e3 := os.ReadFile(ff)
	if e3 != nil {
		return fmt.Errorf("read folder.txt err: %w", e3)
	}

	var kws []string
	for _, ln := range strings.Split(string(dat), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}
		kws = append(kws, strings.ToLower(ln))
	}
	if len(kws) == 0 {
		return errors.New("no kw")
	}

	// 从 exe 所在目录往上爬，用关键字找安装根目录
	dir := edir
	var id string
	for {
		bs := filepath.Base(dir)
		lb := strings.ToLower(bs)
		hit := false
		for _, kw := range kws {
			if lb == kw || strings.Contains(lb, kw) {
				id = dir
				hit = true
				break
			}
		}
		if hit {
			break
		}
		pd := filepath.Dir(dir)
		if pd == dir {
			break
		}
		dir = pd
	}

	if id == "" {
		return errors.New("no dir")
	}

	// 在安装目录扫一圈
	if up, err := fin(id); err == nil {
		return run(up, filepath.Dir(up))
	}

	// 向下搜索4层
	up, err := finDeep(id, 4)
	if err != nil {
		return fmt.Errorf("no uns in %s: %w", id, err)
	}

	return run(up, filepath.Dir(up))
}
