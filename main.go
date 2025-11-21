package main

import (
	"block-ads/utils"
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bi-zone/etw"
	"golang.org/x/sys/windows"
)

// dll
var (
	dllOnce sync.Once
	hasDll  bool
	dllFun  *windows.LazyProc
)

// 扫描配置
var (
	fShort = flag.Bool("shortcircuit", true, "folder命中后是否短路(默认 true)")
	fWork  = flag.Int("workers", runtime.NumCPU(), "启动扫描线程数")
)

// 日志
var (
	appDir string
	logDir string //日志目录
)

// 黑名单 + 白名单
type blkSet struct {
	Signers      map[string]struct{} // sign.txt       黑名单签名
	Folders      map[string]struct{} // folder.txt     黑名单目录
	White        map[string]struct{} // Wfolder.txt    白名单目录
	WhiteSigners map[string]struct{} // Wsign.txt      白名单签名
}

var (
	winDirOnce  sync.Once
	winDirLower string

	// txt缓存
	blkMu   sync.RWMutex
	blkLast time.Time
	blkData *blkSet
)

// 签名缓存
var (
	signCache    = make(map[string]string)
	signCacheMu  sync.RWMutex
	signCacheMax = 5000 // 最大缓存条数
)

// 获取当前规则
func curBlk() *blkSet {
	// 读锁：优先缓存
	blkMu.RLock()
	if blkData != nil && time.Since(blkLast) < 60*time.Second { // 缓存有效期 60 秒
		defer blkMu.RUnlock()
		return blkData
	}
	blkMu.RUnlock()

	// 写锁：刷新
	blkMu.Lock()
	defer blkMu.Unlock()

	if blkData != nil && time.Since(blkLast) < 3*time.Second {
		return blkData
	}

	if appDir == "" {
		exe, _ := os.Executable()
		appDir = filepath.Dir(exe)
	}

	// 读取所有txt
	bl, err := readBlk(appDir)
	if err != nil {
		if blkData != nil {
			return blkData
		}
		return &blkSet{
			Signers:      map[string]struct{}{},
			Folders:      map[string]struct{}{},
			White:        map[string]struct{}{},
			WhiteSigners: map[string]struct{}{},
		}
	}

	blkData = bl
	blkLast = time.Now()
	return blkData
}

// 取签名+缓存
func getSignC(path string) string {
	if path == "" {
		return ""
	}
	//检查缓存
	signCacheMu.RLock()
	if s, ok := signCache[path]; ok {
		signCacheMu.RUnlock()
		return s
	}
	signCacheMu.RUnlock()

	// 没缓存的情况下获取签名
	s, err := utils.GetSignName(path)
	if err != nil {
		s = ""
	}

	// 写入缓存
	signCacheMu.Lock()
	if len(signCache) >= signCacheMax {
		// map满了就清空
		signCache = make(map[string]string)
	}
	signCache[path] = s
	signCacheMu.Unlock()

	return s
}

// 跳过卸载程序
func skipUn(fullPath string) bool {
	if !isExe(fullPath) {
		return false
	}
	base := strings.ToLower(strings.TrimSpace(filepath.Base(fullPath)))
	if base == "" {
		return false
	}

	// 常见卸载程序
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
	for _, n := range uns {
		if base == n {
			return true
		}
	}

	// 模糊匹配
	if strings.Contains(base, "unins") || strings.Contains(base, "uninst") {
		return true
	}

	// 结合安装目录关键字再找一圈
	dir := filepath.Dir(fullPath)
	if dir == "" || dir == "." {
		return false
	}

	type dirNode struct {
		dir   string
		depth int
	}

	walk := func(root string, maxDepth int) bool {
		ents, err := os.ReadDir(root)
		if err != nil {
			return false
		}

		q := make([]dirNode, 0, 32)
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			q = append(q, dirNode{dir: filepath.Join(root, e.Name()), depth: 1})
		}

		for len(q) > 0 {
			n := q[0]
			q = q[1:]

			ents2, err := os.ReadDir(n.dir)
			if err != nil {
				continue
			}
			for _, e := range ents2 {
				if e.IsDir() {
					if n.depth < maxDepth {
						q = append(q, dirNode{dir: filepath.Join(n.dir, e.Name()), depth: n.depth + 1})
					}
					continue
				}
				low := strings.ToLower(e.Name())
				for _, u := range uns {
					if low == u {
						return true
					}
				}
				if strings.Contains(low, "unins") || strings.Contains(low, "uninst") {
					return true
				}
			}
		}
		return false
	}

	// folder.txt 关键字定位
	self, err := os.Executable()
	if err != nil {
		return false
	}
	fdir := filepath.Dir(self)
	ff := filepath.Join(fdir, "folder.txt")
	dat, err := os.ReadFile(ff)
	if err != nil {
		return false
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
		return false
	}

	// 从进程目录往上找关键字目录
	root := dir
	var hit string
	for {
		b := filepath.Base(root)
		lb := strings.ToLower(b)
		match := false
		for _, kw := range kws {
			if lb == kw || strings.Contains(lb, kw) {
				match = true
				break
			}
		}
		if match {
			hit = root
			break
		}
		p := filepath.Dir(root)
		if p == root {
			break
		}
		root = p
	}
	if hit == "" {
		return false
	}

	if walk(hit, 4) {
		return true
	}

	// 在当前目录再扫一圈
	return walk(dir, 1)
}

func readBlk(baseDir string) (*blkSet, error) {
	signSet, _ := readSet(filepath.Join(baseDir, "sign.txt"))
	foldSet, _ := readSet(filepath.Join(baseDir, "folder.txt"))
	whiteFoldSet, _ := readSet(filepath.Join(baseDir, "Wfolder.txt"))
	whiteSignSet, _ := readSet(filepath.Join(baseDir, "Wsign.txt"))
	return &blkSet{
		Signers:      signSet,
		Folders:      foldSet,
		White:        whiteFoldSet,
		WhiteSigners: whiteSignSet,
	}, nil
}

func readSet(path string) (map[string]struct{}, error) {
	out := make(map[string]struct{})

	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		out[line] = struct{}{}
	}
	return out, sc.Err()
}

func windowsDirLower() string {
	winDirOnce.Do(func() {
		if sysDir, err := windows.GetSystemDirectory(); err == nil && sysDir != "" {
			//取上层目录
			winDirLower = strings.ToLower(filepath.Dir(sysDir))
			return
		}
		if w := os.Getenv("WINDIR"); w != "" {
			winDirLower = strings.ToLower(w)
		} else {
			winDirLower = `c:\windows`
		}
	})
	return winDirLower
}

// 初始化dll,预留一个用来调用驱动级结束进程
func initDll() {
	dllOnce.Do(func() {
		dir := appDir
		if dir == "" {
			if ex, err := os.Executable(); err == nil {
				dir = filepath.Dir(ex)
				appDir = dir
			}
		}
		if dir == "" {
			return
		}

		p := filepath.Join(dir, "process.dll")
		if _, err := os.Stat(p); err != nil {
			return
		}

		d := windows.NewLazyDLL(p)
		dllFun = d.NewProc("getout")
		hasDll = true
	})
}

// 预留一个dll用来后期调用驱动级dll
func doKill(pid uint32) {
	initDll()

	if hasDll && dllFun != nil {
		_, _, _ = dllFun.Call(uintptr(pid))
		return
	}

	//没有dll或者没拿到函数就utils.Kill
	utils.Kill(int(pid))
}

func isSysDesk(pid uint32, fullPath string) bool {
	//Idle/System
	if pid == 0 || pid == 4 {
		return true
	}
	//Windows目录
	lp := strings.ToLower(strings.TrimSpace(fullPath))
	if lp == "" {
		return false
	}
	return strings.HasPrefix(lp, windowsDirLower()+`\\`) || lp == windowsDirLower()
}

func splitPath(p string) []string {
	p = strings.ReplaceAll(p, "/", `\`)
	p = strings.Trim(p, " \t\r\n\\")
	if p == "" {
		return nil
	}
	segs := strings.Split(p, `\`)
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// 目录黑名单
func hitFolder(fullPath string, folderSet map[string]struct{}) (bool, string) {
	if len(folderSet) == 0 {
		return false, ""
	}
	for _, seg := range splitPath(fullPath) {
		if _, ok := folderSet[seg]; ok {
			return true, seg
		}
	}
	return false, ""
}

// 签名黑名单
func hitSign(signer string, signSet map[string]struct{}) (bool, string) {
	if len(signSet) == 0 || signer == "" {
		return false, ""
	}
	low := strings.ToLower(strings.TrimSpace(signer))
	for blk := range signSet {
		blkLow := strings.ToLower(strings.TrimSpace(blk))
		if low == blkLow || strings.Contains(low, blkLow) || strings.Contains(blkLow, low) {
			return true, blk
		}
	}
	return false, ""
}

// 白名单
func inWhite(fullPath string, white map[string]struct{}) bool {
	if len(white) == 0 {
		return false
	}
	dir := filepath.Dir(fullPath)
	for _, seg := range splitPath(dir) {
		if _, ok := white[seg]; ok {
			return true
		}
	}
	return false
}

// 处理NT路径
func fixPath(pid uint32, maybePath string) string {
	lp := strings.ToLower(maybePath)
	if strings.Contains(lp, ":\\") && strings.HasSuffix(lp, ".exe") {
		return maybePath
	}
	if p, err := procPath(pid); err == nil && p != "" {
		return p
	}
	return maybePath
}

func procPath(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func isExe(p string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(p)), ".exe")
}

func pickImg(props map[string]interface{}) string {
	keys := []string{
		"ImageName", "ImageFileName", "FullImageName", "FileName", "Image", "ProcessName",
	}
	for _, k := range keys {
		if v, ok := props[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
			if b, ok := v.([]byte); ok && len(b) > 0 {
				return string(b)
			}
		}
	}
	return ""
}

func getU32(props map[string]interface{}, keys ...string) (uint32, bool) {
	for _, k := range keys {
		if v, ok := props[k]; ok && v != nil {
			switch t := v.(type) {
			case uint32:
				return t, true
			case uint64:
				return uint32(t), true
			case int:
				return uint32(t), true
			case int32:
				return uint32(t), true
			case int64:
				return uint32(t), true
			case float64:
				return uint32(t), true
			case string:
				if n, err := strconv.ParseUint(strings.TrimSpace(t), 10, 32); err == nil {
					return uint32(n), true
				}
			case []byte:
				if n, err := strconv.ParseUint(strings.TrimSpace(string(t)), 10, 32); err == nil {
					return uint32(n), true
				}
			}
		}
	}
	return 0, false
}

type hitInfo struct {
	Kind string
	Text string
}

// 跟黑名单比对路径/签名
func chkHit(fullPath string, bl *blkSet, allowShort bool) (hits []hitInfo, signer string) {
	// 目录黑名单
	if ok, seg := hitFolder(fullPath, bl.Folders); ok {
		hits = append(hits, hitInfo{Kind: "folder", Text: seg})
		if allowShort {
			return hits, ""
		}
	}

	// 签名黑名单=0，签名白名单=0，跳过
	if len(bl.Signers) == 0 && len(bl.WhiteSigners) == 0 {
		return hits, ""
	}

	// 获取签名
	signer = getSignC(fullPath)
	if signer == "" {
		return hits, ""
	}

	// 先检查签名白名单
	if len(bl.WhiteSigners) > 0 {
		if ok, _ := hitSign(signer, bl.WhiteSigners); ok {
			return hits, signer
		}
	}

	// 再检查签名黑名单
	if len(bl.Signers) > 0 {
		if ok, which := hitSign(signer, bl.Signers); ok {
			hits = append(hits, hitInfo{Kind: "sign", Text: which})
		}
	}

	return hits, signer
}

// 写日志
func writeLog(kind, val, img, src string) error {
	if appDir == "" {
		exe, _ := os.Executable()
		appDir = filepath.Dir(exe)
	}
	if logDir == "" {
		logDir = filepath.Join(appDir, "log")
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	now := time.Now()
	day := now.Format("2006-01-02")
	time := now.Format("2006-01-02 15:04:05")

	logPath := filepath.Join(logDir, day+".log")

	line := fmt.Sprintf(
		"%s--%s--%s--%s--%s\n",
		time, kind, val, src, img,
	)

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	return err
}

// 结束并记录
func fuck(pid, ppid uint32, img, signer string, hits []hitInfo, src string) {
	if len(hits) == 0 {
		return
	}

	doKill(pid)

	fmt.Printf("[%s] image=\"%s\" signer=\"%s\" reason=[%s] ppid=[%s] \n",
		src, img, signer, ppid)

	//记录日志
	mainKind := hits[0].Kind
	mainText := ""
	if mainKind == "sign" {
		if signer != "" {
			mainText = signer
		} else {
			mainText = hits[0].Text
		}
	} else {
		mainText = hits[0].Text
	}

	if err := writeLog(mainKind, mainText, img, src); err != nil {
		log.Printf("[ERR] 写日志失败: %v", err)
	}
}

func procHit(pid, ppid uint32, fullPath, src string, bl *blkSet, short bool) {
	if !isExe(fullPath) {
		return
	}
	if isSysDesk(pid, fullPath) {
		return
	}
	// UI 发过来的卸载程序在这里直接跳过
	if skipUn(fullPath) {
		return
	}

	//拿缓存
	bl = curBlk()

	//跳过白名单
	if inWhite(fullPath, bl.White) {
		return
	}
	// 跟黑名单比对
	hits, signer := chkHit(fullPath, bl, short && len(bl.Folders) > 0)
	if len(hits) == 0 {
		return
	}
	//干掉黑名单
	fuck(pid, ppid, fullPath, signer, hits, src)
}

// 扫描
func scanNow(bl *blkSet, short bool, workers int) {
	pids := utils.Listpid()
	if len(pids) == 0 {
		return
	}

	self := uint32(os.Getpid())
	jobCh := make(chan uint32, 256)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for pid := range jobCh {
			if pid == 0 || pid == 4 || pid == self {
				continue
			}
			fullPath, err := procPath(pid)
			if err != nil || fullPath == "" {
				continue
			}

			procHit(pid, 0, fullPath, "SCAN-HIT", bl, short)
		}
	}

	if workers <= 0 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}
	for _, pid := range pids {
		jobCh <- pid
	}
	close(jobCh)
	wg.Wait()
}

// 启动ETW
func runETW(bl *blkSet, short bool) (*etw.Session, *sync.WaitGroup, error) {
	//Microsoft-Windows-Kernel-Process
	guid, _ := windows.GUIDFromString("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
	session, err := etw.NewSession(guid, etw.WithName("blockads-ProcMon-ETW"))
	//提高鲁棒性
	if err != nil {
		etw.KillSession("blockads-ProcMon-ETW")
		session, err = etw.NewSession(guid, etw.WithName("blockads-ProcMon-ETW"))
		if err != nil {
			etw.KillSession("blockads-ProcMon-ETW")
			session, err = etw.NewSession(guid, etw.WithName("blockads-ProcMon-ETW1"))
			if err != nil {
				etw.KillSession("blockads-ProcMon-ETW1")
				return nil, nil, fmt.Errorf("创建 ETW 会话失败: %v", err)
			}
		}
	}

	cb := func(e *etw.Event) {
		if e == nil || e.Header.ID != 1 { //只要进程创建事件
			return
		}
		props, err := e.EventProperties()
		if err != nil {
			return
		}

		//从payload取PID，不行再header
		pid, ok := getU32(props, "ProcessID", "ProcessId", "PID")
		if !ok {
			pid = e.Header.ProcessID
		}
		ppid, _ := getU32(props, "ParentProcessID", "ParentProcessId", "ParentId", "ParentID")

		img := fixPath(pid, pickImg(props))
		if img == "" {
			return
		}

		procHit(pid, ppid, img, "ETW-HIT", bl, short)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := session.Process(cb); err != nil {
			log.Printf("[ERR] 处理 ETW 事件出错: %v", err)
		}
	}()
	return session, &wg, nil
}

func run() error {
	flag.Parse()
	exe, _ := os.Executable()
	appDir = filepath.Dir(exe)
	logDir = filepath.Join(appDir, "log")
	bl, _ := readBlk(appDir)

	if len(bl.Signers) == 0 {
		log.Printf("[WARN] sign.txt 缺失或为空")
	}
	if len(bl.Folders) == 0 {
		log.Printf("[WARN] folder.txt 缺失或为空")
	}
	if len(bl.White) == 0 {
		log.Printf("[INFO] Wfolder.txt 缺失或为空")
	}
	if len(bl.WhiteSigners) == 0 {
		log.Printf("[INFO] Wsign.txt 缺失或为空")
	}

	// 初始化txt缓存
	blkMu.Lock()
	blkData = bl
	blkLast = time.Now()
	blkMu.Unlock()

	// 并发扫描
	go scanNow(bl, *fShort, *fWork)

	//runETW
	session, wg, err := runETW(bl, *fShort)
	if err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	if err := session.Close(); err != nil {
		log.Printf("[ERR] 关闭 ETW 会话失败: %v", err)
	}
	wg.Wait()
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}
