package main

import (
	"block-ads/utils"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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
	fWork = flag.Int("workers", runtime.NumCPU(), "启动扫描线程数")
)

// config.json（只存弹窗开关）
type Config struct {
	Notify struct {
		Enabled bool `json:"enabled"`
	} `json:"notify"`
}

var (
	cfgMu   sync.RWMutex
	cfg     Config
	cfgPath string

	// 弹窗并发限制：ETW高频命中时避免创建过多OS线程
	notifySem = make(chan struct{}, 2)

	// 写白名单/配置文件互斥（避免并发写乱）
	ioMu sync.Mutex
)

// 日志
var (
	appDir string
	logDir string // 日志目录
)

// 黑名单 + 白名单
//
// 顺序约定：
//  1. 白名单目录
//  2. 白名单签名
//  3. 黑名单目录
//  4. 黑名单签名
//
// 注意：Windows 路径大小写不敏感，目录集合统一用小写存储/匹配。
type blkSet struct {
	Signers      map[string]struct{} // sign.txt       黑名单签名
	Folders      map[string]struct{} // folder.txt     黑名单目录(小写)
	White        map[string]struct{} // Wfolder.txt    白名单目录(小写)
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

func notifyEnabled() bool {
	cfgMu.RLock()
	en := cfg.Notify.Enabled
	cfgMu.RUnlock()
	return en
}

func setNotifyEnabled(en bool) {
	cfgMu.Lock()
	cfg.Notify.Enabled = en
	cur := cfg
	cfgMu.Unlock()
	_ = saveConfig(cur)
}

func loadConfig() {
	cfgMu.Lock()
	defer cfgMu.Unlock()

	cfg = Config{}
	cfg.Notify.Enabled = true

	b, err := os.ReadFile(cfgPath)
	if err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &cfg)
		if cfg.Notify.Enabled == false {
			// ok
		}
	}

	// 确保落盘（文件不存在/损坏时写默认值）
	_ = saveConfig(cfg)
}

func saveConfig(c Config) error {
	ioMu.Lock()
	defer ioMu.Unlock()

	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return atomicWriteFile(cfgPath, b)
}

func atomicWriteFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	// Windows 上 Rename 覆盖可能失败：先删再换
	_ = os.Remove(path)
	return os.Rename(tmp, path)
}

// 获取当前规则
func curBlk() *blkSet {
	// 读锁：优先缓存
	blkMu.RLock()
	if blkData != nil && time.Since(blkLast) < 60*time.Second {
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

	bl, err := readBlk(appDir)
	if err != nil {
		if blkData != nil {
			return blkData
		}
		blkData = &blkSet{
			Signers:      map[string]struct{}{},
			Folders:      map[string]struct{}{},
			White:        map[string]struct{}{},
			WhiteSigners: map[string]struct{}{},
		}
		blkLast = time.Now()
		return blkData
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

	signCacheMu.RLock()
	if s, ok := signCache[path]; ok {
		signCacheMu.RUnlock()
		return s
	}
	signCacheMu.RUnlock()

	s, err := utils.GetSignName(path)
	if err != nil {
		s = ""
	}

	signCacheMu.Lock()
	if len(signCache) >= signCacheMax {
		signCache = make(map[string]string)
	}
	signCache[path] = s
	signCacheMu.Unlock()
	return s
}

// 跳过卸载程序
func skipUn(fullPath string) bool {
	if !utils.IsExe(fullPath) {
		return false
	}

	base := strings.ToLower(strings.TrimSpace(filepath.Base(fullPath)))
	if base == "" {
		return false
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
	for _, n := range uns {
		if base == n {
			return true
		}
	}
	return strings.Contains(base, "unins") || strings.Contains(base, "uninst")
}

func readBlk(baseDir string) (*blkSet, error) {
	signSet, _ := readSet(filepath.Join(baseDir, "sign.txt"), false)
	foldSet, _ := readSet(filepath.Join(baseDir, "folder.txt"), true)
	whiteFoldSet, _ := readSet(filepath.Join(baseDir, "Wfolder.txt"), true)
	whiteSignSet, _ := readSet(filepath.Join(baseDir, "Wsign.txt"), false)
	return &blkSet{
		Signers:      signSet,
		Folders:      foldSet,
		White:        whiteFoldSet,
		WhiteSigners: whiteSignSet,
	}, nil
}

func readSet(path string, lower bool) (map[string]struct{}, error) {
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
		if lower {
			line = strings.ToLower(strings.ReplaceAll(line, "/", `\\`))
		}
		out[line] = struct{}{}
	}
	return out, sc.Err()
}

func windowsDirLower() string {
	winDirOnce.Do(func() {
		if sysDir, err := windows.GetSystemDirectory(); err == nil && sysDir != "" {
			winDirLower = strings.ToLower(filepath.Dir(sysDir))
			return
		}
		if w := os.Getenv("WINDIR"); w != "" {
			winDirLower = strings.ToLower(w)
		} else {
			winDirLower = `c:\\windows`
		}
	})
	return winDirLower
}

// 初始化dll,预留一个用来调用驱动级结束进程
func initDll() {
	dllOnce.Do(func() {
		p := filepath.Join(appDir, "process.dll")
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
	utils.Kill(int(pid))
}

func isSysDesk(pid uint32, fullPath string) bool {
	// Idle/System
	if pid == 0 || pid == 4 {
		return true
	}
	// Windows目录
	lp := strings.ToLower(strings.TrimSpace(fullPath))
	if lp == "" {
		return false
	}
	wd := windowsDirLower() + `\\`
	return strings.HasPrefix(lp, wd) || lp == strings.TrimSuffix(wd, `\\`)
}

func normDir(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "/", `\\`)
	p = strings.ToLower(p)
	return p
}

// 目录命中
func hitFolder(fullPath string, folderSet map[string]struct{}) (bool, string) {
	if len(folderSet) == 0 {
		return false, ""
	}
	for _, seg := range utils.SplitPath(fullPath) {
		seg = normDir(seg)
		if _, ok := folderSet[seg]; ok {
			return true, seg
		}
	}
	return false, ""
}

// 签名命中
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

// 白名单目录命中
func inWhite(fullPath string, white map[string]struct{}) bool {
	if len(white) == 0 {
		return false
	}
	dir := normDir(filepath.Dir(fullPath))
	for _, seg := range utils.SplitPath(dir) {
		seg = normDir(seg)
		if _, ok := white[seg]; ok {
			return true
		}
	}
	return false
}

// 处理NT路径
func fixPath(pid uint32, maybePath string) string {
	translated := utils.NToWin(maybePath)
	lp := strings.ToLower(translated)
	if strings.Contains(lp, ":\\") && strings.HasSuffix(lp, ".exe") {
		return translated
	}
	if p, err := utils.ProcPath(pid); err == nil && p != "" {
		return utils.NToWin(p)
	}
	return translated
}

func pickImg(props map[string]interface{}) string {
	keys := []string{"ImageName", "ImageFileName", "FullImageName", "FileName", "Image", "ProcessName"}
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

type hitInfo struct {
	Kind string
	Text string
}

// 仅检查黑名单：黑目录 -> 黑签名
func chkBlack(fullPath, signer string, bl *blkSet) (hits []hitInfo) {
	if ok, seg := hitFolder(fullPath, bl.Folders); ok {
		hits = append(hits, hitInfo{Kind: "folder", Text: seg})
	}
	if signer != "" {
		if ok, which := hitSign(signer, bl.Signers); ok {
			hits = append(hits, hitInfo{Kind: "sign", Text: which})
		}
	}
	return hits
}

// 写日志
func writeLog(kind, val, img, src string) error {
	if logDir == "" {
		logDir = filepath.Join(appDir, "log")
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	now := time.Now()
	day := now.Format("2006-01-02")
	ts := now.Format("2006-01-02 15:04:05")
	logPath := filepath.Join(logDir, day+".log")
	line := fmt.Sprintf("%s--%s--%s--%s--%s\n", ts, kind, val, src, img)

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

func isProgram(dir string) bool {
	d := normDir(dir)
	if len(d) == 2 && d[1] == ':' {
		return true
	}
	if len(d) == 3 && d[1] == ':' && d[2] == '\\' {
		return true
	}
	if len(d) < 3 || d[1] != ':' {
		return false
	}
	drive := d[:2]
	pfx := []string{
		drive + `\\program files`,
		drive + `\\program files (x86)`,
		drive + `\\programdata`,
	}
	for _, pre := range pfx {
		if strings.HasPrefix(d, pre) {
			return true
		}
	}
	return false
}

func cloneSet(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in)+1)
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

func appendUnique(path string, val string, exists func() bool) {
	val = strings.TrimSpace(val)
	if val == "" || exists() {
		return
	}

	ioMu.Lock()
	defer ioMu.Unlock()

	// 再检查一次，避免并发重复写
	if exists() {
		return
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	_, _ = f.WriteString(val + "\n")
	_ = f.Close()
}

// 加入白名单：默认签名 + 所在目录；如果目录是分区根/Program* 则只加签名。
func addWhitelist(fullPath, signer string) {
	bl := curBlk()
	dir := normDir(filepath.Dir(fullPath))
	signer = strings.TrimSpace(signer)
	if signer == "" {
		// 没有签名时尝试重新取一次
		signer = getSignC(fullPath)
	}

	specialDir := isProgram(dir)
	wFolderPath := filepath.Join(appDir, "Wfolder.txt")
	wSignPath := filepath.Join(appDir, "Wsign.txt")

	appendUnique(wSignPath, signer, func() bool {
		if signer == "" {
			return true
		}
		ok, _ := hitSign(signer, bl.WhiteSigners)
		return ok
	})

	if !specialDir {
		appendUnique(wFolderPath, dir, func() bool {
			if dir == "" {
				return true
			}
			for _, seg := range utils.SplitPath(dir) {
				if _, ok := bl.White[normDir(seg)]; ok {
					return true
				}
			}
			return false
		})
	}

	// 立刻更新内存缓存
	blkMu.Lock()
	old := blkData
	if old == nil {
		old = bl
	}
	neu := &blkSet{
		Signers:      old.Signers,
		Folders:      old.Folders,
		White:        old.White,
		WhiteSigners: old.WhiteSigners,
	}
	if signer != "" {
		if ok, _ := hitSign(signer, neu.WhiteSigners); !ok {
			m := cloneSet(neu.WhiteSigners)
			m[signer] = struct{}{}
			neu.WhiteSigners = m
		}
	}
	if !specialDir && dir != "" {
		if _, ok := neu.White[dir]; !ok {
			m := cloneSet(neu.White)
			m[dir] = struct{}{}
			neu.White = m
		}
	}
	blkData = neu
	blkLast = time.Now()
	blkMu.Unlock()
}

func reasonText(hits []hitInfo) string {
	if len(hits) == 0 {
		return ""
	}
	switch hits[0].Kind {
	case "folder":
		return "命中黑名单目录"
	case "sign":
		return "命中黑名单签名"
	default:
		return "命中黑名单"
	}
}

func showNotify(fullPath, signer string, hits []hitInfo) {
	if !notifyEnabled() {
		return
	}

	// 并发限流：避免ETW高频命中导致创建大量OS线程
	select {
	case notifySem <- struct{}{}:
		// ok
	default:
		return
	}

	go func() {
		defer func() { <-notifySem }()

		icon := utils.GetIcon(fullPath, false)
		sub := fullPath
		if signer != "" {
			sub = signer + "\n" + fullPath
		}

		ShowNotification(NotifyConfig{
			Title:      "拦截提示",
			TitleIcon:  icon,
			Message:    reasonText(hits),
			SubMessage: sub,
			Icon:       icon,
			Timeout:    12,
			OnIgnore: func() {
				setNotifyEnabled(false)
			},
			OnWhitelist: func() {
				addWhitelist(fullPath, signer)
			},
		})
	}()
}

// 结束并记录
func fuck(pid, ppid uint32, img, signer string, hits []hitInfo, src string) {
	if len(hits) == 0 {
		return
	}

	doKill(pid)

	// 记录日志
	mainKind := hits[0].Kind
	mainText := hits[0].Text
	if mainKind == "sign" && signer != "" {
		mainText = signer
	}
	if err := writeLog(mainKind, mainText, img, src); err != nil {
		log.Printf("[ERR] 写日志失败: %v", err)
	}

	// 弹窗
	showNotify(img, signer, hits)

	fmt.Printf("[%s] pid=%d ppid=%d image=%q signer=%q hits=%v\n", src, pid, ppid, img, signer, hits)
}

func procHit(pid, ppid uint32, fullPath, src string) {
	fullPath = utils.NToWin(fullPath)
	if !utils.IsExe(fullPath) {
		return
	}
	if isSysDesk(pid, fullPath) {
		return
	}
	if skipUn(fullPath) {
		return
	}

	bl := curBlk()

	// 1) 白名单目录
	if inWhite(fullPath, bl.White) {
		return
	}

	// 2) 白名单签名
	signer := ""
	if len(bl.WhiteSigners) > 0 || len(bl.Signers) > 0 {
		signer = getSignC(fullPath)
		if ok, _ := hitSign(signer, bl.WhiteSigners); ok {
			return
		}
	}

	// 3) 黑名单目录 4) 黑名单签名
	hits := chkBlack(fullPath, signer, bl)
	if len(hits) == 0 {
		return
	}
	fuck(pid, ppid, fullPath, signer, hits, src)
}

// 扫描
func scanNow(workers int) {
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
			fullPath, err := utils.ProcPath(pid)
			if err != nil || fullPath == "" {
				continue
			}
			procHit(pid, 0, fullPath, "SCAN-HIT")
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
func runETW() (*etw.Session, *sync.WaitGroup, error) {
	// Microsoft-Windows-Kernel-Process
	guid, _ := windows.GUIDFromString("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
	session, err := etw.NewSession(guid, etw.WithName("blockads-ProcMon-ETW"))
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
		if e == nil || e.Header.ID != 1 { // 只要进程创建事件
			return
		}
		props, err := e.EventProperties()
		if err != nil {
			return
		}

		pid, ok := utils.GetU32(props, "ProcessID", "ProcessId", "PID")
		if !ok {
			pid = e.Header.ProcessID
		}
		ppid, _ := utils.GetU32(props, "ParentProcessID", "ParentProcessId", "ParentId", "ParentID")

		img := fixPath(pid, pickImg(props))
		if img == "" {
			return
		}
		procHit(pid, ppid, img, "ETW-HIT")
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
	cfgPath = filepath.Join(appDir, "config.json")
	loadConfig()

	bl, _ := readBlk(appDir)
	if len(bl.Signers) == 0 {
		log.Printf("[WARN] sign.txt 缺失或为空")
	}
	if len(bl.Folders) == 0 {
		log.Printf("[WARN] folder.txt 缺失或为空")
	}

	blkMu.Lock()
	blkData = bl
	blkLast = time.Now()
	blkMu.Unlock()

	go scanNow(*fWork)

	session, wg, err := runETW()
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
	fmt.Println("正在启动")
	if err := run(); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}
