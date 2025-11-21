package main

import (
	"block-ads-ui/utils"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bi-zone/etw"
	webview "github.com/webview/webview_go"
	"golang.org/x/sys/windows"
	reg "golang.org/x/sys/windows/registry"
)

var lstMap = map[string]string{
	"sign":      "sign.txt",
	"folder":    "folder.txt",
	"whitelist": "Wfoler.txt",
	"signWhite": "Wsign.txt",
}

const (
	noteFile = "note.txt"
	exeName  = "block-ads.exe"
	runName  = "BlockAds"
)

type appDat struct {
	mu  sync.Mutex
	dir string
	lst map[string][]string // key -> 行
	not map[string]string   // 文本 -> 注释
	lg  []string            // 日志
}

type uiSta struct {
	Adm  bool `json:"adm"`
	Run  bool `json:"run"`
	Boot bool `json:"boot"`
}

func newDat(dir string) *appDat {
	d := &appDat{
		dir: dir,
		lst: make(map[string][]string),
		not: make(map[string]string),
		lg:  nil,
	}
	for k, name := range lstMap {
		p := filepath.Join(dir, name)
		d.lst[k] = rdTxt(p)
	}
	d.not = rdNote(filepath.Join(dir, noteFile))
	d.lg = rdLog(dir)
	return d
}

func rdTxt(p string) []string {
	b, err := os.ReadFile(p)
	if err != nil {
		return []string{}
	}
	raw := strings.Split(string(b), "\n")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func rdNote(p string) map[string]string {
	out := make(map[string]string)
	b, err := os.ReadFile(p)
	if err != nil {
		return out
	}
	raw := strings.Split(string(b), "\n")
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		ps := strings.SplitN(v, "--", 2)
		key := strings.TrimSpace(ps[0])
		if key == "" {
			continue
		}
		val := ""
		if len(ps) > 1 {
			val = strings.TrimSpace(ps[1])
		}
		out[key] = val
	}
	return out
}

func rdLog(dir string) []string {
	now := time.Now()
	name := now.Format("2006-01-02") + ".log"
	p := filepath.Join(dir, "log", name)
	return rdTxt(p)
}

func (d *appDat) svLst(key string) error {
	name, ok := lstMap[key]
	if !ok {
		return nil
	}
	p := filepath.Join(d.dir, name)
	v := d.lst[key]

	var b strings.Builder
	for i, s := range v {
		b.WriteString(s)
		if i != len(v)-1 {
			b.WriteString("\n")
		}
	}
	return os.WriteFile(p, []byte(b.String()), 0644)
}

// 拷贝列表
func (d *appDat) all() map[string][]string {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make(map[string][]string, len(d.lst))
	for k, v := range d.lst {
		tmp := make([]string, len(v))
		copy(tmp, v)
		out[k] = tmp
	}
	return out
}

// 拷贝注释
func (d *appDat) note() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make(map[string]string, len(d.not))
	for k, v := range d.not {
		out[k] = v
	}
	return out
}

// 拷贝日志
func (d *appDat) log() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.lg = rdLog(d.dir)
	out := make([]string, len(d.lg))
	copy(out, d.lg)
	return out
}

func (d *appDat) addLn(key, txt string) ([]string, error) {
	txt = strings.TrimSpace(txt)
	if txt == "" {
		return nil, os.ErrInvalid
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	v := d.lst[key]
	v = append(v, txt)
	d.lst[key] = v

	if err := d.svLst(key); err != nil {
		return nil, err
	}

	out := make([]string, len(v))
	copy(out, v)
	return out, nil
}

func (d *appDat) delLn(key string, idx int) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	v := d.lst[key]
	if idx < 0 || idx >= len(v) {
		return nil, os.ErrInvalid
	}
	v = append(v[:idx], v[idx+1:]...)
	d.lst[key] = v

	if err := d.svLst(key); err != nil {
		return nil, err
	}

	out := make([]string, len(v))
	copy(out, v)
	return out, nil
}

// 从日志加入白名单：kind = "folder" / "sign"
func (d *appDat) addWhite(kind, val, path string) (bool, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	val = strings.TrimSpace(val)
	path = strings.TrimSpace(path)

	d.mu.Lock()
	defer d.mu.Unlock()

	switch kind {
	case "folder":
		return d.addWfolder(path)
	case "sign":
		return d.addWsign(val)
	default:
		return false, os.ErrInvalid
	}
}

// sign 模式：把签名加入Wsign.txt
func (d *appDat) addWsign(sign string) (bool, error) {
	if sign == "" {
		return false, os.ErrInvalid
	}
	wl := d.lst["signWhite"]

	// 已存在则不重复写入
	for _, s := range wl {
		if strings.EqualFold(s, sign) {
			return false, nil
		}
	}

	wl = append(wl, sign)
	d.lst["signWhite"] = wl
	if err := d.svLst("signWhite"); err != nil {
		return false, err
	}
	return true, nil
}

// folder 模式：从路径各级目录中找出与 folder.txt 行一致的名字，加入Wfoler.txt
// - 第一段和最后一段不匹配
// - 中间各级目录如果和 folder.txt 中某行相同（忽略大小写），加入白名单
func (d *appDat) addWfolder(path string) (bool, error) {
	if path == "" {
		return false, os.ErrInvalid
	}

	folders := d.lst["folder"]
	if len(folders) == 0 {
		return false, nil
	}
	wl := d.lst["whitelist"]

	// 预处理folder.txt
	fset := make(map[string]struct{})
	for _, ln := range folders {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}
		fset[strings.ToLower(ln)] = struct{}{}
	}

	// 现有白名单集合，用于去重
	wset := make(map[string]struct{})
	for _, ln := range wl {
		wset[strings.ToLower(strings.TrimSpace(ln))] = struct{}{}
	}

	// 统一分隔符
	p := strings.ReplaceAll(path, "/", `\`)
	var segs []string
	for _, part := range strings.Split(p, `\`) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		segs = append(segs, part)
	}
	if len(segs) <= 2 {
		// 只有根和文件名，没啥可匹配的
		return false, nil
	}

	added := false
	// 从第二段到倒数第二段
	for i := 1; i < len(segs)-1; i++ {
		name := strings.TrimSpace(segs[i])
		if name == "" {
			continue
		}
		low := strings.ToLower(name)

		if _, ok := fset[low]; !ok {
			continue
		}
		if _, ok := wset[low]; ok {
			// 已在白名单
			continue
		}

		wl = append(wl, name)
		wset[low] = struct{}{}
		added = true
	}

	if !added {
		return false, nil
	}

	d.lst["whitelist"] = wl
	if err := d.svLst("whitelist"); err != nil {
		return false, err
	}
	return true, nil
}

// 是否管理员
func chkAdm() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// 拦截进程是否运行
func chkRun() bool {
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq "+exeName)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), strings.ToLower(exeName))
}

// 检查开机自启
func hasBoot(exe string) bool {
	k, err := reg.OpenKey(reg.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		reg.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetStringValue(runName)
	if err != nil {
		return false
	}
	val = strings.Trim(val, `"`)
	exe = strings.Trim(exe, `"`)
	return strings.EqualFold(val, exe)
}

// 设置开机自启
func setBoot(exe string, on bool) error {
	k, _, err := reg.CreateKey(reg.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		reg.SET_VALUE|reg.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if on {
		val := `"` + exe + `"`
		return k.SetStringValue(runName, val)
	}

	err = k.DeleteValue(runName)
	if err == reg.ErrNotExist {
		return nil
	}
	return err
}

// 以管理员模式启动
func runExe(exe string) error {
	if _, err := os.Stat(exe); err != nil {
		return err
	}
	verb := "runas"
	dir := filepath.Dir(exe)

	vPtr, _ := syscall.UTF16PtrFromString(verb)
	ePtr, _ := syscall.UTF16PtrFromString(exe)
	dPtr, _ := syscall.UTF16PtrFromString(dir)
	var show int32 = 1

	return windows.ShellExecute(0, vPtr, ePtr, nil, dPtr, show)
}

// 用默认浏览器打开网页
func goUrl(u string) error {
	if u == "" {
		return nil
	}
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	return cmd.Start()
}

// 伪装安装火绒
func reghr() error {
	const sub = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HuorongSysdiag`
	const tgt = `C:\Program Files\Huorong\Sysdiag\bin\HipsMain.exe`

	k, _, err := reg.CreateKey(reg.LOCAL_MACHINE, sub, reg.QUERY_VALUE|reg.SET_VALUE)
	if err != nil {
		return fmt.Errorf("reghr: %w", err)
	}
	defer k.Close()

	v, _, err := k.GetStringValue("DisplayIcon")
	if err == nil {
		if strings.EqualFold(v, tgt) {
			return nil
		}
	}
	if err := k.SetStringValue("DisplayIcon", tgt); err != nil {
		return fmt.Errorf("reghr: %w", err)
	}
	return nil
}

// 伪装虚拟机
func regvm() error {
	const sub = `Applications\VMwareHostOpen.exe\shell\open\command`

	k, _, err := reg.CreateKey(reg.CLASSES_ROOT, sub, reg.SET_VALUE)
	if err != nil {
		return fmt.Errorf("regvm: %w", err)
	}
	defer k.Close()

	if err := k.SetStringValue("", "VMware"); err != nil {
		return fmt.Errorf("regvm: %w", err)
	}
	return nil
}

// 注册表伪装vip
func regvip() error {
	const sub = `SOFTWARE\LDSGameMaster\User`

	k, _, err := reg.CreateKey(reg.LOCAL_MACHINE, sub, reg.SET_VALUE)
	if err != nil {
		return fmt.Errorf("regvip: %w", err)
	}
	defer k.Close()

	if err := dw1(k, "level"); err != nil {
		return fmt.Errorf("regvip: %w", err)
	}
	return nil
}

// ini文件伪装vip
func inivip() error {
	app := os.Getenv("APPDATA")
	if app == "" {
		return fmt.Errorf("inivip: APPDATA not set")
	}
	cfg := filepath.Join(app, "TabXExplorer", "config.ini")

	if err := os.MkdirAll(filepath.Dir(cfg), 0755); err != nil {
		return fmt.Errorf("inivip: %w", err)
	}

	data, err := os.ReadFile(cfg)
	if os.IsNotExist(err) {
		cont := "[settings]\r\nlevel=1\r\n"
		if err := os.WriteFile(cfg, []byte(cont), 0644); err != nil {
			return fmt.Errorf("inivip: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("inivip: %w", err)
	}

	lines := strings.Split(string(data), "\n")

	// 找 [settings]
	secSt := -1
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if len(t) > 1 && t[0] == '[' && t[len(t)-1] == ']' {
			sec := strings.TrimSpace(t[1 : len(t)-1])
			if strings.EqualFold(sec, "settings") {
				secSt = i
				break
			}
		}
	}

	if secSt == -1 {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, "[settings]")
		lines = append(lines, "level=1")
		return os.WriteFile(cfg, []byte(strings.Join(lines, "\n")), 0644)
	}

	// 找 [settings] 结束行
	secEd := len(lines)
	for i := secSt + 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if len(t) > 1 && t[0] == '[' && t[len(t)-1] == ']' {
			secEd = i
			break
		}
	}

	// 找 level
	lvlIdx := -1
	for i := secSt + 1; i < secEd; i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, ";") || strings.HasPrefix(t, "#") {
			continue
		}
		tl := strings.ToLower(t)
		if strings.HasPrefix(tl, "level") {
			lvlIdx = i
			break
		}
	}

	if lvlIdx == -1 {
		newL := make([]string, 0, len(lines)+1)
		newL = append(newL, lines[:secEd]...)
		newL = append(newL, "level=1")
		newL = append(newL, lines[secEd:]...)
		return os.WriteFile(cfg, []byte(strings.Join(newL, "\n")), 0644)
	}

	t := strings.TrimSpace(lines[lvlIdx])
	ps := strings.SplitN(t, "=", 2)
	if len(ps) == 2 {
		val := strings.TrimSpace(ps[1])
		if n, err := strconv.Atoi(val); err == nil && n >= 0 {
			return nil
		}
	}

	lines[lvlIdx] = "level=1"
	return os.WriteFile(cfg, []byte(strings.Join(lines, "\n")), 0644)
}

// 伪装开启360弹窗拦截
func ads360() error {
	const sub = `SOFTWARE\WOW6432Node\360Safe\stat`

	k, _, err := reg.CreateKey(reg.LOCAL_MACHINE, sub, reg.SET_VALUE)
	if err != nil {
		return fmt.Errorf("ads360: %w", err)
	}
	defer k.Close()

	if err := dw1(k, "noadpop"); err != nil {
		return fmt.Errorf("ads360: %w", err)
	}
	if err := dw1(k, "advtool_PopWndTracker"); err != nil {
		return fmt.Errorf("ads360: %w", err)
	}
	return nil
}

// 把DWORD值设置为1
func dw1(k reg.Key, name string) error {
	v, _, err := k.GetIntegerValue(name)
	if err == nil && v == 1 {
		return nil
	}
	if err := k.SetDWordValue(name, 1); err != nil {
		return fmt.Errorf("dw1(%s): %w", name, err)
	}
	return nil
}

func main() {
	utils.HasWV2() // 检查webview2运行时
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	dat := newDat(dir)

	exe := filepath.Join(dir, exeName)

	w := webview.New(false)
	defer w.Destroy()

	w.SetSize(690, 540, webview.HintNone)
	w.SetTitle("拦截管理")

	_ = w.Bind("getAll", func() (map[string][]string, error) {
		return dat.all(), nil
	})
	_ = w.Bind("getNot", func() (map[string]string, error) {
		return dat.note(), nil
	})
	_ = w.Bind("getLog", func() ([]string, error) {
		return dat.log(), nil
	})
	_ = w.Bind("addLn", func(key, txt string) ([]string, error) {
		return dat.addLn(key, txt)
	})
	_ = w.Bind("delLn", func(key string, idx int) ([]string, error) {
		return dat.delLn(key, idx)
	})
	_ = w.Bind("trydel", utils.Del)
	_ = w.Bind("tryrm", utils.Tryrm)

	// 状态检查
	_ = w.Bind("stChk", func() (uiSta, error) {
		st := uiSta{
			Adm:  chkAdm(),
			Run:  chkRun(),
			Boot: hasBoot(exe),
		}
		t := "名单管理"
		if st.Run {
			t += " - 已运行"
		} else {
			t += " - 未运行"
		}
		w.SetTitle(t)
		return st, nil
	})

	_ = w.Bind("doRun", func() (bool, error) {
		if err := runExe(exe); err != nil {
			return false, err
		}
		return true, nil
	})
	_ = w.Bind("doStop", func() (bool, error) {
		if err := utils.Kill("block-ads.exe"); err != nil {
			return false, err
		}
		// 结束ETW
		if err := etw.KillSession("blockads-ProcMon-ETW"); err != nil {
			fmt.Println("结束ETW会话失败:", err)
		}
		//清空skin.txt
		p := filepath.Join(dir, "skin.txt")
		os.WriteFile(p, []byte{}, 0644)

		return true, nil
	})
	//前往GitHub
	_ = w.Bind("doGit", func() (bool, error) {
		if err := goUrl("https://github.com/AzureIvory/block-ads"); err != nil {
			return false, err
		}
		return true, nil
	})
	_ = w.Bind("setAut", func(on bool) (bool, error) {
		if err := setBoot(exe, on); err != nil {
			return false, err
		}
		return hasBoot(exe), nil
	})
	_ = w.Bind("doHel", func() (bool, error) {
		//打开使用指南
		if err := goUrl("https://www.kdocs.cn/l/carLpeQqWued"); err != nil {
			return false, err
		}
		return true, nil
	})
	_ = w.Bind("doFak", func() (bool, error) {
		if !utils.HasProc("Code.exe") {
			cod := filepath.Join(dir, "Code.exe")
			if _, err := os.Stat(cod); err != nil {
				fmt.Println("path Code.exe : ", err)
			}
			cmd := exec.Command(cod)
			cmd.SysProcAttr = &syscall.SysProcAttr{
				HideWindow: true,
			}
			cmd.Dir = dir
			if err := cmd.Start(); err != nil {
				fmt.Println("run Code.exe : ", err)
			}
		}
		//访问知乎，规避浏览器劫持
		_ = goUrl("https://www.zhihu.com/")
		if err := reghr(); err != nil {
			fmt.Println("goUrl zhihu : ", err)
		}
		if err := regvm(); err != nil {
			fmt.Println("regvm: ", err)
		}
		if err := regvip(); err != nil {
			fmt.Println("regvip: ", err)
		}
		if err := inivip(); err != nil {
			fmt.Println("inivip: ", err)
		}
		if err := ads360(); err != nil {
			fmt.Println("ads360: ", err)
		}
		return true, nil
	})

	// 打开资源管理器并选中文件
	_ = w.Bind("opSel", func(p string) (bool, error) {
		p = strings.TrimSpace(p)
		if p == "" {
			return false, nil
		}
		cmd := exec.Command("explorer.exe", "/select,"+p)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}
		if err := cmd.Start(); err != nil {
			return false, err
		}
		return true, nil
	})
	// 从日志记录加入白名单
	_ = w.Bind("addWht", func(kind, val, path string) (bool, error) {
		return dat.addWhite(kind, val, path)
	})

	h := filepath.Join(dir, "index.html")
	h = filepath.ToSlash(h)
	u := "file:///" + h
	w.Navigate(u)
	w.Run()
}
