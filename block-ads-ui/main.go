package main

import (
	"block-ads-ui/utils"
	"encoding/json"
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
	"golang.org/x/sys/windows"
	reg "golang.org/x/sys/windows/registry"
)

var lstMap = map[string]string{
	"sign":      "sign.txt",
	"folder":    "folder.txt",
	"whitelist": "Wfolder.txt",
	"signWhite": "Wsign.txt",
}

var upUrl = []string{
	"http://127.0.0.1:8080/upload",
	"https://api.ttraw.com/block-ads/upload",
}

type upDat struct {
	Time  string `json:"time"`
	Items upItm  `json:"items"`
}
type upItm struct {
	Desk []string `json:"desktop"`
	Proc []string `json:"process"`
	Run  upRun    `json:"run"`
	Un   upUn     `json:"un"`
	Menu []string `json:"menu"`
}
type upRun struct {
	Usr []string `json:"USER"`
	Mac []string `json:"MACHINE"`
}
type upUn struct {
	X64 []string `json:"64"`
	X32 []string `json:"32"`
}

const (
	noteFile    = "note.txt"
	exeName     = "block-ads.exe"
	runName     = "BlockAds"
	codeExeName = "Code.exe"
	runNameCode = "BlockAdsCode"
)

type appDat struct {
	mu  sync.Mutex
	dir string
	lst map[string][]string
	not map[string]string
	lg  []string
	// rules 保存用户层增量（新增/禁用），与 txt 现场分离，使 txt 保持云端只读基准。
	// key 与 lstMap 一致：sign/folder/whitelist/signWhite。
	rules userRules
}

// ruleOverride / userRules 与引擎 main.go 的结构一一对应，JSON 字段名必须保持一致。
type ruleOverride struct {
	Add      []string `json:"add"`
	Disabled []string `json:"disabled"`
}
type userRules map[string]ruleOverride

// userRulesFile 是用户层增量的文件名，与 txt 同目录。
const userRulesFile = "user_rules.json"

type uiSta struct {
	Adm      bool `json:"adm"`
	Run      bool `json:"run"`
	Boot     bool `json:"boot"`
	CodeBoot bool `json:"codeBoot"`
}

func stopAd(dir string) error {
	if err := utils.Kill("block-ads.exe"); err != nil {
		fmt.Println("结束 block-ads.exe 失败:", err)
	}
	if err := etw.KillSession("blockads-ProcMon-ETW"); err != nil {
		fmt.Println("结束ETW会话失败:", err)
	}
	p := filepath.Join(dir, "skin.txt")
	_ = os.WriteFile(p, []byte{}, 0644)

	return nil
}

func selMap(req map[string]interface{}) map[string]bool {
	out := map[string]bool{}
	if req == nil {
		return out
	}
	v, ok := req["sel"]
	if !ok {
		return out
	}
	arr, ok := v.([]interface{})
	if !ok {
		return out
	}
	for _, it := range arr {
		s, ok := it.(string)
		if !ok {
			continue
		}
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			out[s] = true
		}
	}
	return out
}

func getUrl(req map[string]interface{}) []string {
	if req == nil {
		return upUrl
	}
	v, ok := req["urls"]
	if !ok {
		return upUrl
	}
	arr, ok := v.([]interface{})
	if !ok {
		return upUrl
	}
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		s, ok := it.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return upUrl
	}
	return out
}

func mkUp(sel map[string]bool, kws []string) upDat {
	tm := strconv.FormatInt(time.Now().Unix(), 10)
	var wg sync.WaitGroup

	desk := []string{}
	proc := []string{}
	menu := []string{}
	runU := []string{}
	runM := []string{}
	un64 := []string{}
	un32 := []string{}

	if sel["desktop"] {
		wg.Add(1)
		go func() { defer wg.Done(); desk = utils.DeskLst() }()
	}
	if sel["process"] {
		wg.Add(1)
		go func() { defer wg.Done(); proc = utils.ProcLst(kws) }()
	}
	if sel["startup"] {
		wg.Add(1)
		go func() { defer wg.Done(); runU, runM = utils.RunLst() }()
	}
	if sel["uninstall"] {
		wg.Add(1)
		go func() { defer wg.Done(); un64, un32 = utils.UnLst() }()
	}
	if sel["startmenu"] {
		wg.Add(1)
		go func() { defer wg.Done(); menu = utils.MenuLst() }()
	}

	wg.Wait()

	return upDat{
		Time: tm,
		Items: upItm{
			Desk: desk,
			Proc: proc,
			Run:  upRun{Usr: runU, Mac: runM},
			Un:   upUn{X64: un64, X32: un32},
			Menu: menu,
		},
	}
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
	d.rules = rdUserRules(filepath.Join(dir, userRulesFile))
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

// rdUserRules 读取用户层增量文件，缺失或损坏返回空 map（不阻断启动）。
func rdUserRules(p string) userRules {
	out := userRules{}
	b, err := os.ReadFile(p)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

// normRule 与引擎 readSet/readSetLower 的规范化保持一致。
// folder/whitelist 类小写 + filepath.Clean；sign/signWhite 类保持原样。
// 两边规范化不一致会导致 disabled/add 项与规则对不上，开关失效。
func normRule(key, val string) string {
	val = strings.TrimSpace(val)
	if key == "folder" || key == "whitelist" {
		return strings.ToLower(filepath.Clean(val))
	}
	return val
}

// ruleOvLocked 返回某类的 override（无则零值），调用方须持锁。
func (d *appDat) ruleOvLocked(key string) ruleOverride {
	if d.rules == nil {
		d.rules = userRules{}
	}
	return d.rules[key]
}

// mergedViewLocked 合并 txt 行 + add 段（去重，规范化比对），调用方须持锁。
// disabled 不在此剔除：UI 仍需显示被禁用的行以便展示灰行与取消勾选状态。
func (d *appDat) mergedViewLocked(key string) []string {
	base := d.lst[key]
	out := make([]string, 0, len(base))
	seen := make(map[string]struct{}, len(base))
	for _, s := range base {
		n := normRule(key, s)
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, s)
	}
	for _, s := range d.ruleOvLocked(key).Add {
		n := normRule(key, s)
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, s)
	}
	return out
}

// saveRulesLocked 持久化用户层增量，调用方须持锁。
func (d *appDat) saveRulesLocked() error {
	if d.rules == nil {
		d.rules = userRules{}
	}
	b, err := json.MarshalIndent(d.rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.dir, userRulesFile), b, 0644)
}

// disabledSet 返回某类规则被禁用项的规范化 key 集合，供 UI 批量判定（一次加锁）。
func (d *appDat) disabledSet(key string) map[string]struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]struct{}, len(d.rules[key].Disabled))
	for _, x := range d.ruleOvLocked(key).Disabled {
		out[normRule(key, x)] = struct{}{}
	}
	return out
}

// txtSet 返回某类规则 txt 原始行的规范化 key 集合，供 UI 区分来源（一次加锁）。
func (d *appDat) txtSet(key string) map[string]struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]struct{}, len(d.lst[key]))
	for _, s := range d.lst[key] {
		out[normRule(key, s)] = struct{}{}
	}
	return out
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

// 拷贝列表（txt 行 + 用户 add 段去重合并；disabled 不剔除，UI 仍需展示被禁用的行）
func (d *appDat) all() map[string][]string {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make(map[string][]string, len(d.lst))
	for k := range d.lst {
		out[k] = d.mergedViewLocked(k)
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

// addLn 把用户新增规则写入 user_rules.json 的 add 段（不写 txt，txt 保持云端只读基准）。
// 与 txt 已有行、add 已有项去重，避免重复堆积。
func (d *appDat) addLn(key, txt string) ([]string, error) {
	txt = strings.TrimSpace(txt)
	if txt == "" {
		return nil, os.ErrInvalid
	}
	norm := normRule(key, txt)

	d.mu.Lock()
	defer d.mu.Unlock()

	// 与 txt 现有行去重。
	for _, exist := range d.lst[key] {
		if normRule(key, exist) == norm {
			return d.mergedViewLocked(key), nil
		}
	}
	// 与 add 段已有项去重。
	ov := d.ruleOvLocked(key)
	for _, exist := range ov.Add {
		if normRule(key, exist) == norm {
			return d.mergedViewLocked(key), nil
		}
	}
	ov.Add = append(ov.Add, txt)
	d.rules[key] = ov

	if err := d.saveRulesLocked(); err != nil {
		return nil, err
	}
	return d.mergedViewLocked(key), nil
}

// toggleRule 切换某条规则的启用/禁用状态。
//   - custom（用户自定义）规则：取消勾选 = 从 add 段真删（不弹窗）。
//   - txt（云端）规则：勾选状态切换只动 disabled 段。
//
// enable=true 表示启用，enable=false 表示禁用。
func (d *appDat) toggleRule(key, val, source string, enable bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if source == "custom" {
		// 自定义规则只有启用 / 删除两种状态。
		if !enable {
			norm := normRule(key, val)
			ov := d.ruleOvLocked(key)
			next := ov.Add[:0]
			for _, exist := range ov.Add {
				if normRule(key, exist) != norm {
					next = append(next, exist)
				}
			}
			ov.Add = next
			d.rules[key] = ov
			return d.saveRulesLocked()
		}
		return nil
	}

	// txt 规则：用 disabled 段记录禁用。
	norm := normRule(key, val)
	ov := d.ruleOvLocked(key)
	dedup := func(in []string) []string {
		out := in[:0]
		for _, x := range in {
			if normRule(key, x) != norm {
				out = append(out, x)
			}
		}
		return out
	}
	ov.Disabled = dedup(ov.Disabled)
	if !enable {
		ov.Disabled = append(ov.Disabled, val)
	}
	d.rules[key] = ov
	return d.saveRulesLocked()
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

// folder 模式：从路径各级目录中找出与 folder.txt 行一致的名字，加入Wfolder.txt
// - 第一段和最后一段不匹配
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

func hasBootKey(key, exe string) bool {
	k, err := reg.OpenKey(reg.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		reg.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetStringValue(key)
	if err != nil {
		return false
	}
	val = strings.Trim(val, `"`)
	exe = strings.Trim(exe, `"`)
	return strings.EqualFold(val, exe)
}

func setBootKey(key, exe string, on bool) error {
	k, _, err := reg.CreateKey(reg.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		reg.SET_VALUE|reg.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if on {
		val := `"` + exe + `"`
		return k.SetStringValue(key, val)
	}

	err = k.DeleteValue(key)
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
