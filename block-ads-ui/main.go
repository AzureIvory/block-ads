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
}
type uiSta struct {
	Adm  bool `json:"adm"`
	Run  bool `json:"run"`
	Boot bool `json:"boot"`
}

func stopAd(dir string) error {
	if err := utils.Kill("block-ads.exe"); err != nil {
		fmt.Println("缂佹挻娼?block-ads.exe 婢惰精瑙?", err)
	}
	if err := etw.KillSession("blockads-ProcMon-ETW"); err != nil {
		fmt.Println("缂佹挻娼獷TW娴兼俺鐦芥径杈Е:", err)
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

// 閹风柉绀夐崚妤勩€?
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

// 閹风柉绀夊▔銊╁櫞
func (d *appDat) note() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make(map[string]string, len(d.not))
	for k, v := range d.not {
		out[k] = v
	}
	return out
}

// 閹风柉绀夐弮銉ョ箶
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

// 娴犲孩妫╄箛妤€濮為崗銉ф閸氬秴宕熼敍姝琲nd = "folder" / "sign"
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

// sign 濡€崇础閿涙碍濡哥粵鎯ф倳閸旂姴鍙哤sign.txt
func (d *appDat) addWsign(sign string) (bool, error) {
	if sign == "" {
		return false, os.ErrInvalid
	}
	wl := d.lst["signWhite"]

	// 瀹告彃鐡ㄩ崷銊ュ灟娑撳秹鍣告径宥呭晸閸?
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

// folder 濡€崇础閿涙矮绮犵捄顖氱窞閸氬嫮楠囬惄顔肩秿娑擃厽澹橀崙杞扮瑢 folder.txt 鐞涘奔绔撮懛瀵告畱閸氬秴鐡ч敍灞藉閸忣櫇folder.txt
// - 缁楊兛绔村▓闈涙嫲閺堚偓閸氬簼绔村▓鍏哥瑝閸栧綊鍘?
func (d *appDat) addWfolder(path string) (bool, error) {
	if path == "" {
		return false, os.ErrInvalid
	}

	folders := d.lst["folder"]
	if len(folders) == 0 {
		return false, nil
	}
	wl := d.lst["whitelist"]

	// 妫板嫬顦╅悶鍞俹lder.txt
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

	// 閻滅増婀侀惂钘夋倳閸楁洟娉﹂崥鍫礉閻劋绨崢濠氬櫢
	wset := make(map[string]struct{})
	for _, ln := range wl {
		wset[strings.ToLower(strings.TrimSpace(ln))] = struct{}{}
	}

	// 缂佺喍绔撮崚鍡涙缁?
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
		// 閸欘亝婀侀弽鐟版嫲閺傚洣娆㈤崥宥忕礉濞屸€虫殣閸欘垰灏柊宥囨畱
		return false, nil
	}

	added := false
	// 娴犲海顑囨禍灞绢唽閸掓澘鈧帗鏆熺粭顑跨癌濞?
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
			// 瀹告彃婀惂钘夋倳閸?
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

// 閺勵垰鎯佺粻锛勬倞閸?
func chkAdm() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// 閹凤附鍩呮潻娑氣柤閺勵垰鎯佹潻鎰攽
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

// 濡偓閺屻儱绱戦張楦垮殰閸?
func hasBoot(exe string) bool {
	return hasBootKey(runName, exe)
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

// 鐠佸墽鐤嗗鈧張楦垮殰閸?
func setBoot(exe string, on bool) error {
	return setBootKey(runName, exe, on)
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

// 娴犮儳顓搁悶鍡楁喅濡€崇础閸氼垰濮?
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

// 閻劑绮拋銈嗙セ鐟欏牆娅掗幍鎾崇磻缂冩垿銆?
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

// 娴碱亣顥婄€瑰顥婇悘顐ょ钵
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

// 娴碱亣顥婇搹姘珯閺?
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

// 濞夈劌鍞界悰銊ゅ悏鐟佸嵕ip
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

// ini閺傚洣娆㈡导顏囶棅vip
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

	// 閹?[settings]
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

	// 閹?[settings] 缂佹挻娼悰?
	secEd := len(lines)
	for i := secSt + 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if len(t) > 1 && t[0] == '[' && t[len(t)-1] == ']' {
			secEd = i
			break
		}
	}

	// 閹?level
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

// 娴碱亣顥婂鈧崥?60瀵湱鐛ラ幏锔藉焻
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

// 閹跺WORD閸婅壈顔曠純顔昏礋1
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
