package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	ut "scan/utils"

	reg "golang.org/x/sys/windows/registry"
)

const (
	jf    = "signdata.json"
	uf    = "uplog.txt"
	upURL = "http://127.0.0.1/upload"
)

type PInfo struct {
	Pname string `json:"name"`
	Ppath string `json:"path"`
	Psign string `json:"sign"`
	Up    string `json:"up,omitempty"` // 本地上传时间
}

type UInfo struct {
	Pname string `json:"name"`
	Ppath string `json:"path"`
	Psign string `json:"sign"`
}

var dDay string // 上次做深度扫描的日期

func main() {
	upChk()

	for {
		now := time.Now()
		day := now.Format("2006-01-02")
		full := false
		if dDay != day {
			// 新的一天，做一次深度扫描
			dDay = day
			full = true
		}
		scan(full) // full==true 时：进程 + 桌面 + 开始菜单 + 卸载 + 启动项；否则只进程

		time.Sleep(10 * time.Minute)
	}
}

// 扫描：full 为 true 时包含深度扫描，否则只扫进程
func scan(full bool) {
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	fp := filepath.Join(dir, jf)

	var arr []PInfo

	// 读取已有数据
	if b, err := os.ReadFile(fp); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &arr)
	}

	// 构建路径去重表
	seen := make(map[string]bool)
	for _, it := range arr {
		if it.Ppath == "" {
			continue
		}
		_, key := normPth(it.Ppath)
		if key != "" {
			seen[key] = true
		}
	}

	mod := false

	// 深度扫描,每天一次
	if full {
		if scanDesk(&arr, seen) {
			mod = true
		}
		if scanMenu(&arr, seen) {
			mod = true
		}
		if scanUn(&arr, seen) {
			mod = true
		}
		if scanRun(&arr, seen) {
			mod = true
		}
	}

	// 进程扫描
	if scanProc(&arr, seen) {
		mod = true
	}

	if !mod {
		return
	}

	b, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(fp, b, 0644)
}

// 启动时检查是否要上传
func upChk() {
	now := time.Now()

	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	fp := filepath.Join(dir, uf)

	need := false

	if b, err := os.ReadFile(fp); err != nil || len(b) == 0 {
		// 没有记录文件 / 内容为空 => 需要上传
		need = true
	} else {
		s := strings.TrimSpace(string(b))
		if s == "" {
			need = true
		} else {
			t, err := time.Parse("2006-01-02", s)
			if err != nil {
				need = true
			} else {
				// 同一天不传，跨天就传
				if !isDay(t, now) {
					need = true
				}
			}
		}
	}

	if !need {
		return
	}
	upDo(now, dir)
}

// 执行实际上传逻辑
func upDo(now time.Time, dir string) {
	jp := filepath.Join(dir, jf)
	b, err := os.ReadFile(jp)
	if err != nil || len(b) == 0 {
		// 没有数据，直接记录日期
		_ = os.WriteFile(filepath.Join(dir, uf), []byte(now.Format("2006-01-02")), 0644)
		return
	}

	var arr []PInfo
	if err := json.Unmarshal(b, &arr); err != nil {
		return
	}

	var todo []UInfo
	for _, it := range arr {
		if it.Up != "" {
			continue // 已经上传过
		}
		todo = append(todo, UInfo{
			Pname: it.Pname,
			Ppath: it.Ppath,
			Psign: it.Psign,
		})
	}

	if len(todo) == 0 {
		// 没有未上传的数据，只更新日期
		_ = os.WriteFile(filepath.Join(dir, uf), []byte(now.Format("2006-01-02")), 0644)
		return
	}

	db, err := json.Marshal(todo)
	if err != nil {
		return
	}

	resp, err := http.Post(upURL, "application/json", bytes.NewReader(db))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// 失败
		return
	}

	// 上传成功
	upStr := now.Format("2006-01-02 15:04:05")
	for i := range arr {
		if arr[i].Up == "" {
			arr[i].Up = upStr
		}
	}

	nb, err := json.MarshalIndent(arr, "", "  ")
	if err == nil {
		_ = os.WriteFile(jp, nb, 0644)
	}

	// 更新上传日期
	_ = os.WriteFile(filepath.Join(dir, uf), []byte(now.Format("2006-01-02")), 0644)
}

// 进程扫描
func scanProc(arr *[]PInfo, seen map[string]bool) bool {
	pids := ut.Listpid()
	if len(pids) == 0 {
		return false
	}

	mod := false

	for _, pid := range pids {
		pth, err := ut.ProcPath(pid)
		if err != nil || pth == "" {
			continue
		}
		p, key, ok := pathOK(pth)
		if !ok {
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		nm := filepath.Base(p)
		sgn, _ := ut.GetSignName(p)

		*arr = append(*arr, PInfo{
			Pname: nm,
			Ppath: p,
			Psign: sgn,
		})
		mod = true
	}
	return mod
}

// 扫描桌面快捷方式
func scanDesk(arr *[]PInfo, seen map[string]bool) bool {
	mod := false

	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		d := filepath.Join(home, "Desktop")
		if scanLnk(arr, seen, d, 0) { // 第 0 层
			mod = true
		}
	}

	pub := os.Getenv("PUBLIC")
	if pub != "" {
		d := filepath.Join(pub, "Desktop")
		if scanLnk(arr, seen, d, 0) {
			mod = true
		}
	}

	return mod
}

// 扫描开始菜单快捷方式
func scanMenu(arr *[]PInfo, seen map[string]bool) bool {
	mod := false

	app := os.Getenv("APPDATA")
	if app != "" {
		d := filepath.Join(app, "Microsoft", "Windows", "Start Menu", "Programs")
		if scanLnk(arr, seen, d, 0) {
			mod = true
		}
	}

	pd := os.Getenv("ProgramData")
	if pd != "" {
		d := filepath.Join(pd, "Microsoft", "Windows", "Start Menu", "Programs")
		if scanLnk(arr, seen, d, 0) {
			mod = true
		}
	}

	return mod
}

// 扫描一个目录中的 .lnk
func scanLnk(arr *[]PInfo, seen map[string]bool, dir string, dep int) bool {
	if dir == "" {
		return false
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}

	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	mod := false

	for _, ent := range ents {
		nm := ent.Name()
		fp := filepath.Join(dir, nm)

		if ent.IsDir() {
			// 限制递归深度
			if dep >= 3 {
				continue
			}
			if scanLnk(arr, seen, fp, dep+1) {
				mod = true
			}
			continue
		}

		if !strings.HasSuffix(strings.ToLower(nm), ".lnk") {
			continue
		}

		tgt := lnkPth(fp)
		if tgt == "" {
			continue
		}

		p, key, ok := pathOK(tgt)
		if !ok {
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		base := strings.TrimSuffix(nm, filepath.Ext(nm))
		sgn, _ := ut.GetSignName(p)

		*arr = append(*arr, PInfo{
			Pname: base,
			Ppath: p,
			Psign: sgn,
		})
		mod = true
	}
	return mod
}

// 使用PowerShell解析 .lnk 的目标路径
func lnkPth(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", "(New-Object -ComObject WScript.Shell).CreateShortcut($args[0]).TargetPath", p)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(out))
	return s
}

// 扫描卸载信息
func scanUn(arr *[]PInfo, seen map[string]bool) bool {
	mod := false
	if scanUnV(arr, seen, reg.WOW64_64KEY) {
		mod = true
	}
	if scanUnV(arr, seen, reg.WOW64_32KEY) {
		mod = true
	}
	return mod
}

func scanUnV(arr *[]PInfo, seen map[string]bool, view uint32) bool {
	k, err := reg.OpenKey(reg.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		reg.READ|view)
	if err != nil {
		return false
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return false
	}

	mod := false

	for _, nm := range names {
		sk, err := reg.OpenKey(k, nm, reg.READ|view)
		if err != nil {
			continue
		}

		disp, _, err := sk.GetStringValue("DisplayName")
		if err != nil || strings.TrimSpace(disp) == "" {
			sk.Close()
			continue
		}

		us, _, err := sk.GetStringValue("UninstallString")
		sk.Close()
		if err != nil {
			continue
		}

		raw := cmdPth(us)
		if raw == "" {
			continue
		}

		p, key, ok := pathOK(raw)
		if !ok {
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		sgn, _ := ut.GetSignName(p)

		*arr = append(*arr, PInfo{
			Pname: disp,
			Ppath: p,
			Psign: sgn,
		})
		mod = true
	}
	return mod
}

// 扫描启动项
func scanRun(arr *[]PInfo, seen map[string]bool) bool {
	mod := false
	if scanRunK(arr, seen, reg.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`) {
		mod = true
	}
	if scanRunK(arr, seen, reg.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`) {
		mod = true
	}
	return mod
}

func scanRunK(arr *[]PInfo, seen map[string]bool, root reg.Key, path string) bool {
	k, err := reg.OpenKey(root, path, reg.READ)
	if err != nil {
		return false
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return false
	}

	mod := false

	for _, nm := range names {
		val, _, err := k.GetStringValue(nm)
		if err != nil {
			continue
		}

		raw := cmdPth(val)
		if raw == "" {
			continue
		}

		p, key, ok := pathOK(raw)
		if !ok {
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		sgn, _ := ut.GetSignName(p)

		*arr = append(*arr, PInfo{
			Pname: nm,
			Ppath: p,
			Psign: sgn,
		})
		mod = true
	}
	return mod
}

// 从字符串取出路径
func cmdPth(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// 有引号时取第一对引号之间
	if i := strings.Index(s, `"`); i >= 0 {
		j := strings.Index(s[i+1:], `"`)
		if j > 0 {
			p := s[i+1 : i+1+j]
			p = strings.TrimSpace(p)
			if p != "" {
				p = os.ExpandEnv(p)
				return p
			}
		}
	}

	// 没有引号时取第一个空格前
	fs := strings.Fields(s)
	if len(fs) == 0 {
		return ""
	}
	p := fs[0]
	p = strings.Trim(p, `"`)
	p = os.ExpandEnv(p)
	return p
}

// 规范化路径
func normPth(p string) (string, string) {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"`)
	if p == "" {
		return "", ""
	}
	p = os.ExpandEnv(p)
	if p == "" {
		return "", ""
	}
	p = filepath.Clean(p)
	return p, strings.ToLower(p)
}

// 判断路径是否标准exe且非系统目录
func pathOK(p string) (string, string, bool) {
	n, key := normPth(p)
	if n == "" || key == "" {
		return "", "", false
	}
	if !ut.IsExe(n) {
		return "", "", false
	}
	st, err := os.Stat(n)
	if err != nil || st.IsDir() {
		return "", "", false
	}
	if isSys(n) {
		return "", "", false
	}
	return n, key, true
}

// 判断是否系统进程
func isSys(p string) bool {
	if p == "" {
		return false
	}

	pl := strings.ToLower(p)
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	root = strings.ToLower(root)
	if !strings.HasSuffix(root, `\`) {
		root += `\`
	}
	return strings.HasPrefix(pl, root)
}

// 判断两时间是否同一天
func isDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}
