package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	ut "scan/utils"
)

const (
	jf = "signdata.json"
	uf = "uplog.txt"
)

// 测试上传
const upURL = "http://127.0.0.1/upload"

type PInfo struct {
	Pname string `json:"name"`
	Ppath string `json:"path"`
	Psign string `json:"sign"`
	Up    string `json:"up,omitempty"`
}

type UInfo struct {
	Pname string `json:"name"`
	Ppath string `json:"path"`
	Psign string `json:"sign"`
}

func main() {
	upChk() // 检查是否需要上传
	for {
		scan()
		time.Sleep(10 * time.Minute)
	}
}

// 扫描进程
func scan() {
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	fp := filepath.Join(dir, jf)

	var arr []PInfo
	// 读已有数据
	if b, err := os.ReadFile(fp); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &arr)
	}

	// 已有 path 集合，避免重复
	ex := make(map[string]bool)
	for _, it := range arr {
		if it.Ppath != "" {
			ex[it.Ppath] = true
		}
	}

	pids := ut.Listpid()
	if len(pids) == 0 {
		return
	}

	for _, pid := range pids {
		pth, err := ut.ProcPath(pid)
		if err != nil || pth == "" {
			continue
		}
		if !ut.IsExe(pth) {
			continue
		}
		if isSys(pth) {
			continue
		}
		if ex[pth] {
			continue
		}
		ex[pth] = true

		nm := filepath.Base(pth)
		sgn, _ := ut.GetSignName(pth)

		arr = append(arr, PInfo{
			Pname: nm,
			Ppath: pth,
			Psign: sgn,
			// Up 为空，还未上传
		})
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

// 真正执行上传逻辑
func upDo(now time.Time, dir string) {
	jp := filepath.Join(dir, jf)
	b, err := os.ReadFile(jp)
	if err != nil || len(b) == 0 {
		// 没有数据，直接记录日期即可
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
		// 上传失败
		return
	}

	// 上传成功：给这些记录加本地上传时间
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
