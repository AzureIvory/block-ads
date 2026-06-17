package main

import (
	"block-ads-ui/utils"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	updUrls = []string{
		"https://api.ttraw.com/block-ads/update.json",
		"https://raw.githubusercontent.com/AzureIvory/block-ads/refs/heads/main/update/update.json",
	}
	synUrls = []string{
		"https://api.ttraw.com/block-ads/sync.json",
		"https://raw.githubusercontent.com/AzureIvory/block-ads/refs/heads/main/update/sync.json",
	}
)

var httpCli = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	},
}

type UpdateManifest struct {
	Ver    string                `json:"version"`
	UpdAt  string                `json:"updated_at"`
	SupVer string                `json:"Msupported_version"`
	Mand   string                `json:"mandatory"`
	Notes  string                `json:"notes"`
	Items  map[string]UpdateItem `json:"items"`
}

type UpdateItem struct {
	Path string   `json:"path"`
	MD5  string   `json:"md5"`
	Size string   `json:"size"` // KB
	Run  string   `json:"run"`
	URL  []string `json:"url"`
}

type SyncManifest struct {
	UpdAt string              `json:"updated_at"`
	Notes string              `json:"notes"`
	Items map[string]SyncItem `json:"items"`
}

type SyncItem struct {
	MD5   string   `json:"md5"`
	Size  string   `json:"size"` // KB
	Count string   `json:"count"`
	URL   []string `json:"url"`
}

type UpdateInfo struct {
	LocVer string           `json:"local_version"`
	SrvVer string           `json:"server_version"`
	UpdAt  string           `json:"updated_at"`
	SupVer string           `json:"Msupported_version"`
	Mand   bool             `json:"mandatory"`
	Notes  string           `json:"notes"`
	HasUpd bool             `json:"has_update"`
	Items  []UpdateItemInfo `json:"items"`
}

type UpdateItemInfo struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	SizeKB    int64  `json:"size_kb"`
	SizeText  string `json:"size_text"`
	Run       bool   `json:"run"`
	RemoteMD5 string `json:"remote_md5"`
	LocalMD5  string `json:"local_md5"`
	Need      bool   `json:"need"`
	Exists    bool   `json:"exists"`
}

type SyncInfo struct {
	UpdAt string         `json:"updated_at"`
	Notes string         `json:"notes"`
	Items []SyncItemInfo `json:"items"`
}

type SyncItemInfo struct {
	Name      string `json:"name"`
	SizeKB    int64  `json:"size_kb"`
	SizeText  string `json:"size_text"`
	Count     string `json:"count"`
	RemoteMD5 string `json:"remote_md5"`
	LocalMD5  string `json:"local_md5"`
	Need      bool   `json:"need"`
	Exists    bool   `json:"exists"`
}

type PendingUpdate struct {
	ManRaw json.RawMessage     `json:"manifest_raw"`
	TmpDir string              `json:"tmp_dir"`
	Items  []PendingUpdateItem `json:"items"`
}

type PendingUpdateItem struct {
	RelPath string `json:"rel_path"`
	Run     bool   `json:"run"`
}

// 防止进入其他目录
func safeJoin(base, rel string) (string, error) {
	rel = filepath.FromSlash(rel)
	rel = filepath.Clean(rel)

	sep := string(filepath.Separator)
	if filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+sep) {
		return "", fmt.Errorf("bad path: %q", rel)
	}
	pth := filepath.Join(base, rel)
	rrel, err := filepath.Rel(base, pth)
	if err != nil || rrel == ".." || strings.HasPrefix(rrel, ".."+sep) {
		return "", fmt.Errorf("esc path: %q", rel)
	}
	return pth, nil
}

func keySort[T any](mp map[string]T) []string {
	keys := make([]string, 0, len(mp))
	for k := range mp {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func needMD5(pth, rmd5 string) (bool, string, bool) {
	_, err := os.Stat(pth)
	exist := err == nil

	lmd5 := ""
	if exist {
		if m5, err := fileMD5(pth); err == nil {
			lmd5 = m5
		}
	}

	need := false
	if !exist {
		need = true
	} else if strings.TrimSpace(rmd5) != "" {
		need = !strings.EqualFold(lmd5, strings.TrimSpace(rmd5))
	}
	return exist, lmd5, need
}

func boolPars(str string) bool {
	str = strings.TrimSpace(strings.ToLower(str))
	str = strings.Trim(str, `"`)
	str = strings.TrimSpace(strings.ToLower(str))
	str = strings.ReplaceAll(str, " ", "")
	str = strings.ReplaceAll(str, "\t", "")
	str = strings.ReplaceAll(str, "\n", "")
	str = strings.ReplaceAll(str, "\r", "")
	str = strings.ReplaceAll(str, "ture", "true")
	str = strings.ReplaceAll(str, "flase", "false")
	return str == "true" || str == "1" || str == "yes" || str == "y" || str == "on"
}

func kbPars(str string) int64 {
	str = strings.TrimSpace(str)
	if str == "" {
		return 0
	}
	// allow floats, but store as int64 KB
	if strings.Contains(str, ".") {
		f, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return 0
		}
		return int64(f)
	}
	i, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0
	}
	return i
}

func kbText(kb int64) string {
	if kb <= 0 {
		return "-"
	}
	if kb > 1024 {
		mb := float64(kb) / 1024
		return fmt.Sprintf("%.2f MB", mb)
	}
	return fmt.Sprintf("%d KB", kb)
}

func verCmp(a, b string) int {
	as := strings.Split(strings.TrimSpace(a), ".")
	bs := strings.Split(strings.TrimSpace(b), ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai := 0
		bi := 0
		if i < len(as) {
			ai, _ = strconv.Atoi(strings.TrimSpace(as[i]))
		}
		if i < len(bs) {
			bi, _ = strconv.Atoi(strings.TrimSpace(bs[i]))
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

func fileMD5(pth string) (string, error) {
	f, err := os.Open(pth)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func getJSON(urls []string, val any) ([]byte, string, error) {
	var lstErr error
	for _, url := range urls {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			lstErr = err
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "*/*")
		res, err := httpCli.Do(req)
		if err != nil {
			lstErr = err
			continue
		}
		buf, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			lstErr = err
			continue
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			lstErr = fmt.Errorf("http %d", res.StatusCode)
			continue
		}
		if err := json.Unmarshal(buf, val); err != nil {
			lstErr = err
			continue
		}
		return buf, url, nil
	}
	if lstErr == nil {
		lstErr = errors.New("fetch failed")
	}
	return nil, "", lstErr
}

func dlTo(urls []string, outPth string, expMD5 string) (string, error) {
	const rpt = 2
	const stl = 10 * time.Second

	if err := os.MkdirAll(filepath.Dir(outPth), 0755); err != nil {
		return "", err
	}

	part := outPth + ".part"
	var lastErr error

	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}

		for i := 0; i < rpt; i++ {
			_ = os.Remove(part)

			got, err := dl1(u, part, stl)
			if err != nil {
				lastErr = fmt.Errorf("%s: %w", u, err)
				_ = os.Remove(part)
				continue
			}

			if expMD5 != "" &&
				!strings.EqualFold(
					strings.TrimSpace(got),
					strings.TrimSpace(expMD5),
				) {
				lastErr = fmt.Errorf(
					"%s: md5 mismatch: got %s, expected %s",
					u,
					got,
					expMD5,
				)
				_ = os.Remove(part)
				continue
			}

			_ = os.Remove(outPth)

			if err := os.Rename(part, outPth); err != nil {
				if err2 := cpFile(part, outPth); err2 != nil {
					lastErr = fmt.Errorf(
						"replace %s failed (rename: %v; copy: %w)",
						outPth,
						err,
						err2,
					)
					_ = os.Remove(part)
					continue
				}
				_ = os.Remove(part)
			}

			return u, nil
		}
	}

	if lastErr == nil {
		lastErr = errors.New("download failed: no usable URL")
	}

	return "", lastErr
}

func dl1(u, part string, stl time.Duration) (string, error) {
	f, err := os.Create(part)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var n int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "block-ads-ui")

	res, err := httpCli.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", errors.New("stall")
		}
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("http %d", res.StatusCode)
	}

	done := make(chan struct{})
	go watch(done, &n, stl, cancel)
	defer close(done)

	h := md5.New()
	mw := io.MultiWriter(f, h)
	buf := make([]byte, 32*1024)

	for {
		r, er := res.Body.Read(buf)
		if r > 0 {
			if _, ew := mw.Write(buf[:r]); ew != nil {
				return "", ew
			}
			atomic.AddInt64(&n, int64(r))
		}
		if er != nil {
			if er == io.EOF {
				return hex.EncodeToString(h.Sum(nil)), nil
			}
			if errors.Is(er, context.Canceled) || errors.Is(er, context.DeadlineExceeded) {
				return "", errors.New("stall")
			}
			return "", er
		}
	}
}

func watch(done <-chan struct{}, n *int64, stl time.Duration, cancel context.CancelFunc) {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	last := atomic.LoadInt64(n)
	lastT := time.Now()

	for {
		select {
		case <-done:
			return
		case <-t.C:
			cur := atomic.LoadInt64(n)
			if cur != last {
				last = cur
				lastT = time.Now()
				continue
			}
			if time.Since(lastT) >= stl {
				cancel()
				return
			}
		}
	}
}

func cpFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}

	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}

	return out.Close()
}

func hidAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}

var updMu sync.Mutex

func (d *appDat) loadLocUM() (UpdateManifest, error) {
	var man UpdateManifest
	pth := filepath.Join(d.dir, "version.json")
	buf, err := os.ReadFile(pth)
	if err != nil {
		return man, err
	}
	if err := json.Unmarshal(buf, &man); err != nil {
		return UpdateManifest{}, err
	}
	return man, nil
}

func (d *appDat) ChkUpd() (UpdateInfo, error) {
	updMu.Lock()
	defer updMu.Unlock()

	var rmt UpdateManifest
	raw, _, err := getJSON(updUrls, &rmt)
	if err != nil {
		return UpdateInfo{}, err
	}
	_ = raw

	locVer := "0"
	if loc, err := d.loadLocUM(); err == nil {
		if strings.TrimSpace(loc.Ver) != "" {
			locVer = strings.TrimSpace(loc.Ver)
		}
	}

	keys := keySort(rmt.Items)

	items := make([]UpdateItemInfo, 0, len(keys))
	anyNeed := false
	for _, name := range keys {
		it := rmt.Items[name]
		rel := it.Path
		if rel == "" {
			rel = name
		}

		tgt, err := safeJoin(d.dir, rel)
		if err != nil {
			return UpdateInfo{}, err
		}

		exist, lmd5, need := needMD5(tgt, it.MD5)
		if need {
			anyNeed = true
		}

		sz := kbPars(it.Size)
		items = append(items, UpdateItemInfo{
			Name:      name,
			Path:      rel,
			SizeKB:    sz,
			SizeText:  kbText(sz),
			Run:       boolPars(it.Run),
			RemoteMD5: strings.TrimSpace(it.MD5),
			LocalMD5:  lmd5,
			Need:      need,
			Exists:    exist,
		})
	}

	hasUpd := verCmp(rmt.Ver, locVer) > 0 && anyNeed

	return UpdateInfo{
		LocVer: locVer,
		SrvVer: strings.TrimSpace(rmt.Ver),
		UpdAt:  strings.TrimSpace(rmt.UpdAt),
		SupVer: strings.TrimSpace(rmt.SupVer),
		Mand:   boolPars(rmt.Mand),
		Notes:  rmt.Notes,
		HasUpd: hasUpd,
		Items:  items,
	}, nil
}

func (d *appDat) ChkSyn() (SyncInfo, error) {
	updMu.Lock()
	defer updMu.Unlock()

	var rmt SyncManifest
	_, _, err := getJSON(synUrls, &rmt)
	if err != nil {
		return SyncInfo{}, err
	}

	keys := keySort(rmt.Items)

	items := make([]SyncItemInfo, 0, len(keys))
	for _, name := range keys {
		it := rmt.Items[name]

		tgt, err := safeJoin(d.dir, name)
		if err != nil {
			return SyncInfo{}, err
		}

		exist, lmd5, need := needMD5(tgt, it.MD5)

		sz := kbPars(it.Size)
		items = append(items, SyncItemInfo{
			Name:      name,
			SizeKB:    sz,
			SizeText:  kbText(sz),
			Count:     strings.TrimSpace(it.Count),
			RemoteMD5: strings.TrimSpace(it.MD5),
			LocalMD5:  lmd5,
			Need:      need,
			Exists:    exist,
		})
	}

	return SyncInfo{
		UpdAt: strings.TrimSpace(rmt.UpdAt),
		Notes: rmt.Notes,
		Items: items,
	}, nil
}

func (d *appDat) DoSyn(req map[string]interface{}) (bool, error) {
	updMu.Lock()
	defer updMu.Unlock()

	pol := strings.ToLower(strings.TrimSpace(fmt.Sprint(req["policy"])))
	if pol == "" {
		pol = "auto_selected"
	}

	sel := make(map[string]bool)
	if arr, ok := req["selected"].([]interface{}); ok {
		for _, val := range arr {
			sel[fmt.Sprint(val)] = true
		}
	}

	var rmt SyncManifest
	_, _, err := getJSON(synUrls, &rmt)
	if err != nil {
		return false, err
	}

	chg := false
	for name, it := range rmt.Items {
		if pol == "never" {
			continue
		}
		if pol == "auto_selected" && !sel[name] {
			continue
		}

		tgt, err := safeJoin(d.dir, name)
		if err != nil {
			return chg, err
		}

		if strings.TrimSpace(it.MD5) != "" {
			if m5, err := fileMD5(tgt); err == nil {
				if strings.EqualFold(m5, strings.TrimSpace(it.MD5)) {
					continue
				}
			}
		}

		tmp, err := safeJoin(filepath.Join(d.dir, ".sync_tmp"), name)
		if err != nil {
			return chg, err
		}

		if _, err := dlTo(it.URL, tmp, strings.TrimSpace(it.MD5)); err != nil {
			return chg, err
		}

		if err := os.MkdirAll(filepath.Dir(tgt), 0755); err != nil {
			return chg, err
		}

		_ = os.Remove(tgt)
		if err := os.Rename(tmp, tgt); err != nil {
			if err2 := cpFile(tmp, tgt); err2 != nil {
				return chg, fmt.Errorf(
					"replace %s failed (rename: %v; copy: %w)",
					tgt,
					err,
					err2,
				)
			}
			_ = os.Remove(tmp)
		}
		chg = true
	}
	_ = os.RemoveAll(filepath.Join(d.dir, ".sync_tmp"))
	return chg, nil
}

func (d *appDat) DoUpdNative(onExit func()) (bool, error) {
	updMu.Lock()
	defer updMu.Unlock()

	var rmt UpdateManifest
	raw, _, err := getJSON(updUrls, &rmt)
	if err != nil {
		return false, err
	}

	locVer := "0"
	if loc, err := d.loadLocUM(); err == nil {
		if strings.TrimSpace(loc.Ver) != "" {
			locVer = strings.TrimSpace(loc.Ver)
		}
	}

	if verCmp(rmt.Ver, locVer) <= 0 {
		return false, nil
	}

	keys := keySort(rmt.Items)

	toUpd := make([]PendingUpdateItem, 0)
	tmpDir := filepath.Join(d.dir, ".update_tmp")
	_ = os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return false, err
	}
	// 失败时清理临时目录。
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	for _, name := range keys {
		it := rmt.Items[name]
		rel := it.Path
		if rel == "" {
			rel = name
		}

		tgt, err := safeJoin(d.dir, rel)
		if err != nil {
			return false, err
		}

		_, _, need := needMD5(tgt, it.MD5)
		if !need {
			continue
		}

		tmpP, err := safeJoin(tmpDir, rel)
		if err != nil {
			return false, err
		}
		if _, err := dlTo(it.URL, tmpP, strings.TrimSpace(it.MD5)); err != nil {
			return false, err
		}
		toUpd = append(toUpd, PendingUpdateItem{RelPath: rel, Run: boolPars(it.Run)})
	}

	if len(toUpd) == 0 {
		return false, nil
	}

	pend := PendingUpdate{ManRaw: raw, TmpDir: tmpDir, Items: toUpd}
	pendPth := filepath.Join(d.dir, ".pending_update.json")
	buf, _ := json.MarshalIndent(pend, "", "  ")
	if err := os.WriteFile(pendPth, buf, 0644); err != nil {
		return false, err
	}

	self, err := os.Executable()
	if err != nil {
		return false, err
	}
	updExe := filepath.Join(d.dir, ".updater_tmp.exe")
	if err := cpFile(self, updExe); err != nil {
		return false, err
	}

	cmd := exec.Command(updExe, "--apply-update", pendPth, "--wait-pid", strconv.Itoa(os.Getpid()))
	cmd.Dir = d.dir
	cmd.SysProcAttr = hidAttr()
	if err := cmd.Start(); err != nil {
		return false, err
	}

	if onExit != nil {
		go func() {
			time.Sleep(150 * time.Millisecond)
			onExit()
		}()
	}
	success = true
	return true, nil
}

func AppPend(pendPth string, waitPID int) error {
	buf, err := os.ReadFile(pendPth)
	if err != nil {
		return err
	}
	var pend PendingUpdate
	if err := json.Unmarshal(buf, &pend); err != nil {
		return err
	}

	base := filepath.Dir(pendPth)
	if pend.TmpDir == "" {
		pend.TmpDir = filepath.Join(base, ".update_tmp")
	}
	if rel, err := filepath.Rel(base, pend.TmpDir); err != nil ||
		rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		pend.TmpDir = filepath.Join(base, ".update_tmp")
	}
	defer func() {
		_ = os.RemoveAll(pend.TmpDir)
		_ = os.Remove(pendPth)
		DelSelf()
	}()

	// 等待 UI 进程退出释放文件锁
	if waitPID > 0 {
		waitExit(waitPID, 15*time.Second)
	}

	for _, it := range pend.Items {
		rel := it.RelPath

		tmp, err := safeJoin(pend.TmpDir, rel)
		if err != nil {
			return err
		}
		tgt, err := safeJoin(base, rel)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(tgt), 0755); err != nil {
			return err
		}

		isExe := strings.HasSuffix(strings.ToLower(tgt), ".exe")
		if err := UpFRetry(tmp, tgt, isExe); err != nil {
			return err
		}
	}

	// 写 version.json
	if len(pend.ManRaw) > 0 {
		_ = os.WriteFile(filepath.Join(base, "version.json"), pend.ManRaw, 0644)
	}

	for _, it := range pend.Items {
		if !it.Run {
			continue
		}
		tgt, err := safeJoin(base, it.RelPath)
		if err != nil {
			return err
		}
		if strings.HasSuffix(strings.ToLower(tgt), ".exe") {
			cmd := exec.Command(tgt)
			cmd.Dir = base
			cmd.SysProcAttr = hidAttr()
			_ = cmd.Start()
		}
	}
	return nil
}

// 等待指定 PID 退出
func waitExit(pid int, maxWait time.Duration) {
	if pid <= 0 {
		return
	}
	h, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return // 可能已退出
	}
	defer syscall.CloseHandle(h)

	ms := uint32(maxWait / time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	_, _ = syscall.WaitForSingleObject(h, ms)
	time.Sleep(200 * time.Millisecond) // 额外给句柄释放一点时间
}

func UpFRetry(tmp, tgt string, isExe bool) error {
	const attempts = 120 // 120 * 100ms = 12s

	var lastErr error
	for i := 0; i < attempts; i++ {
		if isExe {
			utils.Kill(filepath.Base(tgt))
		}
		_ = utils.Del(tgt)
		if err := os.Rename(tmp, tgt); err == nil {
			return nil
		} else {
			if err2 := cpFile(tmp, tgt); err2 == nil {
				_ = os.Remove(tmp)
				return nil
			} else {
				lastErr = fmt.Errorf("replace %s failed (rename: %v; copy: %v)", tgt, err, err2)
			}
		}

		time.Sleep(100 * time.Millisecond)
	}
	return lastErr
}

// 删除自身
func DelSelf() {
	self, _ := os.Executable()
	if self == "" {
		return
	}
	if strings.EqualFold(filepath.Base(self), ".updater_tmp.exe") {
		cmd := exec.Command("cmd", "/C", "ping 127.0.0.1 -n 2 >NUL & del /F /Q \""+self+"\"")
		cmd.SysProcAttr = hidAttr()
		_ = cmd.Start()
	}
}
