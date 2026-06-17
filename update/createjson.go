package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 默认下载基址（GUI / CLI 共用）。
const (
	defaultBase1 = "https://api.ttraw.com/block-ads/update/"
	defaultBase2 = "https://raw.githubusercontent.com/AzureIvory/block-ads/refs/heads/main/update/update/"
)

type UpdateManifest struct {
	Version           string                `json:"version"`
	UpdatedAt         string                `json:"updated_at"`
	MsupportedVersion string                `json:"Msupported_version"`
	Mandatory         string                `json:"mandatory"`
	Notes             string                `json:"notes"`
	Items             map[string]UpdateItem `json:"items"`
}

type UpdateItem struct {
	Path string   `json:"path"`
	MD5  string   `json:"md5"`
	Size string   `json:"size"` // KB (integer as string)
	Run  string   `json:"run"`  // "True" / "False"
	URL  []string `json:"url"`
}

type SyncManifest struct {
	UpdatedAt string              `json:"updated_at"`
	Notes     string              `json:"notes"`
	Items     map[string]SyncItem `json:"items"`
}

type SyncItem struct {
	MD5   string   `json:"md5"`
	Size  string   `json:"size"`  // KB (integer as string)
	Count string   `json:"count"` // lines as string
	URL   []string `json:"url"`
}

// genOptions 是一次生成的全部输入，GUI 与 CLI 各自填充后调用 generate。
type genOptions struct {
	BaseDir   string // 输出目录（update.json/sync.json 写到这里）
	UpdateDir string // 待发布的源文件目录（被扫描）
	Version   string
	Msupport  string
	Mandatory bool
	UpdatedAt string // 空则取今天
	Notes     string
	NotesFile string // 非空则从该文件读 notes，覆盖 Notes
	RunList   string // 逗号分隔，更新后运行的文件
	ForceTxt  string // 逗号分隔，强制进 update.json 的 .txt
	Base1     string // 下载基址1
	Base2     string // 下载基址2
	OutUpdate string // update.json 文件名
	OutSync   string // sync.json 文件名
}

func main() {
	// 无参数 → GUI；有参数 → 命令行（沿用旧用法，但默认值已内置新 URL）。
	if len(os.Args) <= 1 {
		runGUI()
		return
	}
	runCLI()
}

// runCLI 命令行入口，默认值已内置新 URL 基址。
func runCLI() {
	// 默认 baseDir 为程序/exe 所在目录；CLI 仍可 -base 覆盖。
	exeBase := exeDir()
	baseDir := flag.String("base", exeBase, "输出目录（默认：程序所在目录）")
	updateDir := flag.String("updateDir", "update", "待发布的源文件目录")
	version := flag.String("version", "", "版本号（必填），如 1.2")
	msupport := flag.String("msupported", "0", "最低支持版本")
	mandatory := flag.Bool("mandatory", false, "强制更新")
	updatedAt := flag.String("updatedAt", "", "更新日期，默认今天")
	notes := flag.String("notes", "", "更新说明，支持 \\n")
	notesFile := flag.String("notesFile", "", "从文件读更新说明（覆盖 -notes）")
	base1 := flag.String("fileBase1", defaultBase1, "下载基址1")
	base2 := flag.String("fileBase2", defaultBase2, "下载基址2")
	runList := flag.String("run", "", "更新后运行的文件，逗号分隔，如 UI.exe")
	forceTxt := flag.String("txtInUpdate", "", "强制进 update.json 的 .txt，逗号分隔")
	outUpdate := flag.String("outUpdate", "update.json", "update.json 文件名")
	outSync := flag.String("outSync", "sync.json", "sync.json 文件名")
	flag.Parse()

	o := genOptions{
		BaseDir:   *baseDir,
		UpdateDir: *updateDir,
		Version:   *version,
		Msupport:  *msupport,
		Mandatory: *mandatory,
		UpdatedAt: *updatedAt,
		Notes:     *notes,
		NotesFile: *notesFile,
		Base1:     *base1,
		Base2:     *base2,
		RunList:   *runList,
		ForceTxt:  *forceTxt,
		OutUpdate: *outUpdate,
		OutSync:   *outSync,
	}

	if strings.TrimSpace(o.Version) == "" {
		fmt.Fprintln(os.Stderr, "-version is required")
		os.Exit(2)
	}
	if _, err := generate(o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// generate 扫描 UpdateDir、生成 update.json/sync.json，返回统计。
func generate(o genOptions) (stats string, err error) {
	if strings.TrimSpace(o.Version) == "" {
		return "", fmt.Errorf("version 不能为空")
	}
	if strings.TrimSpace(o.Base1) == "" {
		o.Base1 = defaultBase1
	}
	if strings.TrimSpace(o.Base2) == "" {
		o.Base2 = defaultBase2
	}
	ua := o.UpdatedAt
	if strings.TrimSpace(ua) == "" {
		ua = time.Now().Format("2006-1-2")
	}

	noteText := o.Notes
	if strings.TrimSpace(o.NotesFile) != "" {
		b, e := os.ReadFile(filepath.Join(o.BaseDir, o.NotesFile))
		if e != nil {
			return "", fmt.Errorf("read notesFile: %w", e)
		}
		noteText = string(b)
	}
	noteText = strings.ReplaceAll(noteText, "\\n", "\n")

	runSet := make(map[string]bool)
	for _, s := range splitCSV(o.RunList) {
		runSet[normRel(s)] = true
		runSet[strings.ToLower(filepath.Base(s))] = true
	}
	forceTxtSet := make(map[string]bool)
	for _, s := range splitCSV(o.ForceTxt) {
		forceTxtSet[normRel(s)] = true
		forceTxtSet[strings.ToLower(s)] = true
	}

	// UpdateDir 既支持相对（拼到 BaseDir 下）也支持绝对路径。
	srcDir := o.UpdateDir
	if !filepath.IsAbs(srcDir) {
		srcDir = filepath.Join(o.BaseDir, srcDir)
	}
	st, e := os.Stat(srcDir)
	if e != nil || !st.IsDir() {
		return "", fmt.Errorf("update 目录不存在: %s", srcDir)
	}

	updateItems := make(map[string]UpdateItem)
	syncItems := make(map[string]SyncItem)
	baseNameCount := make(map[string]int)
	updateEntries := make([]struct {
		Rel string
		Key string
	}, 0)

	if e := filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		skip := map[string]bool{"update.json": true, "sync.json": true, "version.json": true}
		if skip[strings.ToLower(name)] {
			return nil
		}
		if strings.HasPrefix(name, ".") {
			return nil
		}

		rel, e := filepath.Rel(srcDir, p)
		if e != nil {
			return e
		}
		rel = normRel(rel)

		md5Hex, e := md5File(p)
		if e != nil {
			return e
		}
		szKB, e := sizeKB(p)
		if e != nil {
			return e
		}

		lowerRel := strings.ToLower(rel)
		isTxt := strings.HasSuffix(strings.ToLower(name), ".txt")
		if isTxt && !forceTxtSet[lowerRel] {
			cnt, e := countLines(p)
			if e != nil {
				return e
			}
			syncItems[rel] = SyncItem{
				MD5:   md5Hex,
				Size:  strconv.FormatInt(szKB, 10),
				Count: strconv.FormatInt(cnt, 10),
				URL:   []string{urlJoin(o.Base1, rel), urlJoin(o.Base2, rel)},
			}
			return nil
		}

		bn := strings.ToLower(filepath.Base(rel))
		baseNameCount[bn]++
		updateEntries = append(updateEntries, struct {
			Rel string
			Key string
		}{Rel: rel, Key: bn})

		runVal := "False"
		if runSet[lowerRel] || runSet[bn] {
			runVal = "True"
		}
		updateItems[rel] = UpdateItem{
			Path: rel,
			MD5:  md5Hex,
			Size: strconv.FormatInt(szKB, 10),
			Run:  runVal,
			URL:  []string{urlJoin(o.Base1, rel), urlJoin(o.Base2, rel)},
		}
		return nil
	}); e != nil {
		return "", fmt.Errorf("walk updateDir: %w", e)
	}

	finalUpdateItems := make(map[string]UpdateItem)
	sort.Slice(updateEntries, func(i, j int) bool { return updateEntries[i].Rel < updateEntries[j].Rel })
	for _, en := range updateEntries {
		it := updateItems[en.Rel]
		bn := strings.ToLower(filepath.Base(en.Rel))
		key := filepath.Base(en.Rel)
		if baseNameCount[bn] > 1 {
			key = en.Rel
		}
		if _, exists := finalUpdateItems[key]; exists {
			key = en.Rel
		}
		finalUpdateItems[key] = it
	}

	um := UpdateManifest{
		Version:           strings.TrimSpace(o.Version),
		UpdatedAt:         strings.TrimSpace(ua),
		MsupportedVersion: strings.TrimSpace(o.Msupport),
		Mandatory:         boolToStr(o.Mandatory),
		Notes:             noteText,
		Items:             finalUpdateItems,
	}
	sm := SyncManifest{
		UpdatedAt: strings.TrimSpace(ua),
		Notes:     noteText,
		Items:     syncItems,
	}

	if e := writeJSON(filepath.Join(o.BaseDir, o.OutUpdate), um); e != nil {
		return "", fmt.Errorf("write update.json: %w", e)
	}
	if e := writeJSON(filepath.Join(o.BaseDir, o.OutSync), sm); e != nil {
		return "", fmt.Errorf("write sync.json: %w", e)
	}
	return fmt.Sprintf("update 项: %d\nsync 项: %d\nupdate.json -> %s\nsync.json   -> %s",
		len(um.Items), len(sm.Items),
		filepath.Join(o.BaseDir, o.OutUpdate),
		filepath.Join(o.BaseDir, o.OutSync)), nil
}

// exeDir 返回当前可执行文件所在目录；非 exe（go run）时回退到工作目录。
func exeDir() string {
	if ex, e := os.Executable(); e == nil {
		return filepath.Dir(ex)
	}
	d, e := os.Getwd()
	if e != nil {
		return "."
	}
	return d
}

func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(p, b, 0644)
}

func md5File(p string) (string, error) {
	f, err := os.Open(p)
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

func sizeKB(p string) (int64, error) {
	st, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	b := st.Size()
	if b <= 0 {
		return 0, nil
	}
	return (b + 1023) / 1024, nil
}

func countLines(p string) (int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	var n int64
	for sc.Scan() {
		n++
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return n, nil
}

func boolToStr(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func normRel(rel string) string {
	rel = filepath.ToSlash(rel)
	rel = strings.TrimPrefix(rel, "./")
	rel = strings.TrimPrefix(rel, "/")
	for strings.Contains(rel, "//") {
		rel = strings.ReplaceAll(rel, "//", "/")
	}
	return rel
}

func urlJoin(base string, rel string) string {
	base = strings.TrimSpace(base)
	rel = normRel(rel)
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" {
		return strings.TrimRight(base, "/") + "/" + rel
	}
	segments := strings.Split(rel, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	u.Path = path.Join(append([]string{u.Path}, segments...)...)
	return u.String()
}
