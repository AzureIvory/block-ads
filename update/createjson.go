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

func main() {
	baseDir := flag.String("base", ".", "Base directory (default: current working directory)")
	updateFolder := flag.String("updateDir", "update", "Folder containing files to publish")

	version := flag.String("version", "", "Update version (required), e.g. 1.2")
	msupported := flag.String("msupported", "0", "Msupported_version, e.g. 1.0")
	mandatory := flag.Bool("mandatory", false, "mandatory update")
	updatedAt := flag.String("updatedAt", "", "updated_at (default: today YYYY-M-D)")

	notes := flag.String("notes", "", "notes text (supports \\n)")
	notesFile := flag.String("notesFile", "", "read notes from file (UTF-8), overrides -notes")

	fileBase1 := flag.String("fileBase1", "https://raw.githubusercontent.com/AzureIvory/block-ads/refs/heads/main/update/update", "Base URL #1 for downloading files")
	fileBase2 := flag.String("fileBase2", "https://api.ttraw.com/block-ads/update", "Base URL #2 for downloading files")

	runList := flag.String("run", "", "Comma-separated file names (or relative paths) to run after update, e.g. UI.exe")
	forceUpdateTxt := flag.String("txtInUpdate", "", "Comma-separated .txt relative paths to force into update.json (otherwise .txt -> sync.json)")

	outUpdate := flag.String("outUpdate", "update.json", "Output update.json filename")
	outSync := flag.String("outSync", "sync.json", "Output sync.json filename")

	flag.Parse()

	if strings.TrimSpace(*version) == "" {
		fmt.Fprintln(os.Stderr, "-version is required")
		os.Exit(2)
	}

	ua := *updatedAt
	if strings.TrimSpace(ua) == "" {
		ua = time.Now().Format("2006-1-2")
	}

	noteText := *notes
	if strings.TrimSpace(*notesFile) != "" {
		b, err := os.ReadFile(filepath.Join(*baseDir, *notesFile))
		if err != nil {
			fmt.Fprintln(os.Stderr, "read notesFile:", err)
			os.Exit(2)
		}
		noteText = string(b)
	}
	// Support literal \n in -notes
	noteText = strings.ReplaceAll(noteText, "\\n", "\n")

	runSet := make(map[string]bool)
	for _, s := range splitCSV(*runList) {
		runSet[normRel(s)] = true
		runSet[strings.ToLower(filepath.Base(s))] = true
	}

	forceTxtSet := make(map[string]bool)
	for _, s := range splitCSV(*forceUpdateTxt) {
		forceTxtSet[normRel(s)] = true
		forceTxtSet[strings.ToLower(s)] = true
	}

	srcDir := filepath.Join(*baseDir, *updateFolder)
	st, err := os.Stat(srcDir)
	if err != nil || !st.IsDir() {
		fmt.Fprintln(os.Stderr, "update directory not found:", srcDir)
		os.Exit(2)
	}

	updateItems := make(map[string]UpdateItem)
	syncItems := make(map[string]SyncItem)

	// Track collisions of basename keys for update.json
	baseNameCount := make(map[string]int)
	updateEntries := make([]struct {
		Rel string
		Key string
	}, 0)

	err = filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		// skip generated outputs if they are put under update/
		skip := map[string]bool{"update.json": true, "sync.json": true, "version.json": true}
		if skip[strings.ToLower(name)] {
			return nil
		}
		if strings.HasPrefix(name, ".") {
			return nil
		}

		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		rel = normRel(rel)

		md5Hex, err := md5File(p)
		if err != nil {
			return err
		}
		szKB, err := sizeKB(p)
		if err != nil {
			return err
		}

		lowerRel := strings.ToLower(rel)
		isTxt := strings.HasSuffix(strings.ToLower(name), ".txt")
		if isTxt && !forceTxtSet[lowerRel] {
			// sync.json item
			cnt, err := countLines(p)
			if err != nil {
				return err
			}
			key := rel // allow subfolder path in key
			syncItems[key] = SyncItem{
				MD5:   md5Hex,
				Size:  strconv.FormatInt(szKB, 10),
				Count: strconv.FormatInt(cnt, 10),
				URL: []string{
					urlJoin(*fileBase1, rel),
					urlJoin(*fileBase2, rel),
				},
			}
			return nil
		}

		// update.json item
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
		updateItems[rel] = UpdateItem{ // temporary key: rel; we'll remap later
			Path: rel,
			MD5:  md5Hex,
			Size: strconv.FormatInt(szKB, 10),
			Run:  runVal,
			URL: []string{
				urlJoin(*fileBase1, rel),
				urlJoin(*fileBase2, rel),
			},
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "walk updateDir:", err)
		os.Exit(2)
	}

	// Remap update.json keys:
	// prefer basename if unique; otherwise use full relative path.
	finalUpdateItems := make(map[string]UpdateItem)
	// Sort for deterministic output (map order not deterministic, but we want stable collision handling)
	sort.Slice(updateEntries, func(i, j int) bool { return updateEntries[i].Rel < updateEntries[j].Rel })
	for _, e := range updateEntries {
		it := updateItems[e.Rel]
		bn := strings.ToLower(filepath.Base(e.Rel))
		key := filepath.Base(e.Rel)
		if baseNameCount[bn] > 1 {
			key = e.Rel
		}
		// Ensure uniqueness even after collision rule
		if _, exists := finalUpdateItems[key]; exists {
			key = e.Rel
		}
		finalUpdateItems[key] = it
	}

	um := UpdateManifest{
		Version:           strings.TrimSpace(*version),
		UpdatedAt:         strings.TrimSpace(ua),
		MsupportedVersion: strings.TrimSpace(*msupported),
		Mandatory:         boolToStr(*mandatory),
		Notes:             noteText,
		Items:             finalUpdateItems,
	}

	sm := SyncManifest{
		UpdatedAt: strings.TrimSpace(ua),
		Notes:     noteText,
		Items:     syncItems,
	}

	if err := writeJSON(filepath.Join(*baseDir, *outUpdate), um); err != nil {
		fmt.Fprintln(os.Stderr, "write update.json:", err)
		os.Exit(2)
	}
	if err := writeJSON(filepath.Join(*baseDir, *outSync), sm); err != nil {
		fmt.Fprintln(os.Stderr, "write sync.json:", err)
		os.Exit(2)
	}

	fmt.Println("OK")
	fmt.Println("  update items:", len(um.Items))
	fmt.Println("  sync items:", len(sm.Items))
	fmt.Println("  update.json ->", filepath.Join(*baseDir, *outUpdate))
	fmt.Println("  sync.json   ->", filepath.Join(*baseDir, *outSync))
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
	kb := (b + 1023) / 1024
	return kb, nil
}

func countLines(p string) (int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// Increase buffer for very long lines
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
	// collapse //
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
		// fallback
		return strings.TrimRight(base, "/") + "/" + rel
	}
	// Join paths safely and escape each segment
	segments := strings.Split(rel, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	u.Path = path.Join(append([]string{u.Path}, segments...)...)
	return u.String()
}
