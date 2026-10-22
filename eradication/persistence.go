//go:build windows

package eradication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type persistenceTarget struct {
	path string
	kind string
}

// MatchPersistenceCommand applies the same precise target rule as the scanners.
func MatchPersistenceCommand(command, artifactPath, kind string) bool {
	_, ok := exactTarget(command, []persistenceTarget{{path: artifactPath, kind: kind}})
	return ok
}

// MatchTaskFile inspects an existing Task Scheduler XML definition.
func MatchTaskFile(path, artifactPath, kind string) (bool, error) {
	match, _, err := taskTarget(path, []persistenceTarget{{path: artifactPath, kind: kind}})
	return match != "", err
}

func systemTool(name string) (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil || dir == "" {
		return "", fmt.Errorf("Windows system directory unavailable: %v", err)
	}
	return filepath.Join(dir, name), nil
}

func highTargets(artifacts []Artifact) []persistenceTarget {
	out := make([]persistenceTarget, 0, len(artifacts))
	for _, a := range artifacts {
		if a.Confidence == "HIGH" && a.SHA256 != "" && a.FileID != "" {
			out = append(out, persistenceTarget{path: a.Path, kind: a.Kind})
		}
	}
	return out
}

func artifactStillMatches(artifacts []Artifact, path string) bool {
	for _, a := range artifacts {
		if a.Confidence != "HIGH" || !samePath(a.Path, path) || a.SHA256 == "" || a.FileID == "" {
			continue
		}
		id, err := FileID(path)
		if err != nil || id != a.FileID {
			return false
		}
		hash, err := fileSHA256(path)
		return err == nil && hash == a.SHA256
	}
	return false
}

func artifactQuarantined(artifacts []Artifact, path string) bool {
	for _, a := range artifacts {
		if !samePath(a.Path, path) || a.Status != "quarantined" || a.SHA256 == "" {
			continue
		}
		if _, err := os.Lstat(a.Path); !os.IsNotExist(err) {
			return false
		}
		hash, err := fileSHA256(a.QuarantinePath)
		return err == nil && hash == a.SHA256
	}
	return false
}

// exactTarget accepts a full artifact path as the executable or an explicit
// wrapper argument (for example rundll32.exe bad.dll,Entry). Names and parent
// directories are never used to authorize removal.
var percentEnvironment = regexp.MustCompile(`%([^%]+)%`)

func expandTargetEnv(value string) string {
	value = percentEnvironment.ReplaceAllStringFunc(value, func(match string) string {
		if expanded, ok := os.LookupEnv(match[1 : len(match)-1]); ok {
			return expanded
		}
		return match
	})
	return os.ExpandEnv(value)
}

func exactTarget(command string, targets []persistenceTarget) (string, bool) {
	command = strings.TrimSpace(expandTargetEnv(command))
	if command == "" {
		return "", false
	}
	args, err := windows.DecomposeCommandLine(command)
	if err != nil {
		return "", false
	}
	for i, arg := range args {
		candidate := strings.Trim(arg, `"`)
		candidate = strings.TrimPrefix(candidate, `\??\`)
		if comma := strings.IndexByte(candidate, ','); comma >= 0 {
			candidate = candidate[:comma]
		}
		for _, target := range targets {
			if !samePath(candidate, target.path) {
				continue
			}
			if executableArgument(args, i, target.kind) {
				return target.path, true
			}
		}
	}
	return "", false
}

func executableArgument(args []string, index int, kind string) bool {
	if index == 0 {
		return true
	}
	if len(args) < 2 {
		return false
	}
	switch strings.ToLower(filepath.Base(args[0])) {
	case "rundll32.exe":
		return kind == "dll" && index == 1
	case "cmd.exe":
		return index == 2 && (strings.EqualFold(args[1], "/c") || strings.EqualFold(args[1], "/k"))
	case "powershell.exe", "pwsh.exe":
		return index > 1 && strings.EqualFold(args[index-1], "-File")
	case "wscript.exe", "cscript.exe":
		return index == 1
	default:
		return false
	}
}

func scanPersistence(artifacts []Artifact) ([]PersistenceItem, []string) {
	targets := highTargets(artifacts)
	if len(targets) == 0 {
		return nil, nil
	}
	items := []PersistenceItem{}
	errors := []string{}
	for _, scan := range []func([]persistenceTarget) ([]PersistenceItem, []string){scanRegistryRun, scanStartupFolder, scanTasks, scanServices} {
		found, errs := scan(targets)
		items = append(items, found...)
		errors = append(errors, errs...)
	}
	return items, errors
}

type runLocation struct {
	root registry.Key
	name string
	view uint32
}

var runLocations = []runLocation{
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, 0},
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, 0},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WOW64_64KEY},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, registry.WOW64_64KEY},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WOW64_32KEY},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, registry.WOW64_32KEY},
}

func rootName(root registry.Key) string {
	if root == registry.CURRENT_USER {
		return "HKCU"
	}
	return "HKLM"
}

func locationName(loc runLocation) string {
	return fmt.Sprintf("%s\\%s [view=%d]", rootName(loc.root), loc.name, loc.view)
}

func scanRegistryRun(targets []persistenceTarget) ([]PersistenceItem, []string) {
	items := []PersistenceItem{}
	errs := []string{}
	for _, loc := range runLocations {
		key, err := registry.OpenKey(loc.root, loc.name, registry.QUERY_VALUE|loc.view)
		if err != nil {
			if err != registry.ErrNotExist {
				errs = append(errs, locationName(loc)+": "+err.Error())
			}
			continue
		}
		names, err := key.ReadValueNames(0)
		if err != nil {
			errs = append(errs, locationName(loc)+": "+err.Error())
		}
		for _, name := range names {
			value, valueType, err := key.GetStringValue(name)
			if err != nil {
				continue
			}
			if target, ok := exactTarget(value, targets); ok {
				items = append(items, PersistenceItem{Type: "registry_run", Name: name, Location: locationName(loc), Target: target, Evidence: value, ValueType: valueType, Confidence: "HIGH", Status: "pending"})
			}
		}
		key.Close()
	}
	return items, errs
}

func startupFolders() []string {
	return []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		filepath.Join(os.Getenv("PROGRAMDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
	}
}

type shortcutDetails struct {
	Target           string `json:"target"`
	Arguments        string `json:"arguments"`
	WorkingDirectory string `json:"working_directory"`
}

func parseShortcutDetails(out []byte) (shortcutDetails, error) {
	var details shortcutDetails
	if err := json.Unmarshal(out, &details); err != nil {
		return details, err
	}
	if details.Target == "" {
		return details, fmt.Errorf("shortcut has no target")
	}
	return details, nil
}

func shortcutTarget(path string) (shortcutDetails, error) {
	tool, err := systemTool("WindowsPowerShell\\v1.0\\powershell.exe")
	if err != nil {
		return shortcutDetails{}, err
	}
	// PowerShell is under System32/WindowsPowerShell, not in an application
	// directory controlled by a matched process.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	script := `$w = New-Object -ComObject WScript.Shell; $l = $w.CreateShortcut($env:BLOCK_ADS_LINK); [Console]::OutputEncoding = [Text.Encoding]::UTF8; @{target=$l.TargetPath; arguments=$l.Arguments; working_directory=$l.WorkingDirectory} | ConvertTo-Json -Compress`
	cmd := exec.CommandContext(ctx, tool, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "BLOCK_ADS_LINK="+path)
	out, err := cmd.Output()
	if err != nil {
		return shortcutDetails{}, err
	}
	return parseShortcutDetails(out)
}

func shortcutMatchedTarget(link shortcutDetails, targets []persistenceTarget) (string, bool) {
	for _, target := range targets {
		if samePath(link.Target, target.path) {
			return target.path, true
		}
	}
	return exactTarget(`"`+strings.Trim(link.Target, `"`)+`" `+link.Arguments, targets)
}

func scanStartupFolder(targets []persistenceTarget) ([]PersistenceItem, []string) {
	items := []PersistenceItem{}
	errs := []string{}
	for _, dir := range startupFolders() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				errs = append(errs, dir+": "+err.Error())
			}
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".lnk") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			link, err := shortcutTarget(path)
			if err != nil {
				errs = append(errs, path+": "+err.Error())
				continue
			}
			if target, ok := shortcutMatchedTarget(link, targets); ok {
				items = append(items, PersistenceItem{Type: "startup_link", Name: entry.Name(), Location: path, Target: target, Evidence: link.Target + " " + link.Arguments, ShortcutTarget: link.Target, ShortcutArguments: link.Arguments, ShortcutWorkingDirectory: link.WorkingDirectory, Confidence: "HIGH", Status: "pending"})
			}
		}
	}
	return items, errs
}

type taskDefinition struct {
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func taskXMLBytes(b []byte) []byte {
	if len(b) < 2 {
		return b
	}
	if (b[0] == 0xff && b[1] == 0xfe) || (b[0] == 0xfe && b[1] == 0xff) {
		little := b[0] == 0xff
		words := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			if little {
				words = append(words, uint16(b[i])|uint16(b[i+1])<<8)
			} else {
				words = append(words, uint16(b[i])<<8|uint16(b[i+1]))
			}
		}
		return []byte(string(utf16.Decode(words)))
	}
	return b
}

func taskTarget(path string, targets []persistenceTarget) (string, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	var task taskDefinition
	decoder := xml.NewDecoder(bytes.NewReader(taskXMLBytes(b)))
	decoder.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := decoder.Decode(&task); err != nil {
		return "", "", err
	}
	for _, action := range task.Actions.Exec {
		command := strings.TrimSpace(`"` + strings.Trim(action.Command, `"`) + `" ` + action.Arguments)
		for _, target := range targets {
			if samePath(action.Command, target.path) {
				return target.path, command, nil
			}
		}
		if target, ok := exactTarget(command, targets); ok {
			return target, command, nil
		}
	}
	return "", "", nil
}

func scanTasks(targets []persistenceTarget) ([]PersistenceItem, []string) {
	root := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	items := []PersistenceItem{}
	errs := []string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			errs = append(errs, path+": "+walkErr.Error())
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		target, command, err := taskTarget(path, targets)
		if err != nil {
			errs = append(errs, path+": "+err.Error())
			return nil
		}
		if target != "" {
			rel, _ := filepath.Rel(root, path)
			name := `\` + strings.ReplaceAll(rel, `/`, `\`)
			items = append(items, PersistenceItem{Type: "task", Name: name, Location: path, Target: target, Evidence: command, Confidence: "HIGH", Status: "pending"})
		}
		return nil
	})
	if err != nil {
		errs = append(errs, root+": "+err.Error())
	}
	return items, errs
}

func scanServices(targets []persistenceTarget) ([]PersistenceItem, []string) {
	const rootPath = `SYSTEM\CurrentControlSet\Services`
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, rootPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, []string{rootPath + ": " + err.Error()}
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(0)
	if err != nil {
		return nil, []string{rootPath + ": " + err.Error()}
	}
	items := []PersistenceItem{}
	for _, name := range names {
		key, err := registry.OpenKey(root, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		command, _, _ := key.GetStringValue("ImagePath")
		key.Close()
		if target, ok := exactTarget(command, targets); ok {
			items = append(items, PersistenceItem{Type: "service", Name: name, Location: rootPath + `\` + name, Target: target, Evidence: command, Confidence: "HIGH", Status: "pending"})
			continue
		}
		params, err := registry.OpenKey(root, name+`\Parameters`, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		dll, _, _ := params.GetStringValue("ServiceDll")
		params.Close()
		if target, ok := exactTarget(dll, targets); ok {
			items = append(items, PersistenceItem{Type: "service", Name: name, Location: rootPath + `\` + name, Target: target, Evidence: dll, Confidence: "HIGH", Status: "pending"})
		}
	}
	return items, nil
}

func (m *Manager) backupPersistence(caseID string, item *PersistenceItem) error {
	if item == nil {
		return fmt.Errorf("nil persistence item")
	}
	if item.Type == "registry_run" {
		// The original value and its registry type are in the durable case plan.
		return nil
	}
	dir := filepath.Join(m.root, "eradication", "backups", caseID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(item.Type + "\x00" + item.Location))
	base := filepath.Join(dir, hex.EncodeToString(sum[:12]))
	switch item.Type {
	case "startup_link", "task":
		b, err := os.ReadFile(item.Location)
		if err != nil {
			return err
		}
		path := base + ".bin"
		if err := atomicWrite(path, b); err != nil {
			return err
		}
		item.BackupPath = path
		return nil
	case "service":
		path := base + ".reg"
		tool, err := systemTool("reg.exe")
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, tool, "export", `HKLM\`+item.Location, path, "/y").CombinedOutput()
		if err != nil {
			return fmt.Errorf("reg export: %w: %s", err, strings.TrimSpace(string(out)))
		}
		if _, err := os.Stat(path); err != nil {
			return err
		}
		item.BackupPath = path
		return nil
	default:
		return fmt.Errorf("unsupported backup type %s", item.Type)
	}
}

func removePersistence(item *PersistenceItem) error {
	if item == nil || item.Confidence != "HIGH" {
		return fmt.Errorf("persistence item lacks high confidence")
	}
	targets := []persistenceTarget{{path: item.Target, kind: strings.TrimPrefix(strings.ToLower(filepath.Ext(item.Target)), ".")}}
	switch item.Type {
	case "registry_run":
		for _, loc := range runLocations {
			if locationName(loc) != item.Location {
				continue
			}
			key, err := registry.OpenKey(loc.root, loc.name, registry.QUERY_VALUE|registry.SET_VALUE|loc.view)
			if err != nil {
				return err
			}
			defer key.Close()
			value, _, err := key.GetStringValue(item.Name)
			if err != nil {
				return err
			}
			if _, ok := exactTarget(value, targets); !ok {
				return fmt.Errorf("Run value changed before deletion")
			}
			if err := key.DeleteValue(item.Name); err != nil {
				return err
			}
			if _, _, err := key.GetStringValue(item.Name); !errors.Is(err, registry.ErrNotExist) {
				return fmt.Errorf("Run value deletion not verified: %v", err)
			}
			return nil
		}
	case "startup_link":
		link, err := shortcutTarget(item.Location)
		if err != nil {
			return err
		}
		if !samePath(link.Target, item.ShortcutTarget) || link.Arguments != item.ShortcutArguments || link.WorkingDirectory != item.ShortcutWorkingDirectory {
			return fmt.Errorf("shortcut changed before deletion")
		}
		if target, ok := shortcutMatchedTarget(link, targets); !ok || !samePath(target, item.Target) {
			return fmt.Errorf("shortcut target association changed before deletion")
		}
		if err := os.Remove(item.Location); err != nil {
			return err
		}
		if _, err := os.Lstat(item.Location); !os.IsNotExist(err) {
			return fmt.Errorf("shortcut still present after removal: %v", err)
		}
		return nil
	case "task":
		target, _, err := taskTarget(item.Location, targets)
		if err != nil {
			return err
		}
		if !samePath(target, item.Target) {
			return fmt.Errorf("task action changed before deletion")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tool, err := systemTool("schtasks.exe")
		if err != nil {
			return err
		}
		out, err := exec.CommandContext(ctx, tool, "/Delete", "/TN", item.Name, "/F").CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks delete: %w: %s", err, strings.TrimSpace(string(out)))
		}
		if _, err := os.Stat(item.Location); !os.IsNotExist(err) {
			return fmt.Errorf("task deletion not verified: %v", err)
		}
		return nil
	case "service":
		return fmt.Errorf("service remediation is experimental and disabled")
	}
	return fmt.Errorf("unsupported persistence item %s", item.Type)
}
