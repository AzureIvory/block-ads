//go:build windows

package tests

import (
	"block-ads/eradication"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestPersistenceCommandMatching(t *testing.T) {
	exe := `C:\Users\Alice\AppData\Roaming\Bad App\bad.exe`
	dll := `C:\Users\Alice\AppData\Roaming\Bad App\payload.dll`
	for _, tc := range []struct {
		command, target, kind string
		want                  bool
	}{
		{`"C:\Users\Alice\AppData\Roaming\Bad App\bad.exe" --update`, exe, "exe", true},
		{`rundll32.exe "C:\Users\Alice\AppData\Roaming\Bad App\payload.dll",Entry`, dll, "dll", true},
		{`notepad.exe "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe, "exe", false},
		{`cmd.exe /c echo "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe, "exe", false},
		{`cmd.exe /c "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe, "exe", true},
		{`powershell.exe -Command Write-Host "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe, "exe", false},
		{`powershell.exe -File "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe, "exe", true},
		{`"C:\Users\Alice\AppData\Roaming\Bad App\bad.exe.backup"`, exe, "exe", false},
	} {
		if got := eradication.MatchPersistenceCommand(tc.command, tc.target, tc.kind); got != tc.want {
			t.Errorf("match %q = %v, want %v", tc.command, got, tc.want)
		}
	}
}

func TestTaskActionMatchingAndUTF16(t *testing.T) {
	t.Setenv("BLOCK_ADS_TEST_APPDATA", `C:\Users\Alice\AppData\Roaming`)
	target := `C:\Users\Alice\AppData\Roaming\Bad App\bad.exe`
	for _, tc := range []struct {
		command, arguments string
		want               bool
	}{
		{target, `--update`, true},
		{`C:\Windows\System32\cmd.exe`, `/c "` + target + `" --update`, true},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `-NoProfile -File "` + target + `"`, true},
		{`%BLOCK_ADS_TEST_APPDATA%\Bad App\bad.exe`, `--update`, true},
		{`C:\Windows\System32\cmd.exe`, `/c echo "` + target + `"`, false},
	} {
		path := filepath.Join(testRoot(t), "Task")
		definition := fmt.Sprintf(`<Task><Actions><Exec><Command>%s</Command><Arguments>%s</Arguments></Exec></Actions></Task>`, tc.command, tc.arguments)
		words := utf16.Encode([]rune(`<?xml version="1.0" encoding="UTF-16"?>` + definition))
		b := []byte{0xff, 0xfe}
		for _, word := range words {
			b = append(b, byte(word), byte(word>>8))
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := eradication.MatchTaskFile(path, target, "exe")
		if err != nil || got != tc.want {
			t.Fatalf("task match for %q %q = %v, %v; want %v", tc.command, tc.arguments, got, err, tc.want)
		}
	}
}

func TestQuarantineRestoreRoundTrip(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("USERPROFILE", root)
	path := filepath.Join(appData, "Bad", "sample.exe")
	testExecutable(t, path)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(eradication.HitEvent{ID: "round-trip", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || len(cases[0].Artifacts) == 0 || cases[0].Artifacts[0].Status != "quarantined" {
		t.Fatalf("quarantine failed: %+v", cases)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("original still present: %v", err)
	}
	if err := eradication.RestoreCase(root, cases[0].ID); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(content) {
		t.Fatalf("restore changed content: %q, %v", got, err)
	}
	if err := eradication.RestoreCase(root, cases[0].ID); err != nil {
		t.Fatalf("repeat restore failed: %v", err)
	}
	if after := readCases(t, root)[0]; after.Status != "restored" {
		t.Fatalf("restore status = %q", after.Status)
	}
	child := startHelper(t, path)
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(child.Process.Pid))
	if err != nil {
		t.Fatalf("restored executable did not start: %v", err)
	}
	defer windows.CloseHandle(h)
	if state, err := windows.WaitForSingleObject(h, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("restored executable exited immediately: %d, %v", state, err)
	}
}

func TestRestoreWaitsForOccupiedExecutableBeforeStartup(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("USERPROFILE", root)
	path := filepath.Join(appData, "Bad", "sample.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("original executable")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(eradication.HitEvent{ID: "occupied-restore", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || len(cases[0].Artifacts) != 1 || cases[0].Artifacts[0].Status != "quarantined" {
		t.Fatalf("test precondition: %+v", cases)
	}
	c := cases[0]
	link := filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup`, "sample.lnk")
	backup := filepath.Join(root, "eradication", "backups", c.ID, "sample.lnk")
	if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(backup), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("shortcut backup"), 0600); err != nil {
		t.Fatal(err)
	}
	c.Persistence = append(c.Persistence, eradication.PersistenceItem{Type: "startup_link", Name: filepath.Base(link), Location: link, Target: path, BackupPath: backup, Status: "removed"})
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "eradication", "cases", c.ID+".json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	// The occupier deliberately has the same bytes. Hash equality alone cannot
	// prove that this is the quarantined artifact.
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := eradication.RestoreCase(root, c.ID); err == nil {
		t.Fatal("occupied executable path was accepted as restored")
	}
	after := readCases(t, root)[0]
	if after.Status != "partial_restore" || after.Artifacts[0].Status != "quarantined" || after.Persistence[0].Status != "removed" {
		t.Fatalf("failed restore advanced state: %+v", after)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("startup link restored before executable: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := eradication.RestoreCase(root, c.ID); err != nil {
		t.Fatalf("restore retry failed: %v", err)
	}
	after = readCases(t, root)[0]
	if after.Status != "restored" || after.Artifacts[0].Status != "restored" || after.Persistence[0].Status != "restored" {
		t.Fatalf("restore retry did not commit both steps: %+v", after)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(content) {
		t.Fatalf("executable content changed: %q, %v", got, err)
	}
	if got, err := os.ReadFile(link); err != nil || string(got) != "shortcut backup" {
		t.Fatalf("startup link not restored after executable: %q, %v", got, err)
	}
}

func TestDLLRestoreFromQuarantine(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	path := filepath.Join(appData, "Bad", "version.dll")
	systemDLL := filepath.Join(os.Getenv("WINDIR"), "System32", "version.dll")
	content, err := os.ReadFile(systemDLL)
	if err != nil {
		t.Skipf("system DLL unavailable: %v", err)
	}
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	quarantine := filepath.Join(root, "eradication", "quarantine", hash+".dll")
	if err := os.MkdirAll(filepath.Dir(quarantine), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(quarantine, content, 0600); err != nil {
		t.Fatal(err)
	}
	c := eradication.Case{ID: "dll-restore", Artifacts: []eradication.Artifact{{Path: path, Kind: "dll", SHA256: hash, QuarantinePath: quarantine, Status: "quarantined"}}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	casePath := filepath.Join(root, "eradication", "cases", c.ID+".json")
	if err := os.MkdirAll(filepath.Dir(casePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(casePath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := eradication.RestoreCase(root, c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(got) != sum {
		t.Fatalf("DLL restore hash changed: %v", err)
	}
	dll, err := windows.LoadDLL(path)
	if err != nil {
		t.Fatalf("restored DLL cannot be loaded: %v", err)
	}
	defer dll.Release()
}

func TestStartupShortcutRoundTrip(t *testing.T) {
	tool, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skipf("Windows PowerShell unavailable: %v", err)
	}
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))
	t.Setenv("USERPROFILE", root)
	t.Setenv("PROGRAMDATA", filepath.Join(root, "ProgramData"))
	path := filepath.Join(appData, "Bad App", "sample.exe")
	testExecutable(t, path)
	link := filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup`, "sample.lnk")
	if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
		t.Fatal(err)
	}
	script := `$w = New-Object -ComObject WScript.Shell; $l = $w.CreateShortcut($env:BLOCK_ADS_LINK); $l.TargetPath = $env:BLOCK_ADS_TARGET; $l.Arguments = '--update "quoted arg"'; $l.WorkingDirectory = $env:BLOCK_ADS_WORKDIR; $l.Save()`
	cmd := exec.Command(tool, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "BLOCK_ADS_LINK="+link, "BLOCK_ADS_TARGET="+path, "BLOCK_ADS_WORKDIR="+filepath.Dir(path))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create test shortcut: %v: %s", err, out)
	}
	before, err := os.ReadFile(link)
	if err != nil {
		t.Fatal(err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(eradication.HitEvent{ID: "shortcut-round-trip", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad App"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 {
		t.Fatalf("expected one case, got %d", len(cases))
	}
	c := cases[0]
	var shortcut *eradication.PersistenceItem
	for i := range c.Persistence {
		if c.Persistence[i].Type == "startup_link" && c.Persistence[i].Location == link {
			shortcut = &c.Persistence[i]
		}
	}
	if shortcut == nil || shortcut.Status != "removed" || !strings.EqualFold(shortcut.ShortcutTarget, path) || shortcut.ShortcutArguments != `--update "quoted arg"` || !strings.EqualFold(shortcut.ShortcutWorkingDirectory, filepath.Dir(path)) {
		t.Fatalf("shortcut metadata or removal incorrect: %+v", c.Persistence)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("shortcut remained after remediation: %v", err)
	}
	if err := eradication.RestoreCase(root, c.ID); err != nil {
		t.Fatalf("shortcut restore failed: %v", err)
	}
	after, err := os.ReadFile(link)
	if err != nil || string(after) != string(before) {
		t.Fatalf("shortcut binary metadata changed: %v", err)
	}
}

func TestFileIdentityReplacementIsReview(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	path := filepath.Join(appData, "Bad", "sample.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(eradication.HitEvent{ID: "old-file", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || len(cases[0].Artifacts) == 0 || cases[0].Artifacts[0].Confidence == "HIGH" {
		t.Fatalf("replacement authorized: %+v", cases)
	}
	if got, err := os.ReadFile(path); err != nil || !strings.EqualFold(string(got), "replacement") {
		t.Fatalf("replacement changed: %q, %v", got, err)
	}
}

func TestLockedArtifactSchedulesPendingReboot(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	path := filepath.Join(appData, "Bad", "locked.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("locked"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	manager := eradication.NewManager(root, 1, 1)
	scheduled := ""
	manager.ScheduleDeleteAtReboot = func(candidate string) error {
		scheduled = candidate
		return nil
	}
	manager.Submit(eradication.HitEvent{ID: "locked", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || cases[0].Status != "pending_reboot" || len(cases[0].Artifacts) == 0 || cases[0].Artifacts[0].Status != "pending_reboot" || scheduled != path {
		t.Fatalf("locked file counted as success: %+v", cases)
	}
	if err := eradication.RestoreCase(root, cases[0].ID); err == nil {
		t.Fatal("scheduled reboot deletion was incorrectly restored without cancellation")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("locked original missing: %v", err)
	}
	foundFailure, foundSchedule := false, false
	for _, operation := range readOperations(t, root) {
		if operation.Action == "delete_original" && operation.Phase == "failed" && operation.Error != "" {
			foundFailure = true
		}
		if operation.Action == "schedule_reboot_delete" && operation.Phase == "committed" {
			foundSchedule = true
		}
	}
	if !foundFailure || !foundSchedule {
		t.Fatal("sharing violation or reboot scheduling was not recorded in the operation journal")
	}
	findings, err := eradication.InspectRecovery(root)
	if err != nil || len(findings) != 1 || findings[0].Disposition != "pending_reboot" {
		t.Fatalf("scheduled deletion was not left pending: %+v, %v", findings, err)
	}
	secondSchedule := false
	next := eradication.NewManager(root, 1, 1)
	next.ScheduleDeleteAtReboot = func(string) error {
		secondSchedule = true
		return nil
	}
	next.Submit(eradication.HitEvent{ID: "locked-again", PID: 0xfffffffe, CreatedLow: 2, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad"})
	next.Close()
	if secondSchedule {
		t.Fatal("pending reboot case scheduled the same path again")
	}
}

func TestShortcutBackupRestoresExactBytes(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	link := filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup`, "sample.lnk")
	backup := filepath.Join(root, "eradication", "backups", "shortcut-case", "link.bin")
	if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(backup), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte{0x4c, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03}
	if err := os.WriteFile(backup, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := eradication.Case{ID: "shortcut-case", Persistence: []eradication.PersistenceItem{{Type: "startup_link", Name: filepath.Base(link), Location: link, Target: filepath.Join(appData, "sample.exe"), BackupPath: backup, Status: "removed"}}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	casePath := filepath.Join(root, "eradication", "cases", c.ID+".json")
	if err := os.MkdirAll(filepath.Dir(casePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(casePath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := eradication.RestoreCase(root, c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(link)
	if err != nil || string(got) != string(data) {
		t.Fatalf("shortcut bytes changed: %x, %v", got, err)
	}
}
