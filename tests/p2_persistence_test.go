//go:build windows

package tests

import (
	"block-ads/eradication"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestRegistryRunAndRunOnceRoundTrip(t *testing.T) {
	if os.Getenv("BLOCK_ADS_TEST_REAL_PERSISTENCE") != "1" {
		t.Skip("requires an isolated Windows runner with registry write access")
	}
	for _, kind := range []string{"Run", "RunOnce"} {
		t.Run(kind, func(t *testing.T) {
			root := testRoot(t)
			appData := filepath.Join(root, "AppData", "Roaming")
			t.Setenv("APPDATA", appData)
			t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))
			t.Setenv("USERPROFILE", root)
			t.Setenv("PROGRAMDATA", filepath.Join(root, "ProgramData"))
			path := filepath.Join(appData, "Bad App", "sample.exe")
			testExecutable(t, path)
			keyPath := `Software\Microsoft\Windows\CurrentVersion\` + kind
			key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Close()
			name := fmt.Sprintf("BlockAdsRoundTrip-%d-%d", os.Getpid(), time.Now().UnixNano())
			t.Cleanup(func() { _ = key.DeleteValue(name) })
			command := `"` + path + `" --update`
			if err := key.SetStringValue(name, command); err != nil {
				t.Fatal(err)
			}
			id, err := eradication.FileID(path)
			if err != nil {
				t.Fatal(err)
			}
			manager := eradication.NewManager(root, 1, 1)
			manager.Submit(eradication.HitEvent{ID: "registry-" + kind, PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad App"})
			manager.Close()
			cases := readCases(t, root)
			if len(cases) != 1 {
				t.Fatalf("case count = %d", len(cases))
			}
			var item *eradication.PersistenceItem
			for i := range cases[0].Persistence {
				if cases[0].Persistence[i].Type == "registry_run" && cases[0].Persistence[i].Name == name {
					item = &cases[0].Persistence[i]
				}
			}
			if item == nil || item.Status != "removed" || item.Evidence != command || item.ValueType != registry.SZ || !strings.EqualFold(item.Target, path) {
				t.Fatalf("Run value not removed with exact backup: %+v", cases[0].Persistence)
			}
			if _, _, err := key.GetStringValue(name); !errors.Is(err, registry.ErrNotExist) {
				t.Fatalf("Run value still exists after remediation: %v", err)
			}
			if err := eradication.RestoreCase(root, cases[0].ID); err != nil {
				t.Fatal(err)
			}
			got, valueType, err := key.GetStringValue(name)
			if err != nil || got != command || valueType != registry.SZ {
				t.Fatalf("Run value round-trip changed: %q, %d, %v", got, valueType, err)
			}
		})
	}
}

func TestScheduledTaskRoundTrip(t *testing.T) {
	if os.Getenv("BLOCK_ADS_TEST_REAL_PERSISTENCE") != "1" {
		t.Skip("requires an isolated Windows runner with Task Scheduler access")
	}
	tool, err := exec.LookPath("schtasks.exe")
	if err != nil {
		t.Fatal(err)
	}
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))
	t.Setenv("USERPROFILE", root)
	t.Setenv("PROGRAMDATA", filepath.Join(root, "ProgramData"))
	path := filepath.Join(appData, "Bad App", "sample.exe")
	testExecutable(t, path)
	name := fmt.Sprintf(`\BlockAdsRoundTrip-%d-%d`, os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() { _ = exec.Command(tool, "/Delete", "/TN", name, "/F").Run() })
	command := `"` + path + `" --update`
	if out, err := exec.Command(tool, "/Create", "/TN", name, "/SC", "DAILY", "/ST", "23:59", "/TR", command, "/F").CombinedOutput(); err != nil {
		t.Fatalf("create task: %v: %s", err, out)
	}
	taskPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks", strings.TrimPrefix(name, `\`))
	if matched, err := eradication.MatchTaskFile(taskPath, path, "exe"); err != nil || !matched {
		t.Fatalf("created task action does not match executable: %v, %v", matched, err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(eradication.HitEvent{ID: "task-round-trip", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad App"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 {
		t.Fatalf("case count = %d", len(cases))
	}
	var task *eradication.PersistenceItem
	for i := range cases[0].Persistence {
		if cases[0].Persistence[i].Type == "task" && cases[0].Persistence[i].Name == name {
			task = &cases[0].Persistence[i]
		}
	}
	if task == nil || task.Status != "removed" || task.BackupPath == "" {
		t.Fatalf("task not backed up and removed: %+v", cases[0].Persistence)
	}
	if _, err := os.Stat(taskPath); !os.IsNotExist(err) {
		t.Fatalf("task definition still present: %v", err)
	}
	if err := eradication.RestoreCase(root, cases[0].ID); err != nil {
		t.Fatalf("task restore failed: %v", err)
	}
	if matched, err := eradication.MatchTaskFile(taskPath, path, "exe"); err != nil || !matched {
		t.Fatalf("restored task action changed: %v, %v", matched, err)
	}
}
