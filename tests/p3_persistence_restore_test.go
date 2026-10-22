//go:build windows

package tests

import (
	"block-ads/eradication"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func writePersistenceRestoreCase(t *testing.T, root string, item eradication.PersistenceItem) string {
	t.Helper()
	c := eradication.Case{ID: "persistence-restore", Status: "pending_verification", Persistence: []eradication.PersistenceItem{item}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "eradication", "cases")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, c.ID+".json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func shortcutRestoreFixture(t *testing.T) (string, string, eradication.PersistenceItem) {
	t.Helper()
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	link := filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup`, "sample.lnk")
	backup := filepath.Join(root, "eradication", "backups", "persistence-restore", "sample.bin")
	for _, dir := range []string{filepath.Dir(link), filepath.Dir(backup)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(backup, []byte("controlled shortcut backup"), 0600); err != nil {
		t.Fatal(err)
	}
	item := eradication.PersistenceItem{Type: "startup_link", Name: "sample.lnk", Location: link,
		Target: filepath.Join(appData, "Bad", "sample.exe"), BackupPath: backup, Status: "removed"}
	return root, writePersistenceRestoreCase(t, root, item), item
}

func TestCrashAtStartupRestoreBoundaries(t *testing.T) {
	for _, tc := range []struct{ stage, disposition string }{
		{"after_intent", "not_observed"},
		{"after_action", "observed_uncommitted"},
		{"after_result", "manual_review"},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			root, id, item := shortcutRestoreFixture(t)
			runCrashChild(t, root, "restore_persistence", tc.stage, id)
			findings, err := eradication.InspectRecovery(root)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range findings {
				op := finding.Operation
				if op.Action != "restore_persistence" || finding.Disposition != tc.disposition {
					continue
				}
				if op.PersistenceLocation != item.Location || op.BackupPath != item.BackupPath || op.RelatedPath != item.Target || op.ExpectedHash == "" {
					t.Fatalf("restore intent lacks recovery evidence: %+v", op)
				}
				found = true
			}
			if !found {
				t.Fatalf("persistence restore crash was hidden: %+v", findings)
			}
			_, err = os.Stat(item.Location)
			if tc.stage == "after_intent" && !os.IsNotExist(err) || tc.stage != "after_intent" && err != nil {
				t.Fatalf("unexpected shortcut presence: %v", err)
			}
			// Auditing must not turn an observation into a durable result.
			c := readCases(t, root)[0]
			if c.Persistence[0].Status != "removed" {
				t.Fatalf("audit changed stale case: %+v", c)
			}
		})
	}
}

func TestStartupRestoreRefusesChangedInputs(t *testing.T) {
	for _, change := range []string{"occupied", "backup changed", "backup missing"} {
		t.Run(change, func(t *testing.T) {
			root, id, item := shortcutRestoreFixture(t)
			err := eradication.RestoreCaseWithObserver(root, id, func(op eradication.OperationEntry, stage string) {
				if op.Action != "restore_persistence" || stage != "after_intent" {
					return
				}
				var err error
				switch change {
				case "occupied":
					err = os.WriteFile(item.Location, []byte("unrelated shortcut"), 0600)
				case "backup changed":
					err = os.WriteFile(item.BackupPath, []byte("changed backup"), 0600)
				case "backup missing":
					err = os.Remove(item.BackupPath)
				}
				if err != nil {
					t.Fatal(err)
				}
			})
			if err == nil {
				t.Fatal("restore accepted changed input")
			}
			c := readCases(t, root)[0]
			if c.Status != "partial_restore" || c.Persistence[0].Status != "removed" || c.Persistence[0].Error == "" {
				t.Fatalf("failed restore reported success: %+v", c)
			}
			if change == "occupied" {
				if b, err := os.ReadFile(item.Location); err != nil || string(b) != "unrelated shortcut" {
					t.Fatalf("occupying shortcut changed: %q, %v", b, err)
				}
			} else if _, err := os.Stat(item.Location); !os.IsNotExist(err) {
				t.Fatalf("changed backup was published: %v", err)
			}
			failed := false
			for _, op := range readOperations(t, root) {
				if op.Action == "restore_persistence" && op.Phase == "failed" && op.Error != "" {
					failed = true
				}
			}
			if !failed {
				t.Fatal("failed action was not journaled")
			}
		})
	}
}

func TestStartupRestoreRecoveryDetectsConflicts(t *testing.T) {
	for _, change := range []string{"target", "backup"} {
		t.Run(change, func(t *testing.T) {
			root, id, item := shortcutRestoreFixture(t)
			runCrashChild(t, root, "restore_persistence", "after_action", id)
			path := item.Location
			if change == "backup" {
				path = item.BackupPath
			}
			if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil || len(findings) != 1 || findings[0].Disposition != "conflict" {
				t.Fatalf("replacement was not classified as a conflict: %+v, %v", findings, err)
			}
		})
	}
}

func TestStartupRestoreCommitsVerifiedEvidence(t *testing.T) {
	root, id, item := shortcutRestoreFixture(t)
	if err := eradication.RestoreCase(root, id); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(item.Location)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	for _, op := range readOperations(t, root) {
		if op.Action == "restore_persistence" && op.ExpectedHash != hex.EncodeToString(sum[:]) {
			t.Fatalf("committed restore hash differs from shortcut: %+v", op)
		}
	}
	findings, err := eradication.InspectRecovery(root)
	if err != nil || len(findings) != 0 {
		t.Fatalf("verified case has recovery findings: %+v, %v", findings, err)
	}
}

func TestRunRestoreChecksValueTypeAndCrashBoundaries(t *testing.T) {
	if os.Getenv("BLOCK_ADS_TEST_REAL_PERSISTENCE") != "1" {
		t.Skip("requires an isolated Windows runner with registry write access")
	}
	keyPath := `Software\Microsoft\Windows\CurrentVersion\Run`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	for _, scenario := range []string{"after_intent", "after_action", "after_result", "wrong type", "binary value", "success"} {
		t.Run(scenario, func(t *testing.T) {
			root := testRoot(t)
			name := fmt.Sprintf("BlockAdsRestore-%d-%d", os.Getpid(), time.Now().UnixNano())
			t.Cleanup(func() { _ = key.DeleteValue(name) })
			item := eradication.PersistenceItem{Type: "registry_run", Name: name, Location: `HKCU\` + keyPath + ` [view=0]`,
				Target: filepath.Join(root, "sample.exe"), Evidence: `"%APPDATA%\Bad\sample.exe" --update`, ValueType: registry.EXPAND_SZ, Status: "removed"}
			id := writePersistenceRestoreCase(t, root, item)
			if scenario == "wrong type" || scenario == "binary value" {
				if scenario == "wrong type" {
					err = key.SetStringValue(name, item.Evidence)
				} else {
					err = key.SetBinaryValue(name, []byte{1, 2, 3})
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := eradication.RestoreCase(root, id); err == nil {
					t.Fatal("existing value with incompatible type was accepted")
				}
				_, valueType, err := key.GetValue(name, nil)
				if err != nil || scenario == "wrong type" && valueType != registry.SZ || scenario == "binary value" && valueType != registry.BINARY {
					t.Fatalf("conflicting Run value was overwritten: %d, %v", valueType, err)
				}
				return
			}
			if scenario == "success" {
				if err := eradication.RestoreCase(root, id); err != nil {
					t.Fatal(err)
				}
			} else {
				runCrashChild(t, root, "restore_persistence", scenario, id)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "success" {
				if len(findings) != 0 {
					t.Fatalf("committed restore has findings: %+v", findings)
				}
			} else {
				want := map[string]string{"after_intent": "not_observed", "after_action": "observed_uncommitted", "after_result": "manual_review"}[scenario]
				if len(findings) != 1 || findings[0].Disposition != want || findings[0].Operation.ExpectedValue != item.Evidence || findings[0].Operation.ValueType != item.ValueType {
					t.Fatalf("Run restore crash misclassified: %+v", findings)
				}
			}
			if scenario != "after_intent" {
				value, valueType, err := key.GetStringValue(name)
				if err != nil || value != item.Evidence || valueType != item.ValueType {
					t.Fatalf("Run restore changed content or type: %q, %d, %v", value, valueType, err)
				}
			}
		})
	}
}
