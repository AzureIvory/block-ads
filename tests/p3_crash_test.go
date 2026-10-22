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

const crashExitCode = 87

func TestJournalCrashChild(t *testing.T) {
	root := os.Getenv("BLOCK_ADS_CRASH_ROOT")
	if root == "" {
		return
	}
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))
	t.Setenv("USERPROFILE", root)
	t.Setenv("PROGRAMDATA", filepath.Join(root, "ProgramData"))
	observer := func(operation eradication.OperationEntry, stage string) {
		if operation.Action == os.Getenv("BLOCK_ADS_CRASH_ACTION") && stage == os.Getenv("BLOCK_ADS_CRASH_STAGE") {
			os.Exit(crashExitCode)
		}
	}
	if id := os.Getenv("BLOCK_ADS_CRASH_RESTORE_CASE"); id != "" {
		if err := eradication.RestoreCaseWithObserver(root, id, observer); err != nil {
			t.Fatal(err)
		}
		t.Fatal("restore did not stop at injected crash boundary")
	}
	path := filepath.Join(appData, "Bad", "sample.exe")
	fileID, err := eradication.FileID(path)
	if err != nil {
		fileID = os.Getenv("BLOCK_ADS_CRASH_FILE_ID")
		if fileID == "" {
			t.Fatal(err)
		}
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.OnOperation = observer
	manager.Submit(eradication.HitEvent{ID: "crash-hit", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	t.Fatal("quarantine did not stop at injected crash boundary")
}

func runCrashChild(t *testing.T, root, action, stage, restoreCase string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestJournalCrashChild$")
	cmd.Env = append(os.Environ(),
		"BLOCK_ADS_CRASH_ROOT="+root,
		"BLOCK_ADS_CRASH_ACTION="+action,
		"BLOCK_ADS_CRASH_STAGE="+stage,
		"BLOCK_ADS_CRASH_RESTORE_CASE="+restoreCase,
	)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != crashExitCode {
		t.Fatalf("crash child exited unexpectedly: %v, output=%s", err, out)
	}
}

func incompleteAction(t *testing.T, root, action string) eradication.OperationEntry {
	t.Helper()
	var intent eradication.OperationEntry
	for _, entry := range readOperations(t, root) {
		if entry.Action == action && entry.Phase == "intent" {
			intent = entry
		}
		if entry.Action == action && entry.Phase != "intent" {
			t.Fatalf("crashed action unexpectedly has result: %+v", entry)
		}
	}
	if intent.ID == "" || intent.Sequence == 0 {
		t.Fatalf("missing durable %s intent", action)
	}
	return intent
}

func TestCrashAtOriginalDeletionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		stage, disposition string
		originalPresent    bool
	}{
		{"after_intent", "not_observed", true},
		{"after_action", "observed_uncommitted", false},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			root := testRoot(t)
			appData := filepath.Join(root, "AppData", "Roaming")
			path := filepath.Join(appData, "Bad", "sample.exe")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			runCrashChild(t, root, "delete_original", tc.stage, "")
			intent := incompleteAction(t, root, "delete_original")
			if _, err := os.Stat(intent.QuarantinePath); err != nil {
				t.Fatalf("quarantine copy missing after crash: %v", err)
			}
			_, err := os.Stat(path)
			if tc.originalPresent && err != nil || !tc.originalPresent && !os.IsNotExist(err) {
				t.Fatalf("original presence after %s: %v", tc.stage, err)
			}
			if _, err := os.Stat(filepath.Join(root, "eradication", "cases", intent.CaseID+"-plan.json")); err != nil {
				t.Fatalf("durable case plan missing after crash: %v", err)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil || len(findings) != 1 || findings[0].Disposition != tc.disposition {
				t.Fatalf("crash recovery classified %s incorrectly: %+v, %v", tc.stage, findings, err)
			}
		})
	}
}

func TestCrashAtQuarantinePreparationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		action, stage, disposition string
	}{
		{"quarantine_copy", "after_intent", "not_observed"},
		{"quarantine_copy", "after_action", "observed_uncommitted"},
		{"quarantine_copy", "after_result", "manual_review"},
		{"quarantine_hash_verify", "after_intent", "manual_review"},
		{"quarantine_hash_verify", "after_action", "manual_review"},
		{"quarantine_hash_verify", "after_result", "manual_review"},
		{"quarantine_publish", "after_intent", "not_observed"},
		{"quarantine_publish", "after_action", "observed_uncommitted"},
		{"quarantine_publish", "after_result", "manual_review"},
	} {
		t.Run(tc.action+"/"+tc.stage, func(t *testing.T) {
			root := testRoot(t)
			path := filepath.Join(root, "AppData", "Roaming", "Bad", "sample.exe")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			runCrashChild(t, root, tc.action, tc.stage, "")
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("preparation crash removed original: %v", err)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil || len(findings) != 1 || findings[0].Disposition != tc.disposition {
				t.Fatalf("preparation crash misclassified: %+v, %v", findings, err)
			}
			if tc.stage == "after_result" {
				if findings[0].Operation.Action != "case_commit" {
					t.Fatalf("committed preparation did not expose missing case: %+v", findings)
				}
			} else if findings[0].Operation.Action != tc.action {
				t.Fatalf("incomplete preparation action was hidden: %+v", findings)
			}
		})
	}
}

func TestCrashAtRestoreFileBoundaries(t *testing.T) {
	for _, tc := range []struct {
		stage, disposition string
		restored           bool
	}{
		{"after_intent", "not_observed", false},
		{"after_action", "observed_uncommitted", true},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			root := testRoot(t)
			appData := filepath.Join(root, "AppData", "Roaming")
			t.Setenv("APPDATA", appData)
			t.Setenv("USERPROFILE", root)
			path := filepath.Join(appData, "Bad", "sample.exe")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			fileID, err := eradication.FileID(path)
			if err != nil {
				t.Fatal(err)
			}
			manager := eradication.NewManager(root, 1, 1)
			manager.Submit(eradication.HitEvent{ID: "restore-crash", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
			manager.Close()
			cases := readCases(t, root)
			if len(cases) != 1 || cases[0].Artifacts[0].Status != "quarantined" {
				t.Fatalf("quarantine precondition failed: %+v", cases)
			}
			runCrashChild(t, root, "restore_file", tc.stage, cases[0].ID)
			incompleteAction(t, root, "restore_file")
			_, err = os.Stat(path)
			if tc.restored && err != nil || !tc.restored && !os.IsNotExist(err) {
				t.Fatalf("restore target presence after %s: %v", tc.stage, err)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil || len(findings) != 1 || findings[0].Disposition != tc.disposition {
				t.Fatalf("restore crash classified %s incorrectly: %+v, %v", tc.stage, findings, err)
			}
		})
	}
}

func TestCrashAtRestorePreparationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		action, stage, disposition string
	}{
		{"restore_copy", "after_intent", "not_observed"},
		{"restore_copy", "after_action", "observed_uncommitted"},
		{"restore_copy", "after_result", "manual_review"},
		{"restore_hash_verify", "after_intent", "manual_review"},
		{"restore_hash_verify", "after_action", "manual_review"},
		{"restore_hash_verify", "after_result", "manual_review"},
	} {
		t.Run(tc.action+"/"+tc.stage, func(t *testing.T) {
			root := testRoot(t)
			appData := filepath.Join(root, "AppData", "Roaming")
			t.Setenv("APPDATA", appData)
			t.Setenv("USERPROFILE", root)
			path := filepath.Join(appData, "Bad", "sample.exe")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			fileID, err := eradication.FileID(path)
			if err != nil {
				t.Fatal(err)
			}
			manager := eradication.NewManager(root, 1, 1)
			manager.Submit(eradication.HitEvent{ID: "restore-prep-crash", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
			manager.Close()
			cases := readCases(t, root)
			if len(cases) != 1 || cases[0].Artifacts[0].Status != "quarantined" {
				t.Fatalf("quarantine precondition failed: %+v", cases)
			}
			runCrashChild(t, root, tc.action, tc.stage, cases[0].ID)
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("restore preparation changed original path: %v", err)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range findings {
				if finding.Operation.Action == tc.action && finding.Disposition == tc.disposition && finding.Operation.TemporaryPath != "" {
					found = true
				}
			}
			if !found {
				t.Fatalf("restore preparation crash misclassified: %+v", findings)
			}
		})
	}
}

func TestCrashAfterResultBeforeCaseCommit(t *testing.T) {
	t.Run("delete_original", func(t *testing.T) {
		root := testRoot(t)
		path := filepath.Join(root, "AppData", "Roaming", "Bad", "sample.exe")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
			t.Fatal(err)
		}
		runCrashChild(t, root, "delete_original", "after_result", "")
		unfinished, err := eradication.UnfinishedOperations(root)
		if err != nil || len(unfinished) != 0 {
			t.Fatalf("completed operation should have no unmatched intent: %+v, %v", unfinished, err)
		}
		findings, err := eradication.InspectRecovery(root)
		if err != nil || len(findings) != 1 || findings[0].Operation.Action != "case_commit" || findings[0].Disposition != "manual_review" {
			t.Fatalf("missing final case was hidden after committed deletion: %+v, %v", findings, err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("original still present after committed deletion: %v", err)
		}
	})
	t.Run("restore_file", func(t *testing.T) {
		root := testRoot(t)
		appData := filepath.Join(root, "AppData", "Roaming")
		t.Setenv("APPDATA", appData)
		t.Setenv("USERPROFILE", root)
		path := filepath.Join(appData, "Bad", "sample.exe")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
			t.Fatal(err)
		}
		fileID, err := eradication.FileID(path)
		if err != nil {
			t.Fatal(err)
		}
		manager := eradication.NewManager(root, 1, 1)
		manager.Submit(eradication.HitEvent{ID: "restore-result-crash", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
		manager.Close()
		cases := readCases(t, root)
		if len(cases) != 1 || cases[0].Artifacts[0].Status != "quarantined" {
			t.Fatalf("quarantine precondition failed: %+v", cases)
		}
		runCrashChild(t, root, "restore_file", "after_result", cases[0].ID)
		unfinished, err := eradication.UnfinishedOperations(root)
		if err != nil || len(unfinished) != 0 {
			t.Fatalf("completed restore operation should have no unmatched intent: %+v, %v", unfinished, err)
		}
		findings, err := eradication.InspectRecovery(root)
		if err != nil || len(findings) != 1 || findings[0].Operation.Action != "restore_file" || findings[0].Disposition != "manual_review" {
			t.Fatalf("stale case state was hidden after committed restore: %+v, %v", findings, err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("restore target missing after committed restore: %v", err)
		}
	})
}

func TestCrashAtCaseCommitBoundaries(t *testing.T) {
	for _, tc := range []struct {
		stage, disposition string
		casePresent        bool
	}{
		{"after_intent", "not_observed", false},
		{"after_action", "observed_uncommitted", true},
		{"after_result", "", true},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			root := testRoot(t)
			path := filepath.Join(root, "AppData", "Roaming", "Bad", "sample.exe")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			runCrashChild(t, root, "case_commit", tc.stage, "")
			cases := readOperations(t, root)
			var commit eradication.OperationEntry
			for _, entry := range cases {
				if entry.Action == "case_commit" && entry.Phase == "intent" {
					commit = entry
				}
			}
			if commit.ID == "" || commit.ExpectedHash == "" || commit.RelatedPath != path {
				t.Fatalf("case commit intent incomplete: %+v", commit)
			}
			_, err := os.Stat(filepath.Join(root, "eradication", "cases", commit.CaseID+".json"))
			if tc.casePresent && err != nil || !tc.casePresent && !os.IsNotExist(err) {
				t.Fatalf("final case presence after %s: %v", tc.stage, err)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil {
				t.Fatal(err)
			}
			if tc.stage == "after_result" {
				if len(findings) != 0 {
					t.Fatalf("committed case has recovery finding: %+v", findings)
				}
			} else if len(findings) != 1 || findings[0].Operation.Action != "case_commit" || findings[0].Disposition != tc.disposition {
				t.Fatalf("case commit crash misclassified: %+v", findings)
			}
		})
	}
}

func TestCrashAtRestoreCaseCommitBoundaries(t *testing.T) {
	for _, tc := range []struct {
		stage, disposition string
	}{
		{"after_intent", "not_observed"},
		{"after_action", "observed_uncommitted"},
		{"after_result", ""},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			root := testRoot(t)
			appData := filepath.Join(root, "AppData", "Roaming")
			t.Setenv("APPDATA", appData)
			t.Setenv("USERPROFILE", root)
			path := filepath.Join(appData, "Bad", "sample.exe")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			fileID, err := eradication.FileID(path)
			if err != nil {
				t.Fatal(err)
			}
			manager := eradication.NewManager(root, 1, 1)
			manager.Submit(eradication.HitEvent{ID: "restore-case-crash", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
			manager.Close()
			cases := readCases(t, root)
			if len(cases) != 1 || cases[0].Artifacts[0].Status != "quarantined" {
				t.Fatalf("quarantine precondition failed: %+v", cases)
			}
			runCrashChild(t, root, "case_commit", tc.stage, cases[0].ID)
			var commit eradication.OperationEntry
			for _, entry := range readOperations(t, root) {
				if entry.Action == "case_commit" && entry.Phase == "intent" && entry.PreviousHash != "" {
					commit = entry
				}
			}
			if commit.ID == "" || commit.ExpectedHash == "" {
				t.Fatalf("restore case commit intent incomplete: %+v", commit)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range findings {
				if finding.Operation.ID == commit.ID && finding.Disposition == tc.disposition {
					found = true
				}
			}
			if tc.stage == "after_result" && found || tc.stage != "after_result" && !found {
				t.Fatalf("restore case commit crash misclassified: %+v", findings)
			}
		})
	}
}

func TestCrashAtSharedReferenceBoundaries(t *testing.T) {
	for _, tc := range []struct {
		action, stage, disposition string
	}{
		{"link_reference", "after_intent", "not_observed"},
		{"link_reference", "after_action", "observed_uncommitted"},
		{"link_reference", "after_result", "manual_review"},
		{"release_reference", "after_intent", "not_observed"},
		{"release_reference", "after_action", "observed_uncommitted"},
		{"release_reference", "after_result", "manual_review"},
	} {
		t.Run(tc.action+"/"+tc.stage, func(t *testing.T) {
			root := testRoot(t)
			appData := filepath.Join(root, "AppData", "Roaming")
			t.Setenv("APPDATA", appData)
			t.Setenv("USERPROFILE", root)
			path := filepath.Join(appData, "Bad", "sample.exe")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			fileID, err := eradication.FileID(path)
			if err != nil {
				t.Fatal(err)
			}
			owner := eradication.NewManager(root, 1, 1)
			owner.Submit(eradication.HitEvent{ID: "shared-owner", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
			owner.Close()
			if tc.action == "release_reference" {
				linked := eradication.NewManager(root, 1, 1)
				linked.Submit(eradication.HitEvent{ID: "shared-linked", PID: 0xfffffffd, CreatedLow: 2, Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
				linked.Close()
				var linkedID string
				for _, c := range readCases(t, root) {
					if c.Hit.ID == "shared-linked" {
						linkedID = c.ID
					}
				}
				if linkedID == "" {
					t.Fatal("linked case missing before release crash")
				}
				runCrashChild(t, root, tc.action, tc.stage, linkedID)
			} else {
				t.Setenv("BLOCK_ADS_CRASH_FILE_ID", fileID)
				runCrashChild(t, root, tc.action, tc.stage, "")
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range findings {
				if finding.Operation.Action == tc.action && finding.Operation.Target == path && finding.Disposition == tc.disposition {
					found = true
				}
			}
			if !found {
				t.Fatalf("shared reference crash misclassified: %+v", findings)
			}
		})
	}
}

func TestCrashAtStartupRemovalBoundaries(t *testing.T) {
	tool, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skipf("Windows PowerShell unavailable: %v", err)
	}
	for _, tc := range []struct {
		stage, disposition string
		linkPresent        bool
	}{
		{"after_intent", "not_observed", true},
		{"after_action", "observed_uncommitted", false},
		{"after_result", "manual_review", false},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			root := testRoot(t)
			appData := filepath.Join(root, "AppData", "Roaming")
			path := filepath.Join(appData, "Bad", "sample.exe")
			link := filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup`, "sample.lnk")
			for _, dir := range []string{filepath.Dir(path), filepath.Dir(link)} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			script := `$w = New-Object -ComObject WScript.Shell; $l = $w.CreateShortcut($env:BLOCK_ADS_LINK); $l.TargetPath = $env:BLOCK_ADS_TARGET; $l.Arguments = '--update'; $l.WorkingDirectory = $env:BLOCK_ADS_WORKDIR; $l.Save()`
			cmd := exec.Command(tool, "-NoProfile", "-NonInteractive", "-Command", script)
			cmd.Env = append(os.Environ(), "BLOCK_ADS_LINK="+link, "BLOCK_ADS_TARGET="+path, "BLOCK_ADS_WORKDIR="+filepath.Dir(path))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("create test shortcut: %v: %s", err, out)
			}
			runCrashChild(t, root, "remove_persistence", tc.stage, "")
			_, err := os.Lstat(link)
			if tc.linkPresent && err != nil || !tc.linkPresent && !os.IsNotExist(err) {
				t.Fatalf("startup link presence after %s: %v", tc.stage, err)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range findings {
				if tc.stage == "after_result" {
					if finding.Operation.Action == "case_commit" && finding.Disposition == tc.disposition {
						found = true
					}
				} else if finding.Operation.Action == "remove_persistence" && finding.Disposition == tc.disposition && finding.Operation.RelatedPath == path && finding.Operation.ExpectedHash != "" {
					found = true
				}
			}
			if !found {
				t.Fatalf("startup removal crash misclassified: %+v", findings)
			}
		})
	}
}

func TestCrashAtRunRemovalBoundaries(t *testing.T) {
	if os.Getenv("BLOCK_ADS_TEST_REAL_PERSISTENCE") != "1" {
		t.Skip("requires an isolated Windows runner with registry write access")
	}
	for _, tc := range []struct {
		stage, disposition string
		valuePresent       bool
	}{
		{"after_intent", "not_observed", true},
		{"after_action", "observed_uncommitted", false},
		{"after_result", "manual_review", false},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			root := testRoot(t)
			path := filepath.Join(root, "AppData", "Roaming", "Bad", "sample.exe")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Close()
			name := fmt.Sprintf("BlockAdsCrash-%d-%d", os.Getpid(), time.Now().UnixNano())
			t.Cleanup(func() { _ = key.DeleteValue(name) })
			command := `"` + path + `" --update`
			if err := key.SetStringValue(name, command); err != nil {
				t.Fatal(err)
			}
			runCrashChild(t, root, "remove_persistence", tc.stage, "")
			value, _, err := key.GetStringValue(name)
			if tc.valuePresent && (err != nil || value != command) || !tc.valuePresent && !errors.Is(err, registry.ErrNotExist) {
				t.Fatalf("Run value presence after %s: %q, %v", tc.stage, value, err)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil {
				t.Fatal(err)
			}
			if !hasRemovalFinding(findings, tc.stage, tc.disposition, "registry_run", path) {
				t.Fatalf("Run removal crash misclassified: %+v", findings)
			}
		})
	}
}

func TestCrashAtTaskRemovalBoundaries(t *testing.T) {
	if os.Getenv("BLOCK_ADS_TEST_REAL_PERSISTENCE") != "1" {
		t.Skip("requires an isolated Windows runner with Task Scheduler access")
	}
	tool, err := exec.LookPath("schtasks.exe")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		stage, disposition string
		taskPresent        bool
	}{
		{"after_intent", "not_observed", true},
		{"after_action", "observed_uncommitted", false},
		{"after_result", "manual_review", false},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			root := testRoot(t)
			path := filepath.Join(root, "AppData", "Roaming", "Bad", "sample.exe")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf(`\BlockAdsCrash-%d-%d`, os.Getpid(), time.Now().UnixNano())
			t.Cleanup(func() { _ = exec.Command(tool, "/Delete", "/TN", name, "/F").Run() })
			command := `"` + path + `" --update`
			if out, err := exec.Command(tool, "/Create", "/TN", name, "/SC", "DAILY", "/ST", "23:59", "/TR", command, "/F").CombinedOutput(); err != nil {
				t.Fatalf("create task: %v: %s", err, out)
			}
			taskPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks", strings.TrimPrefix(name, `\`))
			runCrashChild(t, root, "remove_persistence", tc.stage, "")
			_, err := os.Stat(taskPath)
			if tc.taskPresent && err != nil || !tc.taskPresent && !os.IsNotExist(err) {
				t.Fatalf("task presence after %s: %v", tc.stage, err)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil {
				t.Fatal(err)
			}
			if !hasRemovalFinding(findings, tc.stage, tc.disposition, "task", path) {
				t.Fatalf("task removal crash misclassified: %+v", findings)
			}
		})
	}
}

func hasRemovalFinding(findings []eradication.RecoveryFinding, stage, disposition, kind, path string) bool {
	for _, finding := range findings {
		if stage == "after_result" {
			if finding.Operation.Action == "case_commit" && finding.Disposition == disposition {
				return true
			}
		} else if finding.Operation.Action == "remove_persistence" && finding.Operation.PersistenceType == kind && finding.Operation.RelatedPath == path && finding.Disposition == disposition {
			return true
		}
	}
	return false
}
