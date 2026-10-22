//go:build windows

package tests

import (
	"block-ads/eradication"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func postCleanFixture(t *testing.T) (string, string, eradication.HitEvent) {
	t.Helper()
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))
	t.Setenv("USERPROFILE", root)
	t.Setenv("PROGRAMDATA", filepath.Join(root, "ProgramData"))
	path := filepath.Join(appData, "Bad", "sample.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("controlled artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	return root, path, eradication.HitEvent{ID: "post-clean", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad"}
}

func assertVerificationEvidence(t *testing.T, root string, c eradication.Case) {
	t.Helper()
	if c.Verification == nil || c.Verification.Scope != "immediate" || !c.Verification.RequiresReboot || !c.Verification.RequiresObservation {
		t.Fatalf("verification lacks its scope or remaining requirements: %+v", c.Verification)
	}
	results := map[string]eradication.OperationEntry{}
	for _, operation := range readOperations(t, root) {
		if strings.HasPrefix(operation.Action, "verify_") && operation.Phase != "intent" {
			results[operation.ID] = operation
		}
	}
	for _, check := range c.Verification.Checks {
		result, ok := results[check.OperationID]
		if !ok || result.Outcome != check.Outcome || result.Evidence != check.Evidence || check.At.IsZero() || check.Evidence == "" {
			t.Fatalf("check lacks matching durable evidence: %+v; result=%+v", check, result)
		}
	}
}

func TestPostCleanRecordsImmediateEvidenceWithoutClaimingCompletion(t *testing.T) {
	root, _, hit := postCleanFixture(t)
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(hit)
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 {
		t.Fatalf("case count=%d", len(cases))
	}
	c := cases[0]
	assertVerificationEvidence(t, root, c)
	if c.Status != "pending_verification" || c.Verification.Status != "passed" || len(c.Verification.Checks) != 3 {
		t.Fatalf("immediate verification misreported: %+v", c)
	}
}

func TestPostCleanDetectsFileReappearance(t *testing.T) {
	for _, replacement := range []string{"controlled artifact", "different content"} {
		t.Run(replacement, func(t *testing.T) {
			root, path, hit := postCleanFixture(t)
			manager := eradication.NewManager(root, 1, 1)
			manager.OnOperation = func(operation eradication.OperationEntry, stage string) {
				if operation.Action == "record_ownership" && stage == "after_result" {
					if err := os.WriteFile(path, []byte(replacement), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			manager.Submit(hit)
			manager.Close()
			c := readCases(t, root)[0]
			assertVerificationEvidence(t, root, c)
			if c.Status != "partial_failure" || c.Verification.Status != "failed" {
				t.Fatalf("reappearance hidden: %+v", c)
			}
			if b, err := os.ReadFile(path); err != nil || string(b) != replacement {
				t.Fatalf("verification modified replacement: %q, %v", b, err)
			}
		})
	}
}

func TestPostCleanDetectsRestartedImageWithoutTerminatingIt(t *testing.T) {
	root, path, hit := postCleanFixture(t)
	testExecutable(t, path)
	var err error
	hit.FileID, err = eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var child *exec.Cmd
	manager := eradication.NewManager(root, 1, 1)
	manager.OnOperation = func(operation eradication.OperationEntry, stage string) {
		if operation.Action == "record_ownership" && stage == "after_result" {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			child = startHelper(t, path)
		}
	}
	manager.Submit(hit)
	manager.Close()
	c := readCases(t, root)[0]
	assertVerificationEvidence(t, root, c)
	found := false
	for _, check := range c.Verification.Checks {
		if check.Kind == "process_reappearance" && check.Outcome == "present" && child != nil && strings.Contains(check.Evidence, fmt.Sprintf("PID=%d ", child.Process.Pid)) {
			found = true
		}
	}
	if !found || c.Status != "partial_failure" {
		t.Fatalf("restarted process not reported: %+v", c)
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(child.Process.Pid))
	if err != nil {
		t.Fatalf("restarted process is no longer queryable: %v", err)
	}
	defer windows.CloseHandle(h)
	if state, err := windows.WaitForSingleObject(h, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("verification did not preserve the live restarted process: state=%d err=%v", state, err)
	}
}

func TestPostCleanDetectsStartupRecreation(t *testing.T) {
	tool, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip(err)
	}
	root, path, hit := postCleanFixture(t)
	link := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`, "sample.lnk")
	if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
		t.Fatal(err)
	}
	script := `$w=New-Object -ComObject WScript.Shell; $l=$w.CreateShortcut($env:BLOCK_ADS_LINK); $l.TargetPath=$env:BLOCK_ADS_TARGET; $l.Save()`
	cmd := exec.Command(tool, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "BLOCK_ADS_LINK="+link, "BLOCK_ADS_TARGET="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create shortcut: %v: %s", err, out)
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.OnOperation = func(operation eradication.OperationEntry, stage string) {
		if operation.Action == "remove_persistence" && operation.PersistenceType == "startup_link" && stage == "after_result" {
			if err := os.WriteFile(link, []byte("unrelated replacement"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	manager.Submit(hit)
	manager.Close()
	c := readCases(t, root)[0]
	assertVerificationEvidence(t, root, c)
	if c.Status != "partial_failure" {
		t.Fatalf("Startup reappearance hidden: %+v", c)
	}
	found := false
	for _, check := range c.Verification.Checks {
		if check.Kind == "persistence_absence" && check.Outcome == "present" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Startup observation missing: %+v", c.Verification)
	}
	if b, err := os.ReadFile(link); err != nil || string(b) != "unrelated replacement" {
		t.Fatalf("replacement shortcut modified: %q, %v", b, err)
	}
}

func TestPostCleanDetectsRealPersistenceRecreation(t *testing.T) {
	if os.Getenv("BLOCK_ADS_TEST_REAL_PERSISTENCE") != "1" {
		t.Skip("requires an isolated Windows runner")
	}
	for _, kind := range []string{"registry_run", "task"} {
		t.Run(kind, func(t *testing.T) {
			root, path, hit := postCleanFixture(t)
			name := fmt.Sprintf("BlockAdsPostClean-%d-%d", os.Getpid(), time.Now().UnixNano())
			var recreate func()
			var verifyReplacement func()
			if kind == "registry_run" {
				key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
				if err != nil {
					t.Fatal(err)
				}
				defer key.Close()
				defer key.DeleteValue(name)
				if err := key.SetStringValue(name, `"`+path+`" --update`); err != nil {
					t.Fatal(err)
				}
				recreate = func() {
					if err := key.SetBinaryValue(name, []byte{1, 2, 3}); err != nil {
						t.Fatal(err)
					}
				}
				verifyReplacement = func() {
					_, valueType, err := key.GetValue(name, nil)
					if err != nil || valueType != registry.BINARY {
						t.Fatalf("replacement Run value changed: %d, %v", valueType, err)
					}
				}
			} else {
				tool, err := exec.LookPath("schtasks.exe")
				if err != nil {
					t.Fatal(err)
				}
				name = `\` + name
				defer exec.Command(tool, "/Delete", "/TN", name, "/F").Run()
				create := func(command string) {
					t.Helper()
					if out, err := exec.Command(tool, "/Create", "/TN", name, "/SC", "DAILY", "/ST", "23:59", "/TR", command).CombinedOutput(); err != nil {
						t.Fatalf("create task: %v: %s", err, out)
					}
				}
				create(`"` + path + `" --update`)
				recreate = func() { create(`cmd.exe /c exit 0`) }
				verifyReplacement = func() {
					if err := exec.Command(tool, "/Query", "/TN", name).Run(); err != nil {
						t.Fatalf("replacement task removed: %v", err)
					}
				}
			}
			manager := eradication.NewManager(root, 1, 1)
			manager.OnOperation = func(operation eradication.OperationEntry, stage string) {
				if operation.Action == "remove_persistence" && operation.PersistenceType == kind && stage == "after_result" {
					recreate()
				}
			}
			manager.Submit(hit)
			manager.Close()
			c := readCases(t, root)[0]
			assertVerificationEvidence(t, root, c)
			if c.Status != "partial_failure" {
				t.Fatalf("persistence reappearance hidden: %+v", c)
			}
			verifyReplacement()
		})
	}
}

func TestPostCleanJournalFailureCannotCountAsPassed(t *testing.T) {
	root, _, hit := postCleanFixture(t)
	manager := eradication.NewManager(root, 1, 1)
	manager.OnOperation = func(operation eradication.OperationEntry, stage string) {
		if operation.Action == "verify_file_absence" && stage == "after_intent" {
			path := filepath.Join(root, "eradication", "journal", operation.CaseID, operation.ID+"-committed.json")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	manager.Submit(hit)
	manager.Close()
	c := readCases(t, root)[0]
	if c.Status != "pending_verification" || c.Verification == nil || c.Verification.Status != "incomplete" {
		t.Fatalf("unrecorded verification counted as passed: %+v", c)
	}
	found := false
	for _, check := range c.Verification.Checks {
		if check.Kind == "file_absence" && check.Error != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("journal failure reason missing: %+v", c.Verification)
	}
	unfinished, err := eradication.UnfinishedOperations(root)
	if err != nil || len(unfinished) != 1 || unfinished[0].Action != "verify_file_absence" {
		t.Fatalf("unrecorded result hidden: %+v, %v", unfinished, err)
	}
}

func TestCrashAtPostCleanVerificationBoundaries(t *testing.T) {
	for _, stage := range []string{"after_intent", "after_action", "after_result"} {
		t.Run(stage, func(t *testing.T) {
			root, path, _ := postCleanFixture(t)
			runCrashChild(t, root, "verify_file_absence", stage, "")
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("verification crash changed deletion result: %v", err)
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil || len(findings) != 1 || findings[0].Disposition != "manual_review" {
				t.Fatalf("verification crash hidden: %+v, %v", findings, err)
			}
			want := "verify_file_absence"
			if stage == "after_result" {
				want = "case_commit"
			}
			if findings[0].Operation.Action != want {
				t.Fatalf("wrong crash boundary: %+v", findings)
			}
		})
	}
}
