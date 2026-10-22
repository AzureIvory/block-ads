//go:build windows

package tests

import (
	"block-ads/eradication"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func observationManager(t *testing.T, root string, window, interval time.Duration) (*eradication.Manager, <-chan string) {
	t.Helper()
	m, err := eradication.NewManagerWithObservation(root, 1, 1, eradication.ObservationOptions{Window: window, Interval: interval})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	seed := make(chan string, 1)
	var once sync.Once
	m.OnOperation = func(operation eradication.OperationEntry, stage string) {
		if operation.Action == "case_commit" && stage == "after_result" {
			once.Do(func() { seed <- operation.CaseID })
		}
	}
	return m, seed
}

func waitObservationSeed(t *testing.T, seed <-chan string) string {
	t.Helper()
	select {
	case id := <-seed:
		return id
	case <-time.After(10 * time.Second):
		t.Fatal("initial case was not committed")
		return ""
	}
}

func waitObservationCase(t *testing.T, root, id string) eradication.Case {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(filepath.Join(root, "eradication", "cases", id+".json"))
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var c eradication.Case
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		if c.Observation != nil && c.Observation.Status != "observing" {
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("observation did not finish")
	return eradication.Case{}
}

func TestObservationCompletesBoundedWindowButRequiresReboot(t *testing.T) {
	root, _, hit := postCleanFixture(t)
	m, seed := observationManager(t, root, 1200*time.Millisecond, time.Second)
	m.Submit(hit)
	c := waitObservationCase(t, root, waitObservationSeed(t, seed))
	if c.Status != "pending_verification" || c.Observation.Status != "completed" || c.Observation.Samples < 2 || c.Observation.LastSampleAt.Before(c.Observation.DeadlineAt) || c.Verification.RequiresObservation || !c.Verification.RequiresReboot {
		t.Fatalf("bounded window incorrectly claimed completion: %+v", c)
	}
	results := map[string]eradication.OperationEntry{}
	for _, op := range readOperations(t, root) {
		if strings.Contains(op.Precondition, "scope=bounded") && op.Phase != "intent" {
			results[op.ID] = op
		}
	}
	for _, check := range c.Observation.Checks {
		if result, ok := results[check.OperationID]; !ok || result.Outcome != check.Outcome || result.Evidence != check.Evidence {
			t.Fatalf("sample lacks durable evidence: %+v", check)
		}
	}
}

func TestObservationDetectsDelayedFileReappearance(t *testing.T) {
	root, path, hit := postCleanFixture(t)
	m, seed := observationManager(t, root, 2*time.Second, 200*time.Millisecond)
	m.Submit(hit)
	id := waitObservationSeed(t, seed)
	if err := os.WriteFile(path, []byte("late replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	c := waitObservationCase(t, root, id)
	if c.Verification.Status != "passed" || c.Status != "partial_failure" || c.Observation.Status != "failed" {
		t.Fatalf("delayed reappearance was hidden: %+v", c)
	}
	found := false
	for _, check := range c.Observation.Checks {
		if check.Kind == "file_absence" && check.Outcome == "present" && !check.At.Before(c.Verification.FinishedAt) {
			found = true
		}
	}
	if !found {
		t.Fatalf("late evidence missing: %+v", c.Observation)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "late replacement" {
		t.Fatalf("replacement changed: %q %v", b, err)
	}
}

func TestObservationDoesNotBlockQueueAndCloseInterruptsWindows(t *testing.T) {
	root, path, hit := postCleanFixture(t)
	m, seed := observationManager(t, root, 10*time.Second, 5*time.Second)
	second := hit
	second.ID = "second-observation"
	second.Image = filepath.Join(filepath.Dir(path), "second.exe")
	if err := os.WriteFile(second.Image, []byte("second artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	var err error
	second.FileID, err = eradication.FileID(second.Image)
	if err != nil {
		t.Fatal(err)
	}
	contained := make(chan struct{}, 1)
	m.OnContainment = func(hit eradication.HitEvent, exited bool, err error) {
		if hit.ID == second.ID {
			contained <- struct{}{}
		}
	}
	m.Submit(hit)
	waitObservationSeed(t, seed)
	m.Submit(second)
	select {
	case <-contained:
	case <-time.After(3 * time.Second):
		t.Fatal("observation sleep blocked next cleanup")
	}
	m.Close()
	cases := readCases(t, root)
	if len(cases) != 2 {
		t.Fatalf("case count=%d", len(cases))
	}
	for _, c := range cases {
		if c.Observation == nil || c.Observation.Status != "interrupted" || c.Observation.Samples != 0 || !c.Verification.RequiresObservation {
			t.Fatalf("shutdown counted as completed observation: %+v", c)
		}
	}
}

func TestObservationRefusesToOverwriteConcurrentCaseChange(t *testing.T) {
	root, _, hit := postCleanFixture(t)
	m, seed := observationManager(t, root, 2*time.Second, 100*time.Millisecond)
	previous := m.OnOperation
	changed := make(chan struct{}, 1)
	var once sync.Once
	m.OnOperation = func(op eradication.OperationEntry, stage string) {
		previous(op, stage)
		if op.Action == "verify_file_absence" && stage == "after_result" && strings.Contains(op.Precondition, "scope=bounded") {
			once.Do(func() {
				path := filepath.Join(root, "eradication", "cases", op.CaseID+".json")
				b, err := os.ReadFile(path)
				if err != nil {
					t.Error(err)
					return
				}
				var c eradication.Case
				if err := json.Unmarshal(b, &c); err != nil {
					t.Error(err)
					return
				}
				c.Status = "restored"
				c.Observation.Status = "external_change"
				b, err = json.Marshal(c)
				if err != nil {
					t.Error(err)
					return
				}
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Error(err)
					return
				}
				changed <- struct{}{}
			})
		}
	}
	m.Submit(hit)
	id := waitObservationSeed(t, seed)
	select {
	case <-changed:
	case <-time.After(10 * time.Second):
		t.Fatal("bounded sample did not execute")
	}
	m.Close()
	c := waitObservationCase(t, root, id)
	if c.Status != "restored" || c.Observation.Status != "external_change" {
		t.Fatalf("observation overwrote external change: %+v", c)
	}
}

func TestObservationJournalFailurePreventsCompletedStatus(t *testing.T) {
	root, _, hit := postCleanFixture(t)
	m, seed := observationManager(t, root, 500*time.Millisecond, 100*time.Millisecond)
	previous := m.OnOperation
	m.OnOperation = func(op eradication.OperationEntry, stage string) {
		previous(op, stage)
		if op.Action == "verify_file_absence" && stage == "after_intent" && strings.Contains(op.Precondition, "scope=bounded") {
			if err := os.Mkdir(filepath.Join(root, "eradication", "journal", op.CaseID, op.ID+"-committed.json"), 0700); err != nil {
				t.Error(err)
			}
		}
	}
	m.Submit(hit)
	c := waitObservationCase(t, root, waitObservationSeed(t, seed))
	if c.Observation.Status != "incomplete" || !c.Observation.Incomplete || !c.Verification.RequiresObservation || c.Status != "pending_verification" {
		t.Fatalf("unrecorded sample counted as completion: %+v", c)
	}
}

func TestObservationOptionsAreBounded(t *testing.T) {
	for _, options := range []eradication.ObservationOptions{
		{Window: -time.Second, Interval: time.Second},
		{Window: 2 * time.Minute, Interval: time.Second},
		{Window: time.Second, Interval: time.Millisecond},
		{Window: time.Second, Interval: 2 * time.Second},
	} {
		if m, err := eradication.NewManagerWithObservation(testRoot(t), 1, 1, options); err == nil {
			m.Close()
			t.Fatalf("invalid options accepted: %+v", options)
		}
	}
}

func TestObservationDetectsDelayedProcessReappearance(t *testing.T) {
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
	m, seed := observationManager(t, root, 2*time.Second, 500*time.Millisecond)
	m.Submit(hit)
	id := waitObservationSeed(t, seed)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	child := startHelper(t, path)
	c := waitObservationCase(t, root, id)
	if c.Verification.Status != "passed" || c.Observation.Status != "failed" || c.Status != "partial_failure" {
		t.Fatalf("delayed process restart hidden: %+v", c)
	}
	found := false
	for _, check := range c.Observation.Checks {
		if check.Kind == "process_reappearance" && check.Outcome == "present" && strings.Contains(check.Evidence, fmt.Sprintf("PID=%d ", child.Process.Pid)) && strings.Contains(check.Evidence, fmt.Sprintf("parent_PID=%d ", os.Getpid())) {
			found = true
		}
	}
	if !found {
		t.Fatalf("restarted process identity missing: %+v", c.Observation)
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if state, err := windows.WaitForSingleObject(h, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("observation altered process: %d, %v", state, err)
	}
}

func TestObservationDelayedSamplesCannotCountAsCompleteCoverage(t *testing.T) {
	root, _, hit := postCleanFixture(t)
	m, seed := observationManager(t, root, 300*time.Millisecond, 100*time.Millisecond)
	previous := m.OnOperation
	m.OnOperation = func(op eradication.OperationEntry, stage string) {
		previous(op, stage)
		if op.Action == "verify_process_exit" && stage == "after_result" && strings.Contains(op.Precondition, "scope=bounded") {
			time.Sleep(400 * time.Millisecond)
		}
	}
	m.Submit(hit)
	c := waitObservationCase(t, root, waitObservationSeed(t, seed))
	if c.Observation.Status != "incomplete" || !c.Observation.Incomplete || c.Observation.MaxGapMS <= 200 || !c.Verification.RequiresObservation {
		t.Fatalf("missed samples counted as coverage: %+v", c)
	}
	for _, check := range c.Observation.Checks {
		if check.Outcome != "absent" || check.Error != "" {
			t.Fatalf("test did not isolate timing failure: %+v", check)
		}
	}
}

func TestObservationDetectsRealPersistenceRecreation(t *testing.T) {
	if os.Getenv("BLOCK_ADS_TEST_REAL_PERSISTENCE") != "1" {
		t.Skip("requires an isolated Windows runner")
	}
	for _, kind := range []string{"registry_run", "task"} {
		t.Run(kind, func(t *testing.T) {
			root, path, hit := postCleanFixture(t)
			name := fmt.Sprintf("BlockAdsObservation-%d-%d", os.Getpid(), time.Now().UnixNano())
			var recreate, verifyReplacement func()
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
					if err := key.SetBinaryValue(name, []byte{4, 5, 6}); err != nil {
						t.Fatal(err)
					}
				}
				verifyReplacement = func() {
					_, kind, err := key.GetValue(name, nil)
					if err != nil || kind != registry.BINARY {
						t.Fatalf("replacement modified: %d %v", kind, err)
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
						t.Fatalf("replacement removed: %v", err)
					}
				}
			}
			m, seed := observationManager(t, root, 2*time.Second, 500*time.Millisecond)
			m.Submit(hit)
			id := waitObservationSeed(t, seed)
			recreate()
			c := waitObservationCase(t, root, id)
			if c.Verification.Status != "passed" || c.Observation.Status != "failed" || c.Status != "partial_failure" {
				t.Fatalf("delayed persistence recreation hidden: %+v", c)
			}
			found := false
			for _, check := range c.Observation.Checks {
				if check.Kind == "persistence_absence" && check.Outcome == "present" {
					found = true
				}
			}
			if !found {
				t.Fatalf("persistence observation missing: %+v", c.Observation)
			}
			verifyReplacement()
			m.Close()
		})
	}
}
