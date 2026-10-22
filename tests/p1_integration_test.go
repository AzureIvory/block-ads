//go:build windows

package tests

import (
	"block-ads/eradication"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const helperEnv = "BLOCK_ADS_P1_HELPER"

func TestHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	if dllPath := os.Getenv("BLOCK_ADS_TEST_DLL_PATH"); dllPath != "" {
		dll, err := windows.LoadDLL(dllPath)
		if err != nil {
			t.Fatal(err)
		}
		defer dll.Release()
		if marker := os.Getenv("BLOCK_ADS_TEST_DLL_READY"); marker != "" {
			if err := os.WriteFile(marker, []byte("loaded"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	time.Sleep(30 * time.Second)
}

func testRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "p1-")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var err error
		for attempt := 0; attempt < 20; attempt++ {
			if err = os.RemoveAll(root); err == nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Errorf("remove test directory %s: %v", root, err)
	})
	return root
}

func testExecutable(t *testing.T, path string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
}

func startHelper(t *testing.T, path string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(path, "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

func readCases(t *testing.T, root string) []eradication.Case {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "eradication", "cases"))
	if err != nil {
		t.Fatal(err)
	}
	out := []eradication.Case{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), "-plan.json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, "eradication", "cases", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var c eradication.Case
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func TestP1EventCorrectnessWithLiveProcesses(t *testing.T) {
	root := testRoot(t)
	path := filepath.Join(root, "Candidate", "sample.exe")
	testExecutable(t, path)
	manager := eradication.NewManager(root, 2, 2)
	defer manager.Close()
	gate := eradication.NewProcessGate(20 * time.Second)
	var legacyCalls atomic.Int32
	legacyLog := filepath.Join(root, "legacy.log")
	eventIDs := map[string]bool{}
	for _, source := range []string{"SCAN-HIT", "ETW-HIT"} {
		cmd := startHelper(t, path)
		pid := uint32(cmd.Process.Pid)
		var match eradication.Match
		if source == "SCAN-HIT" {
			var ok bool
			match, ok = eradication.ScanCandidate(pid)
			if !ok {
				t.Fatal("startup scan failed to read live process")
			}
		} else {
			var ok bool
			eventAt := time.Now()
			match, ok = eradication.ProcessCreateFromProperties(map[string]interface{}{
				"ProcessID": pid, "ParentProcessID": uint32(os.Getpid()), "ImageName": path,
			}, 0, eventAt)
			if !ok || !match.EventAt.Equal(eventAt) {
				t.Fatalf("ETW properties decoded incorrectly: %+v", match)
			}
		}
		if match.Source != source || !strings.EqualFold(match.Image, path) || match.PID != pid {
			t.Fatalf("candidate mismatch: %+v", match)
		}
		if !gate.Enter(pid, path) || gate.Enter(pid, path) {
			t.Fatal("same live process did not deduplicate")
		}
		match.ParentPID = uint32(os.Getpid())
		match.RuleKind, match.Rule = "folder", "Candidate"
		hit := eradication.DispatchMatchedProcess(manager, match, func() {
			legacyCalls.Add(1)
			_ = cmd.Process.Kill()
			f, err := os.OpenFile(legacyLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.WriteString(source + "\n")
			_ = f.Close()
			if err != nil {
				t.Fatal(err)
			}
		})
		if hit.ID == "" || eventIDs[hit.ID] || hit.CreatedHigh == 0 && hit.CreatedLow == 0 || hit.FileID == "" || hit.IdentityError != "" {
			t.Fatalf("incomplete or repeated HitEvent: %+v", hit)
		}
		eventIDs[hit.ID] = true
		if hit.PID != pid || hit.ParentPID != uint32(os.Getpid()) || !strings.EqualFold(hit.Image, path) || hit.Source != source || hit.Rule != "Candidate" || hit.DetectedAt.IsZero() {
			t.Fatalf("HitEvent not traceable to source: %+v", hit)
		}
	}
	manager.Close()
	if legacyCalls.Load() != 2 || len(eventIDs) != 2 {
		t.Fatalf("legacy calls=%d, events=%d", legacyCalls.Load(), len(eventIDs))
	}
	logBytes, err := os.ReadFile(legacyLog)
	if err != nil || len(strings.Split(strings.TrimSpace(string(logBytes)), "\n")) != 2 {
		t.Fatalf("legacy log is not one-to-one: %q, %v", logBytes, err)
	}
	cases := readCases(t, root)
	if len(cases) != 2 {
		t.Fatalf("events=%d, cases=%d", len(eventIDs), len(cases))
	}
	for _, c := range cases {
		if !eventIDs[c.Hit.ID] {
			t.Fatalf("case %s lacks source event: %+v", c.ID, c.Hit)
		}
	}
}

func TestP1SharedArtifactRemediatedOnce(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))
	t.Setenv("USERPROFILE", root)
	path := filepath.Join(appData, "BadApp", "sample.exe")
	testExecutable(t, path)
	first := startHelper(t, path)
	second := startHelper(t, path)
	gate := eradication.NewProcessGate(20 * time.Second)
	if !gate.Enter(uint32(first.Process.Pid), path) || !gate.Enter(uint32(second.Process.Pid), path) {
		t.Fatal("different PIDs sharing one image were incorrectly deduplicated")
	}
	manager := eradication.NewManager(root, 2, 2)
	firstContained := make(chan struct{})
	releaseFirst := make(chan struct{})
	manager.OnContainment = func(hit eradication.HitEvent, _ bool, _ error) {
		if hit.Source == "CASE-A" {
			close(firstContained)
			<-releaseFirst
		}
	}
	var actions atomic.Int32
	dispatch := func(cmd *exec.Cmd, source string) eradication.HitEvent {
		match := eradication.Match{PID: uint32(cmd.Process.Pid), Image: path, Source: source, RuleKind: "folder", Rule: "BadApp"}
		return eradication.DispatchMatchedProcess(manager, match, func() {
			actions.Add(1)
			_ = cmd.Process.Kill()
		})
	}
	a := dispatch(first, "CASE-A")
	select {
	case <-firstContained:
	case <-time.After(5 * time.Second):
		t.Fatal("first case never reached containment")
	}
	b := dispatch(second, "CASE-B")
	close(releaseFirst)
	manager.Close()
	if a.FileID == "" || b.FileID != a.FileID || a.ID == b.ID || actions.Load() != 2 {
		t.Fatalf("event identities/actions wrong: %+v %+v %d", a, b, actions.Load())
	}
	cases := readCases(t, root)
	if len(cases) != 2 {
		t.Fatalf("expected one case per hit, got %d", len(cases))
	}
	var owner, linked *eradication.Case
	for i := range cases {
		for _, item := range cases[i].Artifacts {
			if item.Status == "quarantined" {
				owner = &cases[i]
			}
			if item.Status == "linked" {
				linked = &cases[i]
			}
		}
	}
	if owner == nil || linked == nil || len(owner.Artifacts) == 0 || len(linked.Artifacts) == 0 {
		t.Fatalf("shared ownership not recorded: %+v", cases)
	}
	if owner.Artifacts[0].ID != linked.Artifacts[0].ID || linked.Artifacts[0].OwnerCaseID != owner.ID {
		t.Fatalf("case references disagree: owner=%+v linked=%+v", owner.Artifacts, linked.Artifacts)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original was not removed once: %v", err)
	}
	if err := eradication.RestoreCase(root, owner.ID); err == nil || !strings.Contains(err.Error(), "referenced by cases") {
		t.Fatalf("shared owner restore unexpectedly allowed: %v", err)
	}
	if err := eradication.RestoreCase(root, linked.ID); err != nil {
		t.Fatalf("linked case reference release failed: %v", err)
	}
	if after := readCases(t, root); len(after) != 2 {
		t.Fatalf("case count changed after release: %d", len(after))
	}
	if err := eradication.RestoreCase(root, owner.ID); err != nil {
		t.Fatalf("owner restore after reference release failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("shared artifact was not restored: %v", err)
	}
}
