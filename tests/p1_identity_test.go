//go:build windows

package tests

import (
	"block-ads/eradication"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestP1StaleETWEventCannotAuthorizeRemediation(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("USERPROFILE", root)
	path := filepath.Join(appData, "BadApp", "sample.exe")
	testExecutable(t, path)
	child := startHelper(t, path)
	manager := eradication.NewManager(root, 1, 1)
	match := eradication.Match{PID: uint32(child.Process.Pid), Image: path, Source: "ETW-HIT", EventAt: time.Now().Add(-time.Minute), RuleKind: "folder", Rule: "BadApp"}
	hit := eradication.DispatchMatchedProcess(manager, match, func() {})
	manager.Close()
	if hit.IdentityError == "" || hit.FileID != "" || hit.CreatedHigh != 0 || hit.CreatedLow != 0 {
		t.Fatalf("stale event accepted a later process: %+v", hit)
	}
	cases := readCases(t, root)
	if len(cases) != 1 || cases[0].Status != "pending" || cases[0].ProcessExit != "unverified" {
		t.Fatalf("stale event remediation result: %+v", cases)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale event removed file: %v", err)
	}
}

func TestP1MissingOrChangedIdentityDoesNotKillLiveProcess(t *testing.T) {
	root := testRoot(t)
	path := filepath.Join(root, "Candidate", "sample.exe")
	testExecutable(t, path)
	child := startHelper(t, path)
	pid := uint32(child.Process.Pid)
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := eradication.NewManager(root, 4, 1)
	for _, hit := range []eradication.HitEvent{
		{ID: "missing", PID: pid, Image: path, FileID: id},
		{ID: "wrong-path", PID: pid, Image: path + ".other", FileID: id},
		{ID: "wrong-file", PID: pid, Image: path, FileID: id + "-other"},
		{ID: "recycled", PID: pid, Image: path, FileID: id},
	} {
		if hit.ID != "missing" {
			h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
			if err != nil {
				t.Fatal(err)
			}
			var created, exited, kernel, user windows.Filetime
			err = windows.GetProcessTimes(h, &created, &exited, &kernel, &user)
			windows.CloseHandle(h)
			if err != nil {
				t.Fatal(err)
			}
			hit.CreatedHigh, hit.CreatedLow = created.HighDateTime, created.LowDateTime
			if hit.ID == "recycled" {
				hit.CreatedLow++
			}
		}
		manager.Submit(hit)
	}
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 4 {
		t.Fatalf("expected four independent cases, got %d", len(cases))
	}
	for _, c := range cases {
		if c.Status != "pending" || c.ProcessExit != "unverified" {
			t.Fatalf("unsafe identity accepted: %+v", c)
		}
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		t.Fatalf("test child was killed: %v", err)
	}
	defer windows.CloseHandle(h)
	if state, err := windows.WaitForSingleObject(h, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("test child no longer running: %d, %v", state, err)
	}
}

func TestP1DuplicateSubmissionAndStableArtifactID(t *testing.T) {
	root := testRoot(t)
	path := filepath.Join(root, "sample.exe")
	if err := os.WriteFile(path, []byte("sample"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	base := eradication.ArtifactID(path, id, strings.Repeat("a", 64))
	if base == "" || base != eradication.ArtifactID(strings.ToUpper(path), id, strings.Repeat("A", 64)) {
		t.Fatal("artifact ID is not stable across Windows path case")
	}
	if base == eradication.ArtifactID(path, id+"-other", strings.Repeat("a", 64)) || base == eradication.ArtifactID(path, id, strings.Repeat("b", 64)) {
		t.Fatal("artifact ID ignored content or file identity")
	}
	manager := eradication.NewManager(root, 2, 1)
	hit := eradication.HitEvent{ID: "one-event", PID: 0xfffffffe, Image: path, FileID: id, CreatedLow: 1, RuleKind: "folder", Rule: "sample"}
	if !manager.Submit(hit) || manager.Submit(hit) {
		t.Fatal("same HitEvent entered remediation twice")
	}
	manager.Close()
	if got := len(readCases(t, root)); got != 1 {
		t.Fatalf("one event produced %d cases", got)
	}
}
