//go:build windows

package tests

import (
	"block-ads/eradication"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("test child did not load DLL: %s", path)
}

func TestLoadedDLLQuarantineAndRestore(t *testing.T) {
	if os.Getenv("BLOCK_ADS_TEST_LIVE_DLL") != "1" {
		t.Skip("requires a Windows C compiler to create a test DLL")
	}
	compiler, err := exec.LookPath("gcc")
	if err != nil {
		t.Fatalf("test DLL compiler unavailable: %v", err)
	}
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))
	t.Setenv("USERPROFILE", root)
	t.Setenv("PROGRAMDATA", filepath.Join(root, "ProgramData"))
	dir := filepath.Join(appData, "BadApp")
	exe := filepath.Join(dir, "sample.exe")
	dll := filepath.Join(dir, "payload.dll")
	testExecutable(t, exe)
	source := filepath.Join(root, "payload.c")
	if err := os.WriteFile(source, []byte(`__declspec(dllexport) int blockads_test(void) { return 7; }`), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(compiler, "-shared", "-o", dll, source).CombinedOutput(); err != nil {
		t.Fatalf("compile test DLL: %v: %s", err, out)
	}
	exeBefore, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	dllBefore, err := os.ReadFile(dll)
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(root, "dll-ready")
	t.Setenv("BLOCK_ADS_TEST_DLL_PATH", dll)
	t.Setenv("BLOCK_ADS_TEST_DLL_READY", ready)
	child := startHelper(t, exe)
	waitForFile(t, ready)
	manager := eradication.NewManager(root, 1, 1)
	match := eradication.Match{PID: uint32(child.Process.Pid), Image: exe, RuleKind: "folder", Rule: "BadApp", Source: "SCAN-HIT", EventAt: time.Now()}
	hit := eradication.DispatchMatchedProcess(manager, match, func() { _ = child.Process.Kill() })
	manager.Close()
	if hit.IdentityError != "" || len(hit.Modules) == 0 {
		t.Fatalf("loaded DLL not captured before containment: %+v", hit)
	}
	cases := readCases(t, root)
	if len(cases) != 1 || len(cases[0].Artifacts) != 2 {
		t.Fatalf("expected EXE and loaded DLL artifacts: %+v", cases)
	}
	for _, artifact := range cases[0].Artifacts {
		if artifact.Status != "quarantined" || artifact.Confidence != "HIGH" {
			t.Fatalf("artifact was not safely quarantined: %+v", artifact)
		}
		if _, err := os.Stat(artifact.Path); !os.IsNotExist(err) {
			t.Fatalf("quarantined artifact remains at original path: %s: %v", artifact.Path, err)
		}
	}
	if err := eradication.RestoreCase(root, cases[0].ID); err != nil {
		t.Fatalf("EXE/DLL restore failed: %v", err)
	}
	for path, before := range map[string][]byte{exe: exeBefore, dll: dllBefore} {
		after, err := os.ReadFile(path)
		if err != nil || sha256.Sum256(after) != sha256.Sum256(before) {
			t.Fatalf("restored artifact hash changed: %s: %v", path, err)
		}
	}
	if err := os.Remove(ready); err != nil {
		t.Fatal(err)
	}
	restarted := startHelper(t, exe)
	waitForFile(t, ready)
	restartManager := eradication.NewManager(root, 1, 1)
	restartHit := eradication.DispatchMatchedProcess(restartManager, eradication.Match{
		PID: uint32(restarted.Process.Pid), Image: exe, RuleKind: "folder", Rule: "BadApp", Source: "SCAN-HIT", EventAt: time.Now(),
	}, func() { _ = restarted.Process.Kill() })
	restartManager.Close()
	if restartHit.ID == hit.ID || restartHit.FileID == hit.FileID {
		t.Fatalf("restored executable was not treated as a new file identity: first=%+v, restart=%+v", hit, restartHit)
	}
	cases = readCases(t, root)
	if len(cases) != 2 {
		t.Fatalf("process restart did not produce a separate case: %+v", cases)
	}
	newQuarantine := 0
	for _, c := range cases {
		if c.Hit.ID == restartHit.ID {
			for _, artifact := range c.Artifacts {
				if artifact.Status == "quarantined" {
					newQuarantine++
				}
			}
		}
	}
	if newQuarantine != 2 {
		t.Fatalf("restarted EXE/DLL pair not quarantined as new artifacts: %+v", cases)
	}
}
