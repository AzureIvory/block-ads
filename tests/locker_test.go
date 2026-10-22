//go:build windows

package tests

import (
	"block-ads/eradication"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestLockerHelperProcess(t *testing.T) {
	target := os.Getenv("BLOCK_ADS_LOCK_TARGET")
	if target == "" {
		return
	}
	ptr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := os.WriteFile(os.Getenv("BLOCK_ADS_LOCK_READY"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Second)
}

func startLockerHelper(t *testing.T, executable, target, ready string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(executable, "-test.run=^TestLockerHelperProcess$")
	cmd.Env = append(os.Environ(), "BLOCK_ADS_LOCK_TARGET="+target, "BLOCK_ADS_LOCK_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	for attempt := 0; attempt < 100; attempt++ {
		if _, err := os.Stat(ready); err == nil {
			return cmd
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("locker helper did not become ready")
	return nil
}

func TestVerifiedLockerIsTerminatedBeforeDeleteRetry(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))
	t.Setenv("USERPROFILE", root)
	path := filepath.Join(appData, "Bad", "sample.exe")
	testExecutable(t, path)
	fileID, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(root, "locker-ready")
	locker := startLockerHelper(t, path, path, ready)
	manager := eradication.NewManager(root, 1, 1)
	manager.ScheduleDeleteAtReboot = func(string) error { return fmt.Errorf("unexpected reboot scheduling") }
	manager.Submit(eradication.HitEvent{ID: "verified-locker", PID: 0xfffffffe, CreatedLow: 1,
		Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || len(cases[0].Artifacts) == 0 || cases[0].Artifacts[0].Status != "quarantined" {
		t.Fatalf("verified locker was not cleared for deletion: %+v", cases)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("original remains after verified locker termination: %v", err)
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(locker.Process.Pid))
	if err == nil {
		defer windows.CloseHandle(h)
		if event, waitErr := windows.WaitForSingleObject(h, 0); waitErr != nil || event != windows.WAIT_OBJECT_0 {
			t.Fatalf("locker did not exit: event=%d error=%v", event, waitErr)
		}
	}
	foundKill, foundRetry := false, false
	for _, operation := range readOperations(t, root) {
		if operation.Action == "terminate_locker" && operation.Phase == "committed" && operation.ProcessID == uint32(locker.Process.Pid) {
			foundKill = true
		}
		if operation.Action == "delete_retry" && operation.Phase == "committed" {
			foundRetry = true
		}
	}
	if !foundKill || !foundRetry {
		t.Fatal("verified locker termination or delete retry was not journaled")
	}
}

func TestUnrelatedLockerIsNotTerminated(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))
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
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	locker := startLockerHelper(t, self, path, filepath.Join(root, "unrelated-ready"))
	manager := eradication.NewManager(root, 1, 1)
	manager.ScheduleDeleteAtReboot = func(candidate string) error {
		if candidate != path {
			return fmt.Errorf("wrong scheduled path: %s", candidate)
		}
		return nil
	}
	manager.Submit(eradication.HitEvent{ID: "unrelated-locker", PID: 0xfffffffe, CreatedLow: 1,
		Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || cases[0].Status != "pending_reboot" {
		t.Fatalf("unrelated locker changed remediation result: %+v", cases)
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(locker.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if event, waitErr := windows.WaitForSingleObject(h, 0); waitErr != nil || event != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("unrelated locker was terminated: event=%d error=%v", event, waitErr)
	}
	for _, operation := range readOperations(t, root) {
		if operation.Action == "terminate_locker" {
			t.Fatalf("unrelated locker was targeted: %+v", operation)
		}
	}
}

func TestRebootSchedulingFailureKeepsArtifactPending(t *testing.T) {
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
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	manager := eradication.NewManager(root, 1, 1)
	manager.ScheduleDeleteAtReboot = func(string) error { return fmt.Errorf("test scheduling denied") }
	manager.Submit(eradication.HitEvent{ID: "schedule-denied", PID: 0xfffffffe, CreatedLow: 1,
		Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || cases[0].Status != "pending" || cases[0].Artifacts[0].Status != "pending" {
		t.Fatalf("failed reboot scheduling was counted as successful: %+v", cases)
	}
	if err := eradication.RestoreCase(root, cases[0].ID); err == nil {
		t.Fatal("unresolved artifact was incorrectly marked restored")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("locked original changed after failed scheduling: %v", err)
	}
	foundFailedSchedule := false
	for _, operation := range readOperations(t, root) {
		if operation.Action == "schedule_reboot_delete" && operation.Phase == "failed" {
			foundFailedSchedule = true
		}
	}
	if !foundFailedSchedule {
		t.Fatal("failed reboot scheduling was not journaled")
	}
}
