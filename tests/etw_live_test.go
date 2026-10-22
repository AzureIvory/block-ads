//go:build windows

package tests

import (
	"block-ads/eradication"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bi-zone/etw"
	"golang.org/x/sys/windows"
)

// Run from an elevated shell with BLOCK_ADS_TEST_LIVE_ETW=1. A unique session
// name prevents the test from touching the application's own ETW session.
func TestLiveKernelProcessETW(t *testing.T) {
	if os.Getenv("BLOCK_ADS_TEST_LIVE_ETW") != "1" {
		t.Skip("set BLOCK_ADS_TEST_LIVE_ETW=1 in an elevated shell")
	}
	provider, err := windows.GUIDFromString("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
	if err != nil {
		t.Fatal(err)
	}
	name := "blockads-p1-" + strconv.Itoa(os.Getpid())
	session, err := etw.NewSession(provider, etw.WithName(name))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	root := testRoot(t)
	path := filepath.Join(root, "Candidate", "sample.exe")
	testExecutable(t, path)
	seen := make(chan eradication.Match, 64)
	done := make(chan error, 1)
	go func() {
		done <- session.Process(func(event *etw.Event) {
			if event == nil || event.Header.ID != 1 {
				return
			}
			props, err := event.EventProperties()
			if err != nil {
				return
			}
			match, ok := eradication.ProcessCreateFromProperties(props, event.Header.ProcessID, event.Header.TimeStamp)
			if ok {
				select {
				case seen <- match:
				default:
				}
			}
		})
	}()
	time.Sleep(200 * time.Millisecond)
	child := startHelper(t, path)
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case match := <-seen:
			if match.PID != uint32(child.Process.Pid) {
				continue
			}
			if match.Source != "ETW-HIT" || match.ParentPID != uint32(os.Getpid()) || !match.EventAt.Before(time.Now().Add(time.Second)) || !strings.EqualFold(filepath.Clean(match.Image), filepath.Clean(path)) {
				t.Fatalf("live ETW candidate inaccurate: %+v", match)
			}
			manager := eradication.NewManager(root, 1, 1)
			var legacyCalls atomic.Int32
			match.RuleKind, match.Rule = "folder", "Candidate"
			hit := eradication.DispatchMatchedProcess(manager, match, func() {
				legacyCalls.Add(1)
				_ = child.Process.Kill()
			})
			manager.Close()
			if legacyCalls.Load() != 1 || hit.IdentityError != "" || hit.FileID == "" || hit.CreatedHigh == 0 && hit.CreatedLow == 0 || hit.PID != match.PID || !hit.EventAt.Equal(match.EventAt) {
				t.Fatalf("live ETW did not produce one valid HitEvent: %+v, legacy calls=%d", hit, legacyCalls.Load())
			}
			cases := readCases(t, root)
			if len(cases) != 1 || cases[0].Hit.ID != hit.ID || cases[0].Hit.Source != "ETW-HIT" {
				t.Fatalf("live ETW event did not produce one traceable case: %+v", cases)
			}
			return
		case err := <-done:
			t.Fatalf("ETW session ended before process event: %v", err)
		case <-deadline.C:
			t.Fatal("live kernel process event not received")
		}
	}
}
