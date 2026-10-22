//go:build windows

package eradication

import (
	"block-ads/utils"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// Match is the already accepted result of the legacy blacklist and gate.
// DispatchMatchedProcess does not change those decisions.
type Match struct {
	PID       uint32
	ParentPID uint32
	Image     string
	Signer    string
	RuleKind  string
	Rule      string
	Source    string
	EventAt   time.Time
}

// DispatchMatchedProcess snapshots evidence before the legacy action, then
// invokes that action exactly once and submits exactly one event afterward.
func DispatchMatchedProcess(manager *Manager, match Match, legacyAction func()) HitEvent {
	detected := time.Now()
	hit := HitEvent{
		ID:  newCaseID(HitEvent{PID: match.PID}),
		PID: match.PID, ParentPID: match.ParentPID,
		Image: match.Image, Signer: match.Signer,
		RuleKind: match.RuleKind, Rule: match.Rule, Source: match.Source,
		EventAt: match.EventAt, DetectedAt: detected,
	}
	if match.ParentPID != 0 {
		hit.ParentImage, _ = utils.ProcPath(match.ParentPID)
	}
	if created, path, id, err := captureProcessIdentity(match.PID, match.Image, match.EventAt); err == nil {
		hit.CreatedHigh, hit.CreatedLow = created.HighDateTime, created.LowDateTime
		hit.Image, hit.FileID = path, id
	} else {
		hit.IdentityError = err.Error()
	}
	modules, moduleErr := CaptureModules(match.PID)
	hit.ModuleIDs = make(map[string]string)
	for _, module := range modules {
		if strings.EqualFold(filepath.Ext(module), ".dll") && strings.EqualFold(filepath.Dir(module), filepath.Dir(match.Image)) {
			hit.Modules = append(hit.Modules, module)
			if id, err := FileID(module); err == nil {
				hit.ModuleIDs[strings.ToLower(filepath.Clean(module))] = id
			}
		}
	}
	if moduleErr != nil {
		hit.ModuleError = moduleErr.Error()
	}
	legacyAction()
	manager.Submit(hit)
	return hit
}

func captureProcessIdentity(pid uint32, expected string, eventAt time.Time) (windows.Filetime, string, string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return windows.Filetime{}, "", "", fmt.Errorf("open PID %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return windows.Filetime{}, "", "", err
	}
	// FILETIME and ETW timestamps may differ slightly because they are sampled
	// through different clocks. Reject clearly later process creations.
	if !eventAt.IsZero() && time.Unix(0, created.Nanoseconds()).After(eventAt.Add(20*time.Millisecond)) {
		return windows.Filetime{}, "", "", fmt.Errorf("PID %d was created after its source event (%s > %s); possible PID reuse", pid, time.Unix(0, created.Nanoseconds()).Format(time.RFC3339Nano), eventAt.Format(time.RFC3339Nano))
	}
	path, err := processPath(h)
	if err != nil || !samePath(path, expected) {
		return windows.Filetime{}, "", "", fmt.Errorf("PID %d image mismatch: %q vs %q: %v", pid, path, expected, err)
	}
	id, err := FileID(path)
	if err != nil {
		return windows.Filetime{}, "", "", err
	}
	return created, path, id, nil
}
