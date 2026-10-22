//go:build windows

package eradication

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// VerificationSummary is an immediate observation, never a claim of lasting
// eradication. Reboot and bounded observation remain separate requirements.
type VerificationSummary struct {
	Scope               string              `json:"scope"`
	Status              string              `json:"status"`
	StartedAt           time.Time           `json:"started_at"`
	FinishedAt          time.Time           `json:"finished_at"`
	RequiresReboot      bool                `json:"requires_reboot"`
	RequiresObservation bool                `json:"requires_observation"`
	Checks              []VerificationCheck `json:"checks"`
}

type VerificationCheck struct {
	OperationID string    `json:"operation_id"`
	Kind        string    `json:"kind"`
	Target      string    `json:"target"`
	Outcome     string    `json:"outcome"`
	Evidence    string    `json:"evidence"`
	Error       string    `json:"error,omitempty"`
	At          time.Time `json:"at"`
}

func hasRemovedArtifacts(c Case) bool {
	for _, a := range c.Artifacts {
		if a.Status == "quarantined" || a.Status == "linked" {
			return true
		}
	}
	return false
}

func verifyPostClean(root string, c Case, observer OperationObserver) *VerificationSummary {
	return verifyPostCleanScope(root, c, observer, "immediate")
}

func verifyPostCleanScope(root string, c Case, observer OperationObserver, scope string) *VerificationSummary {
	summary := &VerificationSummary{Scope: scope, Status: "passed", StartedAt: time.Now(), RequiresReboot: true, RequiresObservation: true}
	check := func(kind string, entry OperationEntry, observe func() (string, string)) {
		entry.CaseID, entry.Action = c.ID, "verify_"+kind
		entry.Precondition = "scope=" + scope + "; read-only post-clean observation; no retry, deletion or restoration"
		result := VerificationCheck{Kind: kind, Target: entry.Target, Outcome: "unknown"}
		err := runJournaledResult(root, entry, observer, func(operation *OperationEntry) error {
			result.OperationID, result.At = operation.ID, time.Now()
			result.Outcome, result.Evidence = observe()
			operation.Outcome, operation.Evidence = result.Outcome, result.Evidence
			if result.Outcome != "absent" {
				return fmt.Errorf("%s: %s", result.Outcome, result.Evidence)
			}
			return nil
		})
		if result.Outcome == "present" {
			summary.Status = "failed"
		} else if err != nil && summary.Status != "failed" {
			summary.Status = "incomplete"
		}
		if err != nil && result.Evidence == "" {
			result.Evidence = err.Error()
			result.At = time.Now()
		}
		if err != nil {
			result.Error = err.Error()
		}
		summary.Checks = append(summary.Checks, result)
	}
	check("process_exit", OperationEntry{Target: c.Hit.Image, RelatedPath: c.Hit.Image, ProcessID: c.Hit.PID, CreatedHigh: c.Hit.CreatedHigh, CreatedLow: c.Hit.CreatedLow}, func() (string, string) { return observeHitExit(c.Hit) })
	check("process_reappearance", OperationEntry{Target: c.Hit.Image, RelatedPath: c.Hit.Image}, func() (string, string) { return observeImageProcesses(c.Hit.Image) })
	for _, a := range c.Artifacts {
		if a.Status != "quarantined" && a.Status != "linked" {
			continue
		}
		check("file_absence", OperationEntry{Target: a.Path, RelatedPath: a.Path, ArtifactID: a.ID, ExpectedHash: a.SHA256, ExpectedFileID: a.FileID}, func() (string, string) { return observePathAbsence(a.Path) })
	}
	for _, item := range c.Persistence {
		if item.Status != "removed" && item.Status != "linked" {
			continue
		}
		check("persistence_absence", OperationEntry{Target: item.Name, RelatedPath: item.Target, PersistenceID: PersistenceID(item.Type, item.Location, item.Name), PersistenceType: item.Type, PersistenceLocation: item.Location}, func() (string, string) { return observePersistenceAbsence(item) })
	}
	summary.FinishedAt = time.Now()
	return summary
}

func observePathAbsence(path string) (string, string) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "absent", "path is absent at observation time"
	}
	if err != nil {
		return "unknown", "path cannot be checked: " + err.Error()
	}
	return "present", fmt.Sprintf("path reappeared or remains occupied (mode=%s); attribution is unconfirmed", info.Mode())
}

func observeHitExit(hit HitEvent) (string, string) {
	if hit.PID == 0 || hit.CreatedHigh == 0 && hit.CreatedLow == 0 {
		return "unknown", "hit lacks process creation identity"
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, hit.PID)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return "absent", "hit PID is no longer allocated"
	}
	if err != nil {
		return "unknown", "cannot open hit PID: " + err.Error()
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return "unknown", err.Error()
	}
	if created.HighDateTime != hit.CreatedHigh || created.LowDateTime != hit.CreatedLow {
		return "absent", "PID was reused; original process is gone; replacement was not modified"
	}
	state, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return "unknown", err.Error()
	}
	if state == windows.WAIT_OBJECT_0 {
		return "absent", "original process handle is signaled"
	}
	return "present", "original process is still running"
}

func observeImageProcesses(path string) (string, string) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "unknown", err.Error()
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	err = windows.Process32First(snapshot, &entry)
	unknown := ""
	for err == nil {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), filepath.Base(path)) {
			h, openErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, entry.ProcessID)
			if openErr == nil {
				state, waitErr := windows.WaitForSingleObject(h, 0)
				if waitErr == nil && state == windows.WAIT_OBJECT_0 {
					windows.CloseHandle(h)
					err = windows.Process32Next(snapshot, &entry)
					continue
				}
				image, pathErr := processPath(h)
				var created, exited, kernel, user windows.Filetime
				timeErr := windows.GetProcessTimes(h, &created, &exited, &kernel, &user)
				state, waitErr = windows.WaitForSingleObject(h, 0)
				windows.CloseHandle(h)
				if waitErr == nil && state == windows.WAIT_OBJECT_0 {
					err = windows.Process32Next(snapshot, &entry)
					continue
				}
				if pathErr == nil && samePath(image, path) {
					return "present", fmt.Sprintf("image running: PID=%d parent_PID=%d created=%08x:%08x creation_error=%v; no action taken", entry.ProcessID, entry.ParentProcessID, created.HighDateTime, created.LowDateTime, timeErr)
				}
				if pathErr != nil {
					unknown = fmt.Sprintf("candidate PID %d image unavailable: %v", entry.ProcessID, pathErr)
				}
			} else if !errors.Is(openErr, windows.ERROR_INVALID_PARAMETER) {
				unknown = fmt.Sprintf("candidate PID %d cannot be queried: %v", entry.ProcessID, openErr)
			}
		}
		err = windows.Process32Next(snapshot, &entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return "unknown", fmt.Sprintf("process enumeration incomplete: %v", err)
	}
	if unknown != "" {
		return "unknown", unknown
	}
	return "absent", "no process with the exact image path observed in this snapshot"
}

func observePersistenceAbsence(item PersistenceItem) (string, string) {
	switch item.Type {
	case "registry_run":
		for _, loc := range runLocations {
			if locationName(loc) != item.Location {
				continue
			}
			key, err := registry.OpenKey(loc.root, loc.name, registry.QUERY_VALUE|loc.view)
			if errors.Is(err, registry.ErrNotExist) {
				return "absent", "Run location is absent"
			}
			if err != nil {
				return "unknown", err.Error()
			}
			defer key.Close()
			_, valueType, err := key.GetValue(item.Name, nil)
			if errors.Is(err, registry.ErrNotExist) {
				return "absent", "Run value is absent"
			}
			if err != nil {
				return "unknown", err.Error()
			}
			return "present", fmt.Sprintf("Run value exists (type=%d); attribution is unconfirmed; no action taken", valueType)
		}
		return "unknown", "unrecognized Run location"
	case "task":
		if err := taskRestoreLocation(item.Name, item.Location); err != nil {
			return "unknown", err.Error()
		}
		return observePathAbsence(item.Location)
	case "startup_link":
		for _, dir := range startupFolders() {
			if samePath(filepath.Dir(item.Location), dir) {
				return observePathAbsence(item.Location)
			}
		}
		return "unknown", "shortcut location is outside Startup folders"
	}
	return "unknown", "persistence type has no absence check"
}
