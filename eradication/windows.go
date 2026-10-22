//go:build windows

package eradication

import (
	"block-ads/utils"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(expandTargetEnv(a)), filepath.Clean(expandTargetEnv(b)))
}

// FileID identifies the on-disk file independent of a replaceable path.
func FileID(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x-%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}

func processPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func contain(hit HitEvent, knownQuarantined bool) (bool, error) {
	if hit.CreatedHigh == 0 && hit.CreatedLow == 0 {
		return false, fmt.Errorf("PID %d creation time unavailable; refusing containment", hit.PID)
	}
	if hit.FileID == "" {
		return false, fmt.Errorf("PID %d image file identity unavailable; refusing containment", hit.PID)
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, hit.PID)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			// No process currently has this PID. The hit exited before dequeue.
			return true, nil
		}
		return false, fmt.Errorf("open PID %d: %w", hit.PID, err)
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return false, err
	}
	if created.HighDateTime != hit.CreatedHigh || created.LowDateTime != hit.CreatedLow {
		return false, fmt.Errorf("PID %d was recycled", hit.PID)
	}
	if event, err := windows.WaitForSingleObject(h, 0); err == nil && event == windows.WAIT_OBJECT_0 {
		// An exited process can retain a queryable handle while its image path is
		// no longer available. Creation time still proves this is the old PID.
		return true, nil
	}
	path, err := processPath(h)
	if err != nil {
		if event, waitErr := windows.WaitForSingleObject(h, 500); waitErr == nil && event == windows.WAIT_OBJECT_0 {
			return true, nil
		}
		return false, fmt.Errorf("PID %d image unavailable while process is still live: %w", hit.PID, err)
	}
	if !samePath(path, hit.Image) {
		return false, fmt.Errorf("PID %d image changed or unavailable: %q: %v", hit.PID, path, err)
	}
	if id, err := FileID(path); err != nil || id != hit.FileID {
		if !knownQuarantined || !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("PID %d image file identity changed or unavailable: %v", hit.PID, err)
		}
	}
	killErr := windows.TerminateProcess(h, 1)
	event, waitErr := windows.WaitForSingleObject(h, 5000)
	if waitErr != nil {
		return false, fmt.Errorf("terminate: %v; wait: %w", killErr, waitErr)
	}
	if event != windows.WAIT_OBJECT_0 {
		return false, fmt.Errorf("terminate: %v; process exit not observed within 5s", killErr)
	}
	return true, nil
}

func loadedModules(pid uint32) ([]string, error) {
	return moduleSnapshot(pid, 3)
}

func moduleSnapshot(pid uint32, attempts int) ([]string, error) {
	var snap windows.Handle
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		snap, err = windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BAD_LENGTH) {
			return nil, err
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	entry := windows.ModuleEntry32{Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{}))}
	if err := windows.Module32First(snap, &entry); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var paths []string
	for {
		path := windows.UTF16ToString(entry.ExePath[:])
		if path != "" {
			key := strings.ToLower(filepath.Clean(path))
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				paths = append(paths, path)
			}
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ModuleEntry32{}))
		if err := windows.Module32Next(snap, &entry); err != nil {
			break
		}
	}
	return paths, nil
}

// CaptureModules preserves a best-effort module list before the original kill.
func CaptureModules(pid uint32) ([]string, error) {
	return moduleSnapshot(pid, 1)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func signer(path string) string {
	s, _ := utils.GetSignName(path)
	return strings.TrimSpace(s)
}

func beneath(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, os.ErrNotExist) {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
		if parentErr != nil {
			return false
		}
		resolved = filepath.Join(parent, filepath.Base(path))
	} else if err != nil {
		return false
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(base, resolved)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

func inUserAppData(path string) bool {
	for _, root := range []string{os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA"), filepath.Join(os.Getenv("USERPROFILE"), "AppData")} {
		if beneath(path, root) {
			return true
		}
	}
	return false
}

func collectEvidence(hit HitEvent, modules []string) []Artifact {
	items := make([]Artifact, 0, len(modules)+1)
	exe := Artifact{Path: hit.Image, Kind: "exe", Signer: signer(hit.Image), Confidence: "REVIEW", Evidence: "matched " + hit.RuleKind + ":" + hit.Rule, Status: "pending"}
	exe.FileID = hit.FileID
	if hash, err := fileSHA256(hit.Image); err == nil {
		exe.SHA256 = hash
	} else {
		exe.Error = err.Error()
	}
	if currentID, err := FileID(hit.Image); err == nil && hit.FileID != "" && currentID == hit.FileID && exe.SHA256 != "" && inUserAppData(hit.Image) {
		exe.Confidence = "HIGH"
	} else if hit.FileID == "" {
		exe.Evidence += "; file identity unavailable at detection"
	} else {
		exe.Evidence += "; file identity changed or unavailable"
	}
	items = append(items, exe)
	for _, path := range modules {
		if samePath(path, hit.Image) || !strings.EqualFold(filepath.Ext(path), ".dll") {
			continue
		}
		a := Artifact{Path: path, Kind: "dll", Confidence: "LOW", Evidence: "loaded by matched PID", Status: "pending"}
		a.FileID = hit.ModuleIDs[strings.ToLower(filepath.Clean(path))]
		if !samePath(filepath.Dir(path), filepath.Dir(hit.Image)) || !inUserAppData(path) {
			items = append(items, a)
			continue
		}
		a.Signer = signer(path)
		if strings.Contains(strings.ToLower(a.Signer), "microsoft") {
			items = append(items, a)
			continue
		}
		if !((exe.Signer != "" && a.Signer != "" && strings.EqualFold(exe.Signer, a.Signer)) || (hit.RuleKind == "folder" && a.Signer == "")) {
			a.Confidence = "MEDIUM"
			items = append(items, a)
			continue
		}
		if usedByOtherProcess(path, hit.PID) {
			a.Confidence = "MEDIUM"
			a.Evidence += "; also loaded elsewhere"
			items = append(items, a)
			continue
		}
		if expectedID := hit.ModuleIDs[strings.ToLower(filepath.Clean(path))]; expectedID == "" {
			a.Confidence = "MEDIUM"
			a.Evidence += "; file identity unavailable at detection"
			items = append(items, a)
			continue
		} else if currentID, err := FileID(path); err != nil || currentID != expectedID {
			a.Confidence = "MEDIUM"
			a.Evidence += "; file identity changed"
			items = append(items, a)
			continue
		}
		if hash, err := fileSHA256(path); err == nil {
			a.SHA256 = hash
			a.Confidence = "HIGH"
			a.Evidence += "; same directory and signer/rule; no other loader observed"
		} else {
			a.Error = err.Error()
		}
		items = append(items, a)
	}
	return items
}

func usedByOtherProcess(path string, hitPID uint32) bool {
	for _, pid := range utils.Listpid() {
		if pid == hitPID || pid == 0 || pid == 4 {
			continue
		}
		mods, err := moduleSnapshot(pid, 1)
		if err != nil {
			continue
		}
		for _, mod := range mods {
			if samePath(mod, path) {
				return true
			}
		}
	}
	return false
}

type quarantineMetadata struct {
	CaseID       string    `json:"case_id"`
	OriginalPath string    `json:"original_path"`
	SHA256       string    `json:"sha256"`
	Signer       string    `json:"signer,omitempty"`
	Rule         string    `json:"rule"`
	PID          uint32    `json:"pid"`
	Quarantined  time.Time `json:"quarantined_at"`
}

// PendingRebootError means a delete was scheduled, not completed or verified.
type PendingRebootError struct {
	Path   string
	Detail string
}

func (e *PendingRebootError) Error() string {
	message := "delete scheduled for reboot; original remains until a post-reboot check: " + e.Path
	if e.Detail != "" {
		message += "; " + e.Detail
	}
	return message
}

func sharingViolation(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

func removeVerifiedArtifact(path string, original os.FileInfo, a Artifact) error {
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(original, current) {
		return fmt.Errorf("source changed before removal: %v", err)
	}
	if id, err := FileID(path); err != nil || id != a.FileID {
		return fmt.Errorf("source identity changed before removal: %v", err)
	}
	if hash, err := fileSHA256(path); err != nil || hash != a.SHA256 {
		return fmt.Errorf("source hash changed before removal: %v", err)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("source still present after removal: %v", err)
	}
	return nil
}

func (m *Manager) quarantine(caseID string, hit HitEvent, a Artifact) (string, error) {
	if a.SHA256 == "" || !inUserAppData(a.Path) {
		return "", fmt.Errorf("artifact is outside verified user AppData or lacks hash")
	}
	fi, err := os.Lstat(a.Path)
	if err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("source is not a regular file: %v", err)
	}
	if currentID, err := FileID(a.Path); err != nil || a.FileID == "" || currentID != a.FileID {
		return "", fmt.Errorf("source file identity changed: %v", err)
	}
	dir := filepath.Join(m.root, "eradication", "quarantine")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	ext := strings.ToLower(filepath.Ext(a.Path))
	target := filepath.Join(dir, a.SHA256+ext)
	tmpPath := filepath.Join(dir, ".artifact-"+newCaseID(HitEvent{}))
	defer os.Remove(tmpPath)
	artifactID := ArtifactID(a.Path, a.FileID, a.SHA256)
	if err := runJournaled(m.root, OperationEntry{
		CaseID: caseID, ArtifactID: artifactID, Action: "quarantine_copy", Target: a.Path, RelatedPath: a.Path,
		ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: tmpPath,
		Precondition: "source file identity matched; temporary destination must be absent",
	}, m.OnOperation, func() error {
		tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		src, err := os.Open(a.Path)
		if err != nil {
			tmp.Close()
			return err
		}
		_, copyErr := io.Copy(tmp, src)
		src.Close()
		if copyErr != nil {
			tmp.Close()
			return copyErr
		}
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return err
		}
		return tmp.Close()
	}); err != nil {
		return "", err
	}
	if err := runJournaled(m.root, OperationEntry{
		CaseID: caseID, ArtifactID: artifactID, Action: "quarantine_hash_verify", Target: a.Path, RelatedPath: a.Path,
		ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: tmpPath,
		Precondition: "temporary copy closed and synced",
	}, m.OnOperation, func() error {
		copyHash, err := fileSHA256(tmpPath)
		if err != nil || copyHash != a.SHA256 {
			return fmt.Errorf("quarantine copy hash mismatch: %v", err)
		}
		return nil
	}); err != nil {
		return "", err
	}
	if existingHash, err := fileSHA256(target); err == nil {
		if existingHash != a.SHA256 {
			return "", fmt.Errorf("quarantine hash collision at %s", target)
		}
		if fi, err := os.Lstat(target); err != nil || !fi.Mode().IsRegular() || !beneath(target, dir) {
			return "", fmt.Errorf("existing quarantine target is not a regular local file: %v", err)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := runJournaled(m.root, OperationEntry{
			CaseID: caseID, ArtifactID: artifactID, Action: "quarantine_publish", Target: a.Path, RelatedPath: a.Path,
			ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: target,
			Precondition: "temporary copy hash verified; published target was absent",
		}, m.OnOperation, func() error {
			source, err := windows.UTF16PtrFromString(tmpPath)
			if err != nil {
				return err
			}
			destination, err := windows.UTF16PtrFromString(target)
			if err != nil {
				return err
			}
			if err := windows.MoveFileEx(source, destination, windows.MOVEFILE_WRITE_THROUGH); err != nil {
				return err
			}
			if hash, err := fileSHA256(target); err != nil || hash != a.SHA256 {
				return fmt.Errorf("published quarantine hash mismatch: %v", err)
			}
			return nil
		}); err != nil {
			return "", err
		}
	} else {
		return "", err
	}
	meta := quarantineMetadata{CaseID: caseID, OriginalPath: a.Path, SHA256: a.SHA256, Signer: a.Signer, Rule: hit.RuleKind + ":" + hit.Rule, PID: hit.PID, Quarantined: time.Now()}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", err
	}
	if err := atomicWrite(filepath.Join(dir, caseID+"-"+a.SHA256+ext+".json"), b); err != nil {
		return "", err
	}
	current, err := os.Lstat(a.Path)
	if err != nil || !os.SameFile(fi, current) {
		return "", fmt.Errorf("source changed before removal: %v", err)
	}
	if currentID, err := FileID(a.Path); err != nil || currentID != a.FileID {
		return "", fmt.Errorf("source file identity changed before removal: %v", err)
	}
	currentHash, err := fileSHA256(a.Path)
	if err != nil || currentHash != a.SHA256 {
		return "", fmt.Errorf("source hash changed before removal: %v", err)
	}
	precondition := fmt.Sprintf("file_id=%s sha256=%s quarantine=%s", a.FileID, a.SHA256, target)
	if err := runJournaled(m.root, OperationEntry{
		CaseID: caseID, ArtifactID: ArtifactID(a.Path, a.FileID, a.SHA256), Action: "delete_original", Target: a.Path,
		Precondition: precondition, ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: target,
	}, m.OnOperation, func() error {
		return removeVerifiedArtifact(a.Path, fi, a)
	}); err != nil {
		if !sharingViolation(err) {
			return target, err
		}
		var lockers []lockerProcess
		listErr := runJournaled(m.root, OperationEntry{
			CaseID: caseID, ArtifactID: ArtifactID(a.Path, a.FileID, a.SHA256), Action: "enumerate_lockers",
			Target: a.Path, ExpectedHash: a.SHA256, ExpectedFileID: a.FileID,
			Precondition: "immediate deletion failed with a sharing violation",
		}, m.OnOperation, func() error {
			var err error
			lockers, err = enumerateLockers(a.Path)
			return err
		})
		var lockerErrors []error
		for _, locker := range lockers {
			h, authErr := openAuthorizedLocker(locker, hit)
			if authErr != nil {
				continue
			}
			killEntry := OperationEntry{
				CaseID: caseID, ArtifactID: ArtifactID(a.Path, a.FileID, a.SHA256), Action: "terminate_locker",
				Target: hit.Image, RelatedPath: a.Path, ProcessID: locker.PID,
				CreatedHigh: locker.Created.HighDateTime, CreatedLow: locker.Created.LowDateTime,
				ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: target,
				Precondition: "locker creation time, image path and file identity verified",
			}
			killErr := runJournaled(m.root, killEntry, m.OnOperation, func() error { return terminateVerifiedLocker(h) })
			windows.CloseHandle(h)
			if killErr != nil {
				lockerErrors = append(lockerErrors, fmt.Errorf("verified locker PID %d: %w", locker.PID, killErr))
			}
		}
		if retryErr := runJournaled(m.root, OperationEntry{
			CaseID: caseID, ArtifactID: ArtifactID(a.Path, a.FileID, a.SHA256), Action: "delete_retry", Target: a.Path,
			Precondition: "source identity unchanged after locker enumeration", ExpectedHash: a.SHA256,
			ExpectedFileID: a.FileID, QuarantinePath: target,
		}, m.OnOperation, func() error { return removeVerifiedArtifact(a.Path, fi, a) }); retryErr == nil {
			return target, nil
		} else if !sharingViolation(retryErr) {
			return target, retryErr
		}
		if m.ScheduleDeleteAtReboot == nil {
			return target, fmt.Errorf("reboot deletion unavailable after sharing violation; locker enumeration: %v", listErr)
		}
		if err := runJournaled(m.root, OperationEntry{
			CaseID: caseID, ArtifactID: ArtifactID(a.Path, a.FileID, a.SHA256), Action: "schedule_reboot_delete", Target: a.Path,
			Precondition: "source identity and hash unchanged; immediate deletion blocked by sharing violation",
			ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: target,
		}, m.OnOperation, func() error {
			if current, checkErr := os.Lstat(a.Path); checkErr != nil || !os.SameFile(fi, current) {
				return fmt.Errorf("source changed before reboot scheduling: %v", checkErr)
			}
			if id, checkErr := FileID(a.Path); checkErr != nil || id != a.FileID {
				return fmt.Errorf("source identity changed before reboot scheduling: %v", checkErr)
			}
			if hash, checkErr := fileSHA256(a.Path); checkErr != nil || hash != a.SHA256 {
				return fmt.Errorf("source hash changed before reboot scheduling: %v", checkErr)
			}
			return m.ScheduleDeleteAtReboot(a.Path)
		}); err != nil {
			return target, fmt.Errorf("reboot deletion was not scheduled: %w; locker enumeration: %v", err, listErr)
		}
		detail := ""
		if listErr != nil || len(lockerErrors) != 0 {
			detail = fmt.Sprintf("locker enumeration=%v; termination=%v", listErr, errors.Join(lockerErrors...))
		}
		return target, &PendingRebootError{Path: a.Path, Detail: detail}
	}
	return target, nil
}
