//go:build windows

package eradication

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// RestoreCase restores quarantined files and supported persistence entries.
// It never overwrites an existing target. Service backups require manual
// review because SCM deletion can stay pending until reboot.
func RestoreCase(root, id string) error {
	return RestoreCaseWithObserver(root, id, nil)
}

// RestoreCaseWithObserver exposes durable action boundaries for progress
// reporting and controlled crash testing.
func RestoreCaseWithObserver(root, id string, observer OperationObserver) error {
	if id == "" || filepath.Base(id) != id || strings.ContainsAny(id, `/\:`) {
		return fmt.Errorf("invalid case ID")
	}
	casePath := filepath.Join(root, "eradication", "cases", id+".json")
	b, err := os.ReadFile(casePath)
	if err != nil {
		return err
	}
	var c Case
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.ID != id {
		return fmt.Errorf("case ID mismatch")
	}
	if c.Status == "released" || c.Status == "restored" {
		return nil
	}
	for _, artifact := range c.Artifacts {
		if artifact.Status == "pending_reboot" {
			return fmt.Errorf("case %s has a reboot deletion request; restore requires cancellation and post-reboot verification", id)
		}
		if artifact.Status == "pending" || artifact.Status == "failed" {
			return fmt.Errorf("case %s still has an unresolved artifact at %s", id, artifact.Path)
		}
	}
	linked := false
	for _, a := range c.Artifacts {
		if a.Status == "linked" {
			linked = true
		}
	}
	if linked {
		if err := releaseLinkedCase(root, &c, observer); err != nil {
			return err
		}
		return commitCase(root, c, observer)
	}
	for _, a := range c.Artifacts {
		if a.Status == "quarantined" {
			if err := restoreOwnershipAllowed(root, id, a); err != nil {
				return err
			}
		}
	}
	var failures []error
	for i := range c.Artifacts {
		a := &c.Artifacts[i]
		if a.Status != "quarantined" {
			continue
		}
		if err := restoreArtifact(root, id, *a, observer); err != nil {
			failures = append(failures, fmt.Errorf("restore %s: %w", a.Path, err))
			continue
		}
		if a.ID != "" {
			record, err := readArtifactRecord(root, a.Path, a.FileID)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if err := runJournaled(root, OperationEntry{
				CaseID: id, ArtifactID: a.ID, Action: "restore_ownership", Target: a.Path,
				Precondition: "file hash verified after restore", ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: a.QuarantinePath,
			}, observer, func() error {
				record.Status = "restored"
				return writeArtifactRecord(root, record)
			}); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		a.Status = "restored"
	}
	// A startup entry must not be re-enabled while its executable or DLL is
	// still absent. Keep the backup and the item status for a later retry.
	if len(failures) == 0 {
		for i := range c.Persistence {
			item := &c.Persistence[i]
			if item.Status != "removed" && item.Status != "delete_requested" {
				continue
			}
			precondition := fmt.Sprintf("type=%s location=%s backup=%s", item.Type, item.Location, item.BackupPath)
			intent := OperationEntry{
				CaseID: id, PersistenceID: PersistenceID(item.Type, item.Location, item.Name),
				Action: "restore_persistence", Target: item.Name, RelatedPath: item.Target, Precondition: precondition,
				PersistenceType: item.Type, PersistenceLocation: item.Location, BackupPath: item.BackupPath,
				ExpectedValue: item.Evidence, ValueType: item.ValueType,
			}
			if item.Type == "startup_link" || item.Type == "task" {
				if !backupWithin(root, id, item.BackupPath) {
					err := fmt.Errorf("persistence backup outside case directory")
					item.Error = err.Error()
					failures = append(failures, err)
					continue
				}
				hash, err := fileSHA256(item.BackupPath)
				if err != nil {
					item.Error = err.Error()
					failures = append(failures, err)
					continue
				}
				intent.ExpectedHash = hash
			}
			if err := runJournaled(root, intent, observer, func() error {
				if item.Target == "" {
					return fmt.Errorf("restore item lacks an associated artifact path")
				}
				if intent.ExpectedHash != "" {
					if hash, err := fileSHA256(item.BackupPath); err != nil || hash != intent.ExpectedHash {
						return fmt.Errorf("persistence backup changed after intent: %v", err)
					}
				}
				if err := restorePersistence(root, id, *item, intent.ExpectedHash); err != nil {
					return err
				}
				if item.Type == "registry_run" || item.Type == "startup_link" {
					present, err := persistenceRestoreObserved(root, intent)
					if err != nil || !present {
						return fmt.Errorf("restored persistence verification failed (present=%t): %v", present, err)
					}
				}
				return nil
			}); err != nil {
				item.Error = err.Error()
				failures = append(failures, fmt.Errorf("restore %s %s: %w", item.Type, item.Name, err))
			} else {
				item.Status = "restored"
				item.Error = ""
			}
		}
	}
	if len(failures) == 0 {
		c.Status = "restored"
	} else {
		c.Status = "partial_restore"
	}
	if err := commitCase(root, c, observer); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func restoreArtifact(root, caseID string, a Artifact, observer OperationObserver) error {
	artifactID := ArtifactID(a.Path, a.FileID, a.SHA256)
	quarantineRoot := filepath.Join(root, "eradication", "quarantine")
	if !beneath(a.QuarantinePath, quarantineRoot) || !inUserAppData(a.Path) {
		return fmt.Errorf("restore path is outside allowed directories")
	}
	if _, err := os.Lstat(a.Path); err == nil {
		return fmt.Errorf("original path is occupied; refusing to claim an unrelated file as restored")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if hash, err := fileSHA256(a.QuarantinePath); err != nil || hash != a.SHA256 {
		return fmt.Errorf("quarantined file hash mismatch: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(a.Path), 0700); err != nil {
		return err
	}
	tmpPath := filepath.Join(filepath.Dir(a.Path), ".restore-"+newCaseID(HitEvent{}))
	defer os.Remove(tmpPath)
	copyIntent := OperationEntry{
		CaseID: caseID, ArtifactID: artifactID, Action: "restore_copy", Target: a.Path, RelatedPath: a.Path,
		ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: a.QuarantinePath,
		TemporaryPath: tmpPath, Precondition: "quarantine hash verified; temporary destination absent",
	}
	if err := runJournaled(root, copyIntent, observer, func() error {
		tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		src, err := os.Open(a.QuarantinePath)
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
		return err
	}
	if err := runJournaled(root, OperationEntry{
		CaseID: caseID, ArtifactID: artifactID, Action: "restore_hash_verify", Target: a.Path, RelatedPath: a.Path,
		ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: a.QuarantinePath,
		TemporaryPath: tmpPath, Precondition: "temporary restore copy closed and synced",
	}, observer, func() error {
		if hash, err := fileSHA256(tmpPath); err != nil || hash != a.SHA256 {
			return fmt.Errorf("restored copy hash mismatch: %v", err)
		}
		return nil
	}); err != nil {
		return err
	}
	source, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(a.Path)
	if err != nil {
		return err
	}
	// Keep the no-overwrite guarantee even if another process creates the
	// original path after the Lstat check above.
	precondition := fmt.Sprintf("sha256=%s quarantine=%s target_absent=true", a.SHA256, a.QuarantinePath)
	return runJournaled(root, OperationEntry{
		CaseID: caseID, ArtifactID: artifactID, Action: "restore_file", Target: a.Path,
		Precondition: precondition, ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: a.QuarantinePath, TemporaryPath: tmpPath,
	}, observer, func() error {
		if err := windows.MoveFileEx(source, target, windows.MOVEFILE_WRITE_THROUGH); err != nil {
			return err
		}
		if hash, err := fileSHA256(a.Path); err != nil || hash != a.SHA256 {
			return fmt.Errorf("restored file verification failed: %v", err)
		}
		return nil
	})
}

func backupWithin(root, id, path string) bool {
	base := filepath.Join(root, "eradication", "backups", id)
	return beneath(path, base)
}

func restorePersistence(root, id string, item PersistenceItem, expectedBackupHash string) error {
	switch item.Type {
	case "registry_run":
		if item.ValueType != registry.SZ && item.ValueType != registry.EXPAND_SZ {
			return fmt.Errorf("unsupported registry value type %d", item.ValueType)
		}
		for _, loc := range runLocations {
			if locationName(loc) != item.Location {
				continue
			}
			key, _, err := registry.CreateKey(loc.root, loc.name, registry.QUERY_VALUE|registry.SET_VALUE|loc.view)
			if err != nil {
				return err
			}
			defer key.Close()
			if existing, valueType, err := key.GetStringValue(item.Name); err == nil {
				if existing == item.Evidence && valueType == item.ValueType {
					return nil
				}
				return fmt.Errorf("Run value already exists with different content or type")
			} else if !errors.Is(err, registry.ErrNotExist) {
				return fmt.Errorf("cannot inspect existing Run value: %w", err)
			}
			if item.ValueType == registry.EXPAND_SZ {
				return key.SetExpandStringValue(item.Name, item.Evidence)
			}
			return key.SetStringValue(item.Name, item.Evidence)
		}
		return fmt.Errorf("Run location missing from scanner")
	case "startup_link":
		if !backupWithin(root, id, item.BackupPath) {
			return fmt.Errorf("shortcut backup outside case directory")
		}
		allowed := false
		for _, dir := range startupFolders() {
			if samePath(filepath.Dir(item.Location), dir) {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("shortcut location changed")
		}
		if _, err := os.Lstat(item.Location); err == nil {
			return fmt.Errorf("shortcut path already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		b, err := os.ReadFile(item.BackupPath)
		if err != nil {
			return err
		}
		if expectedBackupHash == "" || fmt.Sprintf("%x", sha256.Sum256(b)) != expectedBackupHash {
			return fmt.Errorf("shortcut backup changed before publication")
		}
		return publishRestoredShortcut(item.Location, b)
	case "task":
		if !backupWithin(root, id, item.BackupPath) {
			return fmt.Errorf("task backup outside case directory")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tool, err := systemTool("schtasks.exe")
		if err != nil {
			return err
		}
		if err := exec.CommandContext(ctx, tool, "/Query", "/TN", item.Name).Run(); err == nil {
			return fmt.Errorf("task already exists")
		}
		out, err := exec.CommandContext(ctx, tool, "/Create", "/TN", item.Name, "/XML", item.BackupPath).CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks create: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	case "service":
		if !backupWithin(root, id, item.BackupPath) {
			return fmt.Errorf("service backup outside case directory")
		}
		return fmt.Errorf("service backup retained at %s; restore requires SCM review", item.BackupPath)
	}
	return fmt.Errorf("unsupported persistence type %s", item.Type)
}
