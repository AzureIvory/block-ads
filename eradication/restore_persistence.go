//go:build windows

package eradication

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Publish the synced shortcut without replacing a file created since the
// initial absence check. atomicWrite is unsuitable because it replaces targets.
func publishRestoredShortcut(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".restore-link-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	source, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, target, windows.MOVEFILE_WRITE_THROUGH)
}

// A matching observation is evidence, not proof of which process restored it.
// This helper never writes to the registry or to a persistence location.
func persistenceRestoreObserved(root string, operation OperationEntry) (bool, error) {
	if operation.RelatedPath == "" || operation.PersistenceID != PersistenceID(operation.PersistenceType, operation.PersistenceLocation, operation.Target) {
		return false, fmt.Errorf("restore intent lacks persistence identity or artifact association")
	}
	switch operation.PersistenceType {
	case "task":
		return taskRestoreObserved(root, operation)
	case "registry_run":
		if operation.ValueType != registry.SZ && operation.ValueType != registry.EXPAND_SZ {
			return false, fmt.Errorf("unsupported Run value type")
		}
		for _, loc := range runLocations {
			if locationName(loc) != operation.PersistenceLocation {
				continue
			}
			key, err := registry.OpenKey(loc.root, loc.name, registry.QUERY_VALUE|loc.view)
			if errors.Is(err, registry.ErrNotExist) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			defer key.Close()
			value, valueType, err := key.GetStringValue(operation.Target)
			if errors.Is(err, registry.ErrNotExist) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if value != operation.ExpectedValue || valueType != operation.ValueType {
				return false, fmt.Errorf("Run content or value type differs from restore intent")
			}
			return true, nil
		}
		return false, fmt.Errorf("unrecognized Run location")
	case "startup_link":
		if operation.ExpectedHash == "" || !backupWithin(root, operation.CaseID, operation.BackupPath) {
			return false, fmt.Errorf("restore intent lacks a verified case backup")
		}
		allowed := false
		for _, dir := range startupFolders() {
			if samePath(filepath.Dir(operation.PersistenceLocation), dir) {
				allowed = true
			}
		}
		if !allowed {
			return false, fmt.Errorf("shortcut location is outside Startup folders")
		}
		if hash, err := fileSHA256(operation.BackupPath); err != nil || hash != operation.ExpectedHash {
			return false, fmt.Errorf("shortcut backup differs from restore intent: %v", err)
		}
		info, err := os.Lstat(operation.PersistenceLocation)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("shortcut path is not a regular file")
		}
		if hash, err := fileSHA256(operation.PersistenceLocation); err != nil || hash != operation.ExpectedHash {
			return false, fmt.Errorf("shortcut bytes differ from restore intent: %v", err)
		}
		return true, nil
	}
	return false, fmt.Errorf("persistence type has no read-only restore verification")
}

func inspectPersistenceRestore(root string, operation OperationEntry) (string, string) {
	if operation.PersistenceType != "registry_run" && operation.PersistenceType != "startup_link" && operation.PersistenceType != "task" {
		return "manual_review", "persistence restore requires type-specific verification"
	}
	present, err := persistenceRestoreObserved(root, operation)
	if err != nil {
		return "conflict", err.Error()
	}
	if present {
		return "observed_uncommitted", "persistence matches restore intent but provenance and case commit need review"
	}
	return "not_observed", "restored persistence entry is absent"
}
