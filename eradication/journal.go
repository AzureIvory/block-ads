//go:build windows

package eradication

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// OperationEntry records an action independently of the final case status.
// Intent is durable before the external change; result is a separate file so
// an interrupted action remains visible after a crash.
type OperationEntry struct {
	ID                  string    `json:"id"`
	Sequence            uint64    `json:"sequence,omitempty"`
	CaseID              string    `json:"case_id"`
	OwnerCaseID         string    `json:"owner_case_id,omitempty"`
	ProcessID           uint32    `json:"process_id,omitempty"`
	CreatedHigh         uint32    `json:"created_high,omitempty"`
	CreatedLow          uint32    `json:"created_low,omitempty"`
	ArtifactID          string    `json:"artifact_id,omitempty"`
	PersistenceID       string    `json:"persistence_id,omitempty"`
	PersistenceType     string    `json:"persistence_type,omitempty"`
	PersistenceLocation string    `json:"persistence_location,omitempty"`
	BackupPath          string    `json:"backup_path,omitempty"`
	ExpectedValue       string    `json:"expected_value,omitempty"`
	ValueType           uint32    `json:"value_type,omitempty"`
	ExpectedHash        string    `json:"expected_sha256,omitempty"`
	PreviousHash        string    `json:"previous_sha256,omitempty"`
	ExpectedFileID      string    `json:"expected_file_id,omitempty"`
	QuarantinePath      string    `json:"quarantine_path,omitempty"`
	TemporaryPath       string    `json:"temporary_path,omitempty"`
	RelatedPath         string    `json:"related_path,omitempty"`
	Action              string    `json:"action"`
	Target              string    `json:"target"`
	Precondition        string    `json:"precondition,omitempty"`
	Phase               string    `json:"phase"`
	Error               string    `json:"error,omitempty"`
	At                  time.Time `json:"at"`
}

// OperationObserver receives a durable intent, a finished external action,
// and a durable result in order. It is useful for progress reporting and
// controlled crash testing. It must not mutate the entry.
type OperationObserver func(OperationEntry, string)

func journalPath(root string, entry OperationEntry) string {
	return filepath.Join(root, "eradication", "journal", entry.CaseID, entry.ID+"-"+entry.Phase+".json")
}

func writeOperation(root string, entry OperationEntry) error {
	if !validOperationCaseID(entry.CaseID) {
		return fmt.Errorf("invalid operation case ID")
	}
	if entry.ID == "" || entry.Phase != "intent" && entry.Phase != "committed" && entry.Phase != "failed" {
		return fmt.Errorf("invalid operation entry")
	}
	path := journalPath(root, entry)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, b)
}

func validOperationCaseID(id string) bool {
	return id != "" && filepath.Base(id) == id && !strings.ContainsAny(id, `/\:`)
}

func writeSequencedIntent(root string, entry *OperationEntry) error {
	if !validOperationCaseID(entry.CaseID) {
		return fmt.Errorf("invalid operation case ID")
	}
	dir := filepath.Join(root, "eradication", "journal", entry.CaseID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	lockPath, err := windows.UTF16PtrFromString(filepath.Join(dir, ".sequence.lock"))
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(lockPath, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var overlapped windows.Overlapped
	const lockExclusive = 0x2
	if err := windows.LockFileEx(h, lockExclusive, 0, 1, 0, &overlapped); err != nil {
		return err
	}
	defer windows.UnlockFileEx(h, 0, 1, 0, &overlapped)
	sequence, err := nextOperationSequence(dir)
	if err != nil {
		return err
	}
	entry.Sequence = sequence
	return writeOperation(root, *entry)
}

func nextOperationSequence(dir string) (uint64, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	seen := map[uint64]bool{}
	var max uint64
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), "-intent.json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			return 0, err
		}
		var prior OperationEntry
		if err := json.Unmarshal(b, &prior); err != nil {
			return 0, err
		}
		if prior.Sequence == 0 { // journals written before sequence allocation
			continue
		}
		if seen[prior.Sequence] {
			return 0, fmt.Errorf("duplicate journal sequence %d in %s", prior.Sequence, dir)
		}
		seen[prior.Sequence] = true
		if prior.Sequence > max {
			max = prior.Sequence
		}
	}
	if max == ^uint64(0) {
		return 0, fmt.Errorf("journal sequence overflow")
	}
	for sequence := uint64(1); sequence <= uint64(len(seen)); sequence++ {
		if !seen[sequence] {
			return 0, fmt.Errorf("missing journal sequence %d in %s", sequence, dir)
		}
	}
	if max != uint64(len(seen)) {
		return 0, fmt.Errorf("journal sequence gap in %s", dir)
	}
	return max + 1, nil
}

func runJournaled(root string, entry OperationEntry, observer OperationObserver, perform func() error) error {
	entry.ID = newCaseID(HitEvent{})
	entry.Phase = "intent"
	entry.At = time.Now()
	if err := writeSequencedIntent(root, &entry); err != nil {
		return fmt.Errorf("write %s intent: %w", entry.Action, err)
	}
	if observer != nil {
		observer(entry, "after_intent")
	}
	actionErr := perform()
	if observer != nil {
		observer(entry, "after_action")
	}
	entry.At = time.Now()
	if actionErr == nil {
		entry.Phase = "committed"
	} else {
		entry.Phase = "failed"
		entry.Error = actionErr.Error()
	}
	if err := writeOperation(root, entry); err != nil {
		return errors.Join(actionErr, fmt.Errorf("write %s result: %w", entry.Action, err))
	}
	if observer != nil {
		observer(entry, "after_result")
	}
	return actionErr
}

// ValidateJournalOrder rejects missing or conflicting durable steps before a
// recovery reader infers state from a partially written case.
func ValidateJournalOrder(root string) error {
	dir := filepath.Join(root, "eradication", "journal")
	cases, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, caseDir := range cases {
		if !caseDir.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(dir, caseDir.Name()))
		if err != nil {
			return err
		}
		intents := map[string]OperationEntry{}
		results := map[string]OperationEntry{}
		sequences := map[uint64]string{}
		var max uint64
		for _, file := range entries {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, caseDir.Name(), file.Name()))
			if err != nil {
				return err
			}
			var operation OperationEntry
			if err := json.Unmarshal(b, &operation); err != nil {
				return err
			}
			if operation.CaseID != caseDir.Name() || operation.ID == "" ||
				file.Name() != operation.ID+"-"+operation.Phase+".json" {
				return fmt.Errorf("journal filename or case identity mismatch: %s", file.Name())
			}
			switch operation.Phase {
			case "intent":
				intents[operation.ID] = operation
				if operation.Sequence != 0 {
					if previous := sequences[operation.Sequence]; previous != "" {
						return fmt.Errorf("duplicate journal sequence %d in case %s", operation.Sequence, caseDir.Name())
					}
					sequences[operation.Sequence] = operation.ID
					if operation.Sequence > max {
						max = operation.Sequence
					}
				}
			case "committed", "failed":
				if _, exists := results[operation.ID]; exists {
					return fmt.Errorf("multiple journal results for operation %s", operation.ID)
				}
				results[operation.ID] = operation
			default:
				return fmt.Errorf("invalid journal phase in %s", file.Name())
			}
		}
		for sequence := uint64(1); sequence <= uint64(len(sequences)); sequence++ {
			if sequences[sequence] == "" {
				return fmt.Errorf("missing journal sequence %d in case %s", sequence, caseDir.Name())
			}
		}
		if max != uint64(len(sequences)) {
			return fmt.Errorf("journal sequence gap in case %s", caseDir.Name())
		}
		for id, result := range results {
			intent, ok := intents[id]
			// Only outcome fields may change. Recovery relies on the complete
			// persistence/file identity and preconditions recorded by the intent.
			result.Phase, result.Error, result.At = intent.Phase, intent.Error, intent.At
			if !ok || intent != result {
				return fmt.Errorf("journal result does not match intent %s", id)
			}
		}
	}
	return nil
}

// UnfinishedOperations reports intents without a committed or failed result.
// The caller must inspect external state before retrying or rolling back.
func UnfinishedOperations(root string) ([]OperationEntry, error) {
	if err := ValidateJournalOrder(root); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, "eradication", "journal")
	intents := map[string]OperationEntry{}
	results := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var operation OperationEntry
		if err := json.Unmarshal(b, &operation); err != nil {
			return fmt.Errorf("read operation %s: %w", path, err)
		}
		key := operation.CaseID + "\x00" + operation.ID
		switch operation.Phase {
		case "intent":
			intents[key] = operation
		case "committed", "failed":
			results[key] = true
		default:
			return fmt.Errorf("invalid operation phase in %s", path)
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	unfinished := []OperationEntry{}
	for key, entry := range intents {
		if !results[key] {
			unfinished = append(unfinished, entry)
		}
	}
	sort.Slice(unfinished, func(i, j int) bool {
		if unfinished[i].CaseID == unfinished[j].CaseID && unfinished[i].Sequence != 0 && unfinished[j].Sequence != 0 {
			return unfinished[i].Sequence < unfinished[j].Sequence
		}
		if unfinished[i].At.Equal(unfinished[j].At) {
			return unfinished[i].ID < unfinished[j].ID
		}
		return unfinished[i].At.Before(unfinished[j].At)
	})
	return unfinished, nil
}
