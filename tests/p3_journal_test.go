//go:build windows

package tests

import (
	"block-ads/eradication"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readOperations(t *testing.T, root string) []eradication.OperationEntry {
	t.Helper()
	operations := []eradication.OperationEntry{}
	dir := filepath.Join(root, "eradication", "journal")
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
		var operation eradication.OperationEntry
		if err := json.Unmarshal(b, &operation); err != nil {
			return err
		}
		operations = append(operations, operation)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return operations
}

func TestOperationJournalForQuarantineAndRestore(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("USERPROFILE", root)
	path := filepath.Join(appData, "Bad", "sample.exe")
	testExecutable(t, path)
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(eradication.HitEvent{ID: "journal-hit", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || cases[0].Artifacts[0].Status != "quarantined" {
		t.Fatalf("test precondition: %+v", cases)
	}
	if err := eradication.RestoreCase(root, cases[0].ID); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]eradication.OperationEntry{}
	sequences := map[uint64]string{}
	for _, entry := range readOperations(t, root) {
		if entry.CaseID != cases[0].ID || entry.Target != path {
			t.Fatalf("journal entry lost case or target: %+v", entry)
		}
		if byID[entry.ID] == nil {
			byID[entry.ID] = map[string]eradication.OperationEntry{}
		}
		byID[entry.ID][entry.Phase] = entry
		if entry.Phase == "intent" {
			if entry.Sequence == 0 || sequences[entry.Sequence] != "" {
				t.Fatalf("missing or duplicate case sequence: %+v", entry)
			}
			sequences[entry.Sequence] = entry.ID
		}
	}
	for sequence := uint64(1); sequence <= uint64(len(sequences)); sequence++ {
		if sequences[sequence] == "" {
			t.Fatalf("missing case sequence %d: %+v", sequence, sequences)
		}
	}
	actions := map[string]bool{}
	for _, phases := range byID {
		intent, ok := phases["intent"]
		if !ok || intent.Precondition == "" || phases["committed"].Action != intent.Action || phases["committed"].Sequence != intent.Sequence {
			t.Fatalf("operation lacks a matching intent and commit: %+v", phases)
		}
		if intent.Action == "delete_original" || intent.Action == "restore_file" {
			if intent.ExpectedHash == "" || intent.ExpectedFileID == "" || intent.QuarantinePath == "" {
				t.Fatalf("file operation lacks recovery identity: %+v", intent)
			}
		}
		actions[intent.Action] = true
	}
	for _, action := range []string{"delete_original", "record_ownership", "restore_file", "restore_ownership"} {
		if !actions[action] {
			t.Fatalf("missing journal action %s: %+v", action, actions)
		}
	}
	unfinished, err := eradication.UnfinishedOperations(root)
	if err != nil || len(unfinished) != 0 {
		t.Fatalf("committed operations reported unfinished: %+v, %v", unfinished, err)
	}
}

func TestJournalSequenceCorruptionIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []eradication.OperationEntry
	}{
		{"gap", []eradication.OperationEntry{
			{ID: "first", Sequence: 1, Phase: "intent"},
			{ID: "third", Sequence: 3, Phase: "intent"},
		}},
		{"duplicate", []eradication.OperationEntry{
			{ID: "first", Sequence: 1, Phase: "intent"},
			{ID: "second", Sequence: 1, Phase: "intent"},
		}},
		{"result mismatch", []eradication.OperationEntry{
			{ID: "first", Sequence: 1, Phase: "intent"},
			{ID: "first", Sequence: 2, Phase: "committed"},
		}},
		{"backup hash mismatch", []eradication.OperationEntry{
			{ID: "first", Sequence: 1, Phase: "intent", ExpectedHash: "original"},
			{ID: "first", Sequence: 1, Phase: "committed", ExpectedHash: "replacement"},
		}},
		{"persistence location mismatch", []eradication.OperationEntry{
			{ID: "first", Sequence: 1, Phase: "intent", PersistenceLocation: "Run"},
			{ID: "first", Sequence: 1, Phase: "committed", PersistenceLocation: "RunOnce"},
		}},
		{"registry type mismatch", []eradication.OperationEntry{
			{ID: "first", Sequence: 1, Phase: "intent", ValueType: 1},
			{ID: "first", Sequence: 1, Phase: "committed", ValueType: 2},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testRoot(t)
			dir := filepath.Join(root, "eradication", "journal", "sequence-case")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			for _, entry := range tc.entries {
				entry.CaseID, entry.Action, entry.Target = "sequence-case", "test_action", `C:\test.exe`
				b, err := json.Marshal(entry)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, entry.ID+"-"+entry.Phase+".json"), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := eradication.ValidateJournalOrder(root); err == nil {
				t.Fatal("corrupt operation sequence was accepted")
			}
		})
	}
}

func TestUnfinishedOperationRemainsVisible(t *testing.T) {
	root := testRoot(t)
	entry := eradication.OperationEntry{ID: "interrupted", CaseID: "case-1", Action: "delete_original", Target: `C:\test.exe`, Phase: "intent"}
	dir := filepath.Join(root, "eradication", "journal", entry.CaseID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "interrupted-intent.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	unfinished, err := eradication.UnfinishedOperations(root)
	if err != nil || len(unfinished) != 1 || unfinished[0].Action != "delete_original" {
		t.Fatalf("interrupted operation was hidden: %+v, %v", unfinished, err)
	}
}
