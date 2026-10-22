//go:build windows

package tests

import (
	"block-ads/eradication"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRecoveryIntent(t *testing.T, root string, entry eradication.OperationEntry) {
	t.Helper()
	dir := filepath.Join(root, "eradication", "journal", entry.CaseID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, entry.ID+"-intent.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryInspectsFileStateWithoutRepeatingAction(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	path := filepath.Join(appData, "Bad", "sample.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("controlled artifact")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	fileID, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	quarantine := filepath.Join(root, "eradication", "quarantine", hash+".exe")
	if err := os.MkdirAll(filepath.Dir(quarantine), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(quarantine, content, 0600); err != nil {
		t.Fatal(err)
	}
	entry := eradication.OperationEntry{
		ID: "interrupted-delete", CaseID: "old-case", ArtifactID: eradication.ArtifactID(path, fileID, hash),
		Action: "delete_original", Target: path, ExpectedHash: hash, ExpectedFileID: fileID,
		QuarantinePath: quarantine, Phase: "intent",
	}
	writeRecoveryIntent(t, root, entry)
	findings, err := eradication.InspectRecovery(root)
	if err != nil || len(findings) != 1 || findings[0].Disposition != "not_observed" {
		t.Fatalf("existing original misclassified: %+v, %v", findings, err)
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(eradication.HitEvent{ID: "new-hit", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: fileID, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || cases[0].Status != "pending" || len(cases[0].Errors) == 0 || !strings.Contains(cases[0].Errors[0], "recovery review") {
		t.Fatalf("new remediation ignored unfinished prior operation: %+v", cases)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(content) {
		t.Fatalf("recovery audit changed original: %q, %v", got, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	findings, err = eradication.InspectRecovery(root)
	if err != nil || len(findings) != 1 || findings[0].Disposition != "observed_uncommitted" {
		t.Fatalf("removed original misclassified: %+v, %v", findings, err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err = eradication.InspectRecovery(root)
	if err != nil || len(findings) != 1 || findings[0].Disposition != "conflict" {
		t.Fatalf("replacement conflict misclassified: %+v, %v", findings, err)
	}
}

func TestRecoveryDoesNotTrustSameHashRestoreTarget(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	path := filepath.Join(appData, "Bad", "sample.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("quarantined bytes")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	fileID, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	quarantine := filepath.Join(root, "eradication", "quarantine", hash+".exe")
	if err := os.MkdirAll(filepath.Dir(quarantine), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(quarantine, content, 0600); err != nil {
		t.Fatal(err)
	}
	writeRecoveryIntent(t, root, eradication.OperationEntry{
		ID: "interrupted-restore", CaseID: "old-case", ArtifactID: eradication.ArtifactID(path, fileID, hash),
		Action: "restore_file", Target: path, ExpectedHash: hash, ExpectedFileID: fileID,
		QuarantinePath: quarantine, Phase: "intent",
	})
	findings, err := eradication.InspectRecovery(root)
	if err != nil || len(findings) != 1 || findings[0].Disposition != "not_observed" {
		t.Fatalf("absent restore target misclassified: %+v, %v", findings, err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	findings, err = eradication.InspectRecovery(root)
	if err != nil || len(findings) != 1 || findings[0].Disposition != "observed_uncommitted" || !strings.Contains(findings[0].Evidence, "provenance") {
		t.Fatalf("same-hash restore target was trusted without provenance review: %+v, %v", findings, err)
	}
}
