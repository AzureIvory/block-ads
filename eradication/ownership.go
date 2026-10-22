//go:build windows

package eradication

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ArtifactRecord is the durable owner of one remediated file. Cases reference
// this record rather than owning independent copies of its quarantine state.
type ArtifactRecord struct {
	ID             string    `json:"id"`
	Path           string    `json:"path"`
	FileID         string    `json:"file_id"`
	SHA256         string    `json:"sha256"`
	QuarantinePath string    `json:"quarantine_path"`
	OwnerCaseID    string    `json:"owner_case_id"`
	CaseIDs        []string  `json:"case_ids"`
	Status         string    `json:"status"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ArtifactID includes content, canonical original path and on-disk identity.
// A replacement at the same path is therefore a different artifact.
func ArtifactID(path, fileID, hash string) string {
	if path == "" || fileID == "" || hash == "" {
		return ""
	}
	canonical := strings.ToLower(filepath.Clean(path))
	sum := sha256.Sum256([]byte(strings.ToLower(hash) + "\x00" + canonical + "\x00" + fileID))
	return hex.EncodeToString(sum[:])
}

func artifactLookupID(path, fileID string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path)) + "\x00" + fileID))
	return hex.EncodeToString(sum[:])
}

func artifactRecordPath(root, path, fileID string) string {
	return filepath.Join(root, "eradication", "artifacts", artifactLookupID(path, fileID)+".json")
}

func readArtifactRecord(root, path, fileID string) (ArtifactRecord, error) {
	var record ArtifactRecord
	if path == "" || fileID == "" {
		return record, os.ErrNotExist
	}
	b, err := os.ReadFile(artifactRecordPath(root, path, fileID))
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(b, &record); err != nil {
		return record, err
	}
	if record.ID != ArtifactID(path, fileID, record.SHA256) || !samePath(record.Path, path) || record.FileID != fileID {
		return record, fmt.Errorf("artifact ownership record identity mismatch")
	}
	return record, nil
}

func writeArtifactRecord(root string, record ArtifactRecord) error {
	if record.ID != ArtifactID(record.Path, record.FileID, record.SHA256) {
		return fmt.Errorf("invalid artifact ID")
	}
	path := artifactRecordPath(root, record.Path, record.FileID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	record.UpdatedAt = time.Now()
	b, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, b)
}

func addCaseReference(record *ArtifactRecord, caseID string) bool {
	for _, id := range record.CaseIDs {
		if id == caseID {
			return false
		}
	}
	record.CaseIDs = append(record.CaseIDs, caseID)
	return true
}

func (m *Manager) findPreviouslyQuarantined(hit HitEvent) (ArtifactRecord, bool, error) {
	record, err := readArtifactRecord(m.root, hit.Image, hit.FileID)
	if errors.Is(err, os.ErrNotExist) {
		return ArtifactRecord{}, false, nil
	}
	if err != nil {
		return ArtifactRecord{}, false, err
	}
	if record.Status != "quarantined" {
		return ArtifactRecord{}, false, nil
	}
	if _, err := os.Lstat(record.Path); !errors.Is(err, os.ErrNotExist) {
		return ArtifactRecord{}, false, fmt.Errorf("recorded quarantined artifact path exists or cannot be checked: %v", err)
	}
	if hash, err := fileSHA256(record.QuarantinePath); err != nil || hash != record.SHA256 {
		return ArtifactRecord{}, false, fmt.Errorf("recorded quarantine hash mismatch: %v", err)
	}
	return record, true, nil
}

func (m *Manager) linkSharedCase(caseID string, primary ArtifactRecord) ([]Artifact, []PersistenceItem, error) {
	b, err := os.ReadFile(filepath.Join(m.root, "eradication", "cases", primary.OwnerCaseID+".json"))
	if err != nil {
		return nil, nil, err
	}
	var owner Case
	if err := json.Unmarshal(b, &owner); err != nil || owner.ID != primary.OwnerCaseID {
		return nil, nil, fmt.Errorf("shared artifact owner case is unavailable: %v", err)
	}
	artifacts := []Artifact{}
	for _, a := range owner.Artifacts {
		if a.Status != "quarantined" || a.ID == "" {
			continue
		}
		record, err := readArtifactRecord(m.root, a.Path, a.FileID)
		if err != nil || record.ID != a.ID || record.Status != "quarantined" {
			return nil, nil, fmt.Errorf("shared artifact record unavailable for %s: %v", a.Path, err)
		}
		if _, err := os.Lstat(a.Path); !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("shared artifact path returned: %s: %v", a.Path, err)
		}
		if hash, err := fileSHA256(record.QuarantinePath); err != nil || hash != record.SHA256 {
			return nil, nil, fmt.Errorf("shared artifact quarantine changed: %s: %v", a.Path, err)
		}
		if err := runJournaled(m.root, OperationEntry{
			CaseID: caseID, OwnerCaseID: record.OwnerCaseID, ArtifactID: record.ID,
			Action: "link_reference", Target: a.Path, RelatedPath: a.Path,
			ExpectedHash: record.SHA256, ExpectedFileID: record.FileID, QuarantinePath: record.QuarantinePath,
			Precondition: "owner artifact is quarantined; reference case is absent",
		}, m.OnOperation, func() error {
			addCaseReference(&record, caseID)
			return writeArtifactRecord(m.root, record)
		}); err != nil {
			return nil, nil, err
		}
		a.Status = "linked"
		a.OwnerCaseID = owner.ID
		a.Evidence += "; shared with case " + owner.ID
		artifacts = append(artifacts, a)
	}
	if len(artifacts) == 0 {
		return nil, nil, fmt.Errorf("owner case has no verified quarantined artifacts")
	}
	items := []PersistenceItem{}
	for _, item := range owner.Persistence {
		if item.Status != "removed" {
			continue
		}
		for _, a := range artifacts {
			if samePath(item.Target, a.Path) {
				item.Status = "linked"
				item.OwnerCaseID = owner.ID
				item.ID = PersistenceID(item.Type, item.Location, item.Name)
				items = append(items, item)
				break
			}
		}
	}
	return artifacts, items, nil
}

func PersistenceID(kind, location, name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(kind + "\x00" + location + "\x00" + name)))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) recordQuarantine(caseID string, a *Artifact) error {
	if a == nil || a.Status != "quarantined" {
		return fmt.Errorf("artifact is not verified quarantined")
	}
	record := ArtifactRecord{
		ID:   ArtifactID(a.Path, a.FileID, a.SHA256),
		Path: a.Path, FileID: a.FileID, SHA256: a.SHA256,
		QuarantinePath: a.QuarantinePath, OwnerCaseID: caseID,
		CaseIDs: []string{caseID}, Status: "quarantined",
	}
	if err := writeArtifactRecord(m.root, record); err != nil {
		return err
	}
	a.ID, a.OwnerCaseID = record.ID, caseID
	return nil
}

func restoreOwnershipAllowed(root, caseID string, a Artifact) error {
	if a.ID == "" {
		// Cases created before ownership records existed remain restorable.
		return nil
	}
	record, err := readArtifactRecord(root, a.Path, a.FileID)
	if err != nil {
		return err
	}
	if record.ID != a.ID || record.OwnerCaseID != caseID || record.Status != "quarantined" {
		return fmt.Errorf("artifact %s is owned by case %s", a.ID, record.OwnerCaseID)
	}
	if len(record.CaseIDs) != 1 || record.CaseIDs[0] != caseID {
		return fmt.Errorf("artifact %s is referenced by cases %v; shared restore requires coordinated release", a.ID, record.CaseIDs)
	}
	return nil
}

func releaseLinkedCase(root string, c *Case, observer OperationObserver) error {
	if c == nil {
		return fmt.Errorf("nil case")
	}
	for i := range c.Artifacts {
		a := &c.Artifacts[i]
		if a.Status != "linked" {
			continue
		}
		record, err := readArtifactRecord(root, a.Path, a.FileID)
		if err != nil {
			return err
		}
		if record.ID != a.ID || record.OwnerCaseID != a.OwnerCaseID || record.Status != "quarantined" {
			return fmt.Errorf("shared artifact ownership changed: %s", a.ID)
		}
		references := record.CaseIDs[:0]
		found := false
		for _, id := range record.CaseIDs {
			if id == c.ID {
				found = true
				continue
			}
			references = append(references, id)
		}
		if !found {
			return fmt.Errorf("case %s is not a reference to artifact %s", c.ID, a.ID)
		}
		if err := runJournaled(root, OperationEntry{
			CaseID: c.ID, OwnerCaseID: record.OwnerCaseID, ArtifactID: record.ID,
			Action: "release_reference", Target: a.Path, RelatedPath: a.Path,
			ExpectedHash: record.SHA256, ExpectedFileID: record.FileID, QuarantinePath: record.QuarantinePath,
			Precondition: "linked case is present in quarantined artifact references",
		}, observer, func() error {
			record.CaseIDs = references
			return writeArtifactRecord(root, record)
		}); err != nil {
			return err
		}
		a.Status = "released"
	}
	for i := range c.Persistence {
		if c.Persistence[i].Status == "linked" {
			c.Persistence[i].Status = "released"
		}
	}
	c.Status = "released"
	return nil
}
