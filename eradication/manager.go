//go:build windows

package eradication

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// HitEvent is an immutable snapshot of a rule match. The process key includes
// creation time so a recycled PID cannot become a new cleanup target.
type HitEvent struct {
	ID            string            `json:"id"`
	PID           uint32            `json:"pid"`
	ParentPID     uint32            `json:"parent_pid"`
	ParentImage   string            `json:"parent_image,omitempty"`
	CreatedHigh   uint32            `json:"created_high,omitempty"`
	CreatedLow    uint32            `json:"created_low,omitempty"`
	Image         string            `json:"image"`
	FileID        string            `json:"file_id,omitempty"`
	Signer        string            `json:"signer,omitempty"`
	RuleKind      string            `json:"rule_kind"`
	Rule          string            `json:"rule"`
	Source        string            `json:"source"`
	EventAt       time.Time         `json:"event_at,omitempty"`
	DetectedAt    time.Time         `json:"detected_at"`
	Modules       []string          `json:"modules,omitempty"`
	ModuleIDs     map[string]string `json:"module_ids,omitempty"`
	ModuleError   string            `json:"module_error,omitempty"`
	IdentityError string            `json:"identity_error,omitempty"`
}

type Artifact struct {
	ID             string `json:"id,omitempty"`
	OwnerCaseID    string `json:"owner_case_id,omitempty"`
	Path           string `json:"path"`
	Kind           string `json:"kind"`
	FileID         string `json:"file_id,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	Signer         string `json:"signer,omitempty"`
	Confidence     string `json:"confidence"`
	Evidence       string `json:"evidence"`
	QuarantinePath string `json:"quarantine_path,omitempty"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
}

type PersistenceItem struct {
	ID                       string `json:"id,omitempty"`
	OwnerCaseID              string `json:"owner_case_id,omitempty"`
	Type                     string `json:"type"`
	Name                     string `json:"name"`
	Location                 string `json:"location"`
	Target                   string `json:"target"`
	Evidence                 string `json:"evidence"`
	ValueType                uint32 `json:"value_type,omitempty"`
	BackupPath               string `json:"backup_path,omitempty"`
	Confidence               string `json:"confidence"`
	Status                   string `json:"status"`
	Error                    string `json:"error,omitempty"`
	ShortcutTarget           string `json:"shortcut_target,omitempty"`
	ShortcutArguments        string `json:"shortcut_arguments,omitempty"`
	ShortcutWorkingDirectory string `json:"shortcut_working_directory,omitempty"`
}

type Case struct {
	ID           string               `json:"id"`
	Status       string               `json:"status"`
	Hit          HitEvent             `json:"hit"`
	StartedAt    time.Time            `json:"started_at"`
	FinishedAt   time.Time            `json:"finished_at,omitempty"`
	ProcessExit  string               `json:"process_exit"`
	Errors       []string             `json:"errors,omitempty"`
	Artifacts    []Artifact           `json:"artifacts"`
	Persistence  []PersistenceItem    `json:"persistence"`
	Verification *VerificationSummary `json:"verification,omitempty"`
}

type Manager struct {
	root                   string
	remediateMu            sync.Mutex
	queueMu                sync.Mutex
	queueReady             *sync.Cond
	pending                []HitEvent
	seenEvents             map[string]struct{}
	closed                 bool
	workers                sync.WaitGroup
	closeOnce              sync.Once
	OnContainment          func(HitEvent, bool, error)
	OnOperation            OperationObserver
	ScheduleDeleteAtReboot func(string) error
	recoveryBlocked        map[string]OperationEntry
	recoveryReadErr        error
}

func NewManager(root string, queueSize, workerCount int) *Manager {
	if queueSize < 1 {
		queueSize = 256
	}
	if workerCount < 1 {
		workerCount = 2
	}
	m := &Manager{root: root, pending: make([]HitEvent, 0, queueSize), seenEvents: map[string]struct{}{}, ScheduleDeleteAtReboot: scheduleDeleteAtReboot}
	m.recoveryBlocked = map[string]OperationEntry{}
	if findings, err := InspectRecovery(root); err != nil {
		m.recoveryReadErr = err
	} else {
		for _, finding := range findings {
			operation := finding.Operation
			path := operation.RelatedPath
			if path == "" && (operation.Action == "delete_original" || operation.Action == "enumerate_lockers" || operation.Action == "delete_retry" || operation.Action == "schedule_reboot_delete" || operation.Action == "pending_reboot_verify" || operation.Action == "record_ownership" || operation.Action == "restore_file" || operation.Action == "restore_ownership" || operation.Action == "case_commit") {
				path = operation.Target
			}
			if path != "" {
				m.recoveryBlocked[strings.ToLower(filepath.Clean(path))] = operation
			}
		}
	}
	m.queueReady = sync.NewCond(&m.queueMu)
	for i := 0; i < workerCount; i++ {
		m.workers.Add(1)
		go func() {
			defer m.workers.Done()
			for {
				hit, ok := m.next()
				if !ok {
					return
				}
				m.handle(hit)
			}
		}()
	}
	return m
}

// Submit runs after the legacy kill/log path. It appends exactly one job and
// does not wait for a cleanup worker inside the ETW callback.
func (m *Manager) Submit(hit HitEvent) bool {
	if m == nil {
		return false
	}
	m.queueMu.Lock()
	defer m.queueMu.Unlock()
	if m.closed {
		panic("eradication: submit after close")
	}
	if hit.ID != "" {
		if _, exists := m.seenEvents[hit.ID]; exists {
			return false
		}
		m.seenEvents[hit.ID] = struct{}{}
	}
	m.pending = append(m.pending, hit)
	m.queueReady.Signal()
	return true
}

func (m *Manager) next() (HitEvent, bool) {
	m.queueMu.Lock()
	defer m.queueMu.Unlock()
	for len(m.pending) == 0 && !m.closed {
		m.queueReady.Wait()
	}
	if len(m.pending) == 0 {
		return HitEvent{}, false
	}
	hit := m.pending[0]
	m.pending[0] = HitEvent{}
	m.pending = m.pending[1:]
	return hit, true
}

func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		m.queueMu.Lock()
		m.closed = true
		m.queueReady.Broadcast()
		m.queueMu.Unlock()
	})
	m.workers.Wait()
}

func newCaseID(hit HitEvent) string {
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Sprintf("%d-%d", time.Now().UnixNano(), hit.PID)
	}
	return fmt.Sprintf("%s-%d-%s", time.Now().UTC().Format("20060102T150405.000000000Z"), hit.PID, hex.EncodeToString(suffix[:]))
}

func (m *Manager) handle(hit HitEvent) {
	// Keep a case for every hit, while serializing mutations of shared files and
	// persistence entries across workers.
	m.remediateMu.Lock()
	defer m.remediateMu.Unlock()
	c := Case{ID: newCaseID(hit), Status: "pending", Hit: hit, StartedAt: time.Now(), Artifacts: []Artifact{}, Persistence: []PersistenceItem{}}
	defer func() {
		if c.ProcessExit == "verified" && hasRemovedArtifacts(c) {
			c.Verification = verifyPostClean(m.root, c, m.OnOperation)
		}
		c.Status = caseStatus(c)
		c.FinishedAt = time.Now()
		if err := m.saveCase(c); err != nil {
			log.Printf("[ERADICATION] case %s save failed: %v", c.ID, err)
		}
	}()
	if m.recoveryReadErr != nil {
		c.Errors = append(c.Errors, "recovery journal unreadable: "+m.recoveryReadErr.Error())
		return
	}
	if operation, blocked := m.recoveryBlocked[strings.ToLower(filepath.Clean(hit.Image))]; blocked {
		c.Errors = append(c.Errors, fmt.Sprintf("prior operation %s in case %s requires recovery review", operation.Action, operation.CaseID))
		return
	}

	// A module snapshot must be attempted before termination. Newly created
	// processes may not have an initialized loader table; absence is not proof.
	modules := hit.Modules
	if hit.ModuleError != "" {
		c.Errors = append(c.Errors, "pre-containment module snapshot: "+hit.ModuleError)
	}
	var moduleErr error
	if len(modules) == 0 {
		modules, moduleErr = loadedModules(hit.PID)
	}
	if moduleErr != nil {
		c.Errors = append(c.Errors, "module snapshot: "+moduleErr.Error())
	}
	shared, alreadyQuarantined, sharedErr := m.findPreviouslyQuarantined(hit)
	if sharedErr != nil {
		c.Errors = append(c.Errors, "shared artifact lookup: "+sharedErr.Error())
		return
	}

	exited, err := contain(hit, alreadyQuarantined)
	if err != nil {
		c.Errors = append(c.Errors, "containment: "+err.Error())
	}
	if exited {
		c.ProcessExit = "verified"
	} else {
		c.ProcessExit = "unverified"
	}
	if m.OnContainment != nil {
		m.OnContainment(hit, exited, err)
	}
	if !exited {
		return
	}
	if alreadyQuarantined {
		artifacts, items, err := m.linkSharedCase(c.ID, shared)
		if err != nil {
			c.Errors = append(c.Errors, "shared artifact linkage: "+err.Error())
			return
		}
		c.Artifacts, c.Persistence = artifacts, items
		return
	}

	artifacts := collectEvidence(hit, modules)
	c.Artifacts = artifacts
	items, scanErrors := scanPersistence(artifacts)
	c.Persistence = items
	c.Errors = append(c.Errors, scanErrors...)
	for i := range c.Persistence {
		if c.Persistence[i].Type == "service" {
			c.Persistence[i].Status = "experimental_review"
			c.Persistence[i].Error = "service remediation is experimental; SCM configuration is not automatically restored"
			log.Printf("[ERADICATION] case %s service %s requires experimental review", c.ID, c.Persistence[i].Name)
		}
		if err := m.backupPersistence(c.ID, &c.Persistence[i]); err != nil {
			if c.Persistence[i].Type != "service" {
				c.Persistence[i].Status = "review"
			}
			c.Persistence[i].Error = "backup failed: " + err.Error()
		}
	}
	// Preserve a recovery plan before making any persistence or file changes.
	if err := m.savePlan(c); err != nil {
		c.Errors = append(c.Errors, "recovery plan: "+err.Error())
		return
	}
	for i := range c.Artifacts {
		a := &c.Artifacts[i]
		if a.Confidence != "HIGH" {
			a.Status = "review"
			continue
		}
		if !artifactStillMatches(c.Artifacts, a.Path) {
			a.Status = "review"
			a.Error = "file identity or hash changed before quarantine"
			continue
		}
		path, err := m.quarantine(c.ID, hit, *a)
		if path != "" {
			a.QuarantinePath = path
		}
		if err != nil {
			var reboot *PendingRebootError
			if errors.As(err, &reboot) {
				a.Status = "pending_reboot"
			} else {
				a.Status = "pending"
			}
			a.Error = err.Error()
			continue
		}
		a.Status = "quarantined"
		if err := runJournaled(m.root, OperationEntry{
			CaseID: c.ID, ArtifactID: ArtifactID(a.Path, a.FileID, a.SHA256), Action: "record_ownership", Target: a.Path,
			Precondition: "quarantine verified at " + path, ExpectedHash: a.SHA256, ExpectedFileID: a.FileID, QuarantinePath: path,
		}, m.OnOperation, func() error {
			return m.recordQuarantine(c.ID, a)
		}); err != nil {
			a.Status = "pending"
			a.Error = "ownership record failed after quarantine: " + err.Error()
		}
	}
	for i := range c.Persistence {
		if c.Persistence[i].Status != "pending" {
			continue
		}
		if !artifactQuarantined(c.Artifacts, c.Persistence[i].Target) {
			c.Persistence[i].Status = "pending"
			c.Persistence[i].Error = "target artifact was not verified in quarantine"
			continue
		}
		item := &c.Persistence[i]
		precondition := fmt.Sprintf("type=%s location=%s target=%s", item.Type, item.Location, item.Target)
		entry := OperationEntry{
			CaseID: c.ID, PersistenceID: PersistenceID(item.Type, item.Location, item.Name),
			Action: "remove_persistence", Target: item.Name, RelatedPath: item.Target, Precondition: precondition,
			PersistenceType: item.Type, PersistenceLocation: item.Location, BackupPath: item.BackupPath,
			ExpectedValue: item.Evidence, ValueType: item.ValueType,
		}
		if item.Type == "startup_link" || item.Type == "task" {
			hash, err := fileSHA256(item.BackupPath)
			if err != nil {
				item.Status = "failed"
				item.Error = "persistence backup changed before deletion: " + err.Error()
				continue
			}
			entry.ExpectedHash = hash
		}
		if err := runJournaled(m.root, entry, m.OnOperation, func() error {
			return removePersistence(item)
		}); err != nil {
			c.Persistence[i].Status = "failed"
			c.Persistence[i].Error = err.Error()
		} else if c.Persistence[i].Status == "pending" {
			c.Persistence[i].Status = "removed"
			c.Persistence[i].OwnerCaseID = c.ID
			c.Persistence[i].ID = PersistenceID(c.Persistence[i].Type, c.Persistence[i].Location, c.Persistence[i].Name)
		}
	}
}

func caseStatus(c Case) string {
	if c.ProcessExit != "verified" {
		return "pending"
	}
	// Removal checks prove only the immediate result. A watchdog or updater can
	// recreate files and persistence after this worker exits. A future post-clean
	// observation (including a reboot check) must explicitly mark completion.
	status := "pending_verification"
	pending := false
	for _, a := range c.Artifacts {
		if a.Status == "pending_reboot" {
			return "pending_reboot"
		}
		if a.Status == "pending" || a.Status == "failed" {
			pending = true
		}
		if a.Status == "review" {
			status = "review"
		}
	}
	for _, item := range c.Persistence {
		if item.Status == "pending" || item.Status == "failed" || item.Status == "delete_requested" {
			pending = true
		}
		if item.Status == "review" || item.Status == "experimental_review" {
			status = "review"
		}
	}
	if c.Verification != nil && c.Verification.Status == "failed" {
		return "partial_failure"
	}
	if pending {
		return "pending"
	}
	return status
}

func (m *Manager) saveCase(c Case) error {
	return commitCase(m.root, c, m.OnOperation)
}

func commitCase(root string, c Case, observer OperationObserver) error {
	dir := filepath.Join(root, "eradication", "cases")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	path := filepath.Join(dir, c.ID+".json")
	previousHash, err := fileSHA256(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if os.IsNotExist(err) {
		previousHash = ""
	}
	return runJournaled(root, OperationEntry{
		CaseID: c.ID, Action: "case_commit", Target: c.Hit.Image, RelatedPath: c.Hit.Image,
		ExpectedHash: hex.EncodeToString(sum[:]), PreviousHash: previousHash,
		Precondition: "case snapshot finalized; previous snapshot hash recorded",
	}, observer, func() error {
		currentHash, err := fileSHA256(path)
		if previousHash == "" && !os.IsNotExist(err) || previousHash != "" && (err != nil || currentHash != previousHash) {
			return fmt.Errorf("case snapshot changed before commit: %v", err)
		}
		if err := atomicWrite(path, b); err != nil {
			return err
		}
		hash, err := fileSHA256(path)
		if err != nil || hash != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("case snapshot verification failed: %v", err)
		}
		return nil
	})
}

func (m *Manager) savePlan(c Case) error {
	dir := filepath.Join(m.root, "eradication", "cases")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, c.ID+"-plan.json"), b)
}

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
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
	source, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	destination, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, destination, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
