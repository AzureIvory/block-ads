//go:build windows

package eradication

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type ObservationOptions struct {
	Window   time.Duration
	Interval time.Duration
}

func (o ObservationOptions) validate() error {
	if o.Window == 0 && o.Interval == 0 {
		return nil
	}
	if o.Window <= 0 || o.Window > time.Minute || o.Interval < 100*time.Millisecond || o.Interval > o.Window {
		return fmt.Errorf("observation requires 100ms <= interval <= window <= 1 minute")
	}
	return nil
}

// Completed requires passing samples, no excessive sampling gaps, and a final
// sample starting after the deadline. It proves neither continuous absence nor
// post-reboot state.
type ObservationSummary struct {
	ID           string              `json:"id"`
	Status       string              `json:"status"`
	StartedAt    time.Time           `json:"started_at"`
	DeadlineAt   time.Time           `json:"deadline_at"`
	FinishedAt   time.Time           `json:"finished_at,omitempty"`
	IntervalMS   int64               `json:"interval_ms"`
	Samples      int                 `json:"samples"`
	LastSampleAt time.Time           `json:"last_sample_at,omitempty"`
	MaxGapMS     int64               `json:"max_gap_ms"`
	Incomplete   bool                `json:"incomplete,omitempty"`
	Reason       string              `json:"reason,omitempty"`
	Checks       []VerificationCheck `json:"checks,omitempty"`
}

func newObservation(options ObservationOptions) *ObservationSummary {
	now := time.Now()
	return &ObservationSummary{ID: newCaseID(HitEvent{}), Status: "observing", StartedAt: now, DeadlineAt: now.Add(options.Window), IntervalMS: options.Interval.Milliseconds()}
}

func (m *Manager) observeCase(caseID, observationID string) {
	defer m.observations.Done()
	for {
		// Sleeping never holds the remediation mutex. Only a sample and its case
		// commit serialize with cleanup, preventing manager-local stale writes.
		deadline, active := m.observationDeadline(caseID, observationID)
		if !active {
			return
		}
		delay := time.Until(deadline)
		if delay > m.observationOptions.Interval {
			delay = m.observationOptions.Interval
		}
		if delay < 0 {
			delay = 0
		}
		timer := time.NewTimer(delay)
		stopping := false
		select {
		case <-m.observationStop:
			stopping = true
		case <-timer.C:
		}
		timer.Stop()
		if !m.sampleObservation(caseID, observationID, stopping) {
			return
		}
	}
}

func (m *Manager) loadObservation(caseID, observationID string) (Case, string, error) {
	var c Case
	data, err := os.ReadFile(filepath.Join(m.root, "eradication", "cases", caseID+".json"))
	if err != nil {
		return c, "", err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, "", err
	}
	if c.ID != caseID {
		return c, "", fmt.Errorf("case identity changed during observation")
	}
	if c.Observation == nil || c.Observation.ID != observationID || c.Observation.Status != "observing" ||
		c.Status != "pending_verification" || !hasRemovedArtifacts(c) {
		return c, "", nil // Another operation changed the case; never restore our old snapshot.
	}
	sum := sha256.Sum256(data)
	return c, hex.EncodeToString(sum[:]), nil
}

func (m *Manager) observationDeadline(caseID, observationID string) (time.Time, bool) {
	m.remediateMu.Lock()
	defer m.remediateMu.Unlock()
	c, expected, err := m.loadObservation(caseID, observationID)
	if err != nil {
		log.Printf("[ERADICATION] case %s observation read failed: %v", caseID, err)
	}
	if err != nil || expected == "" {
		return time.Time{}, false
	}
	return c.Observation.DeadlineAt, true
}

func (m *Manager) sampleObservation(caseID, observationID string, stopping bool) bool {
	m.remediateMu.Lock()
	defer m.remediateMu.Unlock()
	c, expected, err := m.loadObservation(caseID, observationID)
	if err != nil || expected == "" {
		if err != nil {
			log.Printf("[ERADICATION] case %s observation read failed: %v", caseID, err)
		}
		return false
	}
	o := c.Observation
	// Check again after acquiring the lock so shutdown never starts a new sample
	// merely because its timer fired at the same moment as Close.
	select {
	case <-m.observationStop:
		stopping = true
	default:
	}
	if stopping {
		o.Status, o.Reason = "interrupted", "manager closed before the observation window finished"
	} else {
		sample := verifyPostCleanScope(m.root, c, m.OnOperation, "bounded")
		previousSample := o.LastSampleAt
		if previousSample.IsZero() {
			previousSample = o.StartedAt
		}
		gap := sample.StartedAt.Sub(previousSample)
		if gap.Milliseconds() > o.MaxGapMS {
			o.MaxGapMS = gap.Milliseconds()
		}
		if gap > 2*m.observationOptions.Interval {
			o.Incomplete = true
		}
		o.LastSampleAt = sample.StartedAt
		o.Samples++
		o.Checks = append(o.Checks, sample.Checks...)
		if sample.Status == "failed" {
			o.Status, o.Reason = "failed", "residual or reappearance observed; attribution remains unconfirmed"
		} else {
			if sample.Status != "passed" {
				o.Incomplete = true
			}
			// Disk writes crossing the deadline cannot replace a sample that
			// actually starts after the full observation window has elapsed.
			if !sample.StartedAt.Before(o.DeadlineAt) {
				o.Status = "completed"
				if o.Incomplete {
					o.Status, o.Reason = "incomplete", "one or more samples were delayed, unverifiable or not journaled"
				}
			}
		}
	}
	if o.Status != "observing" {
		o.FinishedAt = time.Now()
		if c.Verification != nil {
			c.Verification.RequiresObservation = o.Status != "completed"
		}
	}
	c.Status = caseStatus(c)
	if err := commitCaseExpected(m.root, c, m.OnOperation, expected); err != nil {
		log.Printf("[ERADICATION] case %s observation commit failed: %v", caseID, err)
		return false
	}
	return o.Status == "observing"
}
