//go:build windows

package eradication

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CaseReport is a read-only GUI contract. Consumers need not parse case files
// or infer completion from implementation-specific artifact states.
type CaseReport struct {
	ID                  string
	StartedAt           time.Time
	Image               string
	Status              string
	ProcessExit         string
	ObservationStatus   string
	ObservationReason   string
	ObservationSamples  int
	RequiresReboot      bool
	RequiresObservation bool
	Errors              []string
	Artifacts           []ReportItem
	Persistence         []ReportItem
	Checks              []VerificationCheck
}

type ReportItem struct{ Kind, Path, Status, Error string }
type CaseReadIssue struct {
	File  string
	Error string
}

func ReadCaseReport(root, id string) (CaseReport, error) {
	var report CaseReport
	if !validOperationCaseID(id) {
		return report, fmt.Errorf("invalid case ID")
	}
	path := filepath.Join(root, "eradication", "cases", id+".json")
	planOnly := false
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		path = filepath.Join(root, "eradication", "cases", id+"-plan.json")
		info, err = os.Lstat(path)
		planOnly = true
	}
	if err != nil {
		return report, err
	}
	if !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return report, fmt.Errorf("case is not a regular file within size limit")
	}
	var b []byte
	for attempt := 0; attempt < 3; attempt++ {
		b, err = os.ReadFile(path)
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return report, err
	}
	var c Case
	if err := json.Unmarshal(b, &c); err != nil {
		return report, err
	}
	if c.ID != id {
		return report, fmt.Errorf("case identity mismatch")
	}
	report = CaseReport{ID: c.ID, StartedAt: c.StartedAt, Image: c.Hit.Image, Status: c.Status, ProcessExit: c.ProcessExit, Errors: c.Errors, RequiresReboot: c.Status != "restored" && c.Status != "released", RequiresObservation: c.Status != "restored" && c.Status != "released"}
	if c.Verification != nil {
		report.RequiresReboot = c.Verification.RequiresReboot
		report.RequiresObservation = c.Verification.RequiresObservation
		report.Checks = append(report.Checks, c.Verification.Checks...)
	}
	if c.Observation != nil {
		report.ObservationStatus = c.Observation.Status
		report.ObservationReason = c.Observation.Reason
		report.ObservationSamples = c.Observation.Samples
		report.Checks = append(report.Checks, c.Observation.Checks...)
		if c.Observation.Status == "observing" && !time.Now().Before(c.Observation.DeadlineAt) {
			report.ObservationStatus = "incomplete"
			report.ObservationReason = "观察窗口已到期，但尚无完整观察的提交记录。"
			report.RequiresObservation = true
		}
	}
	if c.Status == "restored" || c.Status == "released" {
		report.RequiresReboot = false
		report.RequiresObservation = false
	}
	if planOnly {
		report.Status = "manual_review"
		report.RequiresReboot = true
		report.RequiresObservation = true
		report.Errors = append(report.Errors, "仅有处置计划，缺少最终 case；需核对操作日志与现场，不能认定处置完成。")
	}
	for _, a := range c.Artifacts {
		report.Artifacts = append(report.Artifacts, ReportItem{Kind: a.Kind, Path: a.Path, Status: a.Status, Error: a.Error})
	}
	for _, p := range c.Persistence {
		report.Persistence = append(report.Persistence, ReportItem{Kind: p.Type, Path: p.Location, Status: p.Status, Error: p.Error})
	}
	return report, nil
}

// ListCaseReports returns the newest reports and per-file errors. Corrupt cases
// remain visible as issues instead of making the entire history disappear.
func ListCaseReports(root string, limit int) ([]CaseReport, []CaseReadIssue, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	files, err := os.ReadDir(filepath.Join(root, "eradication", "cases"))
	if os.IsNotExist(err) {
		return []CaseReport{}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	reports := []CaseReport{}
	issues := []CaseReadIssue{}
	seen := map[string]bool{}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimSuffix(f.Name(), ".json"), "-plan")
		if seen[id] {
			continue
		}
		seen[id] = true
		report, err := ReadCaseReport(root, id)
		if err != nil {
			issues = append(issues, CaseReadIssue{File: f.Name(), Error: err.Error()})
			continue
		}
		reports = append(reports, report)
	}
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].StartedAt.Equal(reports[j].StartedAt) {
			return reports[i].ID > reports[j].ID
		}
		return reports[i].StartedAt.After(reports[j].StartedAt)
	})
	if len(reports) > limit {
		reports = reports[:limit]
	}
	return reports, issues, nil
}
