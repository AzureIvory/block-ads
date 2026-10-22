//go:build windows

package tests

import (
	"block-ads/eradication"
	"block-ads/settings"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEradicationModeDefaultsAndPreservesConfiguration(t *testing.T) {
	path := filepath.Join(testRoot(t), "config.json")
	for _, data := range []string{"", `{}`, `{"unrelated":{"keep":true}}`} {
		if data != "" {
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
		cfg, err := settings.Load(path)
		if err != nil || cfg.EradicationMode != settings.Intercept {
			t.Fatalf("legacy config enabled deletion: %+v %v", cfg, err)
		}
	}
	if err := settings.SaveMode(path, settings.AutoQuarantine); err != nil {
		t.Fatal(err)
	}
	cfg, err := settings.Load(path)
	if err != nil || cfg.EradicationMode != settings.AutoQuarantine {
		t.Fatalf("saved mode lost: %+v %v", cfg, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	if string(object["unrelated"]) != "{\n    \"keep\": true\n  }" {
		var keep map[string]bool
		if err := json.Unmarshal(object["unrelated"], &keep); err != nil || !keep["keep"] {
			t.Fatalf("unrelated settings lost: %s", data)
		}
	}
	if err := settings.SaveMode(path, settings.Intercept); err != nil {
		t.Fatal(err)
	}
	cfg, err = settings.Load(path)
	if err != nil || cfg.EradicationMode != settings.Intercept {
		t.Fatal("failed to disable eradication")
	}
}

func TestEradicationModeRejectsInvalidConfigurationWithoutReplacingIt(t *testing.T) {
	for _, data := range []string{`{`, `null`, `[]`, `{"eradication_mode":"typo"}`, `{"eradication_mode":true}`, `{"eradication_mode":null}`} {
		path := filepath.Join(testRoot(t), "config.json")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := settings.Load(path); err == nil {
			t.Fatalf("invalid config accepted: %s", data)
		}
		if err := settings.SaveMode(path, settings.AutoQuarantine); err == nil {
			t.Fatalf("corrupt config replaced: %s", data)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != data {
			t.Fatalf("bad config changed: %s %v", got, err)
		}
	}
}

func TestReadOnlyCaseReportsPreserveEvidenceAndPartialFailures(t *testing.T) {
	root := testRoot(t)
	dir := filepath.Join(root, "eradication", "cases")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := eradication.Case{ID: "gui-case", Status: "partial_failure", StartedAt: time.Now(), Hit: eradication.HitEvent{Image: `C:\Bad\sample.exe`}, ProcessExit: "verified",
		Artifacts:    []eradication.Artifact{{Kind: "exe", Path: `C:\Bad\sample.exe`, Status: "quarantined"}},
		Verification: &eradication.VerificationSummary{Status: "passed", RequiresReboot: true, RequiresObservation: true},
		Observation:  &eradication.ObservationSummary{Status: "failed", Samples: 2, Reason: "reappeared", Checks: []eradication.VerificationCheck{{OperationID: "check-1", Kind: "file_absence", Outcome: "present", Evidence: "file returned", At: time.Now()}}}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, c.ID+".json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, c.ID+"-plan.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "corrupt.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	reports, issues, err := eradication.ListCaseReports(root, 100)
	if err != nil || len(reports) != 1 || len(issues) != 1 {
		t.Fatalf("partial list lost: %+v %+v %v", reports, issues, err)
	}
	r := reports[0]
	if r.Status != "partial_failure" || r.ObservationSamples != 2 || !r.RequiresReboot || len(r.Checks) != 1 || r.Checks[0].OperationID != "check-1" || r.Artifacts[0].Status != "quarantined" {
		t.Fatalf("GUI contract lost evidence: %+v", r)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != string(b) {
		t.Fatal("read-only API modified the case")
	}
	if _, err := os.Stat(filepath.Join(root, "eradication", "journal")); !os.IsNotExist(err) {
		t.Fatal("read-only API wrote an operation")
	}
	if _, err := eradication.ReadCaseReport(root, `..\outside`); err == nil {
		t.Fatal("case traversal accepted")
	}
}

func TestCaseReportsExposeUncommittedPlansAndExpiredWindows(t *testing.T) {
	root := testRoot(t)
	dir := filepath.Join(root, "eradication", "cases")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := eradication.Case{ID: "plan-only", Status: "pending", StartedAt: time.Now()}
	b, _ := json.Marshal(c)
	if err := os.WriteFile(filepath.Join(dir, c.ID+"-plan.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := eradication.ReadCaseReport(root, c.ID)
	if err != nil || report.Status != "manual_review" || len(report.Errors) == 0 {
		t.Fatalf("missing commit hidden: %+v %v", report, err)
	}
	c.ID = "expired"
	c.Status = "pending_verification"
	c.Observation = &eradication.ObservationSummary{Status: "observing", DeadlineAt: time.Now().Add(-time.Second)}
	b, _ = json.Marshal(c)
	if err := os.WriteFile(filepath.Join(dir, c.ID+".json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	report, err = eradication.ReadCaseReport(root, c.ID)
	if err != nil || report.ObservationStatus != "incomplete" || !report.RequiresObservation {
		t.Fatalf("stale window reported live or complete: %+v %v", report, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, c.ID+".json")); err != nil {
		t.Fatal(err)
	} else {
		var unchanged eradication.Case
		json.Unmarshal(b, &unchanged)
		if unchanged.Observation.Status != "observing" {
			t.Fatal("report rewrote expired window")
		}
	}
}
