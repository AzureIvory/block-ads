//go:build windows

package tests

import (
	"block-ads/eradication"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

const taskXMLFixture = `<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task" version="1.2"><RegistrationInfo><URI>\Test</URI></RegistrationInfo><Triggers><CalendarTrigger><StartBoundary>2099-01-01T23:59:00</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><Enabled>true</Enabled><Hidden>false</Hidden></Settings><Actions Context="Author"><Exec><Command>C:\Bad App\bad.exe</Command><Arguments> --update &amp; keep spaces </Arguments><WorkingDirectory>C:\Bad App</WorkingDirectory></Exec><Exec><Command>helper.exe</Command></Exec></Actions></Task>`

func TestTaskXMLMatchesCompleteDefinition(t *testing.T) {
	for _, tc := range []struct {
		name, actual string
		match        bool
	}{
		{"identical", taskXMLFixture, true},
		{"indentation", strings.ReplaceAll(taskXMLFixture, "><", ">\r\n  <"), true},
		{"comments", strings.Replace(taskXMLFixture, "<Settings>", "<!-- preserved semantics --><Settings>", 1), true},
		{"attribute order", strings.Replace(taskXMLFixture, `xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task" version="1.2"`, `version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"`, 1), true},
		{"trigger", strings.Replace(taskXMLFixture, "2099-01-01", "2098-01-01", 1), false},
		{"principal", strings.Replace(taskXMLFixture, "S-1-5-18", "S-1-5-19", 1), false},
		{"run level", strings.Replace(taskXMLFixture, "LeastPrivilege", "HighestAvailable", 1), false},
		{"settings", strings.Replace(taskXMLFixture, "<Hidden>false", "<Hidden>true", 1), false},
		{"working directory", strings.Replace(taskXMLFixture, `<WorkingDirectory>C:\Bad App`, `<WorkingDirectory>C:\Other`, 1), false},
		{"argument whitespace", strings.Replace(taskXMLFixture, " --update &amp; keep spaces ", "--update &amp; keep spaces", 1), false},
		{"argument value", strings.Replace(taskXMLFixture, "--update", "--different", 1), false},
		{"second action", strings.Replace(taskXMLFixture, "helper.exe", "other.exe", 1), false},
		{"task URI", strings.Replace(taskXMLFixture, `\Test`, `\Other`, 1), false},
		{"namespace", strings.Replace(taskXMLFixture, "mit/task", "mit/other", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := eradication.TaskXMLMatches([]byte(taskXMLFixture), []byte(tc.actual))
			if got != tc.match || tc.match && err != nil {
				t.Fatalf("match=%t, err=%v; want %t", got, err, tc.match)
			}
		})
	}
	// Prefixes and UTF-16 byte order do not affect expanded element names.
	prefixed := strings.ReplaceAll(taskXMLFixture, "<", "<t:")
	prefixed = strings.ReplaceAll(prefixed, "<t:/", "</t:")
	prefixed = strings.Replace(prefixed, "xmlns=", "xmlns:t=", 1)
	for _, little := range []bool{true, false} {
		data := []byte{0xfe, 0xff}
		if little {
			data = []byte{0xff, 0xfe}
		}
		for _, word := range utf16.Encode([]rune(`<?xml version="1.0" encoding="UTF-16"?>` + prefixed)) {
			if little {
				data = append(data, byte(word), byte(word>>8))
			} else {
				data = append(data, byte(word>>8), byte(word))
			}
		}
		if matched, err := eradication.TaskXMLMatches([]byte(taskXMLFixture), data); err != nil || !matched {
			t.Fatalf("prefixed UTF-16 task comparison: %t, %v", matched, err)
		}
	}
}

func TestTaskXMLRejectsIncompleteOrAmbiguousDefinitions(t *testing.T) {
	for _, data := range [][]byte{
		{}, []byte(`<Task>`), []byte(taskXMLFixture + taskXMLFixture),
		[]byte(strings.Replace(taskXMLFixture, `version="1.2"`, `version="1.2" version="1.3"`, 1)),
		[]byte(`<!DOCTYPE Task>` + taskXMLFixture),
		[]byte(strings.Replace(taskXMLFixture, "<Settings>", "<Settings>unexpected text", 1)),
		{0xff, 0xfe, 0x41},
	} {
		if matched, err := eradication.TaskXMLMatches([]byte(taskXMLFixture), data); err == nil || matched {
			t.Fatalf("invalid task accepted: matched=%t, err=%v, data=%q", matched, err, data)
		}
	}
}

func TestTaskRestoreVerificationAndCrashBoundaries(t *testing.T) {
	if os.Getenv("BLOCK_ADS_TEST_REAL_PERSISTENCE") != "1" {
		t.Skip("requires an isolated Windows runner with Task Scheduler access")
	}
	tool, err := exec.LookPath("schtasks.exe")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"success", "after_intent", "after_action", "after_result", "changed task", "changed backup", "occupied", "wrong location"} {
		t.Run(scenario, func(t *testing.T) {
			root := testRoot(t)
			name := fmt.Sprintf(`\BlockAdsRestore-%d-%d`, os.Getpid(), time.Now().UnixNano())
			t.Cleanup(func() { _ = exec.Command(tool, "/Delete", "/TN", name, "/F").Run() })
			target := filepath.Join(root, "Bad App", "sample.exe")
			command := `"` + target + `" --update`
			create := func(command string) {
				t.Helper()
				if out, err := exec.Command(tool, "/Create", "/TN", name, "/SC", "DAILY", "/ST", "23:59", "/TR", command).CombinedOutput(); err != nil {
					t.Fatalf("create task: %v: %s", err, out)
				}
			}
			create(command)
			location := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks", strings.TrimPrefix(name, `\`))
			definition, err := os.ReadFile(location)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(tool, "/Delete", "/TN", name, "/F").CombinedOutput(); err != nil {
				t.Fatalf("delete fixture task: %v: %s", err, out)
			}
			backup := filepath.Join(root, "eradication", "backups", "persistence-restore", "task.bin")
			if err := os.MkdirAll(filepath.Dir(backup), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(backup, definition, 0600); err != nil {
				t.Fatal(err)
			}
			item := eradication.PersistenceItem{Type: "task", Name: name, Location: location, Target: target, BackupPath: backup, Status: "removed"}
			if scenario == "wrong location" {
				item.Location = filepath.Join(root, "unrelated-task")
			}
			id := writePersistenceRestoreCase(t, root, item)
			if scenario == "occupied" {
				create(`"` + target + `" --different`)
				before, err := os.ReadFile(location)
				if err != nil {
					t.Fatal(err)
				}
				if err := eradication.RestoreCase(root, id); err == nil {
					t.Fatal("occupied task was accepted")
				}
				after, err := os.ReadFile(location)
				if err != nil || string(before) != string(after) {
					t.Fatalf("occupied task changed: %v", err)
				}
				return
			}
			if scenario == "changed backup" || scenario == "wrong location" {
				err := eradication.RestoreCaseWithObserver(root, id, func(op eradication.OperationEntry, stage string) {
					if scenario == "changed backup" && op.Action == "restore_persistence" && stage == "after_intent" {
						if err := os.WriteFile(backup, []byte(taskXMLFixture), 0600); err != nil {
							t.Fatal(err)
						}
					}
				})
				if err == nil {
					t.Fatal("invalid task restoration was accepted")
				}
				if _, err := os.Stat(location); !os.IsNotExist(err) {
					t.Fatalf("task was registered despite invalid input: %v", err)
				}
				c := readCases(t, root)[0]
				if c.Status != "partial_restore" || c.Persistence[0].Error == "" {
					t.Fatalf("failure missing from case: %+v", c)
				}
				return
			}
			if scenario == "success" {
				if err := eradication.RestoreCase(root, id); err != nil {
					t.Fatal(err)
				}
				actual, err := os.ReadFile(location)
				if err != nil {
					t.Fatal(err)
				}
				if matched, err := eradication.TaskXMLMatches(definition, actual); err != nil || !matched {
					t.Fatalf("task definition changed: %t, %v", matched, err)
				}
			} else {
				stage := scenario
				if scenario == "changed task" {
					stage = "after_action"
				}
				runCrashChild(t, root, "restore_persistence", stage, id)
				if scenario == "changed task" {
					if out, err := exec.Command(tool, "/Change", "/TN", name, "/DISABLE").CombinedOutput(); err != nil {
						t.Fatalf("change restored task: %v: %s", err, out)
					}
				}
			}
			findings, err := eradication.InspectRecovery(root)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "success" {
				if len(findings) != 0 {
					t.Fatalf("committed task has recovery findings: %+v", findings)
				}
			} else {
				want := map[string]string{"after_intent": "not_observed", "after_action": "observed_uncommitted", "after_result": "manual_review", "changed task": "conflict"}[scenario]
				if len(findings) != 1 || findings[0].Operation.PersistenceType != "task" || findings[0].Disposition != want {
					t.Fatalf("task restore crash misclassified: %+v; want %s", findings, want)
				}
			}
		})
	}
}
