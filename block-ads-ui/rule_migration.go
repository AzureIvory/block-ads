package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const legacyMigrationMarker = ".legacy_rules_migrated"

// Older versions stored some custom rules directly in downloaded txt files.
// Import local-only lines once, including when user_rules.json already exists.
type legacyRuleMigration struct {
	enabled bool
	touched bool
	rules   userRules
}

func newLegacyRuleMigration(dir string) (*legacyRuleMigration, error) {
	_, err := os.Stat(filepath.Join(dir, legacyMigrationMarker))
	if err == nil {
		return &legacyRuleMigration{}, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	rules := userRules{}
	b, err := os.ReadFile(filepath.Join(dir, userRulesFile))
	if err == nil {
		if err := json.Unmarshal(b, &rules); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if rules == nil {
		rules = userRules{}
	}
	return &legacyRuleMigration{enabled: true, rules: rules}, nil
}

func (m *legacyRuleMigration) preserve(dir, rel, incoming string) error {
	if !m.enabled {
		return nil
	}
	var key string
	for k, name := range lstMap {
		if strings.EqualFold(filepath.Clean(rel), name) {
			key = k
			break
		}
	}
	if key == "" {
		return nil
	}
	m.touched = true
	old := rdTxt(filepath.Join(dir, rel))
	if len(old) == 0 {
		return nil
	}
	if _, err := os.Stat(incoming); err != nil {
		return err
	}
	newSet := map[string]struct{}{}
	for _, line := range rdTxt(incoming) {
		newSet[normRule(key, line)] = struct{}{}
	}
	ov := m.rules[key]
	seen := map[string]struct{}{}
	for _, line := range ov.Add {
		seen[normRule(key, line)] = struct{}{}
	}
	changed := false
	for _, line := range old {
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		n := normRule(key, line)
		if _, ok := newSet[n]; ok {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		ov.Add = append(ov.Add, line)
		seen[n] = struct{}{}
		changed = true
	}
	if !changed {
		return nil
	}
	m.rules[key] = ov
	return writeUserRules(filepath.Join(dir, userRulesFile), m.rules)
}

func (m *legacyRuleMigration) finish(dir string) error {
	if !m.enabled || !m.touched {
		return nil
	}
	return os.WriteFile(filepath.Join(dir, legacyMigrationMarker), []byte("1\n"), 0644)
}
