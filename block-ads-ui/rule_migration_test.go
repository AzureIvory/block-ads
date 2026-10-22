package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyRuleMigrationRunsOnce(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "sign.txt")
	incoming := filepath.Join(dir, "incoming.txt")
	if err := os.WriteFile(old, []byte("upstream\nmy-rule\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(incoming, []byte("upstream\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := newLegacyRuleMigration(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.preserve(dir, "sign.txt", incoming); err != nil {
		t.Fatal(err)
	}
	rules := rdUserRules(filepath.Join(dir, userRulesFile))
	if got := rules["sign"].Add; len(got) != 1 || got[0] != "my-rule" {
		t.Fatalf("migrated rules = %v", got)
	}
	if err := m.finish(dir); err != nil {
		t.Fatal(err)
	}
	m2, err := newLegacyRuleMigration(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m2.enabled {
		t.Fatal("migration must not run after marker exists")
	}
}

func TestWhitelistAddUsesUserRules(t *testing.T) {
	dir := t.TempDir()
	white := filepath.Join(dir, "Wsign.txt")
	if err := os.WriteFile(white, []byte("upstream\n"), 0644); err != nil {
		t.Fatal(err)
	}
	d := newDat(dir)
	added, err := d.addWhite("sign", "my-signer", "")
	if err != nil || !added {
		t.Fatalf("addWhite = %v, %v", added, err)
	}
	b, err := os.ReadFile(white)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "upstream\n" {
		t.Fatalf("remote baseline modified: %q", b)
	}
	if got := rdUserRules(filepath.Join(dir, userRulesFile))["signWhite"].Add; len(got) != 1 || got[0] != "my-signer" {
		t.Fatalf("custom whitelist = %v", got)
	}
	if got := newDat(dir).all()["signWhite"]; len(got) != 2 || got[1] != "my-signer" {
		t.Fatalf("merged whitelist = %v", got)
	}
}

func TestLegacyMigrationKeepsExistingCustomRules(t *testing.T) {
	dir := t.TempDir()
	if err := writeUserRules(filepath.Join(dir, userRulesFile), userRules{
		"folder": {Add: []string{"existing"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Wsign.txt"), []byte("old-custom\n"), 0644); err != nil {
		t.Fatal(err)
	}
	incoming := filepath.Join(dir, "new-sign.txt")
	if err := os.WriteFile(incoming, []byte("new-upstream\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := newLegacyRuleMigration(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.preserve(dir, "Wsign.txt", incoming); err != nil {
		t.Fatal(err)
	}
	rules := rdUserRules(filepath.Join(dir, userRulesFile))
	if len(rules["folder"].Add) != 1 || len(rules["signWhite"].Add) != 1 {
		t.Fatalf("migration lost or duplicated rules: %v", rules)
	}
}
