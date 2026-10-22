package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 使用新文件，避免把旧全局标记误认为所有文件均已完成。
const legacyMigrationMarker = ".legacy_rules_migrated_v2.json"

type legacyRuleMigration struct {
	// key 为规范化后的规则文件名，例如 sign.txt、wsign.txt。
	done map[string]bool
}

func newLegacyRuleMigration(dir string) (*legacyRuleMigration, error) {
	m := &legacyRuleMigration{
		done: make(map[string]bool),
	}

	path := filepath.Join(dir, legacyMigrationMarker)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(b, &m.done); err != nil {
		return nil, fmt.Errorf(
			"read migration state %s: %w", path, err,
		)
	}
	if m.done == nil {
		return nil, fmt.Errorf(
			"invalid migration state %s: expected JSON object", path,
		)
	}

	return m, nil
}

func (m *legacyRuleMigration) preserve(
	dir, rel, incoming string,
) error {
	// 只处理 lstMap 中已知的规则文件。
	var key, file string
	cleanRel := filepath.Clean(rel)

	for k, name := range lstMap {
		if strings.EqualFold(cleanRel, name) {
			key = k
			file = strings.ToLower(name)
			break
		}
	}

	if key == "" || m.done[file] {
		return nil
	}

	// 旧文件不存在可以按空处理；其他读取错误必须中止。
	oldLines, err := readLegacyMigrationLines(
		filepath.Join(dir, rel), true,
	)
	if err != nil {
		return err
	}

	// 下载的新文件必须存在且可读。
	newLines, err := readLegacyMigrationLines(incoming, false)
	if err != nil {
		return err
	}

	// 每次迁移都重新读取当前用户规则，再合并本次新增项。
	rules, err := readLegacyMigrationRules(
		filepath.Join(dir, userRulesFile),
	)
	if err != nil {
		return err
	}

	newSet := make(map[string]struct{}, len(newLines))
	for _, line := range newLines {
		newSet[normRule(key, line)] = struct{}{}
	}

	ov := rules[key]
	seen := make(map[string]struct{}, len(ov.Add))
	for _, line := range ov.Add {
		seen[normRule(key, line)] = struct{}{}
	}

	changed := false
	for _, line := range oldLines {
		if strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "//") {
			continue
		}

		n := normRule(key, line)

		// 新云端文件仍然包含，不需要转入用户规则。
		if _, ok := newSet[n]; ok {
			continue
		}

		// 用户规则已经包含，不重复添加。
		if _, ok := seen[n]; ok {
			continue
		}

		ov.Add = append(ov.Add, line)
		seen[n] = struct{}{}
		changed = true
	}

	// 必须先保存用户规则，成功后才能记录迁移完成。
	if changed {
		rules[key] = ov
		if err := writeUserRules(
			filepath.Join(dir, userRulesFile), rules,
		); err != nil {
			return err
		}
	}

	// 保留其他文件的历史进度，只增加当前文件。
	nextDone := make(map[string]bool, len(m.done)+1)
	for name, done := range m.done {
		nextDone[name] = done
	}
	nextDone[file] = true

	// 立即保存本文件进度。
	// 保存失败时返回错误，调用方不能继续覆盖旧 txt。
	if err := saveLegacyMigrationState(dir, nextDone); err != nil {
		return err
	}

	m.done = nextDone
	return nil
}

// 迁移时必须区分“空文件”和“读取失败”，不能使用吞掉错误的 rdTxt。
func readLegacyMigrationLines(
	path string, allowMissing bool,
) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if allowMissing && os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func readLegacyMigrationRules(path string) (userRules, error) {
	rules := userRules{}

	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return rules, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, fmt.Errorf(
			"read user rules %s: %w", path, err,
		)
	}
	if rules == nil {
		rules = userRules{}
	}

	return rules, nil
}

func saveLegacyMigrationState(
	dir string, done map[string]bool,
) error {
	b, err := json.MarshalIndent(done, "", "  ")
	if err != nil {
		return err
	}

	// 先完整写入同目录临时文件，再替换状态文件。
	f, err := os.CreateTemp(dir, ".legacy_rules_migrated_*.tmp")
	if err != nil {
		return err
	}

	tmp := f.Name()
	defer os.Remove(tmp)

	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(
		tmp,
		filepath.Join(dir, legacyMigrationMarker),
	)
}
