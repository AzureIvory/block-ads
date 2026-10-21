//go:build windows

package eradication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

type taskXMLNode struct {
	Name       xml.Name
	Attributes []xml.Attr
	Text       string
	Children   []*taskXMLNode
}

// TaskXMLMatches compares the entire definition, including triggers, principals,
// settings and every action. Only encoding, namespace prefixes, attribute order,
// comments and indentation between elements are ignored. Leaf text is exact.
func TaskXMLMatches(expected, actual []byte) (bool, error) {
	a, err := normalizedTaskXML(expected)
	if err != nil {
		return false, fmt.Errorf("invalid expected task XML: %w", err)
	}
	b, err := normalizedTaskXML(actual)
	if err != nil {
		return false, fmt.Errorf("invalid observed task XML: %w", err)
	}
	return bytes.Equal(a, b), nil
}

func normalizedTaskXML(data []byte) ([]byte, error) {
	if len(data) >= 2 && (bytes.HasPrefix(data, []byte{0xff, 0xfe}) || bytes.HasPrefix(data, []byte{0xfe, 0xff})) && len(data)%2 != 0 {
		return nil, fmt.Errorf("truncated UTF-16 task XML")
	}
	decoder := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(taskXMLBytes(data), []byte{0xef, 0xbb, 0xbf})))
	decoder.CharsetReader = func(charset string, r io.Reader) (io.Reader, error) {
		if !strings.EqualFold(charset, "UTF-16") && !strings.EqualFold(charset, "UTF-8") {
			return nil, fmt.Errorf("unsupported task XML encoding %s", charset)
		}
		return r, nil
	}
	var root *taskXMLNode
	var stack []*taskXMLNode
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			if len(stack) >= 128 {
				return nil, fmt.Errorf("task XML exceeds nesting limit")
			}
			node := &taskXMLNode{Name: value.Name}
			seen := map[xml.Name]bool{}
			for _, attr := range value.Attr {
				if attr.Name.Space == "xmlns" || attr.Name.Space == "" && attr.Name.Local == "xmlns" {
					continue
				}
				if seen[attr.Name] {
					return nil, fmt.Errorf("duplicate XML attribute")
				}
				seen[attr.Name] = true
				node.Attributes = append(node.Attributes, attr)
			}
			sort.Slice(node.Attributes, func(i, j int) bool {
				a, b := node.Attributes[i].Name, node.Attributes[j].Name
				if a.Space != b.Space {
					return a.Space < b.Space
				}
				return a.Local < b.Local
			})
			if len(stack) == 0 {
				if root != nil || value.Name.Local != "Task" || value.Name.Space != "http://schemas.microsoft.com/windows/2004/02/mit/task" {
					return nil, fmt.Errorf("expected one Task root in the Task Scheduler namespace")
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			node := stack[len(stack)-1]
			if len(node.Children) != 0 {
				if strings.TrimSpace(node.Text) != "" {
					return nil, fmt.Errorf("mixed task XML content is unsupported")
				}
				node.Text = ""
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) != 0 {
				stack[len(stack)-1].Text += string(value)
			} else if strings.TrimSpace(string(value)) != "" {
				return nil, fmt.Errorf("text outside Task root")
			}
		case xml.Directive:
			return nil, fmt.Errorf("task XML directives are unsupported")
		case xml.ProcInst:
			if value.Target != "xml" {
				return nil, fmt.Errorf("task XML processing instructions are unsupported")
			}
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, fmt.Errorf("incomplete task XML")
	}
	return json.Marshal(root)
}

func taskRestoreLocation(name, location string) error {
	if !strings.HasPrefix(name, `\`) || strings.ContainsAny(name, "/:\x00") {
		return fmt.Errorf("invalid task name")
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, `\`), `\`) {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("invalid task name component")
		}
	}
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	expected := filepath.Join(systemDir, "Tasks", strings.TrimPrefix(name, `\`))
	if !samePath(expected, location) {
		return fmt.Errorf("task location does not match its scheduler name")
	}
	return nil
}

func taskRestoreObserved(root string, operation OperationEntry) (bool, error) {
	if err := taskRestoreLocation(operation.Target, operation.PersistenceLocation); err != nil {
		return false, err
	}
	if operation.ExpectedHash == "" || !backupWithin(root, operation.CaseID, operation.BackupPath) {
		return false, fmt.Errorf("task restore intent lacks a verified case backup")
	}
	backup, err := os.ReadFile(operation.BackupPath)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(backup)) != operation.ExpectedHash {
		return false, fmt.Errorf("task backup differs from restore intent: %v", err)
	}
	if _, err := normalizedTaskXML(backup); err != nil {
		return false, err
	}
	info, err := os.Lstat(operation.PersistenceLocation)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("task definition is not a regular file")
	}
	actual, err := os.ReadFile(operation.PersistenceLocation)
	if err != nil {
		return false, err
	}
	matched, err := TaskXMLMatches(backup, actual)
	if err != nil {
		return false, err
	}
	if !matched {
		return false, fmt.Errorf("complete task XML differs from restore intent")
	}
	return true, nil
}

func restoreTask(root, id string, item PersistenceItem, expectedHash string) error {
	if !backupWithin(root, id, item.BackupPath) {
		return fmt.Errorf("task backup outside case directory")
	}
	if err := taskRestoreLocation(item.Name, item.Location); err != nil {
		return err
	}
	if _, err := os.Lstat(item.Location); err == nil {
		return fmt.Errorf("task definition already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := os.ReadFile(item.BackupPath)
	if err != nil {
		return err
	}
	if expectedHash == "" || fmt.Sprintf("%x", sha256.Sum256(data)) != expectedHash {
		return fmt.Errorf("task backup changed before registration")
	}
	if _, err := normalizedTaskXML(data); err != nil {
		return err
	}
	// Keep a private snapshot open without write sharing while schtasks reads it.
	// Changes to the original backup cannot change the XML being registered.
	path := filepath.Join(filepath.Dir(item.BackupPath), ".task-restore-"+newCaseID(HitEvent{})+".xml")
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(pathPtr, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), path)
	defer os.Remove(path)
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
	h, err = windows.CreateFile(pathPtr, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f = os.NewFile(uintptr(h), path)
	defer f.Close()
	locked, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(data, locked) {
		return fmt.Errorf("task snapshot changed before registration: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tool, err := systemTool("schtasks.exe")
	if err != nil {
		return err
	}
	if err := exec.CommandContext(ctx, tool, "/Query", "/TN", item.Name).Run(); err == nil {
		return fmt.Errorf("task already exists")
	}
	// No /F: a concurrent registration must never be overwritten.
	out, err := exec.CommandContext(ctx, tool, "/Create", "/TN", item.Name, "/XML", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
