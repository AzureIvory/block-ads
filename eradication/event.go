//go:build windows

package eradication

import (
	"block-ads/utils"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// ProcessCreateFromProperties decodes the fields used by the ETW callback.
// It also accepts a header PID if the provider omitted the payload PID.
func ProcessCreateFromProperties(props map[string]interface{}, headerPID uint32, eventAt time.Time) (Match, bool) {
	pid, ok := utils.GetU32(props, "ProcessID", "ProcessId", "PID")
	if !ok {
		pid = headerPID
	}
	ppid, _ := utils.GetU32(props, "ParentProcessID", "ParentProcessId", "ParentId", "ParentID")
	var image string
	for _, key := range []string{"ImageName", "ImageFileName", "FullImageName", "FileName", "Image", "ProcessName"} {
		if value, exists := props[key]; exists {
			switch v := value.(type) {
			case string:
				image = v
			case []byte:
				image = string(v)
			}
			if image != "" {
				break
			}
		}
	}
	image = utils.NToWin(image)
	if !strings.Contains(strings.ToLower(image), `:\`) || !strings.HasSuffix(strings.ToLower(image), ".exe") {
		if current, err := utils.ProcPath(pid); err == nil && current != "" {
			image = utils.NToWin(current)
		}
	}
	if pid == 0 || image == "" {
		return Match{}, false
	}
	return Match{PID: pid, ParentPID: ppid, Image: image, Source: "ETW-HIT", EventAt: eventAt}, true
}

// ScanCandidate reads a live process image for the startup scan.
func ScanCandidate(pid uint32) (Match, bool) {
	image, err := utils.ProcPath(pid)
	if err != nil || image == "" {
		return Match{}, false
	}
	return Match{PID: pid, Image: image, Source: "SCAN-HIT", EventAt: time.Now()}, true
}

// ProcessGate preserves the legacy 20-second process deduplication semantics.
type ProcessGate struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time
}

func NewProcessGate(ttl time.Duration) *ProcessGate {
	return &ProcessGate{ttl: ttl, seen: map[string]time.Time{}}
}

func (g *ProcessGate) Enter(pid uint32, image string) bool {
	key := processGateKey(pid, image)
	now := time.Now()
	cutoff := now.Add(-g.ttl)
	g.mu.Lock()
	defer g.mu.Unlock()
	for existing, seenAt := range g.seen {
		if seenAt.Before(cutoff) {
			delete(g.seen, existing)
		}
	}
	if seenAt, exists := g.seen[key]; exists && now.Sub(seenAt) < g.ttl {
		return false
	}
	g.seen[key] = now
	return true
}

func processGateKey(pid uint32, image string) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err == nil {
		var created, exited, kernel, user windows.Filetime
		if err = windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err == nil {
			windows.CloseHandle(h)
			return fmt.Sprintf("%d:%d:%d", pid, created.HighDateTime, created.LowDateTime)
		}
		windows.CloseHandle(h)
	}
	image = strings.TrimSpace(image)
	if image != "" {
		image = strings.ToLower(filepath.Clean(image))
	}
	return fmt.Sprintf("%d:%s", pid, image)
}
