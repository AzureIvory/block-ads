//go:build windows

// Package settings is the configuration contract shared by the core and GUI.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type Mode string

const (
	Intercept      Mode = "block"
	AutoQuarantine Mode = "auto_quarantine"
)

type Config struct {
	EradicationMode Mode `json:"eradication_mode"`
}

func Default() Config { return Config{EradicationMode: Intercept} }

func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(b, &object); err != nil {
		return c, err
	}
	if object == nil {
		return c, fmt.Errorf("configuration must be a JSON object")
	}
	if value, ok := object["eradication_mode"]; ok {
		if string(value) == "null" {
			return c, fmt.Errorf("eradication_mode must be a string")
		}
		if err := json.Unmarshal(value, &c.EradicationMode); err != nil {
			return Default(), err
		}
		if c.EradicationMode != Intercept && c.EradicationMode != AutoQuarantine {
			return Default(), fmt.Errorf("unsupported eradication_mode %q", c.EradicationMode)
		}
	}
	return c, nil
}

// SaveMode preserves unrelated configuration fields and publishes atomically.
// The caller must stop the core first: modes apply to the next core run.
func SaveMode(path string, mode Mode) error {
	if mode != Intercept && mode != AutoQuarantine {
		return fmt.Errorf("invalid eradication mode")
	}
	if _, err := Load(path); err != nil {
		return err
	}
	object := map[string]json.RawMessage{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &object); err != nil {
			return err
		}
		if object == nil {
			return fmt.Errorf("configuration must be a JSON object")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	object["eradication_mode"], _ = json.Marshal(mode)
	b, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
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
	src, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
