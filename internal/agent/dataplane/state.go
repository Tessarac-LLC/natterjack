/*
Copyright 2026 Tessarac, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dataplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
)

const (
	marksFile = "marks.json"
	roleFile  = "gateway.json"
)

// LoadMarks reads the mark table the last Apply saved. Conntrack entries
// carry these marks, so an agent restart must reuse them; a reboot empties
// both together.
func LoadMarks(dir string) (map[uint32]netip.Addr, error) {
	b, err := os.ReadFile(filepath.Join(dir, marksFile)) //nolint:gosec // under the configured state directory
	if errors.Is(err, fs.ErrNotExist) {
		return map[uint32]netip.Addr{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read mark table: %w", err)
	}
	var m map[uint32]netip.Addr
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse mark table %s: %w", filepath.Join(dir, marksFile), err)
	}
	return m, nil
}

// SaveMarks replaces the saved mark table atomically.
func SaveMarks(dir string, m map[uint32]netip.Addr) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode mark table: %w", err)
	}
	if err := writeAtomic(dir, marksFile, b); err != nil {
		return fmt.Errorf("save mark table: %w", err)
	}
	return nil
}

// LoadRole reads the gateway assignment the agent last served, as the
// controller wrote it, or "" when it served none.
func LoadRole(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, roleFile)) //nolint:gosec // under the configured state directory
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read gateway assignment: %w", err)
	}
	return string(b), nil
}

// SaveRole records the gateway assignment being served, so that the next
// agent on the node keeps serving it while the controller catches up. An
// empty role removes the record.
func SaveRole(dir, role string) error {
	if role == "" {
		if err := os.Remove(filepath.Join(dir, roleFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove gateway assignment: %w", err)
		}
		return nil
	}
	if err := writeAtomic(dir, roleFile, []byte(role)); err != nil {
		return fmt.Errorf("save gateway assignment: %w", err)
	}
	return nil
}

func writeAtomic(dir, name string, b []byte) error {
	tmp, err := os.CreateTemp(dir, name+".*")
	if err != nil {
		return err //nolint:wrapcheck // wrapped by the callers
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // fails harmlessly after the rename
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err //nolint:wrapcheck // wrapped by the callers
	}
	if err := tmp.Close(); err != nil {
		return err //nolint:wrapcheck // wrapped by the callers
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name)) //nolint:wrapcheck // wrapped by the callers
}
