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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Tessarac-LLC/natterjack/internal/version"
)

func TestRun(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	cases := []struct {
		name           string
		args           []string
		code           int
		stdout, stderr string
	}{
		{"no command", nil, exitUsage, "", "Usage:"},
		{"version", []string{"version"}, exitGo, version.Version + "\n", ""},
		{"--version", []string{"--version"}, exitGo, version.Version + "\n", ""},
		{"help", []string{"help"}, exitGo, "Usage:", ""},
		{"unknown command", []string{"dance"}, exitUsage, "", `unknown command "dance"`},
		{"bad flag", []string{"doctor", "--frobnicate"}, exitUsage, "", "flag provided but not defined"},
		{"bad output", []string{"doctor", "-o", "yaml"}, exitUsage, "", `unknown output format "yaml"`},
		{"no kubeconfig", []string{"doctor", "--kubeconfig", missing}, exitUsage, "", "cannot load a Kubernetes configuration"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(c.args, &stdout, &stderr); code != c.code {
				t.Fatalf("exit %d, want %d; stderr %q", code, c.code, stderr.String())
			}
			if !strings.Contains(stdout.String(), c.stdout) || (c.stdout == "" && stdout.Len() != 0) {
				t.Errorf("stdout %q, want %q", stdout.String(), c.stdout)
			}
			if !strings.Contains(stderr.String(), c.stderr) || (c.stderr == "" && stderr.Len() != 0) {
				t.Errorf("stderr %q, want %q", stderr.String(), c.stderr)
			}
		})
	}
}

func TestMain(m *testing.M) {
	// The kubeconfig in the environment must not decide a test.
	_ = os.Unsetenv("KUBECONFIG")
	os.Exit(m.Run())
}
