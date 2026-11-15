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

package doctor

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

var marks = map[Severity]string{OK: "ok", Warn: "WARN", Fail: "FAIL"}

// Print writes the report for a terminal or a test log.
func Print(w io.Writer, r Report) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, f := range r.Findings {
		// One line per finding: cloud SDK errors can span lines.
		msg := strings.Join(strings.Fields(f.Message), " ")
		if _, err := fmt.Fprintf(tw, "[%s]\t%s\t%s\n", marks[f.Severity], f.Check, msg); err != nil {
			return fmt.Errorf("write the report: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write the report: %w", err)
	}
	fails, warns := 0, 0
	for _, f := range r.Findings {
		switch f.Severity {
		case Fail:
			fails++
		case Warn:
			warns++
		}
	}
	var err error
	switch {
	case fails > 0:
		_, err = fmt.Fprintf(w, "\nNO-GO: %d problem(s) must be fixed before traffic moves; %d warning(s).\n", fails, warns)
	case warns > 0:
		_, err = fmt.Fprintf(w, "\nGO, with %d warning(s).\n", warns)
	default:
		_, err = fmt.Fprintln(w, "\nGO.")
	}
	if err != nil {
		return fmt.Errorf("write the report: %w", err)
	}
	return nil
}
