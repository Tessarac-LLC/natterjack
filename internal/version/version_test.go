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

package version

import (
	"runtime"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestBuildInfoNamesComponentAndRelease(t *testing.T) {
	old := Version
	Version = "v1.2.3"
	t.Cleanup(func() { Version = old })

	want := `
# HELP natterjack_build_info Always 1; the labels name the component, its release and the Go version it was built with.
# TYPE natterjack_build_info gauge
natterjack_build_info{component="agent",go_version="` + runtime.Version() + `",version="v1.2.3"} 1
`
	if err := testutil.CollectAndCompare(BuildInfo("agent"), strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}
