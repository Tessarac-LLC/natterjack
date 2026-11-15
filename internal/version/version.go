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

// Package version reports which release a binary is.
package version

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
)

// Version is the release, set at build time with
// -ldflags "-X github.com/Tessarac-LLC/natterjack/internal/version.Version=v1.2.3".
var Version = "dev"

// BuildInfo is natterjack_build_info{component, version, go_version} = 1, so
// dashboards and alerts can tell which release each pod runs.
func BuildInfo(component string) prometheus.Collector {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "natterjack_build_info",
		Help:        "Always 1; the labels name the component, its release and the Go version it was built with.",
		ConstLabels: prometheus.Labels{"component": component, "version": Version, "go_version": runtime.Version()},
	})
	g.Set(1)
	return g
}
