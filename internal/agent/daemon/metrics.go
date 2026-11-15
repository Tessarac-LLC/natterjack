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

package daemon

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	gatewaysDown = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "natterjack_agent_gateways_down",
		Help: "Gateways that stopped answering this node's probes.",
	})
	gatewayServing = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "natterjack_agent_gateway_serving",
		Help: "1 when this node's slot is in its gateway namespace and carries traffic.",
	})
	problemCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "natterjack_agent_problems",
		Help: "Problems in the cluster configuration this node's agent reports in its log.",
	})
	applyFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "natterjack_agent_apply_failures_total",
		Help: "Failed attempts to apply the data path.",
	})
	selfTestFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "natterjack_agent_self_test_failures_total",
		Help: "Failed self-tests through this node's slot.",
	})
	steeringMode = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "natterjack_agent_steering_mode",
		Help: "1 for how this node steers pod traffic: nftables, or ebpf for the fast path on its uplinks.",
	}, []string{"mode"})
	divertedPackets atomic.Uint64
	divertedTotal   = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "natterjack_agent_ebpf_diverted_packets_total",
		Help: "Pod packets the eBPF fast path sent to be steered.",
	}, func() float64 { return float64(divertedPackets.Load()) })
)

func init() {
	metrics.Registry.MustRegister(gatewaysDown, gatewayServing, problemCount, applyFailures, selfTestFailuresTotal, steeringMode, divertedTotal)
}
