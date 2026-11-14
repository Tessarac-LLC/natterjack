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

package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/cloud"
)

var (
	slotsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "natterjack_slots",
		Help: "Egress slots by pool, zone and state.",
	}, []string{"pool", "zone", "state"})
	gatewaysReady = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "natterjack_gateways_ready",
		Help: "Ready gateways by pool and zone.",
	}, []string{"pool", "zone"})
	strayGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "natterjack_slots_unclaimed",
		Help: "Egress-tagged slots that no pool of this cluster uses: unmatched by any pool, or tagged for another cluster.",
	})
	slotMoves = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "natterjack_slot_detaches_total",
		Help: "Slots detached from a node, by pool.",
	}, []string{"pool"})
	cloudErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "natterjack_cloud_errors_total",
		Help: "Failed cloud API operations, by operation.",
	}, []string{"operation"})
)

func init() {
	metrics.Registry.MustRegister(slotsGauge, gatewaysReady, strayGauge, slotMoves, cloudErrors)
}

// record publishes the plan's slot table as gauges.
func record(plan Plan, strays []cloud.Stray) {
	slotsGauge.Reset()
	gatewaysReady.Reset()
	for pool, slots := range plan.Pools {
		for _, s := range slots {
			slotsGauge.WithLabelValues(pool, s.Zone, string(s.State)).Inc()
			g := gatewaysReady.WithLabelValues(pool, s.Zone)
			if s.State == v1.SlotActive {
				g.Inc()
			}
		}
	}
	strayGauge.Set(float64(len(plan.Unmatched) + len(strays)))
}
