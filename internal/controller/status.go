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
	"fmt"
	"maps"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

// Status builds a pool's status from its slot table. nodeZones are the zones
// that have nodes with an agent, because pods there need egress even when
// the zone has no slot.
func Status(generation int64, slots []v1.SlotStatus, nodeZones []string, old []metav1.Condition) v1.EgressPoolStatus {
	st := v1.EgressPoolStatus{ObservedGeneration: generation, Slots: slots, Conditions: slices.Clone(old)}

	zones := map[string]*v1.ZoneStatus{}
	zone := func(name string) *v1.ZoneStatus {
		if zones[name] == nil {
			zones[name] = &v1.ZoneStatus{Zone: name}
		}
		return zones[name]
	}
	for _, z := range nodeZones {
		zone(z)
	}
	byState := map[v1.SlotState][]string{}
	ips := map[string]bool{}
	for _, s := range slots {
		z := zone(s.Zone)
		z.Slots++
		if s.State == v1.SlotActive {
			z.ReadyGateways++
		}
		byState[s.State] = append(byState[s.State], s.ID)
		// Foreign slots are not this pool's to use, so their address is not
		// one partners should allow.
		if s.PublicIP != "" && s.State != v1.SlotForeign {
			ips[s.PublicIP] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(zones)) {
		st.Zones = append(st.Zones, *zones[name])
	}
	st.PublicIPs = slices.Sorted(maps.Keys(ips))

	var noGateway, noRedundancy []string
	ready := 0
	for _, z := range st.Zones {
		ready += int(z.ReadyGateways)
		switch z.ReadyGateways {
		case 0:
			noGateway = append(noGateway, z.Zone)
		case 1:
			noRedundancy = append(noRedundancy, z.Zone)
		}
	}

	cond := func(t string, ok bool, reason, msg string) {
		s := metav1.ConditionFalse
		if ok {
			s = metav1.ConditionTrue
		}
		meta.SetStatusCondition(&st.Conditions, metav1.Condition{Type: t, Status: s, Reason: reason, Message: msg, ObservedGeneration: generation})
	}

	if ready > 0 {
		cond(v1.ConditionReady, true, "GatewaysReady", fmt.Sprintf("%d gateways ready", ready))
	} else {
		cond(v1.ConditionReady, false, "NoReadyGateway", "no gateway is ready; see the slot table for each slot's reason")
	}

	degraded := []string{}
	if len(noGateway) > 0 {
		degraded = append(degraded, "no ready gateway in "+strings.Join(noGateway, ", "))
	}
	if len(noRedundancy) > 0 {
		degraded = append(degraded, "a single gateway, so no in-zone redundancy, in "+strings.Join(noRedundancy, ", "))
	}
	if len(degraded) > 0 {
		cond(v1.ConditionDegraded, true, "ZoneRedundancy", strings.Join(degraded, "; "))
	} else {
		cond(v1.ConditionDegraded, false, "Redundant", "every zone has at least two ready gateways")
	}

	if len(noGateway) > 0 && ready > 0 {
		cond(v1.ConditionCrossZoneEgress, true, "ZoneWithoutGateway",
			"traffic from "+strings.Join(noGateway, ", ")+" leaves through other zones, which adds inter-zone data transfer charges")
	} else {
		cond(v1.ConditionCrossZoneEgress, false, "InZone", "no traffic needs to cross zones")
	}

	list := func(t string, state v1.SlotState, reason, what string) {
		if ids := byState[state]; len(ids) > 0 {
			cond(t, true, reason, fmt.Sprintf("%s: %s", what, strings.Join(ids, ", ")))
		} else {
			cond(t, false, "None", "none")
		}
	}
	cond(v1.ConditionCloudAccess, true, "CloudReadable", "the controller reads slots from the cloud")
	list(v1.ConditionSlotsQuarantined, v1.SlotQuarantined, "SafetyCheckFailed", "slots failing safety checks")
	list(v1.ConditionSlotsUnschedulable, v1.SlotUnschedulable, "NoEligibleNode", "slots with no eligible node")
	list(v1.ConditionForeignSlots, v1.SlotForeign, "AttachedOutsideCluster", "slots attached outside this cluster")
	return st
}
