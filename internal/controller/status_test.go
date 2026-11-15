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
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

func cond(t *testing.T, st v1.EgressPoolStatus, typ string) metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(st.Conditions, typ)
	if c == nil {
		t.Fatalf("condition %s missing", typ)
	}
	return *c
}

func TestStatusHealthy(t *testing.T) {
	st := Status(3, []v1.SlotStatus{
		{ID: "eni-1", Zone: "a", PublicIP: "203.0.113.1", State: v1.SlotActive},
		{ID: "eni-2", Zone: "a", PublicIP: "203.0.113.2", State: v1.SlotActive},
		{ID: "eni-3", Zone: "a", PublicIP: "203.0.113.3", State: v1.SlotSpare},
	}, []string{"a"}, nil)
	for typ, want := range map[string]metav1.ConditionStatus{
		v1.ConditionReady: metav1.ConditionTrue, v1.ConditionDegraded: metav1.ConditionFalse, v1.ConditionCrossZoneEgress: metav1.ConditionFalse,
		v1.ConditionSlotsQuarantined: metav1.ConditionFalse, v1.ConditionSlotsUnschedulable: metav1.ConditionFalse, v1.ConditionForeignSlots: metav1.ConditionFalse,
		v1.ConditionCloudAccess: metav1.ConditionTrue,
	} {
		if c := cond(t, st, typ); c.Status != want || c.ObservedGeneration != 3 {
			t.Errorf("%s: %+v", typ, c)
		}
	}
	if !slices.Equal(st.PublicIPs, []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}) {
		t.Fatalf("spares must be listed for partner allowlists: %v", st.PublicIPs)
	}
	if !slices.Equal(st.Zones, []v1.ZoneStatus{{Zone: "a", Slots: 3, ReadyGateways: 2}}) {
		t.Fatalf("zones %+v", st.Zones)
	}
}

func TestStatusProblems(t *testing.T) {
	st := Status(1, []v1.SlotStatus{
		{ID: "eni-1", Zone: "a", PublicIP: "203.0.113.1", State: v1.SlotActive},
		{ID: "eni-2", Zone: "b", PublicIP: "203.0.113.2", State: v1.SlotQuarantined},
		{ID: "eni-3", Zone: "b", State: v1.SlotUnschedulable},
		{ID: "eni-4", Zone: "a", PublicIP: "198.51.100.9", State: v1.SlotForeign},
	}, []string{"a", "b", "c"}, nil)
	if c := cond(t, st, v1.ConditionDegraded); c.Status != metav1.ConditionTrue || c.Message != "no ready gateway in b, c; a single gateway, so no in-zone redundancy, in a" {
		t.Fatalf("degraded %+v", c)
	}
	if c := cond(t, st, v1.ConditionCrossZoneEgress); c.Status != metav1.ConditionTrue {
		t.Fatalf("cross-zone %+v", c)
	}
	for typ, id := range map[string]string{v1.ConditionSlotsQuarantined: "eni-2", v1.ConditionSlotsUnschedulable: "eni-3", v1.ConditionForeignSlots: "eni-4"} {
		if c := cond(t, st, typ); c.Status != metav1.ConditionTrue || !slices.Contains([]string{c.Message[len(c.Message)-5:]}, id) {
			t.Errorf("%s: %+v", typ, c)
		}
	}
	if slices.Contains(st.PublicIPs, "198.51.100.9") {
		t.Fatal("a foreign slot's address must not be published")
	}
}

func TestStatusNothingReady(t *testing.T) {
	st := Status(1, nil, []string{"a"}, nil)
	if cond(t, st, v1.ConditionReady).Status != metav1.ConditionFalse || cond(t, st, v1.ConditionCrossZoneEgress).Status != metav1.ConditionFalse {
		t.Fatalf("%+v", st.Conditions)
	}
}
