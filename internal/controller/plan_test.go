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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/cloud"
)

var t0 = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func slot(id, zone string) cloud.Slot {
	return cloud.Slot{ID: id, Zone: zone, PublicIP: "203.0.113." + id[len(id)-1:], MAC: "02:00:00:00:00:0" + id[len(id)-1:], Tags: map[string]string{}}
}

func attached(s cloud.Slot, instance string) cloud.Slot {
	s.Instance = instance
	s.InstanceInCluster = true
	return s
}

// node returns a ready Linux node with a ready agent, created age minutes
// before t0.
func node(name, zone string, age int) Node {
	return Node{
		Name: name, Instance: "i-" + name, Zone: zone, Created: t0.Add(-time.Duration(age) * time.Minute),
		Labels: map[string]string{corev1.LabelOSStable: "linux"}, Ready: true,
		Agent: &Agent{Pod: "agent-" + name, Ready: true},
	}
}

// serving marks n's agent as a ready gateway for s.
func serving(n Node, s cloud.Slot) Node {
	n.Agent.GatewayReady = true
	n.Agent.Gateway = &v1.Gateway{Pool: "default", SlotID: s.ID}
	return n
}

func pool(spec v1.EgressPoolSpec) []Pool { return []Pool{{Name: "default", Spec: spec}} }

func run(pools []Pool, slots []cloud.Slot, nodes ...Node) Plan {
	return Compute(Input{Pools: pools, Slots: slots, Nodes: nodes, Now: t0})
}

func state(t *testing.T, p Plan, pool, id string) v1.SlotStatus {
	t.Helper()
	for _, s := range p.Pools[pool] {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("slot %s not in pool %s status: %+v", id, pool, p.Pools[pool])
	return v1.SlotStatus{}
}

func expect(t *testing.T, got v1.SlotStatus, want v1.SlotState, reason string) {
	t.Helper()
	if got.State != want || !strings.Contains(got.Reason, reason) {
		t.Fatalf("slot %s: got %s %q, want %s containing %q", got.ID, got.State, got.Reason, want, reason)
	}
}

func TestFreeSlotGoesToOldestEligibleNodeInZone(t *testing.T) {
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{slot("eni-1", "a")},
		node("young", "a", 5), node("old", "a", 50), node("other-zone", "b", 500))
	if !slices.Equal(p.Attaches, []Attach{{Slot: "eni-1", Node: "old", Instance: "i-old"}}) {
		t.Fatalf("attaches %+v", p.Attaches)
	}
	got := p.Agents["agent-old"].Gateway
	if got.SlotID != "eni-1" || got.MAC == "" || got.PublicIP == "" || got.Tunnel != v1.TunnelGeneve || got.Pool != "default" {
		t.Fatalf("assignment %+v", got)
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotAttaching, "")
}

func TestOneGatewayPerNodeAndRouteTargetsFirst(t *testing.T) {
	plain, target := slot("eni-1", "a"), slot("eni-2", "a")
	target.RouteTarget = true
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{plain, target}, node("n1", "a", 10))
	if len(p.Attaches) != 1 || p.Attaches[0].Slot != "eni-2" {
		t.Fatalf("the route-target slot must win the only node: %+v", p.Attaches)
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotUnschedulable, "n1: already a gateway")
}

func TestActiveSlotStays(t *testing.T) {
	s := attached(slot("eni-1", "a"), "i-n1")
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{s}, serving(node("n1", "a", 10), s), node("n2", "a", 99))
	if len(p.Attaches)+len(p.Detaches) != 0 {
		t.Fatalf("a healthy gateway must not move: %+v %+v", p.Attaches, p.Detaches)
	}
	if p.Agents["agent-n1"].Gateway.SlotID != "eni-1" {
		t.Fatal("assignment dropped")
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotActive, "")
}

func TestAttachedButNotYetReady(t *testing.T) {
	s := attached(slot("eni-1", "a"), "i-n1")
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{s}, node("n1", "a", 10))
	expect(t, state(t, p, "default", "eni-1"), v1.SlotAttaching, "waiting for the gateway")
}

func TestForeignSlotIsNeverTouched(t *testing.T) {
	s := slot("eni-1", "a")
	s.Instance = "i-elsewhere"
	p := run(pool(v1.EgressPoolSpec{SafetyChecks: v1.SafetyChecksWarn}), []cloud.Slot{s}, node("n1", "a", 10))
	if len(p.Attaches)+len(p.Detaches) != 0 {
		t.Fatalf("foreign slot touched: %+v %+v", p.Attaches, p.Detaches)
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotForeign, "i-elsewhere")
}

func TestQuarantine(t *testing.T) {
	bad := slot("eni-1", "a")
	bad.Problems = []string{"security group sg-1 allows inbound traffic"}
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{bad}, node("n1", "a", 10))
	if len(p.Attaches) != 0 {
		t.Fatal("quarantined slot attached")
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotQuarantined, "sg-1")
}

func TestQuarantineDetachesASlotInUse(t *testing.T) {
	bad := attached(slot("eni-1", "a"), "i-n1")
	bad.Problems = []string{"no Elastic IP"}
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{bad}, serving(node("n1", "a", 10), bad))
	if len(p.Detaches) != 1 || p.Detaches[0].Force || !strings.Contains(p.Detaches[0].Reason, "no Elastic IP") {
		t.Fatalf("detaches %+v", p.Detaches)
	}
	if _, ok := p.Agents["agent-n1"]; ok {
		t.Fatal("agent kept its assignment for a quarantined slot")
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotQuarantined, "no Elastic IP")
}

func TestWarnModeUsesAFailingSlotAndSaysSo(t *testing.T) {
	bad := slot("eni-1", "a")
	bad.Problems = []string{"no Elastic IP"}
	p := run(pool(v1.EgressPoolSpec{SafetyChecks: v1.SafetyChecksWarn}), []cloud.Slot{bad}, node("n1", "a", 10))
	if len(p.Attaches) != 1 {
		t.Fatal("warn mode must still use the slot")
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotAttaching, "no Elastic IP")
}

func TestNodeNotReadyForcesDetach(t *testing.T) {
	s := attached(slot("eni-1", "a"), "i-n1")
	dead := serving(node("n1", "a", 10), s)
	dead.Ready = false
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{s}, dead, node("n2", "a", 5))
	if !slices.Equal(p.Detaches, []Detach{{Slot: "eni-1", Node: "n1", Force: true, Reason: "node n1 is not ready"}}) {
		t.Fatalf("detaches %+v", p.Detaches)
	}
	if len(p.Attaches) != 0 {
		t.Fatal("re-attach must wait until the detach is observed")
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotPending, "not ready")
}

func TestNodeGoneForcesDetach(t *testing.T) {
	s := attached(slot("eni-1", "a"), "i-gone")
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{s}, node("n1", "a", 10))
	if len(p.Detaches) != 1 || !p.Detaches[0].Force || p.Detaches[0].Node != "" {
		t.Fatalf("detaches %+v", p.Detaches)
	}
}

func TestRestartingAgentKeepsSlot(t *testing.T) {
	s := attached(slot("eni-1", "a"), "i-n1")
	n := node("n1", "a", 10)
	n.Agent, n.AgentGone, n.LastServed = nil, t0.Add(-20*time.Second), "eni-1"
	in := Input{
		Pools: pool(v1.EgressPoolSpec{MaxGatewaysPerZone: ptr.To[int32](1)}), Slots: []cloud.Slot{s, slot("eni-2", "a")},
		Nodes: []Node{n, node("n2", "a", 99)}, Now: t0, AgentGrace: time.Minute,
	}
	p := Compute(in)
	if len(p.Detaches)+len(p.Attaches) != 0 {
		t.Fatalf("a restarting agent must not lose its slot: %+v %+v", p.Detaches, p.Attaches)
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotActive, "agent on node n1 is restarting; the slot moves if it is not back in 40s")
	expect(t, state(t, p, "default", "eni-2"), v1.SlotSpare, "")
	if p.RequeueAfter != 40*time.Second {
		t.Fatalf("requeue %s, want the end of the grace", p.RequeueAfter)
	}

	// The new agent pod is up before the controller assigns it again. The
	// slot stays Active while it comes back on the same slot, and is
	// assigned to it; anything else it reports ends that.
	for _, tc := range []struct {
		name   string
		agent  Agent
		active bool
	}{
		{name: "no condition yet", agent: Agent{Pending: true}, active: true},
		{name: "self-test pending", agent: Agent{Pending: true, Gateway: &v1.Gateway{SlotID: "eni-1"}}, active: true},
		{name: "serving its saved slot", agent: Agent{Serves: "eni-1"}, active: true},
		{name: "serving another slot", agent: Agent{Serves: "eni-9"}},
		{name: "self-test failed", agent: Agent{Gateway: &v1.Gateway{SlotID: "eni-1"}}},
		{name: "not assigned", agent: Agent{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := in
			in.Nodes = slices.Clone(in.Nodes)
			a := tc.agent
			a.Pod, a.Ready = "agent-n1-new", true
			in.Nodes[0].Agent, in.Nodes[0].AgentGone = &a, time.Time{}
			p := Compute(in)
			if len(p.Detaches)+len(p.Attaches) != 0 {
				t.Fatalf("the restarted agent lost its slot: %+v %+v", p.Detaches, p.Attaches)
			}
			if p.Agents["agent-n1-new"].Gateway.SlotID != "eni-1" {
				t.Fatalf("the restarted agent is not assigned its slot: %+v", p.Agents)
			}
			got := state(t, p, "default", "eni-1").State
			if (got == v1.SlotActive) != tc.active {
				t.Fatalf("state %s, want active %v", got, tc.active)
			}
		})
	}

	// Never served: still kept, but not reported active.
	in.Nodes[0].LastServed = ""
	expect(t, state(t, Compute(in), "default", "eni-1"), v1.SlotAttaching, "restarting")

	// Grace over: the slot moves.
	in.Now = t0.Add(41 * time.Second)
	if p := Compute(in); len(p.Detaches) != 1 || p.Detaches[0].Slot != "eni-1" {
		t.Fatalf("detaches after the grace %+v", p.Detaches)
	}

	// A node going away does not wait.
	in.Now = t0
	in.Nodes[0].Disruption = "node n1 is cordoned"
	if p := Compute(in); len(p.Detaches) != 1 {
		t.Fatalf("detaches on a cordoned node %+v", p.Detaches)
	}

	// Nor does a node that is not ready.
	in.Nodes[0].Disruption, in.Nodes[0].Ready = "", false
	if p := Compute(in); len(p.Detaches) != 1 || !p.Detaches[0].Force {
		t.Fatalf("detaches on a failed node %+v", p.Detaches)
	}
}

func TestNodeWithoutAgentGivesUpSlot(t *testing.T) {
	s := attached(slot("eni-1", "a"), "i-n1")
	n := node("n1", "a", 10)
	n.Agent = nil
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{s}, n)
	if len(p.Detaches) != 1 || p.Detaches[0].Force {
		t.Fatalf("detaches %+v", p.Detaches)
	}
}

func TestPlannedDisruptionDrainsThenMoves(t *testing.T) {
	s := attached(slot("eni-1", "a"), "i-n1")
	spec := v1.EgressPoolSpec{DrainSeconds: 60}
	cordoned := serving(node("n1", "a", 10), s)
	cordoned.Disruption = "node n1 is cordoned"

	p := run(pool(spec), []cloud.Slot{s}, cordoned, node("n2", "a", 5))
	if len(p.Detaches) != 0 || p.Agents["agent-n1"].DrainStarted != t0 || p.RequeueAfter != time.Minute {
		t.Fatalf("drain did not start: %+v requeue %s", p, p.RequeueAfter)
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotDraining, "cordoned")

	cordoned.Agent.DrainStarted = t0.Add(-40 * time.Second)
	p = run(pool(spec), []cloud.Slot{s}, cordoned, node("n2", "a", 5))
	if len(p.Detaches) != 0 || p.RequeueAfter != 20*time.Second || p.Agents["agent-n1"].DrainStarted != cordoned.Agent.DrainStarted {
		t.Fatalf("drain window not kept: %+v", p)
	}

	cordoned.Agent.DrainStarted = t0.Add(-61 * time.Second)
	p = run(pool(spec), []cloud.Slot{s}, cordoned, node("n2", "a", 5))
	if !slices.Equal(p.Detaches, []Detach{{Slot: "eni-1", Node: "n1", Reason: "node n1 is cordoned"}}) {
		t.Fatalf("detaches %+v", p.Detaches)
	}
	if _, ok := p.Agents["agent-n1"]; ok {
		t.Fatal("assignment kept after the drain window")
	}
}

func TestUncordonCancelsDrain(t *testing.T) {
	s := attached(slot("eni-1", "a"), "i-n1")
	n := serving(node("n1", "a", 10), s)
	n.Agent.DrainStarted = t0.Add(-10 * time.Second)
	p := run(pool(v1.EgressPoolSpec{DrainSeconds: 60}), []cloud.Slot{s}, n)
	if !p.Agents["agent-n1"].DrainStarted.IsZero() {
		t.Fatal("drain kept on a node that is no longer leaving")
	}
	expect(t, state(t, p, "default", "eni-1"), v1.SlotActive, "")
}

func TestSelectorChangeDrains(t *testing.T) {
	s := attached(slot("eni-1", "a"), "i-n1")
	p := run(pool(v1.EgressPoolSpec{GatewayNodeSelector: map[string]string{"role": "egress"}}), []cloud.Slot{s}, serving(node("n1", "a", 10), s))
	expect(t, state(t, p, "default", "eni-1"), v1.SlotPending, "gatewayNodeSelector role=egress")
}

func TestTaintsAndTolerations(t *testing.T) {
	n := node("n1", "a", 10)
	n.Taints = []corev1.Taint{{Key: "dedicated", Value: "egress", Effect: corev1.TaintEffectNoSchedule}, {Key: "soft", Effect: corev1.TaintEffectPreferNoSchedule}}
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{slot("eni-1", "a")}, n)
	expect(t, state(t, p, "default", "eni-1"), v1.SlotUnschedulable, "taint dedicated=egress:NoSchedule")

	tol := []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "egress", Effect: corev1.TaintEffectNoSchedule}}
	p = run(pool(v1.EgressPoolSpec{GatewayTolerations: tol}), []cloud.Slot{slot("eni-1", "a")}, n)
	if len(p.Attaches) != 1 {
		t.Fatalf("tolerated taint blocked the node: %+v", p.Pools)
	}
}

func TestUnschedulableExplainsEveryNode(t *testing.T) {
	notReady := node("n1", "a", 1)
	notReady.Ready = false
	noAgent := node("n2", "a", 2)
	noAgent.Agent = nil
	agentStarting := node("n3", "a", 3)
	agentStarting.Agent.Ready = false
	leaving := node("n4", "a", 4)
	leaving.Disruption = "Karpenter is removing node n4"
	windows := node("n5", "a", 5)
	windows.Labels[corev1.LabelOSStable] = "windows"
	full := node("n6", "a", 6)

	p := Compute(Input{
		Pools: pool(v1.EgressPoolSpec{}), Slots: []cloud.Slot{slot("eni-1", "a")}, Now: t0,
		Nodes: []Node{notReady, noAgent, agentStarting, leaving, windows, full},
		Avoid: map[string]string{"n6": "no free network interface slot"},
	})
	got := state(t, p, "default", "eni-1")
	for _, want := range []string{"n1: not ready", "n2: no agent", "n3: agent not ready", "n4: Karpenter", "n5 is not Linux", "n6: no free network interface"} {
		expect(t, got, v1.SlotUnschedulable, want)
	}

	p = run(pool(v1.EgressPoolSpec{}), []cloud.Slot{slot("eni-1", "c")}, node("n1", "a", 1))
	expect(t, state(t, p, "default", "eni-1"), v1.SlotUnschedulable, "no nodes in zone c")
}

func TestMaxGatewaysPerZone(t *testing.T) {
	a1, a2 := slot("eni-1", "a"), slot("eni-2", "a")
	spec := v1.EgressPoolSpec{MaxGatewaysPerZone: ptr.To[int32](1)}
	p := run(pool(spec), []cloud.Slot{a1, a2, slot("eni-3", "b")}, node("n1", "a", 1), node("n2", "a", 2), node("n3", "b", 3))
	expect(t, state(t, p, "default", "eni-2"), v1.SlotSpare, "maxGatewaysPerZone")
	expect(t, state(t, p, "default", "eni-3"), v1.SlotAttaching, "")
	if len(p.Attaches) != 2 {
		t.Fatalf("attaches %+v", p.Attaches)
	}
}

func TestLoweringTheCapDrainsExtras(t *testing.T) {
	a1, a2 := attached(slot("eni-1", "a"), "i-n1"), attached(slot("eni-2", "a"), "i-n2")
	a2.RouteTarget = true
	p := run(pool(v1.EgressPoolSpec{MaxGatewaysPerZone: ptr.To[int32](1)}), []cloud.Slot{a1, a2},
		serving(node("n1", "a", 1), a1), serving(node("n2", "a", 2), a2))
	expect(t, state(t, p, "default", "eni-2"), v1.SlotActive, "")
	expect(t, state(t, p, "default", "eni-1"), v1.SlotPending, "above maxGatewaysPerZone")
}

func TestDrainingSlotDoesNotBlockItsReplacement(t *testing.T) {
	s, spare := attached(slot("eni-1", "a"), "i-n1"), slot("eni-2", "a")
	n1 := serving(node("n1", "a", 10), s)
	n1.Disruption = "node n1 is cordoned"
	p := run(pool(v1.EgressPoolSpec{DrainSeconds: 60, MaxGatewaysPerZone: ptr.To[int32](1)}), []cloud.Slot{s, spare}, n1, node("n2", "a", 5))
	if !slices.Equal(p.Attaches, []Attach{{Slot: "eni-2", Node: "n2", Instance: "i-n2"}}) {
		t.Fatalf("the spare must come up while the old gateway drains: %+v", p.Attaches)
	}
}

func TestSecondSlotOnOneNodeIsMovedOff(t *testing.T) {
	s1, s2 := attached(slot("eni-1", "a"), "i-n1"), attached(slot("eni-2", "a"), "i-n1")
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{s1, s2}, serving(node("n1", "a", 10), s1))
	if !slices.Equal(p.Detaches, []Detach{{Slot: "eni-2", Node: "n1", Reason: "node n1 already serves slot eni-1"}}) {
		t.Fatalf("detaches %+v", p.Detaches)
	}
}

func TestPoolMatching(t *testing.T) {
	untagged := slot("eni-1", "a")
	partners := slot("eni-2", "a")
	partners.Tags[v1.TagPool] = "partners"
	orphan := slot("eni-3", "a")
	orphan.Tags[v1.TagPool] = "nobody"
	pools := []Pool{
		{Name: "default"},
		{Name: "partners", Spec: v1.EgressPoolSpec{Discovery: v1.Discovery{ExtraTags: map[string]string{v1.TagPool: "partners"}}}},
	}
	p := run(pools, []cloud.Slot{untagged, partners, orphan}, node("n1", "a", 1), node("n2", "a", 2))
	if len(p.Pools["default"]) != 1 || p.Pools["default"][0].ID != "eni-1" || len(p.Pools["partners"]) != 1 || p.Pools["partners"][0].ID != "eni-2" {
		t.Fatalf("pools %+v", p.Pools)
	}
	if !slices.Equal(p.Unmatched, []string{"eni-3"}) {
		t.Fatalf("unmatched %v", p.Unmatched)
	}
}

func TestSlotClaimedByTwoPoolsIsQuarantinedInBoth(t *testing.T) {
	s := slot("eni-1", "a")
	s.Tags["team"] = "x"
	pools := []Pool{
		{Name: "a", Spec: v1.EgressPoolSpec{Discovery: v1.Discovery{ExtraTags: map[string]string{"team": "x"}}}},
		{Name: "b"},
	}
	p := run(pools, []cloud.Slot{s}, node("n1", "a", 1))
	expect(t, state(t, p, "a", "eni-1"), v1.SlotQuarantined, "claimed by more than one EgressPool (a, b)")
	expect(t, state(t, p, "b", "eni-1"), v1.SlotQuarantined, "claimed by more than one EgressPool")
	if len(p.Attaches) != 0 {
		t.Fatal("ambiguous slot attached")
	}
}

func TestNodeBusyInAnotherPoolIsNotReused(t *testing.T) {
	theirs := attached(slot("eni-1", "a"), "i-n1")
	theirs.Tags[v1.TagPool] = "partners"
	pools := []Pool{
		{Name: "default"},
		{Name: "partners", Spec: v1.EgressPoolSpec{Discovery: v1.Discovery{ExtraTags: map[string]string{v1.TagPool: "partners"}}}},
	}
	p := run(pools, []cloud.Slot{theirs, slot("eni-2", "a")}, node("n1", "a", 1))
	expect(t, state(t, p, "default", "eni-2"), v1.SlotUnschedulable, "n1: already a gateway")
}

func TestWireGuardPoolTellsTheAgent(t *testing.T) {
	p := run(pool(v1.EgressPoolSpec{Tunnel: v1.TunnelWireGuard}), []cloud.Slot{slot("eni-1", "a")}, node("n1", "a", 1))
	if p.Agents["agent-n1"].Gateway.Tunnel != v1.TunnelWireGuard {
		t.Fatalf("tunnel %+v", p.Agents["agent-n1"])
	}
}

func TestUnclaimedSlotIsDetached(t *testing.T) {
	s := attached(slot("eni-1", "a"), "i-n1")
	s.Tags[v1.TagPool] = "deleted"
	foreign := slot("eni-2", "a")
	foreign.Tags[v1.TagPool] = "deleted"
	foreign.Instance = "i-elsewhere"
	p := run(pool(v1.EgressPoolSpec{}), []cloud.Slot{s, foreign}, serving(node("n1", "a", 1), s))
	if !slices.Equal(p.Detaches, []Detach{{Slot: "eni-1", Node: "n1", Reason: "no EgressPool claims it"}}) {
		t.Fatalf("detaches %+v", p.Detaches)
	}
	if len(p.Agents) != 0 {
		t.Fatalf("agents %+v", p.Agents)
	}
}
