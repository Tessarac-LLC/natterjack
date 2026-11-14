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

// Package controller assigns egress slots to gateway nodes. The planner in
// this file is a pure function of the observed cloud and cluster state; the
// reconciler gathers that state, applies the plan and reports it.
package controller

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/cloud"
)

// Node is a cluster node as the planner sees it.
type Node struct {
	Name     string
	Instance string
	// Zone of the node's instance.
	Zone    string
	Created time.Time
	Labels  map[string]string
	Taints  []corev1.Taint
	// Ready is the node's Ready condition.
	Ready bool
	// Disruption is why the node is going away (cordon, drain, Karpenter or
	// autoscaler removal), or empty.
	Disruption string
	// Agent is the node's agent pod, or nil when none runs there.
	Agent *Agent
}

// Agent is the agent pod on a node.
type Agent struct {
	Pod string
	// Ready reports whether the agent container is ready to take a slot.
	Ready bool
	// GatewayReady is the pod's gateway readiness gate.
	GatewayReady bool
	// Gateway is the assignment currently written on the pod, if any.
	Gateway *v1.Gateway
	// DrainStarted is when the controller asked this gateway to drain.
	DrainStarted time.Time
}

// Pool is an EgressPool as the planner needs it.
type Pool struct {
	Name string
	Spec v1.EgressPoolSpec
}

// Input is everything the planner looks at.
type Input struct {
	Pools []Pool
	// Slots are every slot of this cluster, from the cloud.
	Slots []cloud.Slot
	Nodes []Node
	// Avoid are nodes that recently refused an attach (for example, at their
	// interface limit), with the reason.
	Avoid map[string]string
	Now   time.Time
}

// Detach removes a slot from its node.
type Detach struct {
	Slot   string
	Node   string // empty when the node no longer exists
	Force  bool
	Reason string
}

// Attach puts a slot on a node.
type Attach struct {
	Slot     string
	Node     string
	Instance string
}

// Plan is what the reconciler must do, and the resulting status.
type Plan struct {
	// Detaches run first; the agent's assignment is cleared before each.
	Detaches []Detach
	Attaches []Attach
	// Agents is the desired assignment of every agent pod. A pod not listed
	// has no assignment.
	Agents map[string]AgentWant
	// Pools holds the slot table of each pool.
	Pools map[string][]v1.SlotStatus
	// Unmatched are slots of this cluster that no pool claims.
	Unmatched []string
	// RequeueAfter is when a drain window ends, or zero.
	RequeueAfter time.Duration
}

// AgentWant is the desired gateway state of one agent pod.
type AgentWant struct {
	Gateway      v1.Gateway
	DrainStarted time.Time // zero unless draining
}

// Compute plans one reconcile.
func Compute(in Input) Plan {
	p := Plan{Agents: map[string]AgentWant{}, Pools: map[string][]v1.SlotStatus{}}
	owners, unmatched := matchPools(in.Pools, in.Slots)
	p.Unmatched = unmatched

	byInstance := map[string]*Node{}
	for i := range in.Nodes {
		byInstance[in.Nodes[i].Instance] = &in.Nodes[i]
	}
	// A node runs at most one gateway, whatever the pool.
	occupied := map[string]bool{}
	served := map[string]string{}
	for _, s := range in.Slots {
		if n := byInstance[s.Instance]; s.Instance != "" && n != nil {
			occupied[n.Name] = true
		}
	}

	for _, pool := range in.Pools {
		pp := planner{in: in, pool: pool, plan: &p, byInstance: byInstance, occupied: occupied, served: served}
		var mine []cloud.Slot
		for _, s := range in.Slots {
			if slices.Contains(owners[s.ID], pool.Name) {
				mine = append(mine, s)
			}
		}
		p.Pools[pool.Name] = pp.run(mine, owners)
	}

	// A slot no pool claims has no gateway to keep its interface isolated,
	// so it does not stay on a node of this cluster.
	for _, s := range in.Slots {
		if !slices.Contains(unmatched, s.ID) || s.Instance == "" || !s.InstanceInCluster {
			continue
		}
		d := Detach{Slot: s.ID, Force: true, Reason: "no EgressPool claims it"}
		if n := byInstance[s.Instance]; n != nil {
			d.Node, d.Force = n.Name, !n.Ready
		}
		p.Detaches = append(p.Detaches, d)
	}
	return p
}

// matchPools maps each slot to the pools that claim it. A pool claims a slot
// when every extra tag matches; a pool that does not ask for a pool tag only
// claims slots that have none.
func matchPools(pools []Pool, slots []cloud.Slot) (map[string][]string, []string) {
	owners := map[string][]string{}
	var unmatched []string
	for _, s := range slots {
		for _, pool := range pools {
			tags := pool.Spec.Discovery.ExtraTags
			if _, ok := tags[v1.TagPool]; !ok {
				if _, tagged := s.Tags[v1.TagPool]; tagged {
					continue
				}
			}
			match := true
			for k, v := range tags {
				if s.Tags[k] != v {
					match = false
					break
				}
			}
			if match {
				owners[s.ID] = append(owners[s.ID], pool.Name)
			}
		}
		if len(owners[s.ID]) == 0 {
			unmatched = append(unmatched, s.ID)
		}
	}
	return owners, unmatched
}

type planner struct {
	in         Input
	pool       Pool
	plan       *Plan
	byInstance map[string]*Node
	occupied   map[string]bool
	// served maps a node to the slot it serves, across pools.
	served map[string]string
}

func (pp *planner) run(slots []cloud.Slot, owners map[string][]string) []v1.SlotStatus {
	// Slots that private route tables point at carry node traffic before any
	// agent steers it, so they are placed first.
	sort.SliceStable(slots, func(i, j int) bool {
		if slots[i].RouteTarget != slots[j].RouteTarget {
			return slots[i].RouteTarget
		}
		return slots[i].ID < slots[j].ID
	})

	status := map[string]v1.SlotStatus{}
	set := func(s cloud.Slot, state v1.SlotState, node, reason string) {
		status[s.ID] = v1.SlotStatus{ID: s.ID, Zone: s.Zone, PublicIP: s.PublicIP, State: state, Node: node, Reason: reason}
	}

	// serving holds slots that stay on a healthy node, per zone, in priority
	// order; any above the zone cap are drained below.
	serving := map[string][]cloud.Slot{}
	var free []cloud.Slot
	for _, s := range slots {
		problems := pp.problems(s, owners)
		node := pp.byInstance[s.Instance]
		switch {
		case s.Instance != "" && !s.InstanceInCluster:
			set(s, v1.SlotForeign, "", fmt.Sprintf("attached to instance %s, which is not in this cluster; Natterjack never touches it", s.Instance))
		case s.Instance != "" && node == nil:
			pp.detach(s, "", true, fmt.Sprintf("instance %s has no node in the cluster", s.Instance))
			set(s, v1.SlotPending, "", "detaching from an instance whose node is gone")
		case s.Instance != "" && len(problems) > 0 && pp.enforce():
			pp.detach(s, node.Name, !node.Ready, "failed safety checks: "+strings.Join(problems, "; "))
			set(s, v1.SlotQuarantined, "", strings.Join(problems, "; "))
		case s.Instance != "" && !node.Ready:
			pp.detach(s, node.Name, true, fmt.Sprintf("node %s is not ready", node.Name))
			set(s, v1.SlotPending, "", fmt.Sprintf("moving off node %s, which is not ready", node.Name))
		case s.Instance != "" && node.Agent == nil:
			pp.detach(s, node.Name, false, fmt.Sprintf("node %s has no agent", node.Name))
			set(s, v1.SlotPending, "", fmt.Sprintf("moving off node %s, which has no agent", node.Name))
		case s.Instance != "":
			if why := pp.leaving(node); why != "" {
				pp.drain(s, node, why, set)
				continue
			}
			serving[s.Zone] = append(serving[s.Zone], s)
		case len(problems) > 0 && pp.enforce():
			set(s, v1.SlotQuarantined, "", strings.Join(problems, "; "))
		default:
			free = append(free, s)
		}
	}

	capacity := map[string]int{}
	for _, zone := range slices.Sorted(maps.Keys(serving)) {
		for _, s := range serving[zone] {
			node := pp.byInstance[s.Instance]
			if other, ok := pp.served[node.Name]; ok {
				pp.detach(s, node.Name, false, fmt.Sprintf("node %s already serves slot %s", node.Name, other))
				set(s, v1.SlotPending, "", fmt.Sprintf("moving off node %s, which already serves slot %s", node.Name, other))
				continue
			}
			if pp.atCap(capacity[zone]) {
				pp.drain(s, node, "above maxGatewaysPerZone", set)
				continue
			}
			capacity[zone]++
			pp.serve(s, node)
			reason := strings.Join(pp.problems(s, owners), "; ")
			if node.Agent.GatewayReady && node.Agent.Gateway != nil && node.Agent.Gateway.SlotID == s.ID {
				set(s, v1.SlotActive, node.Name, reason)
			} else {
				set(s, v1.SlotAttaching, node.Name, joinReason("waiting for the gateway to report ready", reason))
			}
		}
	}

	for _, s := range free {
		if pp.atCap(capacity[s.Zone]) {
			set(s, v1.SlotSpare, "", fmt.Sprintf("zone %s already has maxGatewaysPerZone gateways", s.Zone))
			continue
		}
		node, why := pp.choose(s.Zone)
		if node == nil {
			set(s, v1.SlotUnschedulable, "", why)
			continue
		}
		pp.occupied[node.Name] = true
		capacity[s.Zone]++
		pp.plan.Attaches = append(pp.plan.Attaches, Attach{Slot: s.ID, Node: node.Name, Instance: node.Instance})
		pp.serve(s, node)
		set(s, v1.SlotAttaching, node.Name, strings.Join(pp.problems(s, owners), "; "))
	}

	out := slices.Collect(maps.Values(status))
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (pp *planner) enforce() bool { return pp.pool.Spec.SafetyChecks != v1.SafetyChecksWarn }

func (pp *planner) atCap(n int) bool {
	c := pp.pool.Spec.MaxGatewaysPerZone
	return c != nil && n >= int(*c)
}

// problems are the slot's failed safety checks, plus being claimed by more
// than one pool.
func (pp *planner) problems(s cloud.Slot, owners map[string][]string) []string {
	out := slices.Clone(s.Problems)
	if o := owners[s.ID]; len(o) > 1 {
		out = append(out, fmt.Sprintf("claimed by more than one EgressPool (%s); give it a %s tag", strings.Join(o, ", "), v1.TagPool))
	}
	return out
}

// leaving reports why a node holding a slot must give it up in an orderly
// way, or "" when it may keep it.
func (pp *planner) leaving(n *Node) string {
	if n.Disruption != "" {
		return n.Disruption
	}
	return pp.ineligible(n)
}

// ineligible reports why this pool may not run a gateway on the node.
func (pp *planner) ineligible(n *Node) string {
	if n.Labels[corev1.LabelOSStable] != "linux" {
		return fmt.Sprintf("node %s is not Linux", n.Name)
	}
	for k, v := range pp.pool.Spec.GatewayNodeSelector {
		if n.Labels[k] != v {
			return fmt.Sprintf("node %s does not match gatewayNodeSelector %s=%s", n.Name, k, v)
		}
	}
	for i := range n.Taints {
		t := &n.Taints[i]
		if t.Effect == corev1.TaintEffectPreferNoSchedule {
			continue
		}
		if !slices.ContainsFunc(pp.pool.Spec.GatewayTolerations, func(tol corev1.Toleration) bool { return tol.ToleratesTaint(logr.Discard(), t, false) }) {
			return fmt.Sprintf("node %s has taint %s=%s:%s, which gatewayTolerations do not tolerate", n.Name, t.Key, t.Value, t.Effect)
		}
	}
	return ""
}

// drain keeps the slot in place for the pool's drain window with the agent
// told to take no new flows, then detaches it.
func (pp *planner) drain(s cloud.Slot, n *Node, why string, set func(cloud.Slot, v1.SlotState, string, string)) {
	started := n.Agent.DrainStarted
	if started.IsZero() {
		started = pp.in.Now
	}
	window := time.Duration(pp.pool.Spec.DrainSeconds) * time.Second
	if left := started.Add(window).Sub(pp.in.Now); left > 0 {
		pp.plan.Agents[n.Agent.Pod] = AgentWant{Gateway: pp.gateway(s), DrainStarted: started}
		if pp.plan.RequeueAfter == 0 || left < pp.plan.RequeueAfter {
			pp.plan.RequeueAfter = left
		}
		set(s, v1.SlotDraining, n.Name, fmt.Sprintf("%s; moving in %s", why, left.Round(time.Second)))
		return
	}
	pp.detach(s, n.Name, false, why)
	set(s, v1.SlotPending, "", "moved off node "+n.Name+": "+why)
}

func (pp *planner) detach(s cloud.Slot, node string, force bool, reason string) {
	pp.plan.Detaches = append(pp.plan.Detaches, Detach{Slot: s.ID, Node: node, Force: force, Reason: reason})
}

func (pp *planner) serve(s cloud.Slot, n *Node) {
	pp.served[n.Name] = s.ID
	pp.plan.Agents[n.Agent.Pod] = AgentWant{Gateway: pp.gateway(s)}
}

func (pp *planner) gateway(s cloud.Slot) v1.Gateway {
	tunnel := pp.pool.Spec.Tunnel
	if tunnel == "" {
		tunnel = v1.TunnelGeneve
	}
	return v1.Gateway{Pool: pp.pool.Name, SlotID: s.ID, MAC: s.MAC, PrivateIP: s.PrivateIP, SubnetCIDR: s.SubnetCIDR, PublicIP: s.PublicIP, Tunnel: tunnel}
}

// choose picks the node for a free slot: an eligible node in the slot's zone
// with a ready agent and no gateway, oldest first because long-lived nodes
// are the least likely to be consolidated. It explains an empty result.
func (pp *planner) choose(zone string) (*Node, string) {
	var best *Node
	var refused []string
	inZone := 0
	for i := range pp.in.Nodes {
		n := &pp.in.Nodes[i]
		if n.Zone != zone {
			continue
		}
		inZone++
		why := ""
		switch {
		case pp.occupied[n.Name]:
			why = "already a gateway"
		case !n.Ready:
			why = "not ready"
		case n.Disruption != "":
			why = n.Disruption
		case n.Agent == nil:
			why = "no agent"
		case !n.Agent.Ready:
			why = "agent not ready"
		case pp.in.Avoid[n.Name] != "":
			why = pp.in.Avoid[n.Name]
		default:
			why = pp.ineligible(n)
		}
		if why != "" {
			refused = append(refused, n.Name+": "+why)
			continue
		}
		if best == nil || n.Created.Before(best.Created) || (n.Created.Equal(best.Created) && n.Name < best.Name) {
			best = n
		}
	}
	if best != nil {
		return best, ""
	}
	if inZone == 0 {
		return nil, fmt.Sprintf("no nodes in zone %s", zone)
	}
	sort.Strings(refused)
	return nil, fmt.Sprintf("no eligible node in zone %s (%s)", zone, strings.Join(refused, "; "))
}

func joinReason(a, b string) string {
	if b == "" {
		return a
	}
	return a + "; " + b
}
