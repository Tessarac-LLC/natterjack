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

package agent

import (
	"encoding/json"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

// Hold keeps using a gateway while its agent restarts. The gateway's kernel
// state outlives the agent, so traffic through it keeps flowing; only its
// pod goes away, and the new pod carries no assignment until the controller
// writes one. Without the hold every source would move the gateway's flows
// elsewhere and back again. Probes still decide liveness throughout.
//
// An agent that itself started while a gateway restarted never saw that
// gateway serve. It takes the controller's word instead: the controller
// keeps a restarting gateway's slot active on its node.
//
// The hold ends when the node's new agent reports anything other than
// starting up on the same slot, when the slot is drained or reassigned, when
// the node goes, or after For.
type Hold struct {
	For  time.Duration
	last map[string]held // by node name
	// from the pools' status, by node name: the slot whose hold was taken,
	// so an ended hold does not come back while the slot stays active.
	fromPool map[string]string
}

type held struct {
	pod   corev1.Pod
	since time.Time // zero while the gateway is up
}

// Apply puts held gateways, and their WireGuard keys, back into s. It
// returns how long until the first hold runs out, or 0 when none is held.
func (h *Hold) Apply(s *Snapshot, now time.Time) time.Duration {
	var next time.Duration
	if h.last == nil {
		h.last = map[string]held{}
		h.fromPool = map[string]string{}
	}
	nodes := map[string]bool{}
	for i := range s.Nodes {
		nodes[s.Nodes[i].Name] = true
	}
	live := map[string]*corev1.Pod{}
	for i := range s.Agents {
		if p := &s.Agents[i]; p.DeletionTimestamp == nil {
			live[p.Spec.NodeName] = p
		}
	}
	up := map[string]bool{}
	for i := range s.Gateways {
		p := &s.Gateways[i]
		if slot := slotOf(p); slot != "" && p.DeletionTimestamp == nil && v1.GatewayReady(p, slot) && p.Annotations[v1.AnnotationDrainStarted] == "" {
			up[p.Spec.NodeName] = true
			h.last[p.Spec.NodeName] = held{pod: *p.DeepCopy()}
		}
	}
	for node := range h.fromPool {
		if up[node] {
			delete(h.fromPool, node)
		}
	}
	for i := range s.Pools {
		pool := &s.Pools[i]
		for _, st := range pool.Status.Slots {
			node := st.Node
			if _, ok := h.last[node]; ok || st.State != v1.SlotActive || node == "" || up[node] || h.fromPool[node] == st.ID {
				continue
			}
			h.fromPool[node] = st.ID
			h.last[node] = held{pod: servingPod(pool, st)}
		}
	}
	for node, g := range h.last {
		if up[node] {
			continue
		}
		if !nodes[node] || !starting(live[node], slotOf(&g.pod)) {
			delete(h.last, node)
			continue
		}
		if g.since.IsZero() {
			g.since = now
			h.last[node] = g
		}
		left := g.since.Add(h.For).Sub(now)
		if left <= 0 {
			delete(h.last, node)
			continue
		}
		if next == 0 || left < next {
			next = left
		}
		p := g.pod.DeepCopy() // taken while it served, so not terminating
		s.Gateways = slices.DeleteFunc(slices.Clone(s.Gateways), func(g corev1.Pod) bool { return g.Spec.NodeName == node })
		s.Gateways = append(s.Gateways, *p)
		// First, so a key the new agent publishes wins.
		s.Agents = append([]corev1.Pod{*p}, s.Agents...)
	}
	return next
}

// servingPod stands in for the agent pod of the gateway serving st, for a
// hold taken from the pool's status. Its node's live agent pod supplies the
// WireGuard key.
func servingPod(pool *v1.EgressPool, st v1.SlotStatus) corev1.Pod {
	tunnel := pool.Spec.Tunnel
	if tunnel == "" {
		tunnel = v1.TunnelGeneve
	}
	raw, _ := json.Marshal(v1.Gateway{Pool: pool.Name, SlotID: st.ID, Tunnel: tunnel})
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "held-" + st.Node,
			Labels:      map[string]string{v1.LabelGateway: "true", v1.LabelPool: pool.Name},
			Annotations: map[string]string{v1.AnnotationGateway: string(raw)},
		},
		Spec: corev1.PodSpec{NodeName: st.Node},
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{
			Type: v1.ConditionGatewayReady, Status: corev1.ConditionTrue, Reason: "Serving", Message: v1.GatewayReadyMessage(st.ID),
		}}},
	}
}

// starting reports whether p, the node's live agent pod if any, is still
// coming up to serve slot.
func starting(p *corev1.Pod, slot string) bool {
	if p == nil {
		return true // the old pod is going or gone; the new one is not here yet
	}
	if p.Annotations[v1.AnnotationDrainStarted] != "" {
		return false
	}
	if s := slotOf(p); s != "" && s != slot {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type != v1.ConditionGatewayReady {
			continue
		}
		// Serving the slot before the controller has labeled the pod, or
		// waiting for its self-tests through it to settle.
		return (c.Status == corev1.ConditionTrue && c.Message == v1.GatewayReadyMessage(slot)) || c.Reason == v1.ReasonSelfTestPending
	}
	return true
}

func slotOf(p *corev1.Pod) string {
	var g v1.Gateway
	if p.Labels[v1.LabelGateway] != "true" || json.Unmarshal([]byte(p.Annotations[v1.AnnotationGateway]), &g) != nil {
		return ""
	}
	return g.SlotID
}
