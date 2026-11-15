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
	"net/netip"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

// restarting is the snapshot of cluster() in which a1's agent pod is
// replaced by newPod, or by nothing.
func restarting(newPod *corev1.Pod) *Snapshot {
	s := cluster()
	s.Gateways = slices.DeleteFunc(s.Gateways, func(p corev1.Pod) bool { return p.Spec.NodeName == "a1" })
	s.Agents = slices.Clone(s.Gateways)
	if newPod != nil {
		s.Agents = append(s.Agents, *newPod)
		if newPod.Labels[v1.LabelGateway] == "true" {
			s.Gateways = append(s.Gateways, *newPod)
		}
	}
	return s
}

// freshAgent is a1's new agent pod before the controller assigns it.
func freshAgent(conds ...corev1.PodCondition) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "agent-a1-new", Labels: map[string]string{}, Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{NodeName: "a1"},
		Status:     corev1.PodStatus{Conditions: conds},
	}
}

func gatewayCond(status corev1.ConditionStatus, reason, msg string) corev1.PodCondition {
	return corev1.PodCondition{Type: v1.ConditionGatewayReady, Status: status, Reason: reason, Message: msg}
}

func TestHoldKeepsARestartingGateway(t *testing.T) {
	a1 := netip.MustParseAddr("10.0.1.10")
	t0 := time.Unix(1_800_000_000, 0)
	key := withKey(gatewayPod("a1", true), keyA1)

	for _, tc := range []struct {
		name string
		// The old pod, terminating, is still listed.
		terminating bool
		next        *corev1.Pod
		after       time.Duration
		held        bool
	}{
		{name: "old pod terminating, no new pod", terminating: true, held: true},
		{name: "old pod gone, no new pod", held: true},
		{name: "new pod has no condition yet", next: freshAgent(), held: true},
		{name: "new pod serves the inherited slot", next: freshAgent(gatewayCond(corev1.ConditionTrue, "Serving", v1.GatewayReadyMessage("eni-a1"))), held: true},
		{name: "new pod waits for its self-test", next: freshAgent(gatewayCond(corev1.ConditionFalse, v1.ReasonSelfTestPending, "")), held: true},
		{name: "new pod failed its self-test", next: freshAgent(gatewayCond(corev1.ConditionFalse, "SelfTestFailed", "timeout"))},
		{name: "new pod cannot apply", next: freshAgent(gatewayCond(corev1.ConditionFalse, "ApplyFailed", "no device"))},
		{name: "new pod serves no slot", next: freshAgent(gatewayCond(corev1.ConditionFalse, "NotAssigned", ""))},
		{name: "new pod serves another slot", next: freshAgent(gatewayCond(corev1.ConditionTrue, "Serving", v1.GatewayReadyMessage("eni-other")))},
		{name: "past the hold", after: 90 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hold{For: 90 * time.Second}
			up := cluster()
			up.Agents = []corev1.Pod{key}
			if left := h.Apply(up, t0); left != 0 {
				t.Fatalf("a gateway that is up is held for %s", left)
			}
			s := restarting(tc.next)
			if tc.terminating {
				old := gatewayPod("a1", true)
				old.DeletionTimestamp = &metav1.Time{Time: t0}
				s.Gateways = append(s.Gateways, old)
				s.Agents = append(s.Agents, old)
			}
			left := h.Apply(s, t0.Add(10*time.Second))
			if tc.after > 0 {
				s = restarting(nil)
				left = h.Apply(s, t0.Add(10*time.Second+tc.after))
			}
			d, problems := Compute(s, mustMarks(t))
			if len(problems) > 0 {
				t.Fatal(problems)
			}
			inRing := slices.Contains(ringGateways(d), a1)
			if inRing != tc.held {
				t.Fatalf("a1 in the ring: %v, want %v", inRing, tc.held)
			}
			if tc.held && left != 90*time.Second {
				t.Fatalf("hold ends in %s, want the full 90s from when the gateway went", left)
			}
			if tc.held && s.Agents[0].DeletionTimestamp != nil {
				t.Fatal("the held key comes from a terminating pod")
			}
		})
	}
}

func TestHoldEnds(t *testing.T) {
	a1 := netip.MustParseAddr("10.0.1.10")
	t0 := time.Unix(1_800_000_000, 0)
	h := &Hold{For: 90 * time.Second}
	h.Apply(cluster(), t0)

	// Once the controller assigns the new pod and it serves, it is used as
	// is and the hold is gone: a later restart starts a new hold.
	next := gatewayPod("a1", true)
	next.Name = "agent-a1-new"
	s := restarting(&next)
	if left := h.Apply(s, t0.Add(time.Second)); left != 0 {
		t.Fatalf("hold of %s kept after the new pod serves", left)
	}

	// Drained: the slot is leaving, so no hold.
	drained := gatewayPod("a1", false)
	drained.Annotations[v1.AnnotationDrainStarted] = "2026-11-15T00:00:00Z"
	s = restarting(&drained)
	if left := h.Apply(s, t0.Add(2*time.Second)); left != 0 {
		t.Fatalf("drained gateway held for %s", left)
	}
	d, _ := Compute(s, mustMarks(t))
	if slices.Contains(ringGateways(d), a1) {
		t.Fatal("a drained gateway is in the ring")
	}

	// The node itself going ends it.
	h = &Hold{For: 90 * time.Second}
	h.Apply(cluster(), t0)
	s = restarting(nil)
	s.Nodes = slices.DeleteFunc(s.Nodes, func(n corev1.Node) bool { return n.Name == "a1" })
	if left := h.Apply(s, t0.Add(time.Second)); left != 0 {
		t.Fatalf("gateway of a deleted node held for %s", left)
	}

	// A hold ends once and stays ended for that outage.
	h = &Hold{For: 90 * time.Second}
	h.Apply(cluster(), t0)
	h.Apply(restarting(freshAgent(gatewayCond(corev1.ConditionFalse, "SelfTestFailed", "timeout"))), t0.Add(time.Second))
	if left := h.Apply(restarting(nil), t0.Add(2*time.Second)); left != 0 {
		t.Fatalf("hold came back for %s after it ended", left)
	}
}

func TestHoldKeepsTheWireGuardKey(t *testing.T) {
	a1 := netip.MustParseAddr("10.0.1.10")
	t0 := time.Unix(1_800_000_000, 0)
	raw, err := json.Marshal(v1.Gateway{Pool: "web", SlotID: "eni-a1", Tunnel: v1.TunnelWireGuard})
	if err != nil {
		t.Fatal(err)
	}
	gw := withKey(gatewayPod("a1", true), keyA1)
	gw.Annotations[v1.AnnotationGateway] = string(raw)
	up := cluster()
	up.Gateways[0] = gw
	up.Agents = []corev1.Pod{gw}
	h := &Hold{For: 90 * time.Second}
	h.Apply(up, t0)

	// The terminating pod's key is not used; the held one is.
	old := gw.DeepCopy()
	old.DeletionTimestamp = &metav1.Time{Time: t0}
	s := restarting(nil)
	s.Agents = append(s.Agents, *old)
	h.Apply(s, t0.Add(time.Second))
	d, problems := Compute(s, mustMarks(t))
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	if !slices.Contains(ringGateways(d), a1) {
		t.Fatal("a held WireGuard gateway lost its key")
	}
}
