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
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

var ip = netip.MustParseAddr

func node(name, zone, addr string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{corev1.LabelTopologyZone: zone}},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: addr}}},
	}
}

// gatewayPod is a gateway of the "web" pool.
func gatewayPod(nodeName string, ready bool) corev1.Pod {
	st := corev1.ConditionFalse
	if ready {
		st = corev1.ConditionTrue
	}
	slot := "eni-" + nodeName
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "agent-" + nodeName,
			Labels:      map[string]string{v1.LabelGateway: "true", v1.LabelPool: "web"},
			Annotations: map[string]string{v1.AnnotationGateway: `{"pool":"web","slotID":"` + slot + `"}`},
		},
		Spec: corev1.PodSpec{NodeName: nodeName},
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			{Type: v1.ConditionGatewayReady, Status: st, Message: v1.GatewayReadyMessage(slot)},
		}},
	}
}

func pod(ns, name, addr string, lbls map[string]string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbls},
		Spec:       corev1.PodSpec{ServiceAccountName: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIPs: []corev1.PodIP{{IP: addr}, {IP: "fd00::1"}}},
	}
}

func cluster() *Snapshot {
	nodes := []corev1.Node{
		node("a1", "zone-a", "10.0.1.10"), node("a2", "zone-a", "10.0.1.11"),
		node("b1", "zone-b", "10.0.2.10"), node("src", "zone-a", "10.0.1.50"),
	}
	return &Snapshot{
		Node: &nodes[3], Nodes: nodes, Excluded: DefaultExcluded,
		Gateways: []corev1.Pod{gatewayPod("a1", true), gatewayPod("a2", true), gatewayPod("b1", true)},
	}
}

func mustMarks(t *testing.T) *Marks {
	t.Helper()
	m, err := NewMarks(0x00ff0000)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// ringGateways are the gateways in the "web" pool's ring.
func ringGateways(d Desired) []netip.Addr {
	var out []netip.Addr
	for _, m := range d.Rings["web"] {
		out = append(out, d.Gateways[m])
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

func TestRingPrefersOwnZone(t *testing.T) {
	d, problems := Compute(cluster(), mustMarks(t))
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	if got := ringGateways(d); !slices.Equal(got, []netip.Addr{ip("10.0.1.10"), ip("10.0.1.11")}) {
		t.Fatalf("ring uses %v; want only zone-a gateways", got)
	}
	if len(d.Gateways) != 3 {
		t.Fatalf("every gateway needs a mark so its flows survive: %v", d.Gateways)
	}
	if d.NodeIP != ip("10.0.1.50") || len(d.Nodes) != 4 {
		t.Fatalf("node %v nodes %v", d.NodeIP, d.Nodes)
	}
	if len(d.CrossZone) != 0 {
		t.Fatalf("cross-zone pools %v with live gateways in the zone", d.CrossZone)
	}
}

func TestRingFallsBackAcrossZones(t *testing.T) {
	s := cluster()
	s.Down = map[netip.Addr]bool{ip("10.0.1.10"): true}
	s.Gateways[1].Annotations[v1.AnnotationDrainStarted] = "2026-11-14T00:00:00Z"
	d, _ := Compute(s, mustMarks(t))
	if got := ringGateways(d); !slices.Equal(got, []netip.Addr{ip("10.0.2.10")}) {
		t.Fatalf("ring uses %v; want the other zone when this zone has no live gateway", got)
	}
	if want := slices.Collect(maps.Keys(d.Rings)); !slices.Equal(d.CrossZone, want) {
		t.Fatalf("cross-zone pools %v, want %v", d.CrossZone, want)
	}
	if len(d.Gateways) != 3 {
		t.Fatal("down and draining gateways keep their marks")
	}
	if len(d.Failed) != 1 || d.Gateways[d.Failed[0]] != ip("10.0.1.10") {
		t.Fatalf("failed marks %v; want only the down gateway's, not the draining one's", d.Failed)
	}
}

// A terminated instance can lose its slot while it still answers probes for
// the rest of its shutdown; its kubelet says so first.
func TestGatewayOnAShuttingDownNodeTakesNoNewFlows(t *testing.T) {
	s := cluster()
	ready := func(status corev1.ConditionStatus, msg string) []corev1.NodeCondition {
		return []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status, Reason: "KubeletNotReady", Message: msg}}
	}
	s.Nodes[0].Status.Conditions = ready(corev1.ConditionFalse, "node is shutting down")
	d, problems := Compute(s, mustMarks(t))
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	if got := ringGateways(d); !slices.Equal(got, []netip.Addr{ip("10.0.1.11")}) {
		t.Fatalf("ring uses %v; a gateway whose node is shutting down must take no new flows", got)
	}
	if len(d.Gateways) != 3 || len(d.Failed) != 0 {
		t.Fatalf("marks %v failed %v; the gateway keeps its mark and its flows are not flushed", d.Gateways, d.Failed)
	}
	// Any other reason for NotReady, such as a kubelet that lost the API
	// server, says nothing about the slot: the probes decide.
	for _, c := range [][]corev1.NodeCondition{
		ready(corev1.ConditionUnknown, "Kubelet stopped posting node status."),
		ready(corev1.ConditionFalse, "container runtime network not ready"),
		ready(corev1.ConditionTrue, "kubelet is posting ready status"),
	} {
		s.Nodes[0].Status.Conditions = c
		d, _ = Compute(s, mustMarks(t))
		if got := ringGateways(d); !slices.Equal(got, []netip.Addr{ip("10.0.1.10"), ip("10.0.1.11")}) {
			t.Fatalf("Ready %s %q: ring uses %v", c[0].Status, c[0].Message, got)
		}
	}
}

func TestNoLiveGatewayMeansNoRing(t *testing.T) {
	s := cluster()
	for i := range s.Gateways {
		s.Gateways[i].Status.Conditions[1].Status = corev1.ConditionFalse
	}
	// A condition left from the agent's previous slot vouches for nothing.
	s.Gateways[0].Status.Conditions[1] = corev1.PodCondition{Type: v1.ConditionGatewayReady, Status: corev1.ConditionTrue, Message: v1.GatewayReadyMessage("eni-old")}
	d, _ := Compute(s, mustMarks(t))
	if _, ok := d.Rings["web"]; ok {
		t.Fatal("a pool with no ready gateway must have no ring")
	}
}

func TestMarksAreStable(t *testing.T) {
	m := mustMarks(t)
	s := cluster()
	d1, _ := Compute(s, m)
	s.Gateways = s.Gateways[1:]
	d2, _ := Compute(s, m)
	for mark, addr := range d2.Gateways {
		if d1.Gateways[mark] != addr {
			t.Fatalf("mark %#x moved from %v to %v", mark, d1.Gateways[mark], addr)
		}
	}
	if len(d2.Gateways) != 2 {
		t.Fatal("a removed gateway must release its mark")
	}
}

func TestMarksRestoreAndCapacity(t *testing.T) {
	m, err := NewMarks(0x000f0000)
	if err != nil {
		t.Fatal(err)
	}
	m.Restore(map[uint32]netip.Addr{0x00070000: ip("10.0.0.7"), 0x01000000: ip("10.0.0.8")})
	var want []netip.Addr
	for i := range 20 {
		want = append(want, netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
	}
	got, full := m.Assign(want)
	if got[0x00070000] != ip("10.0.0.7") {
		t.Fatal("a restored mark must be kept")
	}
	if len(got) != 15 || len(full) != 5 {
		t.Fatalf("a 4-bit mask holds 15 gateways: got %d, %d left out", len(got), len(full))
	}
	for mark := range got {
		if mark&^0x000f0000 != 0 || mark == 0 {
			t.Fatalf("mark %#x outside the mask", mark)
		}
	}
}

func TestNewMarksRejectsBadMasks(t *testing.T) {
	for _, mask := range []uint32{0, 0x0f0f0000, 0x00070000} {
		if _, err := NewMarks(mask); err == nil {
			t.Errorf("mask %#x accepted", mask)
		}
	}
}

func TestRingIsEvenAndMovesLittle(t *testing.T) {
	g := map[netip.Addr]uint32{ip("10.0.0.1"): 1, ip("10.0.0.2"): 2, ip("10.0.0.3"): 3, ip("10.0.0.4"): 4}
	r1 := Ring(g)
	count := map[uint32]int{}
	for _, m := range r1 {
		count[m]++
	}
	for m, c := range count {
		if c < 6 || c > 26 {
			t.Errorf("gateway %d holds %d of %d buckets", m, c, Buckets)
		}
	}
	delete(g, ip("10.0.0.4"))
	r2 := Ring(g)
	for b := range r1 {
		if r1[b] != 4 && r1[b] != r2[b] {
			t.Fatalf("bucket %d moved from %d to %d though its gateway stayed", b, r1[b], r2[b])
		}
	}
}

func TestPolicySelection(t *testing.T) {
	s := cluster()
	s.Namespaces = []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "shop", Labels: map[string]string{"egress": "yes"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "batch"}},
	}
	s.Pods = []corev1.Pod{
		pod("shop", "web", "192.168.0.1", map[string]string{"app": "web"}),
		pod("shop", "db", "192.168.0.2", map[string]string{"app": "db"}),
		pod("batch", "job", "192.168.0.3", nil),
	}
	hostNet := pod("shop", "host", "10.0.1.50", map[string]string{"app": "web"})
	hostNet.Spec.HostNetwork = true
	done := pod("shop", "done", "192.168.0.4", map[string]string{"app": "web"})
	done.Status.Phase = corev1.PodSucceeded
	other := pod("shop", "robot", "192.168.0.5", map[string]string{"app": "web"})
	other.Spec.ServiceAccountName = "robot"
	s.Pods = append(s.Pods, hostNet, done, other)
	s.Policies = []v1.EgressPolicy{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"},
		Spec: v1.EgressPolicySpec{
			PoolName: "web", PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			ServiceAccountNames: []string{"default"}, ExcludedCIDRs: []string{"198.51.100.0/24"},
		},
	}}
	s.ClusterPolicies = []v1.ClusterEgressPolicy{
		{ObjectMeta: metav1.ObjectMeta{Name: "labeled"}, Spec: v1.ClusterEgressPolicySpec{PoolName: "web", NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"egress": "yes"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "nodes"}, Spec: v1.ClusterEgressPolicySpec{PoolName: "web", NodeTraffic: true}},
	}
	d, problems := Compute(s, mustMarks(t))
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	got := map[string]Steer{}
	for _, st := range d.Steers {
		got[st.Name] = st
	}
	if src := got["ns/shop/web"].Sources; !slices.Equal(src, []netip.Addr{ip("192.168.0.1")}) {
		t.Errorf("EgressPolicy selects %v; want only the running, non-host-network web pod running as default", src)
	}
	if ex := got["ns/shop/web"].Excluded; len(ex) != 1 || ex[0].String() != "198.51.100.0/24" {
		t.Errorf("excluded %v", ex)
	}
	if src := got["cluster/labeled"].Sources; len(src) != 3 {
		t.Errorf("ClusterEgressPolicy selects %v; want every live pod in labeled namespaces", src)
	}
	if st := got["cluster/nodes"]; !st.Node || len(st.Sources) != 0 {
		t.Errorf("an unset namespace selector selects no pods, only node traffic: %+v", st)
	}
}

func gatewayAnnotation(t *testing.T, g v1.Gateway) string {
	t.Helper()
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestGatewayRole(t *testing.T) {
	s := cluster()
	self := gatewayPod("src", false)
	self.Annotations = map[string]string{v1.AnnotationGateway: gatewayAnnotation(t, v1.Gateway{
		Pool: "web", SlotID: "eni-1", MAC: "02:AA:00:00:00:01", PrivateIP: "10.0.9.20", SubnetCIDR: "10.0.9.0/24", PublicIP: "203.0.113.9",
		RoutedSources: []string{"10.0.0.0/16", "100.64.0.0/16"},
	})}
	s.Self = &self
	d, problems := Compute(s, mustMarks(t))
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	want := GatewayRole{
		Pool: "web", SlotID: "eni-1", MAC: "02:aa:00:00:00:01", Address: netip.MustParsePrefix("10.0.9.20/24"), Router: ip("10.0.9.1"), Public: ip("203.0.113.9"),
		Routed: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("100.64.0.0/16")},
	}
	if d.Gateway == nil || !reflect.DeepEqual(*d.Gateway, want) {
		t.Fatalf("role %+v", d.Gateway)
	}

	// A routed source the agent cannot read would otherwise be dropped from
	// the set silently; refusing the role keeps the old ruleset in place.
	for _, bad := range []string{"10.0.0.0", "2001:db8::/32", "10.0.0.0/33"} {
		self.Annotations[v1.AnnotationGateway] = gatewayAnnotation(t, v1.Gateway{
			Pool: "web", SlotID: "eni-1", PrivateIP: "10.0.9.20", SubnetCIDR: "10.0.9.0/24", PublicIP: "203.0.113.9", RoutedSources: []string{bad},
		})
		d, problems = Compute(s, mustMarks(t))
		if d.Gateway != nil || len(problems) != 1 || !strings.Contains(problems[0], "invalid routed source") {
			t.Fatalf("routed source %q: role %+v problems %v", bad, d.Gateway, problems)
		}
	}

	self.Annotations[v1.AnnotationGateway] = gatewayAnnotation(t, v1.Gateway{Pool: "web", SlotID: "eni-1", PrivateIP: "10.0.8.20", SubnetCIDR: "10.0.9.0/24", PublicIP: "203.0.113.9"})
	d, problems = Compute(s, mustMarks(t))
	if d.Gateway != nil || len(problems) != 1 || !strings.Contains(problems[0], "inconsistent") {
		t.Fatalf("an address outside its subnet must be refused: %+v %v", d.Gateway, problems)
	}

	delete(self.Labels, v1.LabelGateway)
	if d, _ = Compute(s, mustMarks(t)); d.Gateway != nil {
		t.Fatal("without the gateway label the node is not a gateway")
	}
}

// withKey publishes a WireGuard key on an agent pod.
func withKey(p corev1.Pod, key string) corev1.Pod {
	p.Status.Conditions = append(p.Status.Conditions, corev1.PodCondition{Type: v1.ConditionWireGuardKey, Status: corev1.ConditionTrue, Message: key})
	return p
}

const (
	keyA1  = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	keyA2  = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	keySrc = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
)

func TestWireGuardGateways(t *testing.T) {
	s := cluster()
	for i := range s.Gateways[:2] {
		s.Gateways[i].Annotations[v1.AnnotationGateway] = `{"pool":"web","slotID":"eni-` + s.Gateways[i].Spec.NodeName + `","tunnel":"WireGuard"}`
	}
	// a1 has published its key; a2 has not yet.
	s.Agents = []corev1.Pod{withKey(s.Gateways[0], keyA1), s.Gateways[1], s.Gateways[2], withKey(pod("", "agent-src", "", nil), keySrc)}
	s.Agents[3].Spec.NodeName = "src"
	d, problems := Compute(s, mustMarks(t))
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	if got := ringGateways(d); !slices.Equal(got, []netip.Addr{ip("10.0.1.10")}) {
		t.Fatalf("ring uses %v; a WireGuard gateway without a key cannot take flows", got)
	}
	keys := map[netip.Addr]string{}
	for m, k := range d.WireGuard {
		keys[d.Gateways[m]] = k
	}
	want := map[netip.Addr]string{ip("10.0.1.10"): keyA1, ip("10.0.1.11"): ""}
	if len(keys) != len(want) || keys[ip("10.0.1.10")] != keyA1 || keys[ip("10.0.1.11")] != "" {
		t.Fatalf("WireGuard gateways %v, want %v; the GENEVE gateway b1 must not appear", keys, want)
	}
	if _, ok := keys[ip("10.0.1.11")]; !ok {
		t.Fatal("a WireGuard gateway without a key must still be marked as WireGuard, or it would be reached unencrypted")
	}
}

func TestWireGuardGatewayPeers(t *testing.T) {
	s := cluster()
	self := gatewayPod("a1", true)
	self.Annotations[v1.AnnotationGateway] = `{"pool":"web","slotID":"eni-a1","mac":"02:00:00:00:00:01","privateIP":"10.0.9.10",` +
		`"subnetCIDR":"10.0.9.0/24","publicIP":"198.51.100.7","tunnel":"WireGuard"}`
	s.Node, s.Self = &s.Nodes[0], &self
	src := withKey(pod("", "agent-src", "", nil), keySrc)
	src.Spec.NodeName = "src"
	gone := withKey(pod("", "agent-a2", "", nil), keyA2)
	gone.Spec.NodeName = "a2"
	gone.DeletionTimestamp = &metav1.Time{}
	bad := withKey(pod("", "agent-b1", "", nil), "not-a-key")
	bad.Spec.NodeName = "b1"
	s.Agents = []corev1.Pod{withKey(self, keyA1), src, gone, bad}
	d, problems := Compute(s, mustMarks(t))
	if d.Gateway == nil || !d.Gateway.WireGuard {
		t.Fatalf("gateway role %+v; want WireGuard", d.Gateway)
	}
	want := map[netip.Addr]string{ip("10.0.1.50"): keySrc}
	if len(d.Gateway.Peers) != 1 || d.Gateway.Peers[ip("10.0.1.50")] != keySrc {
		t.Fatalf("peers %v, want %v: not itself, not a terminating agent, not an invalid key", d.Gateway.Peers, want)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "agent-b1 publishes an invalid WireGuard key") {
		t.Fatalf("problems %q", problems)
	}
}
