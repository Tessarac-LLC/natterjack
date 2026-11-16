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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

// DefaultExcluded are destinations never steered: private, shared, loopback,
// link-local (instance metadata, pod identity), multicast and reserved
// ranges. Cluster and VPC addresses fall inside them on every supported
// cloud; a VPC that uses public ranges adds them with --excluded-cidrs.
var DefaultExcluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// Snapshot is what the agent knows about the cluster.
type Snapshot struct {
	// Node is this node.
	Node *corev1.Node
	// Self is this agent's pod.
	Self *corev1.Pod
	// Nodes are all nodes.
	Nodes []corev1.Node
	// Pods are the pods on this node.
	Pods []corev1.Pod
	// Namespaces with their labels, for ClusterEgressPolicy.
	Namespaces []corev1.Namespace
	// Gateways are the agent pods labeled as gateways.
	Gateways []corev1.Pod
	// Agents are every agent pod, for the WireGuard keys of their nodes.
	Agents          []corev1.Pod
	Policies        []v1.EgressPolicy
	ClusterPolicies []v1.ClusterEgressPolicy
	// Excluded destinations for every policy.
	Excluded []netip.Prefix
	// Down are gateways this node's probes see as down.
	Down map[netip.Addr]bool
}

// Compute derives the node's data path. Problems are reported, not fatal:
// the rest of the data path is still built.
func Compute(s *Snapshot, marks *Marks) (Desired, []string) {
	var problems []string
	d := Desired{Excluded: s.Excluded, Rings: map[string][Buckets]uint32{}}

	ipOf := map[string]netip.Addr{}
	zoneOf := map[string]string{}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if ip, ok := NodeIP(n); ok {
			ipOf[n.Name] = ip
			d.Nodes = append(d.Nodes, ip)
		}
		zoneOf[n.Name] = n.Labels[corev1.LabelTopologyZone]
	}
	slices.SortFunc(d.Nodes, func(a, b netip.Addr) int { return a.Compare(b) })
	d.Nodes = slices.Compact(d.Nodes)
	if ip, ok := NodeIP(s.Node); ok {
		d.NodeIP = ip
	} else {
		problems = append(problems, fmt.Sprintf("node %s has no IPv4 InternalIP; it cannot steer traffic or serve as a gateway", s.Node.Name))
	}

	keyOf := map[netip.Addr]string{}
	for i := range s.Agents {
		p := &s.Agents[i]
		ip, ok := ipOf[p.Spec.NodeName]
		key := v1.WireGuardKey(p)
		if !ok || key == "" || p.DeletionTimestamp != nil {
			continue
		}
		if !ValidWireGuardKey(key) {
			problems = append(problems, fmt.Sprintf("agent pod %s publishes an invalid WireGuard key", p.Name))
			continue
		}
		keyOf[ip] = key
	}

	if s.Self != nil {
		role, err := gatewayRole(s.Self)
		if err != nil {
			problems = append(problems, err.Error())
		}
		if role != nil && role.WireGuard {
			role.Peers = map[netip.Addr]string{}
			for ip, k := range keyOf {
				if ip != d.NodeIP {
					role.Peers[ip] = k
				}
			}
		}
		d.Gateway = role
	}

	// Gateways: every one gets a mark while it exists; live ones, preferring
	// this node's zone, fill the pool's ring.
	type gw struct {
		ip    netip.Addr
		zone  string
		ready bool
	}
	byPool := map[string][]gw{}
	var all []netip.Addr
	// WireGuard gateways, with their keys; "" until a gateway publishes one.
	wg := map[netip.Addr]string{}
	for i := range s.Gateways {
		p := &s.Gateways[i]
		ip, ok := ipOf[p.Spec.NodeName]
		pool := p.Labels[v1.LabelPool]
		if !ok || pool == "" || p.DeletionTimestamp != nil {
			continue
		}
		all = append(all, ip)
		// A gateway takes new flows once its agent says its slot carries
		// traffic, until it drains or this node's probes lose it.
		var g v1.Gateway
		ready := json.Unmarshal([]byte(p.Annotations[v1.AnnotationGateway]), &g) == nil &&
			v1.GatewayReady(p, g.SlotID) && p.Annotations[v1.AnnotationDrainStarted] == "" && !s.Down[ip]
		if g.Tunnel == v1.TunnelWireGuard {
			// Without the gateway's key there is no tunnel to it.
			wg[ip] = keyOf[ip]
			ready = ready && keyOf[ip] != ""
		}
		byPool[pool] = append(byPool[pool], gw{ip: ip, zone: zoneOf[p.Spec.NodeName], ready: ready})
	}
	gateways, full := marks.Assign(all)
	for _, ip := range full {
		problems = append(problems, fmt.Sprintf("gateway %s has no free packet mark; widen --mark-mask", ip))
	}
	d.Gateways = gateways
	markOf := map[netip.Addr]uint32{}
	for m, ip := range gateways {
		markOf[ip] = m
		if k, ok := wg[ip]; ok {
			if d.WireGuard == nil {
				d.WireGuard = map[uint32]string{}
			}
			d.WireGuard[m] = k
		}
		if s.Down[ip] {
			d.Failed = append(d.Failed, m)
		}
	}
	slices.Sort(d.Failed)
	myZone := zoneOf[s.Node.Name]
	for pool, gws := range byPool {
		local, anyZone := map[netip.Addr]uint32{}, map[netip.Addr]uint32{}
		for _, g := range gws {
			m, ok := markOf[g.ip]
			if !g.ready || !ok {
				continue
			}
			anyZone[g.ip] = m
			if g.zone == myZone {
				local[g.ip] = m
			}
		}
		switch {
		case len(local) > 0:
			d.Rings[pool] = Ring(local)
		case len(anyZone) > 0:
			d.Rings[pool] = Ring(anyZone)
			d.CrossZone = append(d.CrossZone, pool)
		}
	}
	slices.Sort(d.CrossZone)

	d.Steers, problems = steers(s, problems)
	return d, problems
}

func steers(s *Snapshot, problems []string) ([]Steer, []string) {
	nsLabels := map[string]labels.Set{}
	for i := range s.Namespaces {
		nsLabels[s.Namespaces[i].Name] = s.Namespaces[i].Labels
	}
	var pods []*corev1.Pod
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Spec.HostNetwork || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		pods = append(pods, p)
	}

	var out []Steer
	for i := range s.Policies {
		pol := &s.Policies[i]
		sel, err := selector(pol.Spec.PodSelector, true)
		if err != nil {
			problems = append(problems, fmt.Sprintf("EgressPolicy %s/%s: %v", pol.Namespace, pol.Name, err))
			continue
		}
		st := Steer{Name: "ns/" + pol.Namespace + "/" + pol.Name, Pool: pol.Spec.PoolName, Excluded: prefixes(pol.Spec.ExcludedCIDRs)}
		for _, p := range pods {
			if p.Namespace != pol.Namespace || !sel.Matches(labels.Set(p.Labels)) {
				continue
			}
			if len(pol.Spec.ServiceAccountNames) > 0 && !slices.Contains(pol.Spec.ServiceAccountNames, p.Spec.ServiceAccountName) {
				continue
			}
			st.Sources = append(st.Sources, podIPs(p)...)
		}
		out = append(out, st)
	}
	for i := range s.ClusterPolicies {
		pol := &s.ClusterPolicies[i]
		st := Steer{Name: "cluster/" + pol.Name, Pool: pol.Spec.PoolName, Node: pol.Spec.NodeTraffic, Excluded: prefixes(pol.Spec.ExcludedCIDRs)}
		if pol.Spec.NamespaceSelector != nil {
			nsSel, err := selector(pol.Spec.NamespaceSelector, true)
			if err == nil {
				var podSel labels.Selector
				podSel, err = selector(pol.Spec.PodSelector, true)
				for _, p := range pods {
					if err == nil && nsSel.Matches(nsLabels[p.Namespace]) && podSel.Matches(labels.Set(p.Labels)) {
						st.Sources = append(st.Sources, podIPs(p)...)
					}
				}
			}
			if err != nil {
				problems = append(problems, fmt.Sprintf("ClusterEgressPolicy %s: %v", pol.Name, err))
				continue
			}
		}
		out = append(out, st)
	}
	for i := range out {
		slices.SortFunc(out[i].Sources, func(a, b netip.Addr) int { return a.Compare(b) })
		out[i].Sources = slices.Compact(out[i].Sources)
	}
	slices.SortFunc(out, func(a, b Steer) int { return strings.Compare(a.Name, b.Name) })
	return out, problems
}

// selector converts a label selector; nil selects everything when
// nilMatchesAll is set.
func selector(ls *metav1.LabelSelector, nilMatchesAll bool) (labels.Selector, error) {
	if ls == nil {
		if nilMatchesAll {
			return labels.Everything(), nil
		}
		return labels.Nothing(), nil
	}
	sel, err := metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return nil, fmt.Errorf("invalid selector: %w", err)
	}
	return sel, nil
}

func gatewayRole(p *corev1.Pod) (*GatewayRole, error) {
	raw := p.Annotations[v1.AnnotationGateway]
	if raw == "" || p.Labels[v1.LabelGateway] != "true" {
		return nil, nil
	}
	var g v1.Gateway
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		return nil, fmt.Errorf("gateway annotation is not valid JSON: %w", err)
	}
	priv, err1 := netip.ParseAddr(g.PrivateIP)
	subnet, err2 := netip.ParsePrefix(g.SubnetCIDR)
	pub, err3 := netip.ParseAddr(g.PublicIP)
	if err1 != nil || err2 != nil || err3 != nil || !priv.Is4() || !subnet.Contains(priv) || subnet.Bits() > 30 {
		return nil, fmt.Errorf("gateway assignment for %s is incomplete or inconsistent: private %q, subnet %q, public %q", g.SlotID, g.PrivateIP, g.SubnetCIDR, g.PublicIP)
	}
	var routed []netip.Prefix
	for _, s := range g.RoutedSources {
		r, err := netip.ParsePrefix(s)
		if err != nil || !r.Addr().Is4() {
			return nil, fmt.Errorf("gateway assignment for %s has an invalid routed source %q", g.SlotID, s)
		}
		routed = append(routed, r.Masked())
	}
	// Every supported cloud puts the subnet router at the first host
	// address.
	router := subnet.Masked().Addr().Next()
	return &GatewayRole{
		Pool: g.Pool, SlotID: g.SlotID, MAC: strings.ToLower(g.MAC), Address: netip.PrefixFrom(priv, subnet.Bits()),
		Router: router, Public: pub, Routed: routed, Draining: p.Annotations[v1.AnnotationDrainStarted] != "",
		WireGuard: g.Tunnel == v1.TunnelWireGuard,
	}, nil
}

// ValidWireGuardKey reports whether key is a base64 Curve25519 public key,
// as wg(8) prints it.
func ValidWireGuardKey(key string) bool {
	b, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(b) == 32
}

// NodeIP is the node's IPv4 InternalIP.
func NodeIP(n *corev1.Node) (netip.Addr, bool) {
	for _, a := range n.Status.Addresses {
		if a.Type != corev1.NodeInternalIP {
			continue
		}
		if ip, err := netip.ParseAddr(a.Address); err == nil && ip.Is4() {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func podIPs(p *corev1.Pod) []netip.Addr {
	var out []netip.Addr
	for _, a := range p.Status.PodIPs {
		if ip, err := netip.ParseAddr(a.IP); err == nil && ip.Is4() {
			out = append(out, ip)
		}
	}
	return out
}

func prefixes(in []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}
