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

// Package agent computes and applies the data path of one node: steering
// selected traffic to gateways and, on a gateway node, serving a slot.
package agent

import (
	"net/netip"
)

// Buckets is the number of hash buckets per pool. New flows hash into a
// bucket; each bucket names one gateway. A fixed bucket count lets the agent
// change gateways by rewriting map elements, never rules.
const Buckets = 64

// Desired is the complete data path one node should have.
type Desired struct {
	// NodeIP is this node's IPv4 address. Steered flows are translated to it
	// before they enter the tunnel, so replies find their way back.
	NodeIP netip.Addr
	// Nodes are the IPv4 addresses of every node in the cluster: the only
	// sources a gateway accepts tunnel traffic from, and the destinations it
	// returns replies to.
	Nodes []netip.Addr
	// Excluded destinations are never steered.
	Excluded []netip.Prefix
	// Steers select traffic, one per policy that applies to this node.
	Steers []Steer
	// Rings map each pool's buckets to gateway marks. A pool with no live
	// gateway has no ring, and its traffic is left to the node's own routes.
	Rings map[string][Buckets]uint32
	// CrossZone are the pools, sorted, whose rings use other zones'
	// gateways because none in this node's zone is live.
	CrossZone []string
	// Gateways map each mark in use to the gateway's node IP. Marks stay
	// while a gateway drains so its established flows keep working.
	Gateways map[uint32]netip.Addr
	// WireGuard holds the public key of each gateway, by mark, whose pool
	// encrypts its tunnel. Other gateways are reached over GENEVE.
	WireGuard map[uint32]string
	// Failed are the marks of gateways this node's probes see as down. Flows
	// pinned to them are flushed, so their next packet picks a live gateway.
	Failed []uint32
	// Gateway is set when this node serves a slot.
	Gateway *GatewayRole
}

// Steer selects traffic for one pool.
type Steer struct {
	// Name identifies the policy, unique on the node.
	Name string
	// Pool whose gateways carry the traffic.
	Pool string
	// Sources are the IPv4 addresses of selected pods on this node.
	Sources []netip.Addr
	// Node steers the node's own traffic, including host-network pods.
	Node bool
	// Excluded destinations, in addition to Desired.Excluded.
	Excluded []netip.Prefix
}

// GatewayRole is the slot this node serves.
type GatewayRole struct {
	Pool string
	// SlotID is the cloud identifier of the slot, named in the readiness
	// condition.
	SlotID string
	// MAC finds the slot interface when it appears on the node.
	MAC string
	// Address is the slot's private IP with its subnet's prefix length.
	Address netip.Prefix
	// Router is the subnet's router, the slot's next hop to the internet.
	Router netip.Addr
	// Public is the address traffic leaves from, checked by the self-test.
	Public netip.Addr
	// Draining is set when the gateway must stop taking new flows.
	Draining bool
	// WireGuard is set when the pool encrypts its tunnel. The gateway then
	// accepts traffic only over WireGuard, from Peers.
	WireGuard bool
	// Peers are the WireGuard public keys of the cluster's nodes, by node IP.
	// A node's key is accepted only for traffic from that node's address.
	Peers map[netip.Addr]string
}
