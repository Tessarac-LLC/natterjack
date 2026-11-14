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

// Package dataplane programs a node's kernel from an agent.Desired: the
// tunnel device, nftables, policy routing and, on a gateway, the isolated
// gateway network namespace. No packet passes through Go.
package dataplane

import (
	"fmt"
	"math/bits"
	"net/netip"
)

// Names of the kernel objects the agent owns. Everything else on the node is
// left alone.
const (
	// TableName is the nftables table, in the host and gateway namespaces.
	TableName = "natterjack"
	// TunnelLink is the GENEVE device in the host namespace.
	TunnelLink = "nj0"
	// VethHost is the host end of the link into the gateway namespace.
	VethHost = "njgw-h"
	// VethGateway is the gateway namespace end of that link.
	VethGateway = "njgw"
	// EgressLink is the slot interface once inside the gateway namespace.
	EgressLink = "egress0"
	// VNI is the GENEVE virtual network identifier on every tunnel packet.
	VNI = 0x4e4a
)

// Config sets what the agent may use on the node.
type Config struct {
	// MarkMask is the packet mark bits the agent owns.
	MarkMask uint32
	// TableBase is the first routing table ID the agent owns; it uses
	// TableBase .. TableBase+2+(MarkMask>>shift).
	TableBase int
	// RulePriority is the priority of the agent's policy routing rules. It
	// must sort after the local table (0) and before main (32766).
	RulePriority int
	// TunnelPort is the GENEVE UDP port.
	TunnelPort uint16
	// Link is the /30 between the host and gateway namespaces.
	Link netip.Prefix
	// ProbePort is where the gateway answers liveness probes.
	ProbePort uint16
	// StateDir holds the gateway namespace mount and the mark table. It must
	// survive agent restarts and be emptied by a node reboot (a tmpfs under
	// /run), like conntrack.
	StateDir string
	// MSS is the TCP MSS ceiling for flows leaving the slot. Internet paths
	// carry 1500 byte packets even when the VPC carries jumbo frames.
	MSS uint16
}

// DefaultConfig works with the AWS VPC CNI, kube-proxy, Calico and Cilium
// defaults.
func DefaultConfig() Config {
	return Config{
		MarkMask: 0x00ff0000, TableBase: 7700, RulePriority: 7700, TunnelPort: 6081,
		Link: netip.MustParsePrefix("169.254.73.0/30"), ProbePort: 6086,
		StateDir: "/run/natterjack", MSS: 1460,
	}
}

// Validate reports a configuration the data path cannot use.
func (c Config) Validate() error {
	if c.RulePriority <= 0 || c.RulePriority+2 >= 32766 {
		return fmt.Errorf("rule priority %d must be between 1 and 32763", c.RulePriority)
	}
	if c.MarkMask == 0 {
		return fmt.Errorf("mark mask must not be empty")
	}
	if last := c.TableBase + 16 + int(c.MarkMask>>bits.TrailingZeros32(c.MarkMask)); c.TableBase < 256 || last > 1<<30 {
		return fmt.Errorf("routing tables %d-%d must not overlap the kernel's (0-255)", c.TableBase, last)
	}
	if !c.Link.Addr().Is4() || c.Link.Bits() != 30 || !c.Link.Addr().IsLinkLocalUnicast() {
		return fmt.Errorf("gateway link %s must be an IPv4 link-local /30", c.Link)
	}
	if c.Link.Masked() != c.Link {
		return fmt.Errorf("gateway link %s must be the network address of its /30", c.Link)
	}
	if !c.TunnelAddr().IsLinkLocalUnicast() {
		return fmt.Errorf("gateway link %s leaves no link-local address after it for the tunnel device", c.Link)
	}
	if c.TunnelPort == 0 || c.ProbePort == 0 || c.StateDir == "" || c.MSS < 536 {
		return fmt.Errorf("tunnel port, probe port, state directory and an MSS of at least 536 are required")
	}
	return nil
}

// TunnelAddr is the address of the tunnel device, the one after the gateway
// link. Nothing sends from it; reverse path filtering drops packets arriving
// on an interface without an IPv4 address.
func (c Config) TunnelAddr() netip.Addr {
	a := c.Link.Addr()
	for range 4 {
		a = a.Next()
	}
	return a
}

// HostAddr is the host end of the gateway link.
func (c Config) HostAddr() netip.Addr { return c.Link.Addr().Next() }

// GatewayAddr is the gateway namespace end, where probes are answered.
func (c Config) GatewayAddr() netip.Addr { return c.Link.Addr().Next().Next() }

// Status is what Apply found on a gateway node.
type Status struct {
	// Serving is true once the slot is in the gateway namespace with its
	// address, routes and rules.
	Serving bool
	// Reason says why the gateway is not serving.
	Reason string
}
