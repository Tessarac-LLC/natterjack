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

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// Attributes of an IPv4 lightweight tunnel (enum lwtunnel_ip_t).
const (
	lwtIPID  = 1
	lwtIPDst = 2
)

// tunnelEncap is the per-route metadata for the collect-metadata GENEVE
// device: which VNI to use and which node to send to. It is what
// `ip route ... encap ip id VNI dst NODE` sets.
type tunnelEncap struct {
	ID  uint64
	Dst netip.Addr
}

var _ netlink.Encap = (*tunnelEncap)(nil)

func (e *tunnelEncap) Type() int { return nl.LWTUNNEL_ENCAP_IP }

func (e *tunnelEncap) Decode(buf []byte) error {
	attrs, err := nl.ParseRouteAttr(buf)
	if err != nil {
		return fmt.Errorf("decode tunnel encap: %w", err)
	}
	for _, a := range attrs {
		switch a.Attr.Type {
		case lwtIPID:
			if len(a.Value) != 8 {
				return errors.New("decode tunnel encap: bad id length")
			}
			e.ID = binary.BigEndian.Uint64(a.Value)
		case lwtIPDst:
			ip, ok := netip.AddrFromSlice(a.Value)
			if !ok {
				return errors.New("decode tunnel encap: bad destination")
			}
			e.Dst = ip.Unmap()
		}
	}
	return nil
}

func (e *tunnelEncap) Encode() ([]byte, error) {
	if !e.Dst.Is4() {
		return nil, fmt.Errorf("tunnel destination %s is not IPv4", e.Dst)
	}
	id := nl.NewRtAttr(lwtIPID, binary.BigEndian.AppendUint64(nil, e.ID))
	dst := e.Dst.As4()
	return append(id.Serialize(), nl.NewRtAttr(lwtIPDst, dst[:]).Serialize()...), nil
}

func (e *tunnelEncap) String() string { return fmt.Sprintf("ip id %d dst %s", e.ID, e.Dst) }

func (e *tunnelEncap) Equal(x netlink.Encap) bool {
	o, ok := x.(*tunnelEncap)
	return ok && o.ID == e.ID && o.Dst == e.Dst
}
