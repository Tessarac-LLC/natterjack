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
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
)

// Marks gives each gateway a packet mark inside a mask, and keeps it for as
// long as the gateway exists. Established flows carry their gateway's mark in
// conntrack, so a mark must never be reused while flows may still hold it.
type Marks struct {
	mask  uint32
	shift int
	max   uint32
	byIP  map[netip.Addr]uint32
}

// NewMarks returns an allocator for a contiguous mask of at least four bits.
// Other components (kube-proxy, CNIs) own the remaining bits.
func NewMarks(mask uint32) (*Marks, error) {
	shift := bits.TrailingZeros32(mask)
	width := bits.OnesCount32(mask)
	if mask == 0 || mask>>shift != (1<<width)-1 {
		return nil, fmt.Errorf("mark mask %#x must be one contiguous run of bits", mask)
	}
	if width < 4 {
		return nil, fmt.Errorf("mark mask %#x has %d bits; at least 4 are needed", mask, width)
	}
	return &Marks{mask: mask, shift: shift, max: (1 << width) - 1, byIP: map[netip.Addr]uint32{}}, nil
}

// Mask returns the bits the allocator owns.
func (m *Marks) Mask() uint32 { return m.mask }

// Restore adopts marks found in the kernel after a restart, so flows that
// were established before the restart keep their gateway.
func (m *Marks) Restore(existing map[uint32]netip.Addr) {
	for mark, ip := range existing {
		if mark&^m.mask == 0 && mark != 0 {
			m.byIP[ip] = mark
		}
	}
}

// Assign returns the mark of every gateway in want, keeping existing marks
// and releasing those of gateways no longer wanted. Gateways beyond the
// mask's capacity are left out and reported.
func (m *Marks) Assign(want []netip.Addr) (map[uint32]netip.Addr, []netip.Addr) {
	keep := map[netip.Addr]bool{}
	for _, ip := range want {
		keep[ip] = true
	}
	used := map[uint32]bool{}
	for ip, mark := range m.byIP {
		if keep[ip] {
			used[mark] = true
		} else {
			delete(m.byIP, ip)
		}
	}
	sorted := slices.Clone(want)
	slices.SortFunc(sorted, func(a, b netip.Addr) int { return a.Compare(b) })
	var full []netip.Addr
	next := uint32(1)
	for _, ip := range slices.Compact(sorted) {
		if _, ok := m.byIP[ip]; ok {
			continue
		}
		for next <= m.max && used[next<<m.shift] {
			next++
		}
		if next > m.max {
			full = append(full, ip)
			continue
		}
		m.byIP[ip] = next << m.shift
		used[next<<m.shift] = true
	}
	out := make(map[uint32]netip.Addr, len(m.byIP))
	for ip, mark := range m.byIP {
		out[mark] = ip
	}
	return out, full
}
