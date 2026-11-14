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
	"encoding/binary"
	"hash/fnv"
	"net/netip"
)

// Ring spreads the buckets over gateways by rendezvous hashing: each bucket
// goes to the gateway with the highest score for it. Adding or removing a
// gateway moves only the buckets that gateway wins or held, so the share of
// new flows on the other gateways is undisturbed.
func Ring(gateways map[netip.Addr]uint32) [Buckets]uint32 {
	var ring [Buckets]uint32
	for b := range Buckets {
		var best uint64
		var bestIP netip.Addr
		for ip, mark := range gateways {
			s := score(b, ip)
			// Ties, astronomically rare, go to the lower address so every
			// node computes the same ring.
			if ring[b] == 0 || s > best || (s == best && ip.Less(bestIP)) {
				ring[b], best, bestIP = mark, s, ip
			}
		}
	}
	return ring
}

func score(bucket int, ip netip.Addr) uint64 {
	h := fnv.New64a()
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(bucket)) //nolint:gosec // bucket < Buckets
	_, _ = h.Write(b[:])
	a := ip.As16()
	_, _ = h.Write(a[:])
	// FNV alone mixes inputs that differ in their last bytes poorly; the
	// splitmix64 finalizer spreads them.
	z := h.Sum64()
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}
