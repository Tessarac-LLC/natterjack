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
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

// FuzzParseProbe feeds arbitrary datagrams to the probe parser, which reads
// whatever arrives on the probe socket. It must never panic, must accept
// only what probePacket builds, and must read back the sequence number.
func FuzzParseProbe(f *testing.F) {
	ok := probePacket(42)
	f.Add(ok[:], uint64(42))
	f.Add([]byte{}, uint64(0))
	f.Add([]byte("NJP1"), uint64(1))
	f.Add(append(ok[:], 0), uint64(7))
	f.Fuzz(func(t *testing.T, b []byte, seq uint64) {
		if got, ok := parseProbe(b); ok {
			p := probePacket(got)
			if !bytes.Equal(p[:], b) {
				t.Fatalf("parseProbe accepted %x, which probePacket(%d) does not build", b, got)
			}
		}
		p := probePacket(seq)
		got, ok := parseProbe(p[:])
		if !ok || got != seq {
			t.Fatalf("parseProbe(probePacket(%d)) = %d, %v", seq, got, ok)
		}
	})
}

// FuzzGatewayRole feeds arbitrary gateway annotations, which the controller
// writes but anyone able to edit the pod could change, to the agent. A role
// it accepts must be one the data plane can program.
func FuzzGatewayRole(f *testing.F) {
	good, err := json.Marshal(v1.Gateway{
		Pool: "p", SlotID: "eni-1", MAC: "0A:00:00:00:00:01", PrivateIP: "10.0.1.10",
		SubnetCIDR: "10.0.1.0/24", PublicIP: "203.0.113.7", Tunnel: v1.TunnelWireGuard,
		RoutedSources: []string{"10.0.0.0/16", "10.1.2.3/8"},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(good))
	f.Add(`{"privateIP":"10.0.0.1","subnetCIDR":"10.0.0.0/31","publicIP":"1.1.1.1"}`)
	f.Add(`{"privateIP":"::1","subnetCIDR":"::/64","publicIP":"::2"}`)
	f.Add(`{"privateIP":"10.0.0.5","subnetCIDR":"10.0.0.0/30","publicIP":"1.1.1.1","routedSources":["::/0"]}`)
	f.Add(`not json`)
	f.Fuzz(func(t *testing.T, raw string) {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Labels:      map[string]string{v1.LabelGateway: "true"},
			Annotations: map[string]string{v1.AnnotationGateway: raw},
		}}
		r, err := gatewayRole(p)
		if err != nil || r == nil {
			return
		}
		subnet := r.Address.Masked()
		if !r.Address.Addr().Is4() || r.Address.Bits() > 30 {
			t.Fatalf("accepted address %s", r.Address)
		}
		if !subnet.Contains(r.Router) {
			t.Fatalf("router %s is not a host of %s", r.Router, subnet)
		}
		if r.Router == subnet.Addr() {
			t.Fatalf("router %s is the network address of %s", r.Router, subnet)
		}
		if !r.Public.IsValid() {
			t.Fatalf("accepted invalid public address")
		}
		for _, s := range r.Routed {
			if !s.Addr().Is4() || s != s.Masked() {
				t.Fatalf("accepted routed source %s", s)
			}
		}
	})
}

// FuzzRing checks the rendezvous properties the data plane relies on: every
// node computes the same ring, every bucket goes to a live gateway, and
// removing a gateway moves only the buckets it held.
func FuzzRing(f *testing.F) {
	f.Add([]byte{10, 0, 1, 10, 10, 0, 2, 10, 10, 0, 3, 10}, uint8(1))
	f.Add([]byte{192, 168, 0, 1}, uint8(0))
	f.Fuzz(func(t *testing.T, addrs []byte, drop uint8) {
		gws := map[netip.Addr]uint32{}
		for i := 0; i+4 <= len(addrs) && len(gws) < 32; i += 4 {
			gws[netip.AddrFrom4([4]byte(addrs[i:i+4]))] = uint32(len(gws) + 1) //nolint:gosec // < 33
		}
		ring := Ring(gws)
		if ring != Ring(gws) {
			t.Fatal("ring is not deterministic")
		}
		marks := map[uint32]netip.Addr{}
		for ip, m := range gws {
			marks[m] = ip
		}
		for b, m := range ring {
			if len(gws) == 0 {
				if m != 0 {
					t.Fatalf("bucket %d has mark %d with no gateways", b, m)
				}
				continue
			}
			if _, ok := marks[m]; !ok {
				t.Fatalf("bucket %d has mark %d, which no gateway carries", b, m)
			}
		}
		if len(gws) < 2 {
			return
		}
		gone := uint32(int(drop)%len(gws) + 1) //nolint:gosec // <= 32
		rest := map[netip.Addr]uint32{}
		for ip, m := range gws {
			if m != gone {
				rest[ip] = m
			}
		}
		after := Ring(rest)
		for b := range ring {
			if ring[b] != gone && after[b] != ring[b] {
				t.Fatalf("removing mark %d moved bucket %d from %d to %d", gone, b, ring[b], after[b])
			}
			if after[b] == gone {
				t.Fatalf("bucket %d still on removed mark %d", b, gone)
			}
		}
	})
}
