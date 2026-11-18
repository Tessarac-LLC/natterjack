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
	"net/netip"
	"testing"
)

// FuzzTunnelEncap decodes arbitrary route attributes, as the kernel returns
// them when routes are listed, and checks that encoding round-trips.
func FuzzTunnelEncap(f *testing.F) {
	good, err := (&tunnelEncap{ID: 7, Dst: netip.MustParseAddr("10.0.1.10")}).Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good, uint64(7), []byte{10, 0, 1, 10})
	f.Add([]byte{}, uint64(0), []byte{0, 0, 0, 0})
	f.Add([]byte{4, 0, 1, 0}, uint64(1), []byte{1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, buf []byte, id uint64, dst []byte) {
		var e tunnelEncap
		_ = e.Decode(buf)
		if len(dst) != 4 {
			return
		}
		in := tunnelEncap{ID: id, Dst: netip.AddrFrom4([4]byte(dst))}
		b, err := in.Encode()
		if err != nil {
			t.Fatal(err)
		}
		var out tunnelEncap
		if err := out.Decode(b); err != nil {
			t.Fatal(err)
		}
		if !in.Equal(&out) {
			t.Fatalf("round trip: %s became %s", in.String(), out.String())
		}
	})
}
