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
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// respondObject is bpf/respond.c, built by `make bpf`.
//
//go:embed bpf/respond_bpfel.o
var respondObject []byte

// routeCheck is the address the responder checks the gateway namespace can
// route to before it answers: any address outside the cluster takes the
// default route through the slot.
var routeCheck = netip.MustParseAddr("192.0.2.1")

// applyResponder answers probes in the kernel, on the gateway namespace's
// end of the link from the host, while serving. The program outlives the
// agent: a restarted agent's first Apply replaces it in one step.
func (d *Dataplane) applyResponder(nh *netlink.Handle, nodes []netip.Addr, serving bool) error {
	if d.respond == nil {
		coll, err := d.loadResponder()
		if err != nil {
			return err
		}
		d.respond = coll
	}
	if err := syncProbeNodes(d.respond.Maps["nj_probe_nodes"], nodes); err != nil {
		return err
	}
	on := uint32(0)
	if serving {
		on = 1
	}
	if err := d.respond.Maps["nj_probe_serving"].Put(uint32(0), on); err != nil {
		return fmt.Errorf("set the probe responder serving: %w", err)
	}

	peer, err := nh.LinkByName(VethGateway)
	if err != nil {
		return fmt.Errorf("find %s: %w", VethGateway, err)
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{LinkIndex: peer.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT},
		QdiscType:  "clsact",
	}
	if err := nh.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact to %s: %w", VethGateway, err)
	}
	// Replacing the filter swaps the program in place: no probe goes
	// unanswered while a new agent takes over.
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: peer.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS,
			Handle: 1, Priority: 1, Protocol: unix.ETH_P_IP,
		},
		Fd: d.respond.Programs["nj_respond"].FD(), Name: "nj_respond", DirectAction: true,
	}
	if err := nh.FilterReplace(filter); err != nil {
		return fmt.Errorf("attach the probe responder to %s: %w", VethGateway, err)
	}
	return nil
}

func (d *Dataplane) loadResponder() (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(respondObject))
	if err != nil {
		return nil, fmt.Errorf("read the probe responder: %w", err)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], d.cfg.ProbePort)
	for name, v := range map[string]any{
		"probe_addr":  d.cfg.GatewayAddr().As4(),
		"probe_port":  port,
		"route_check": routeCheck.As4(),
	} {
		if err := spec.Variables[name].Set(v); err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load the probe responder: %w\n%s", err, fmt.Sprintf("%+v", ve))
		}
		return nil, fmt.Errorf("load the probe responder: %w", err)
	}
	return coll, nil
}

// syncProbeNodes makes m hold exactly nodes.
func syncProbeNodes(m *ebpf.Map, nodes []netip.Addr) error {
	want := map[[4]byte]bool{}
	for _, n := range nodes {
		if n.Is4() {
			want[n.As4()] = true
		}
	}
	var (
		k     [4]byte
		v     uint8
		stale [][4]byte
	)
	it := m.Iterate()
	for it.Next(&k, &v) {
		if !want[k] {
			stale = append(stale, k)
		}
		delete(want, k)
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("read the probe responder's nodes: %w", err)
	}
	for _, k := range stale {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("remove a node from the probe responder: %w", err)
		}
	}
	for k := range want {
		if err := m.Put(k, uint8(1)); err != nil {
			return fmt.Errorf("add a node to the probe responder: %w", err)
		}
	}
	return nil
}

// closeResponder lets go of the program; the kernel keeps it while it stays
// attached.
func (d *Dataplane) closeResponder() {
	if d.respond != nil {
		d.respond.Close()
		d.respond = nil
	}
}
