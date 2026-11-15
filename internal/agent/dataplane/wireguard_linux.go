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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/Tessarac-LLC/natterjack/internal/agent"
)

// wireGuardPerPacket is the WireGuard over IPv4 overhead: outer IPv4, UDP,
// and WireGuard's header and authentication tag.
const wireGuardPerPacket = 20 + 8 + 32

// keyFile holds the node's WireGuard private key. It lives in the state
// directory, so it survives agent restarts and a reboot makes a new one.
const keyFile = "wireguard.key"

// loadKey reads the node's private key, creating it on first use.
func loadKey(dir string) (wgtypes.Key, error) {
	path := filepath.Join(dir, keyFile)
	raw, err := os.ReadFile(path) // #nosec G304 -- the agent's own state directory, from its flags
	if err == nil {
		k, perr := wgtypes.ParseKey(strings.TrimSpace(string(raw)))
		if perr == nil {
			return k, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, fmt.Errorf("read WireGuard key: %w", err)
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("generate WireGuard key: %w", err)
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(k.String()+"\n"), 0o600); err != nil {
		return wgtypes.Key{}, fmt.Errorf("write WireGuard key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return wgtypes.Key{}, fmt.Errorf("write WireGuard key: %w", err)
	}
	return k, nil
}

// WireGuardKey is the node's WireGuard public key, which the agent publishes
// on its pod.
func (d *Dataplane) WireGuardKey() string { return d.key.PublicKey().String() }

// wireGuardName is the source node's device for the gateway with mark m.
func (d *Dataplane) wireGuardName(m uint32) string {
	return WireGuardPrefix + strconv.FormatUint(uint64(m>>d.shift), 10)
}

// applyWireGuard makes the WireGuard devices match want: on a source node,
// one per encrypted gateway with that gateway as its only peer; on a gateway
// of an encrypted pool, one whose peers are the cluster's nodes, each allowed
// only its own address. It returns the source devices by mark and the
// gateway device, or nil.
func (d *Dataplane) applyWireGuard(want *agent.Desired, underlayMTU int) (map[uint32]netlink.Link, netlink.Link, error) {
	mtu := min(underlayMTU-wireGuardPerPacket, geneveMaxMTU)
	keep := map[string]bool{}
	var wg *wgctrl.Client
	client := func() (*wgctrl.Client, error) {
		if wg != nil {
			return wg, nil
		}
		c, err := wgctrl.New()
		if err != nil {
			return nil, fmt.Errorf("WireGuard control: %w", err)
		}
		wg = c
		return c, nil
	}
	defer func() {
		if wg != nil {
			_ = wg.Close()
		}
	}()

	links := map[uint32]netlink.Link{}
	for m, key := range want.WireGuard {
		ip, ok := want.Gateways[m]
		if !ok || key == "" || ip == want.NodeIP {
			continue // no key yet, or this node's own gateway: no tunnel
		}
		pub, err := wgtypes.ParseKey(key)
		if err != nil {
			return nil, nil, fmt.Errorf("gateway %s WireGuard key: %w", ip, err)
		}
		name := d.wireGuardName(m)
		keep[name] = true
		l, err := d.ensureWireGuard(name, mtu)
		if err != nil {
			return nil, nil, err
		}
		c, err := client()
		if err != nil {
			return nil, nil, err
		}
		// The gateway is the only peer, and every destination goes to it: the
		// mark's routing table, not WireGuard, picks the gateway.
		peer := wgtypes.PeerConfig{
			PublicKey: pub, ReplaceAllowedIPs: true,
			Endpoint:   &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(d.cfg.WireGuardPort)},
			AllowedIPs: []net.IPNet{*defaultDst()},
		}
		if err := c.ConfigureDevice(name, wgtypes.Config{PrivateKey: &d.key, ReplacePeers: true, Peers: []wgtypes.PeerConfig{peer}}); err != nil {
			return nil, nil, fmt.Errorf("configure %s: %w", name, err)
		}
		links[m] = l
	}

	var gwLink netlink.Link
	if g := want.Gateway; g != nil && g.WireGuard {
		keep[WireGuardLink] = true
		l, err := d.ensureWireGuard(WireGuardLink, mtu)
		if err != nil {
			return nil, nil, err
		}
		c, err := client()
		if err != nil {
			return nil, nil, err
		}
		var peers []wgtypes.PeerConfig
		for ip, key := range g.Peers {
			pub, err := wgtypes.ParseKey(key)
			if err != nil {
				return nil, nil, fmt.Errorf("node %s WireGuard key: %w", ip, err)
			}
			// A node may send only from its own address, which steered
			// traffic is translated to: WireGuard drops anything else.
			peers = append(peers, wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*hostPrefix(ip)}})
		}
		port := int(d.cfg.WireGuardPort)
		if err := c.ConfigureDevice(WireGuardLink, wgtypes.Config{PrivateKey: &d.key, ListenPort: &port, ReplacePeers: true, Peers: peers}); err != nil {
			return nil, nil, fmt.Errorf("configure %s: %w", WireGuardLink, err)
		}
		gwLink = l
	}
	return links, gwLink, d.removeWireGuard(keep)
}

func (d *Dataplane) ensureWireGuard(name string, mtu int) (netlink.Link, error) {
	l, err := netlink.LinkByName(name)
	switch {
	case isNotFound(err):
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}}); err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) {
				return nil, fmt.Errorf("create %s: the kernel has no WireGuard (Linux 5.6 or later, module wireguard): %w", name, err)
			}
			return nil, fmt.Errorf("create %s: %w", name, err)
		}
		if l, err = netlink.LinkByName(name); err != nil {
			return nil, fmt.Errorf("find %s: %w", name, err)
		}
	case err != nil:
		return nil, fmt.Errorf("find %s: %w", name, err)
	case l.Type() != "wireguard":
		return nil, fmt.Errorf("%s exists and is not a WireGuard device but %s", name, l.Type())
	}
	if l.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(l, mtu); err != nil {
			return nil, fmt.Errorf("set %s MTU %d: %w", name, mtu, err)
		}
	}
	// Like nj0: an address only so reverse path filtering accepts what
	// arrives on the device.
	addr := &netlink.Addr{IPNet: hostPrefix(d.cfg.TunnelAddr()), Scope: unix.RT_SCOPE_HOST}
	if err := netlink.AddrReplace(l, addr); err != nil {
		return nil, fmt.Errorf("address %s on %s: %w", addr.IPNet, name, err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return nil, fmt.Errorf("set %s up: %w", name, err)
	}
	if err := writeSysctl("net/ipv4/conf/"+name+"/rp_filter", "2"); err != nil {
		return nil, err
	}
	return l, nil
}

// removeWireGuard deletes the agent's WireGuard devices not in keep.
func (d *Dataplane) removeWireGuard(keep map[string]bool) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	var errs []error
	for _, l := range links {
		name := l.Attrs().Name
		if l.Type() != "wireguard" || keep[name] || (name != WireGuardLink && !strings.HasPrefix(name, WireGuardPrefix)) {
			continue
		}
		if err := netlink.LinkDel(l); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Errorf("remove %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
