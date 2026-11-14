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
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// GatewayNS is the gateway network namespace. It is pinned by a bind mount
// under the state directory, so it outlives the agent process: a restart
// must not drop the slot interface back into the host namespace or cut the
// flows it carries.
type GatewayNS struct {
	path string
	ns   netns.NsHandle
}

func nsPath(stateDir string) string { return filepath.Join(stateDir, "netns", "gateway") }

// openGatewayNS opens the pinned namespace, if there is one.
func openGatewayNS(stateDir string) (*GatewayNS, error) {
	p := nsPath(stateDir)
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", p, err)
	}
	if st.Type != unix.NSFS_MAGIC {
		return nil, nil
	}
	ns, err := netns.GetFromPath(p)
	if err != nil {
		return nil, fmt.Errorf("open gateway namespace: %w", err)
	}
	return &GatewayNS{path: p, ns: ns}, nil
}

// createGatewayNS makes and pins a new namespace. It runs on a locked thread
// that is thrown away if it cannot return to the host namespace.
func createGatewayNS(stateDir string) (*GatewayNS, error) {
	p := nsPath(stateDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", filepath.Dir(p), err)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDONLY, 0o400) //nolint:gosec // under the configured state directory
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", p, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("create %s: %w", p, err)
	}

	type result struct {
		ns  netns.NsHandle
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		host, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			ch <- result{err: fmt.Errorf("open host namespace: %w", err)}
			return
		}
		defer func() { _ = host.Close() }()
		ns, err := netns.New()
		if err != nil {
			ch <- result{err: fmt.Errorf("create gateway namespace: %w", err)}
			return // the thread may be in an unknown namespace: let it die
		}
		mountErr := unix.Mount(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), p, "", unix.MS_BIND, "")
		if err := netns.Set(host); err != nil {
			_ = ns.Close()
			ch <- result{err: fmt.Errorf("return to host namespace: %w", err)}
			return
		}
		runtime.UnlockOSThread()
		if mountErr != nil {
			_ = ns.Close()
			ch <- result{err: fmt.Errorf("pin gateway namespace at %s (is the state directory a shared host mount?): %w", p, mountErr)}
			return
		}
		ch <- result{ns: ns}
	}()
	r := <-ch
	if r.err != nil {
		return nil, r.err
	}
	return &GatewayNS{path: p, ns: r.ns}, nil
}

// Fd is the namespace file descriptor.
func (g *GatewayNS) Fd() int { return int(g.ns) }

// Do runs fn with its OS thread in the gateway namespace. Sockets fn opens
// belong to the gateway namespace; so do /proc/sys/net writes.
func (g *GatewayNS) Do(fn func() error) error {
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		host, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			ch <- fmt.Errorf("open host namespace: %w", err)
			return
		}
		defer func() { _ = host.Close() }()
		if err := netns.Set(g.ns); err != nil {
			runtime.UnlockOSThread()
			ch <- fmt.Errorf("enter gateway namespace: %w", err)
			return
		}
		fnErr := fn()
		if err := netns.Set(host); err != nil {
			ch <- fmt.Errorf("return to host namespace: %w", err)
			return // keep the thread locked so it dies with the goroutine
		}
		runtime.UnlockOSThread()
		ch <- fnErr
	}()
	return <-ch
}

// Close releases the handle; the pinned namespace stays.
func (g *GatewayNS) Close() error {
	if err := g.ns.Close(); err != nil {
		return fmt.Errorf("close gateway namespace: %w", err)
	}
	return nil
}

// remove unpins the namespace. The kernel frees it once nothing holds it.
func (g *GatewayNS) remove() error {
	_ = g.Close()
	if err := unix.Unmount(g.path, unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("unpin gateway namespace: %w", err)
	}
	if err := os.Remove(g.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", g.path, err)
	}
	return nil
}

func writeSysctl(name, value string) error {
	p := filepath.Join("/proc/sys", filepath.FromSlash(name))
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil { // sysctls exist; the mode is unused
		return fmt.Errorf("sysctl %s=%s: %w", name, value, err)
	}
	return nil
}

func readSysctl(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc/sys", filepath.FromSlash(name)))
	if err != nil {
		return "", fmt.Errorf("sysctl %s: %w", name, err)
	}
	return string(b[:len(b)-1]), nil
}
