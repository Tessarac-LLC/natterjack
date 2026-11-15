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

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vishvananda/netns"
)

func main() {
	var (
		configPath  = flag.String("config", "/fakecloud/config.json", "the fake VPC")
		listen      = flag.String("listen", ":4566", "address of the EC2 API")
		out         = flag.String("out", "/fakecloud/out", "directory for ca.crt and the ready marker")
		detachDelay = flag.Duration("detach-delay", time.Second, "how long a detach takes")
	)
	flag.Parse()
	if err := run(*configPath, *listen, *out, *detachDelay); err != nil {
		log.Fatal(err)
	}
}

func run(configPath, listen, out string, detachDelay time.Duration) error {
	raw, err := os.ReadFile(configPath) //nolint:gosec // the test's own file
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	ctx := context.Background()
	world, err := NewWorld(ctx, &cfg)
	if err != nil {
		return err
	}
	fake, err := NewEC2(cfg, world)
	if err != nil {
		return err
	}
	fake.DetachDelay = detachDelay

	caPEM, cert, err := certificate(internetHost)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", out, err)
	}
	// Readable by all: the fake runs as root and the test that reads the
	// certificate through the bind mount does not, and a CA certificate is
	// public.
	if err := os.WriteFile(filepath.Join(out, "ca.crt"), caPEM, 0o644); err != nil { //nolint:gosec // see above

		return fmt.Errorf("write CA: %w", err)
	}
	tlsLn, plainLn, err := world.listenInternet(ctx)
	if err != nil {
		return err
	}
	errs := make(chan error, 3)
	whoamiSrv := &http.Server{Handler: http.HandlerFunc(whoami), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		errs <- whoamiSrv.Serve(tls.NewListener(tlsLn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	}()
	go func() {
		errs <- (&http.Server{Handler: internetHandler(), ReadHeaderTimeout: 10 * time.Second}).Serve(plainLn)
	}()
	apiLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	go func() { errs <- (&http.Server{Handler: fake, ReadHeaderTimeout: 10 * time.Second}).Serve(apiLn) }()
	if err := os.WriteFile(filepath.Join(out, "ready"), nil, 0o600); err != nil {
		return fmt.Errorf("write ready marker: %w", err)
	}
	log.Printf("fake cloud ready: EC2 on %s, internet host %s", listen, internetHost)
	return <-errs
}

// listenInternet opens the internet host's HTTPS and HTTP sockets in its
// namespace. HTTP answers on every address there, so a test can add hosts
// to the internet with ip addr add.
func (w *World) listenInternet(ctx context.Context) (net.Listener, net.Listener, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := netns.Set(w.inet); err != nil {
		return nil, nil, fmt.Errorf("enter internet namespace: %w", err)
	}
	var lc net.ListenConfig
	tlsLn, err1 := lc.Listen(ctx, "tcp4", internetHost+":443")
	plainLn, err2 := lc.Listen(ctx, "tcp4", ":80")
	if err := netns.Set(w.world); err != nil {
		// This thread is stuck in the internet; never reuse it.
		runtime.LockOSThread()
		return nil, nil, fmt.Errorf("leave internet namespace: %w", err)
	}
	if err := errors.Join(err1, err2); err != nil {
		return nil, nil, fmt.Errorf("listen on the internet host: %w", err)
	}
	return tlsLn, plainLn, nil
}
