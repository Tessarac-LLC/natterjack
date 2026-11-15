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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

// whoami answers with the caller's address, as checkip.amazonaws.com does.
func whoami(w http.ResponseWriter, r *http.Request) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(ap.Addr().Unmap().String() + "\n")) // #nosec G705 -- an IP address, served as plain text
}

// stream answers with the caller's address and a count, a line every
// 200ms, for up to ?seconds= (default 60) or until the caller goes: one
// long-lived connection, for checking it survives what happens meanwhile.
func stream(w http.ResponseWriter, r *http.Request) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d := time.Minute
	if s, err := strconv.Atoi(r.URL.Query().Get("seconds")); err == nil && s > 0 {
		d = time.Duration(s) * time.Second
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	flush, _ := w.(http.Flusher)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	end := time.After(d)
	for n := 0; ; n++ {
		if _, err := fmt.Fprintf(w, "%s %d\n", ap.Addr().Unmap(), n); err != nil { // #nosec G705 -- an IP address and a count, served as plain text
			return
		}
		if flush != nil {
			flush.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-end:
			return
		case <-tick.C:
		}
	}
}

// internetHandler serves the internet host: /stream, and whoami elsewhere.
func internetHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stream", stream)
	mux.HandleFunc("/", whoami)
	return mux
}

// certificate makes a throwaway CA and a certificate from it for ip. It
// returns the CA in PEM for the clients to trust.
func certificate(ip string) ([]byte, tls.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("CA key: %w", err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "natterjack fake cloud CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("CA: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("key: %w", err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: ip},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP(ip)},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("certificate: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return caPEM, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
