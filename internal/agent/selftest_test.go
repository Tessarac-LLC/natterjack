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
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestSelfTest(t *testing.T) {
	answer, status := "203.0.113.9\n", http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, answer)
	}))
	defer srv.Close()
	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	var dialed []string
	want := netip.MustParseAddr("203.0.113.9")
	if err := SelfTest(t.Context(), dialer(&dialed), url, want); err != nil {
		t.Fatal(err)
	}
	if len(dialed) == 0 || !strings.HasPrefix(dialed[0], "127.0.0.1:") {
		t.Fatalf("dialed %v; the name must be resolved before the gateway dial", dialed)
	}
	for _, c := range []struct {
		answer string
		status int
		err    string
	}{
		{"198.51.100.1", http.StatusOK, "not the slot's public IP"},
		{"<html>", http.StatusOK, "not an IP address"},
		{"203.0.113.9", http.StatusBadGateway, "502"},
	} {
		answer, status = c.answer, c.status
		if err := SelfTest(t.Context(), dialer(&dialed), url, want); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("answer %q status %d: error %v; want %q", c.answer, c.status, err, c.err)
		}
	}
}

// dialer records each address it is asked for; the self-test hands it IPs.
func dialer(dialed *[]string) Dialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		*dialed = append(*dialed, addr)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
}
