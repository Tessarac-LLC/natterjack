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
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/cloud"
	awsprovider "github.com/Tessarac-LLC/natterjack/internal/cloud/aws"
)

type recordLinks struct {
	mu    sync.Mutex
	calls []string
}

func (l *recordLinks) Attach(s *Slot, in *Instance) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, "attach "+s.ID+" "+in.Node)
	return nil
}

func (l *recordLinks) Detach(s *Slot) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, "detach "+s.ID)
	return nil
}

func (l *recordLinks) got() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.calls)
}

func slotTags(cluster string) map[string]string {
	return map[string]string{v1.TagEgress: "true", v1.TagCluster: cluster, awsprovider.TagNoManage: "true"}
}

func testConfig() Config {
	inCluster := map[string]string{"kubernetes.io/cluster/e2e": "owned"}
	noManage := slotTags("e2e")
	delete(noManage, awsprovider.TagNoManage)
	return Config{
		Cluster: "e2e", VPC: "vpc-fake",
		Subnets: []Subnet{
			{ID: "subnet-a", Zone: "zone-a", CIDR: "10.250.1.0/24"},
			{ID: "subnet-b", Zone: "zone-b", CIDR: "10.250.2.0/24"},
			{ID: "subnet-private", Zone: "zone-a", CIDR: "10.250.3.0/24", NoInternet: true},
		},
		SecurityGroups: []SecurityGroup{{ID: "sg-closed"}, {ID: "sg-open", Inbound: true}, {ID: "sg-routed", InboundFromVPC: true}},
		Slots: []Slot{
			{ID: "eni-a1", Subnet: "subnet-a", PrivateIP: "10.250.1.10", PublicIP: "198.51.100.10", MAC: "02:4e:4a:01:00:0a", Groups: []string{"sg-closed"}, Tags: slotTags("e2e")},
			{ID: "eni-b1", Subnet: "subnet-b", PrivateIP: "10.250.2.10", PublicIP: "198.51.100.20", MAC: "02:4e:4a:02:00:0a", Groups: []string{"sg-closed", "sg-routed"}, Tags: slotTags("e2e"), RouteTarget: true},
			{ID: "eni-bad", Subnet: "subnet-private", PrivateIP: "10.250.3.10", MAC: "02:4e:4a:03:00:0a", Groups: []string{"sg-open"}, SourceDestCheck: true, Tags: noManage},
			{ID: "eni-other", Subnet: "subnet-a", PrivateIP: "10.250.1.11", PublicIP: "198.51.100.11", MAC: "02:4e:4a:01:00:0b", Groups: []string{"sg-closed"}, Tags: slotTags("other")},
		},
		Instances: []Instance{
			{ID: "i-0000000000000001", Zone: "zone-a", Node: "worker", Tags: inCluster},
			{ID: "i-0000000000000002", Zone: "zone-b", Node: "worker2", Tags: inCluster},
			{ID: "i-0000000000000003", Zone: "zone-a", Node: "stranger"},
			{ID: "i-0000000000000004", Zone: "zone-b", Node: "full", Tags: inCluster, MaxInterfaces: 1},
		},
	}
}

func fakeProvider(t *testing.T) (*awsprovider.Provider, *recordLinks, *httptest.Server) {
	t.Helper()
	links := &recordLinks{}
	fake, err := NewEC2(testConfig(), links)
	if err != nil {
		t.Fatal(err)
	}
	fake.DetachDelay = 100 * time.Millisecond
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	client := ec2.New(ec2.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(srv.URL),
		Credentials: aws.AnonymousCredentials{},
	})
	return awsprovider.New(client, "e2e"), links, srv
}

func bySlot(slots []cloud.Slot) map[string]cloud.Slot {
	out := map[string]cloud.Slot{}
	for _, s := range slots {
		out[s.ID] = s
	}
	return out
}

// TestProviderAgainstFake runs the real AWS provider against the fake, so
// the fake answers in the shapes the SDK and the provider read.
func TestProviderAgainstFake(t *testing.T) {
	p, links, _ := fakeProvider(t)
	ctx := t.Context()

	slots, err := p.Slots(ctx, cloud.Discovery{ClusterName: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	got := bySlot(slots)
	if len(got) != 3 {
		t.Fatalf("slots %v, want eni-a1, eni-b1 and eni-bad", slices.Sorted(maps.Keys(got)))
	}
	a1 := got["eni-a1"]
	if !a1.Usable() || a1.PublicIP != "198.51.100.10" || a1.SubnetCIDR != "10.250.1.0/24" ||
		a1.MAC != "02:4e:4a:01:00:0a" || a1.Zone != "zone-a" || a1.PrivateIP != "10.250.1.10" || a1.Instance != "" {
		t.Errorf("eni-a1 = %+v", a1)
	}
	if b1 := got["eni-b1"]; !b1.Usable() {
		t.Errorf("eni-b1 admits only its VPC, yet: %v", b1.Problems)
	}
	if !got["eni-b1"].RouteTarget || got["eni-a1"].RouteTarget {
		t.Errorf("route targets: eni-b1 %v, eni-a1 %v", got["eni-b1"].RouteTarget, got["eni-a1"].RouteTarget)
	}
	bad := strings.Join(got["eni-bad"].Problems, "\n")
	for _, want := range []string{"no Elastic IP", "source/destination check", awsprovider.TagNoManage, "sg-open allows inbound", "no 0.0.0.0/0 route"} {
		if !strings.Contains(bad, want) {
			t.Errorf("eni-bad problems lack %q:\n%s", want, bad)
		}
	}

	strays, err := p.Strays(ctx, "e2e")
	if err != nil {
		t.Fatal(err)
	}
	if len(strays) != 1 || strays[0].ID != "eni-other" || strays[0].Cluster != "other" {
		t.Errorf("strays = %+v, want eni-other of cluster other", strays)
	}

	if err := p.Attach(ctx, "eni-a1", "i-0000000000000001"); err != nil {
		t.Fatal(err)
	}
	if err := p.Attach(ctx, "eni-a1", "i-0000000000000001"); err != nil {
		t.Fatalf("attaching again to the same instance: %v", err)
	}
	if err := p.Attach(ctx, "eni-a1", "i-0000000000000003"); !errors.Is(err, cloud.ErrAttachedElsewhere) {
		t.Errorf("attach to another instance: %v, want ErrAttachedElsewhere", err)
	}
	if err := p.Attach(ctx, "eni-b1", "i-0000000000000001"); err == nil || !strings.Contains(err.Error(), "zone-b") {
		t.Errorf("attach across zones: %v, want a zone error", err)
	}
	slots, err = p.Slots(ctx, cloud.Discovery{ClusterName: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	if a := bySlot(slots)["eni-a1"]; a.Instance != "i-0000000000000001" || !a.InstanceInCluster {
		t.Errorf("after attach eni-a1 = %+v", a)
	}

	if err := p.Detach(ctx, "eni-a1", false); err != nil {
		t.Fatal(err)
	}
	if err := p.Detach(ctx, "eni-a1", false); err != nil {
		t.Fatalf("detaching a free slot: %v", err)
	}
	if err := p.Attach(ctx, "eni-a1", "i-0000000000000003"); err != nil {
		t.Fatal(err)
	}
	slots, err = p.Slots(ctx, cloud.Discovery{ClusterName: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	if a := bySlot(slots)["eni-a1"]; a.Instance != "i-0000000000000003" || a.InstanceInCluster {
		t.Errorf("on an instance outside the cluster eni-a1 = %+v", a)
	}
	want := []string{"attach eni-a1 worker", "detach eni-a1", "attach eni-a1 stranger"}
	if !slices.Equal(links.got(), want) {
		t.Errorf("links calls %q, want %q", links.got(), want)
	}
}

// TestInterfaceLimit checks that an instance at its type's interface limit
// refuses an attach with EC2's error, which the provider reads as no free slot.
func TestInterfaceLimit(t *testing.T) {
	p, links, _ := fakeProvider(t)
	err := p.Attach(t.Context(), "eni-b1", "i-0000000000000004")
	if !errors.Is(err, cloud.ErrNoFreeDeviceIndex) || !strings.Contains(err.Error(), "AttachmentLimitExceeded") {
		t.Fatalf("attach to a full instance: %v", err)
	}
	if len(links.got()) != 0 {
		t.Fatalf("a refused attach moved the interface: %q", links.got())
	}
	if err := p.Attach(t.Context(), "eni-b1", "i-0000000000000002"); err != nil {
		t.Fatalf("attach to an instance with room: %v", err)
	}
}

func TestFaults(t *testing.T) {
	p, _, srv := fakeProvider(t)
	ctx := t.Context()
	fault := func(action, code string, n string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/_fake/fault?action="+action+"&code="+code+"&count="+n, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("fault: %s", resp.Status)
		}
	}

	// A transient error is retried by the SDK.
	fault("DescribeNetworkInterfaces", "Unavailable", "1")
	if _, err := p.Slots(ctx, cloud.Discovery{ClusterName: "e2e"}); err != nil {
		t.Errorf("after one transient error: %v", err)
	}
	// A permission error is not.
	fault("AttachNetworkInterface", "UnauthorizedOperation", "1")
	if err := p.Attach(ctx, "eni-a1", "i-0000000000000001"); err == nil || !strings.Contains(err.Error(), "UnauthorizedOperation") {
		t.Errorf("attach with a permission error: %v", err)
	}
	if err := p.Attach(ctx, "eni-a1", "i-0000000000000001"); err != nil {
		t.Errorf("attach once the fault is spent: %v", err)
	}
	// Unknown IDs answer the way EC2 does.
	if err := p.Detach(ctx, "eni-missing", false); !errors.Is(err, cloud.ErrNotFound) {
		t.Errorf("detach of a missing slot: %v, want ErrNotFound", err)
	}
}
