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

package v1alpha1_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

// The CRDs are applied to a real API server so the OpenAPI and CEL rules in
// config/crd are what is tested, not the Go types.
var k8s client.Client

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// Fail loudly rather than skip: a skipped validation suite looks green.
		println("KUBEBUILDER_ASSETS is not set; run `make test`")
		os.Exit(1)
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		panic(err)
	}
	scheme := runtime.NewScheme()
	if err := v1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	k8s, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		panic(err)
	}
	code := m.Run()
	if err := env.Stop(); err != nil {
		panic(err)
	}
	os.Exit(code)
}

type tc struct {
	name    string
	obj     client.Object
	wantErr string // substring of the API server's rejection; empty means accepted
}

func run(t *testing.T, cases []tc) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := k8s.Create(context.Background(), c.obj, client.DryRunAll)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("want accepted, got %v", err)
			case c.wantErr != "" && err == nil:
				t.Fatalf("want rejection containing %q, got accepted", c.wantErr)
			case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
				t.Fatalf("want rejection containing %q, got %v", c.wantErr, err)
			}
		})
	}
}

func pool(spec v1.EgressPoolSpec) *v1.EgressPool {
	return &v1.EgressPool{ObjectMeta: metav1.ObjectMeta{Name: "p"}, Spec: spec}
}

func TestEgressPoolValidation(t *testing.T) {
	run(t, []tc{
		{name: "empty spec takes defaults", obj: pool(v1.EgressPoolSpec{})},
		{name: "wireguard", obj: pool(v1.EgressPoolSpec{Tunnel: v1.TunnelWireGuard})},
		{name: "unknown tunnel", obj: pool(v1.EgressPoolSpec{Tunnel: "IPIP"}), wantErr: "spec.tunnel"},
		{name: "zero max gateways", obj: pool(v1.EgressPoolSpec{MaxGatewaysPerZone: ptr.To[int32](0)}), wantErr: "maxGatewaysPerZone must be at least 1"},
		{name: "probe too fast", obj: pool(v1.EgressPoolSpec{Probe: v1.Probe{IntervalMilliseconds: 5}}), wantErr: "spec.probe.intervalMilliseconds"},
		{name: "warn mode", obj: pool(v1.EgressPoolSpec{SafetyChecks: v1.SafetyChecksWarn})},
		{name: "unknown safety mode", obj: pool(v1.EgressPoolSpec{SafetyChecks: "Off"}), wantErr: "spec.safetyChecks"},
		{name: "drain too long", obj: pool(v1.EgressPoolSpec{DrainSeconds: 3601}), wantErr: "spec.drainSeconds"},
	})
}

func TestEgressPoolDefaults(t *testing.T) {
	p := pool(v1.EgressPoolSpec{})
	p.Name = "defaults"
	if err := k8s.Create(context.Background(), p, client.DryRunAll); err != nil {
		t.Fatal(err)
	}
	if p.Spec.Tunnel != v1.TunnelGeneve || p.Spec.DrainSeconds != 60 ||
		p.Spec.Probe.IntervalMilliseconds != 100 || p.Spec.Probe.FailureThreshold != 3 ||
		p.Spec.SafetyChecks != v1.SafetyChecksEnforce {
		t.Fatalf("defaults not applied: %+v", p.Spec)
	}
}

func policy(spec v1.EgressPolicySpec) *v1.EgressPolicy {
	return &v1.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"}, Spec: spec}
}

func TestEgressPolicyValidation(t *testing.T) {
	all := &metav1.LabelSelector{}
	run(t, []tc{
		{name: "empty selector selects all", obj: policy(v1.EgressPolicySpec{PoolName: "p", PodSelector: all})},
		{name: "service accounts only", obj: policy(v1.EgressPolicySpec{PoolName: "p", ServiceAccountNames: []string{"app"}})},
		{name: "no selection", obj: policy(v1.EgressPolicySpec{PoolName: "p"}), wantErr: "set podSelector or serviceAccountNames"},
		{name: "no pool", obj: policy(v1.EgressPolicySpec{PodSelector: all}), wantErr: "spec.poolName"},
		{name: "ipv4 cidrs", obj: policy(v1.EgressPolicySpec{PoolName: "p", PodSelector: all, ExcludedCIDRs: []string{"203.0.113.0/24", "198.51.100.7/32"}})},
		{name: "bad cidr", obj: policy(v1.EgressPolicySpec{PoolName: "p", PodSelector: all, ExcludedCIDRs: []string{"203.0.113.0"}}), wantErr: "every entry must be an IPv4 CIDR"},
		{name: "ipv6 cidr", obj: policy(v1.EgressPolicySpec{PoolName: "p", PodSelector: all, ExcludedCIDRs: []string{"2001:db8::/32"}}), wantErr: "every entry must be an IPv4 CIDR"},
	})
}

func clusterPolicy(spec v1.ClusterEgressPolicySpec) *v1.ClusterEgressPolicy {
	return &v1.ClusterEgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p"}, Spec: spec}
}

func TestClusterEgressPolicyValidation(t *testing.T) {
	run(t, []tc{
		{name: "node traffic only", obj: clusterPolicy(v1.ClusterEgressPolicySpec{PoolName: "p", NodeTraffic: true})},
		{name: "all namespaces", obj: clusterPolicy(v1.ClusterEgressPolicySpec{PoolName: "p", NamespaceSelector: &metav1.LabelSelector{}})},
		{name: "selects nothing", obj: clusterPolicy(v1.ClusterEgressPolicySpec{PoolName: "p"}), wantErr: "set namespaceSelector, nodeTraffic, or both"},
		{name: "bad cidr", obj: clusterPolicy(v1.ClusterEgressPolicySpec{PoolName: "p", NodeTraffic: true, ExcludedCIDRs: []string{"nope"}}), wantErr: "every entry must be an IPv4 CIDR"},
	})
}
