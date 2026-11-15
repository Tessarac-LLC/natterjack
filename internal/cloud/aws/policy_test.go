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

package aws

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

type statement struct {
	Sid       string
	Effect    string
	Action    []string
	Resource  string
	Condition map[string]map[string]any
}

func policy(t *testing.T) []statement {
	t.Helper()
	doc, err := Policy("prod")
	if err != nil {
		t.Fatal(err)
	}
	var p struct{ Statement []statement }
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatal(err)
	}
	return p.Statement
}

// Every EC2 call the provider can make is granted, and nothing else is.
func TestPolicyGrantsExactlyTheEC2Interface(t *testing.T) {
	var want []string
	it := reflect.TypeFor[EC2]()
	for i := range it.NumMethod() {
		want = append(want, "ec2:"+it.Method(i).Name)
	}
	var got []string
	for _, s := range policy(t) {
		if s.Effect != "Allow" {
			t.Fatalf("%s: unexpected effect %s", s.Sid, s.Effect)
		}
		for _, a := range s.Action {
			if !slices.Contains(got, a) {
				got = append(got, a)
			}
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("policy grants %v, provider uses %v", got, want)
	}
}

// Writes are never granted on "*" and always carry a tag condition.
func TestPolicyScopesWrites(t *testing.T) {
	for _, s := range policy(t) {
		write := slices.ContainsFunc(s.Action, func(a string) bool { return !strings.HasPrefix(a, "ec2:Describe") })
		if !write {
			continue
		}
		if s.Resource == "*" || len(s.Condition["StringEquals"]) == 0 {
			t.Fatalf("%s grants a write without a resource tag condition", s.Sid)
		}
	}
	eni := policy(t)[1].Condition["StringEquals"]
	if eni["aws:ResourceTag/"+v1.TagEgress] != "true" || eni["aws:ResourceTag/"+v1.TagCluster] != "prod" {
		t.Fatalf("ENI statement does not require the egress and cluster tags: %v", eni)
	}
	if _, ok := policy(t)[3].Condition["StringEquals"]["aws:ResourceTag/kubernetes.io/cluster/prod"]; !ok {
		t.Fatal("cluster name not substituted into the self-managed node tag key")
	}
}

func TestPolicyRejectsUnsafeClusterNames(t *testing.T) {
	for _, bad := range []string{"", `a"b`, "a/b", "-a", strings.Repeat("a", 101), "CLUSTER NAME"} {
		if _, err := Policy(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The Terraform module grants the controller the same policy the provider
// documents; a change to one without the other fails here.
func TestTerraformModuleGrantsThisPolicy(t *testing.T) {
	module, err := os.ReadFile("../../../deploy/terraform/aws/controller-policy.json.tftpl")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(string(module), "${cluster_name}", "CLUSTER_NAME"); got != policyTemplate {
		t.Fatalf("deploy/terraform/aws/controller-policy.json.tftpl differs from policy.json:\n%s", got)
	}
}
