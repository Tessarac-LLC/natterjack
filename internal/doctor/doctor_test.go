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

package doctor

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
)

const ns = "natterjack"

var now = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func componentLabels(release, component string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/part-of":   "natterjack",
		"app.kubernetes.io/instance":  release,
		"app.kubernetes.io/name":      "natterjack-" + component,
		"app.kubernetes.io/component": component,
	}
}

func readyPod(name, node, component string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: componentLabels("nj", component), Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue},
		}},
	}
}

func agentPod(node string) *corev1.Pod {
	p := readyPod("agent-"+node, node, "agent")
	p.Status.Conditions = append(p.Status.Conditions, corev1.PodCondition{Type: v1.ConditionDataplaneReady, Status: corev1.ConditionTrue, Reason: "Applied"})
	return p
}

func gateway(p *corev1.Pod, slot string, serving bool) {
	raw, _ := json.Marshal(v1.Gateway{Pool: "default", SlotID: slot})
	p.Labels[v1.LabelGateway] = "true"
	p.Annotations[v1.AnnotationGateway] = string(raw)
	if serving {
		p.Status.Conditions = append(p.Status.Conditions, corev1.PodCondition{
			Type: v1.ConditionGatewayReady, Status: corev1.ConditionTrue, Reason: "Serving", Message: v1.GatewayReadyMessage(slot),
		})
	}
}

func condition(t string, s metav1.ConditionStatus, msg string) metav1.Condition {
	return metav1.Condition{Type: t, Status: s, Reason: "Test", Message: msg}
}

// healthy is an installation doctor must call a go: two nodes, both
// gateways serving, a reconciled pool and an accepted policy.
func healthy() map[string]client.Object {
	gw1, gw2 := agentPod("node-1"), agentPod("node-2")
	gateway(gw1, "eni-1", true)
	gateway(gw2, "eni-2", true)
	objs := map[string]client.Object{
		"deployment": &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nj-controller", Labels: componentLabels("nj", "controller")},
			Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](2)},
		},
		"daemonset": &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nj-agent", Labels: componentLabels("nj", "agent")},
			Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
			}}},
		},
		"controller-a": readyPod("controller-a", "node-1", "controller"),
		"controller-b": readyPod("controller-b", "node-2", "controller"),
		"lease": &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: LeaseName},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity: ptr.To("controller-a_0b7f"), LeaseDurationSeconds: ptr.To[int32](15),
				RenewTime: &metav1.MicroTime{Time: now.Add(-5 * time.Second)},
			},
		},
		"node-1":  &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1", Labels: map[string]string{"kubernetes.io/os": "linux"}}},
		"node-2":  &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-2", Labels: map[string]string{"kubernetes.io/os": "linux"}}},
		"windows": &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "win-1", Labels: map[string]string{"kubernetes.io/os": "windows"}}},
		"agent-1": gw1,
		"agent-2": gw2,
		"pool": &v1.EgressPool{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 2},
			Status: v1.EgressPoolStatus{
				ObservedGeneration: 2, PublicIPs: []string{"203.0.113.1", "203.0.113.2"},
				Slots: []v1.SlotStatus{
					{ID: "eni-1", Zone: "a", State: v1.SlotActive, Node: "node-1"},
					{ID: "eni-2", Zone: "a", State: v1.SlotActive, Node: "node-2"},
				},
				Conditions: []metav1.Condition{
					condition(v1.ConditionReady, metav1.ConditionTrue, "2 gateways ready"),
					condition(v1.ConditionCloudAccess, metav1.ConditionTrue, "ok"),
					condition(v1.ConditionDegraded, metav1.ConditionFalse, "redundant"),
				},
			},
		},
		"policy": &v1.EgressPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"},
			Status:     v1.PolicyStatus{Conditions: []metav1.Condition{condition(v1.ConditionAccepted, metav1.ConditionTrue, "in force")}},
		},
	}
	for _, c := range []string{"agent", "controller"} {
		name := "nj-" + c
		objs["vap-"+c] = &admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: componentLabels("nj", c)}}
		objs["binding-"+c] = &admissionv1.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: componentLabels("nj", c)},
			Spec:       admissionv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: name, ValidationActions: []admissionv1.ValidationAction{admissionv1.Deny}},
		}
	}
	return objs
}

func runDoctor(t *testing.T, objs map[string]client.Object, minor string) Report {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := v1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	b := fake.NewClientBuilder().WithScheme(s)
	for _, o := range objs {
		b = b.WithObjects(o)
	}
	return Run(t.Context(), Options{
		Client: b.Build(), Now: now,
		ServerVersion: func() (*version.Info, error) {
			return &version.Info{Major: "1", Minor: minor, GitVersion: "v1." + strings.TrimSuffix(minor, "+") + ".2"}, nil
		},
	})
}

func messages(r Report, sev Severity) string {
	var out []string
	for _, f := range r.Findings {
		if f.Severity == sev {
			out = append(out, f.Check+": "+f.Message)
		}
	}
	return strings.Join(out, "\n")
}

func TestHealthyIsGo(t *testing.T) {
	r := runDoctor(t, healthy(), "34+")
	if !r.Go || messages(r, Fail) != "" || messages(r, Warn) != "" {
		t.Fatalf("healthy install: go=%v\nfail:\n%s\nwarn:\n%s", r.Go, messages(r, Fail), messages(r, Warn))
	}
	if r.Namespace != ns || r.Release != "nj" {
		t.Fatalf("located %s/%s", r.Namespace, r.Release)
	}
	var buf bytes.Buffer
	if err := Print(&buf, r); err != nil || !strings.HasSuffix(buf.String(), "\nGO.\n") {
		t.Fatalf("printed %q, %v", buf.String(), err)
	}
}

func TestEveryProblemIsReported(t *testing.T) {
	for _, tc := range []struct {
		name  string
		minor string
		edit  func(map[string]client.Object)
		sev   Severity
		want  string
	}{
		{"old kubernetes", "33", nil, Fail, "older than 1.34"},
		{"not installed", "", func(o map[string]client.Object) { delete(o, "deployment"); delete(o, "daemonset") }, Fail, "no Natterjack release found"},
		{"two releases", "", func(o map[string]client.Object) {
			o["other"] = &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "x", Labels: componentLabels("x", "agent")}}
		}, Fail, "found 2 releases (natterjack/nj, other/x)"},
		{"cloud unreadable", "", func(o map[string]client.Object) {
			p := o["pool"].(*v1.EgressPool)
			p.Status.Conditions[1] = condition(v1.ConditionCloudAccess, metav1.ConditionFalse, "discover slots: UnauthorizedOperation (the controller authenticates as system:serviceaccount:natterjack:nj-controller")
		}, Fail, "cannot read the cloud: discover slots: UnauthorizedOperation (the controller authenticates as system:serviceaccount:natterjack:nj-controller"},
		{"pool not reconciled", "", func(o map[string]client.Object) { o["pool"].(*v1.EgressPool).Generation = 3 }, Fail, "not yet reconciled by the controller (generation 3, observed 2)"},
		{"pool not ready", "", func(o map[string]client.Object) {
			o["pool"].(*v1.EgressPool).Status.Conditions[0] = condition(v1.ConditionReady, metav1.ConditionFalse, "no gateway is ready")
		}, Fail, "pool default: no gateway is ready"},
		{"no pool", "", func(o map[string]client.Object) { delete(o, "pool") }, Fail, "no EgressPool exists"},
		{"degraded", "", func(o map[string]client.Object) {
			o["pool"].(*v1.EgressPool).Status.Conditions[2] = condition(v1.ConditionDegraded, metav1.ConditionTrue, "zone a has one ready gateway")
		}, Warn, "Degraded: zone a has one ready gateway"},
		{"quarantined slot", "", func(o map[string]client.Object) {
			p := o["pool"].(*v1.EgressPool)
			p.Status.Slots = append(p.Status.Slots, v1.SlotStatus{ID: "eni-3", Zone: "b", State: v1.SlotQuarantined, Reason: "security group sg-1 allows inbound traffic"})
		}, Warn, "slot eni-3 in b is Quarantined: security group sg-1 allows inbound traffic"},
		{"node without agent", "", func(o map[string]client.Object) { delete(o, "agent-2") }, Fail, "node node-2 has no agent pod"},
		{"data path failing", "", func(o map[string]client.Object) {
			p := o["agent-2"].(*corev1.Pod)
			p.Status.Conditions[1] = corev1.PodCondition{Type: v1.ConditionDataplaneReady, Status: corev1.ConditionFalse, Message: "net.ipv4.conf.all.rp_filter is 1 (strict)"}
		}, Fail, "node node-2: data path not applied: net.ipv4.conf.all.rp_filter is 1 (strict)"},
		{"agent crashing", "", func(o map[string]client.Object) {
			p := o["agent-2"].(*corev1.Pod)
			p.Status.Conditions[0].Status = corev1.ConditionFalse
			p.Status.ContainerStatuses = []corev1.ContainerStatus{{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: "back-off 5m0s"}}}}
		}, Fail, "node node-2: agent agent-node-2 is not ready: CrashLoopBackOff: back-off 5m0s"},
		{"gateway not serving", "", func(o map[string]client.Object) {
			p := o["agent-2"].(*corev1.Pod)
			p.Status.Conditions[2] = corev1.PodCondition{Type: v1.ConditionGatewayReady, Status: corev1.ConditionFalse, Reason: "SelfTestFailed", Message: "reply was 198.51.100.7"}
		}, Warn, "node node-2 holds slot eni-2 but does not serve it: SelfTestFailed: reply was 198.51.100.7"},
		{"no gateway serving", "", func(o map[string]client.Object) {
			for _, k := range []string{"agent-1", "agent-2"} {
				o[k].(*corev1.Pod).Status.Conditions = o[k].(*corev1.Pod).Status.Conditions[:2]
			}
		}, Fail, "0 of 2 gateways serve their slot"},
		{"no controller ready", "", func(o map[string]client.Object) {
			for _, k := range []string{"controller-a", "controller-b"} {
				o[k].(*corev1.Pod).Status.Conditions[0].Status = corev1.ConditionFalse
			}
		}, Fail, "no controller replica is ready (0 of 2)"},
		{"controller image missing", "", func(o map[string]client.Object) {
			p := o["controller-b"].(*corev1.Pod)
			p.Status.Phase = corev1.PodPending
			p.Status.ContainerStatuses = []corev1.ContainerStatus{{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "not found"}}}}
		}, Warn, "pod controller-b is not ready: ImagePullBackOff: not found"},
		{"no leader", "", func(o map[string]client.Object) {
			o["lease"].(*coordinationv1.Lease).Spec.RenewTime = &metav1.MicroTime{Time: now.Add(-time.Minute)}
		}, Fail, "no controller holds the leader Lease"},
		{"leader elsewhere", "", func(o map[string]client.Object) {
			o["lease"].(*coordinationv1.Lease).Spec.HolderIdentity = ptr.To("old-controller_1")
		}, Fail, "held by old-controller, which is not a running controller pod"},
		{"admission policy missing", "", func(o map[string]client.Object) { delete(o, "vap-agent") }, Fail, "the agent admission policy is missing"},
		{"admission binding missing", "", func(o map[string]client.Object) { delete(o, "binding-controller") }, Fail, "the controller admission policy nj-controller has no denying binding"},
		{"admission audit only", "", func(o map[string]client.Object) {
			o["binding-agent"].(*admissionv1.ValidatingAdmissionPolicyBinding).Spec.ValidationActions = []admissionv1.ValidationAction{admissionv1.Audit}
		}, Fail, "the agent admission policy nj-agent has no denying binding"},
		{"policy rejected", "", func(o map[string]client.Object) {
			o["policy"].(*v1.EgressPolicy).Status.Conditions[0] = condition(v1.ConditionAccepted, metav1.ConditionFalse, `pool "fast" does not exist`)
		}, Fail, `EgressPolicy apps/web is not in force: pool "fast" does not exist`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := healthy()
			if tc.edit != nil {
				tc.edit(objs)
			}
			r := runDoctor(t, objs, cmp.Or(tc.minor, "35"))
			got := messages(r, tc.sev)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("%s findings lack %q:\n%s\nall: %+v", tc.sev, tc.want, got, r.Findings)
			}
			if r.Go != (messages(r, Fail) == "") || (tc.sev == Fail && r.Go) {
				t.Fatalf("go=%v with failures:\n%s", r.Go, messages(r, Fail))
			}
			if tc.sev == Warn && !r.Go {
				t.Fatalf("a warning alone made it a no-go:\n%s", messages(r, Fail))
			}
		})
	}
}

func TestVersionError(t *testing.T) {
	r := Run(t.Context(), Options{
		Client:        fake.NewClientBuilder().Build(),
		ServerVersion: func() (*version.Info, error) { return nil, errors.New("connection refused") },
	})
	if r.Go || !strings.Contains(messages(r, Fail), "cannot read the API server version: connection refused") {
		t.Fatalf("%+v", r)
	}
}

func TestPrintNoGo(t *testing.T) {
	var buf bytes.Buffer
	err := Print(&buf, Report{Findings: []Finding{
		{Check: "pool default", Severity: Fail, Message: "get credentials: refresh\nretry quota exceeded  (as system:serviceaccount:a:b)"},
		{Check: "gateways", Severity: Warn, Message: "slow"},
	}})
	want := "[FAIL]  pool default  get credentials: refresh retry quota exceeded (as system:serviceaccount:a:b)\n[WARN]  gateways      slow\n\nNO-GO: 1 problem(s) must be fixed before traffic moves; 1 warning(s).\n"
	if err != nil || buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}
