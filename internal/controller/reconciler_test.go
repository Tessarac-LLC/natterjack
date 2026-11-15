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

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1 "github.com/Tessarac-LLC/natterjack/api/v1alpha1"
	"github.com/Tessarac-LLC/natterjack/internal/cloud"
)

var k8s client.Client

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		println("KUBEBUILDER_ASSETS is not set; run `make test`")
		os.Exit(1)
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd")}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		panic(err)
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if k8s, err = client.New(cfg, client.Options{Scheme: scheme}); err != nil {
		panic(err)
	}
	if err := k8s.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		panic(err)
	}
	code := m.Run()
	if err := env.Stop(); err != nil {
		panic(err)
	}
	os.Exit(code)
}

// fakeCloud is an in-memory cloud.Provider.
type fakeCloud struct {
	mu       sync.Mutex
	slots    map[string]*cloud.Slot
	detaches []string
	failNext error
}

var providerID = regexp.MustCompile(`^aws:///([a-z0-9-]+)/(i-[a-z0-9-]+)$`)

func (f *fakeCloud) Slots(context.Context, cloud.Discovery) ([]cloud.Slot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failNext; err != nil {
		f.failNext = nil
		return nil, err
	}
	var out []cloud.Slot
	for _, s := range f.slots {
		out = append(out, *s)
	}
	return out, nil
}

func (f *fakeCloud) Strays(context.Context, string) ([]cloud.Stray, error) { return nil, nil }

func (f *fakeCloud) InstanceForProviderID(id string) (cloud.Instance, error) {
	m := providerID.FindStringSubmatch(id)
	if m == nil {
		return cloud.Instance{}, errors.New("bad provider ID")
	}
	return cloud.Instance{Zone: m[1], ID: m[2]}, nil
}

func (f *fakeCloud) Attach(_ context.Context, slot, instance string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.slots[slot]
	s.Instance, s.InstanceInCluster = instance, true
	return nil
}

func (f *fakeCloud) Detach(_ context.Context, slot string, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detaches = append(f.detaches, slot)
	s := f.slots[slot]
	s.Instance, s.InstanceInCluster = "", false
	return nil
}

func (f *fakeCloud) instanceOf(slot string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.slots[slot].Instance
}

const ns = "natterjack-system"

type harness struct {
	t     *testing.T
	ctx   context.Context
	cloud *fakeCloud
	r     *Reconciler
	now   time.Time
}

func newHarness(t *testing.T, prefix string) *harness {
	t.Helper()
	h := &harness{t: t, ctx: context.Background(), now: time.Now(), cloud: &fakeCloud{slots: map[string]*cloud.Slot{}}}
	h.r = &Reconciler{
		Client: k8s, Provider: h.cloud, Recorder: events.NewFakeRecorder(100),
		ClusterName: "prod", Namespace: ns, ServiceAccount: "natterjack-controller",
		AgentSelector: labels.SelectorFromSet(labels.Set{"app": "agent-" + prefix}),
		Resync:        30 * time.Second, Health: &Health{}, Now: func() time.Time { return h.now },
	}
	return h
}

func (h *harness) create(o client.Object) {
	h.t.Helper()
	if err := k8s.Create(h.ctx, o); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = k8s.Delete(context.Background(), o) })
}

func (h *harness) node(name, zone string) {
	h.t.Helper()
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{corev1.LabelOSStable: "linux"}},
		Spec:       corev1.NodeSpec{ProviderID: fmt.Sprintf("aws:///%s/i-%s", zone, name)},
	}
	h.create(n)
	// Admission taints new nodes not-ready; the node lifecycle controller,
	// which envtest does not run, removes the taint once the node is ready.
	n.Spec.Taints = nil
	if err := k8s.Update(h.ctx, n); err != nil {
		h.t.Fatal(err)
	}
	n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
	if err := k8s.Status().Update(h.ctx, n); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) agent(prefix, node string) {
	h.t.Helper()
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "agent-" + node, Namespace: ns, Labels: map[string]string{"app": "agent-" + prefix}},
		Spec:       corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "agent", Image: "agent"}}},
	}
	h.create(p)
	p.Status.Phase = corev1.PodRunning
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.ContainersReady, Status: corev1.ConditionTrue}}
	if err := k8s.Status().Update(h.ctx, p); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) reconcile() {
	h.t.Helper()
	if _, err := h.r.Reconcile(h.ctx, request); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) pod(name string) *corev1.Pod {
	h.t.Helper()
	p := &corev1.Pod{}
	if err := k8s.Get(h.ctx, client.ObjectKey{Namespace: ns, Name: name}, p); err != nil {
		h.t.Fatal(err)
	}
	return p
}

// pool is the "lifecycle" pool.
func (h *harness) pool() *v1.EgressPool {
	h.t.Helper()
	p := &v1.EgressPool{}
	if err := k8s.Get(h.ctx, client.ObjectKey{Name: "lifecycle"}, p); err != nil {
		h.t.Fatal(err)
	}
	return p
}

// slotState is the status of slot eni-1 of the "lifecycle" pool.
func (h *harness) slotState() v1.SlotStatus {
	h.t.Helper()
	const id = "eni-1"
	for _, s := range h.pool().Status.Slots {
		if s.ID == id {
			return s
		}
	}
	h.t.Fatalf("slot %s missing from the lifecycle pool", id)
	return v1.SlotStatus{}
}

func TestAttachReadyCordonDrainMove(t *testing.T) {
	h := newHarness(t, "lifecycle")
	h.create(&v1.EgressPool{ObjectMeta: metav1.ObjectMeta{Name: "lifecycle"}, Spec: v1.EgressPoolSpec{DrainSeconds: 30}})
	h.node("lc-1", "us-east-2a")
	h.node("lc-2", "us-east-2a")
	h.agent("lifecycle", "lc-1")
	h.agent("lifecycle", "lc-2")
	h.cloud.slots["eni-1"] = &cloud.Slot{ID: "eni-1", Zone: "us-east-2a", PublicIP: "203.0.113.1", MAC: "02:00:00:00:00:01", PrivateIP: "10.0.0.5", SubnetCIDR: "10.0.0.0/24", Tags: map[string]string{}}

	// Attach to the first node; the agent pod carries the assignment.
	h.reconcile()
	if h.cloud.instanceOf("eni-1") != "i-lc-1" {
		t.Fatalf("attached to %q; pool status %+v", h.cloud.instanceOf("eni-1"), h.pool().Status)
	}
	p := h.pod("agent-lc-1")
	var g v1.Gateway
	if err := json.Unmarshal([]byte(p.Annotations[v1.AnnotationGateway]), &g); err != nil {
		t.Fatal(err)
	}
	if p.Labels[v1.LabelGateway] != "true" || p.Labels[v1.LabelPool] != "lifecycle" ||
		g != (v1.Gateway{Pool: "lifecycle", SlotID: "eni-1", MAC: "02:00:00:00:00:01", PrivateIP: "10.0.0.5", SubnetCIDR: "10.0.0.0/24", PublicIP: "203.0.113.1", Tunnel: v1.TunnelGeneve}) {
		t.Fatalf("agent contract not written: labels %v gateway %+v", p.Labels, g)
	}
	if s := h.slotState(); s.State != v1.SlotAttaching || s.Node != "lc-1" {
		t.Fatalf("status %+v", s)
	}
	if st := h.pool().Status; !meta.IsStatusConditionFalse(st.Conditions, v1.ConditionReady) || len(st.PublicIPs) != 1 {
		t.Fatalf("pool status %+v", st)
	}

	// A ready condition left from another slot does not count.
	p.Status.Conditions = append(p.Status.Conditions, corev1.PodCondition{Type: v1.ConditionGatewayReady, Status: corev1.ConditionTrue, Message: v1.GatewayReadyMessage("eni-old")})
	if err := k8s.Status().Update(h.ctx, p); err != nil {
		t.Fatal(err)
	}
	h.reconcile()
	if s := h.slotState(); s.State != v1.SlotAttaching {
		t.Fatalf("a stale ready condition activated the slot: %+v", s)
	}

	// The agent reports ready.
	p.Status.Conditions[len(p.Status.Conditions)-1].Message = v1.GatewayReadyMessage("eni-1")
	if err := k8s.Status().Update(h.ctx, p); err != nil {
		t.Fatal(err)
	}
	h.reconcile()
	if s := h.slotState(); s.State != v1.SlotActive {
		t.Fatalf("status %+v", s)
	}
	if !meta.IsStatusConditionTrue(h.pool().Status.Conditions, v1.ConditionReady) {
		t.Fatal("pool not ready")
	}

	// Cordon: the gateway drains for the window, then the slot moves.
	n := &corev1.Node{}
	if err := k8s.Get(h.ctx, client.ObjectKey{Name: "lc-1"}, n); err != nil {
		t.Fatal(err)
	}
	n.Spec.Unschedulable = true
	if err := k8s.Update(h.ctx, n); err != nil {
		t.Fatal(err)
	}
	h.reconcile()
	if h.pod("agent-lc-1").Annotations[v1.AnnotationDrainStarted] == "" || h.cloud.instanceOf("eni-1") != "i-lc-1" {
		t.Fatal("drain not started, or slot moved before the window")
	}
	if s := h.slotState(); s.State != v1.SlotDraining || !strings.Contains(s.Reason, "cordoned") {
		t.Fatalf("status %+v", s)
	}

	h.now = h.now.Add(31 * time.Second)
	h.reconcile()
	if h.cloud.instanceOf("eni-1") != "" {
		t.Fatal("slot not detached after the drain window")
	}
	if p := h.pod("agent-lc-1"); p.Labels[v1.LabelGateway] != "" || p.Annotations[v1.AnnotationGateway] != "" || p.Annotations[v1.AnnotationDrainStarted] != "" {
		t.Fatalf("old gateway not cleared: %v %v", p.Labels, p.Annotations)
	}
	h.reconcile()
	if h.cloud.instanceOf("eni-1") != "i-lc-2" || h.pod("agent-lc-2").Labels[v1.LabelGateway] != "true" {
		t.Fatalf("slot not moved to lc-2: %q", h.cloud.instanceOf("eni-1"))
	}
}

func TestAgentRolloutKeepsTheSlot(t *testing.T) {
	h := newHarness(t, "rollout")
	h.create(&v1.EgressPool{ObjectMeta: metav1.ObjectMeta{Name: "rollout"}})
	h.node("ro-1", "us-east-2a")
	h.node("ro-2", "us-east-2a")
	h.agent("rollout", "ro-1")
	h.agent("rollout", "ro-2")
	h.cloud.slots["eni-1"] = &cloud.Slot{ID: "eni-1", Zone: "us-east-2a", PublicIP: "203.0.113.1", MAC: "02:00:00:00:00:01", PrivateIP: "10.0.0.5", SubnetCIDR: "10.0.0.0/24", Tags: map[string]string{}}
	h.reconcile()
	old := h.pod("agent-ro-1")
	old.Status.Conditions = append(old.Status.Conditions, corev1.PodCondition{Type: v1.ConditionGatewayReady, Status: corev1.ConditionTrue, Message: v1.GatewayReadyMessage("eni-1")})
	if err := k8s.Status().Update(h.ctx, old); err != nil {
		t.Fatal(err)
	}
	h.reconcile()
	status := func() v1.SlotStatus {
		t.Helper()
		p := &v1.EgressPool{}
		if err := k8s.Get(h.ctx, client.ObjectKey{Name: "rollout"}, p); err != nil {
			t.Fatal(err)
		}
		return p.Status.Slots[0]
	}
	if s := status(); s.State != v1.SlotActive || s.Node != "ro-1" {
		t.Fatalf("status %+v", s)
	}

	// The DaemonSet deletes the old pod. With no kubelet it stays
	// terminating, as it does while the agent shuts down.
	if err := k8s.Delete(h.ctx, old); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(5 * time.Second)
	h.reconcile()
	if h.cloud.instanceOf("eni-1") != "i-ro-1" {
		t.Fatal("the slot moved while the agent restarted")
	}
	if s := status(); s.State != v1.SlotActive || !strings.Contains(s.Reason, "restarting") {
		t.Fatalf("status %+v", s)
	}
	if p := h.pod("agent-ro-1"); p.Annotations[v1.AnnotationGateway] == "" {
		t.Fatal("the terminating agent's assignment was cleared")
	}

	// Its replacement gets the assignment.
	repl := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "agent-ro-1-new", Namespace: ns, Labels: map[string]string{"app": "agent-rollout"}},
		Spec:       corev1.PodSpec{NodeName: "ro-1", Containers: []corev1.Container{{Name: "agent", Image: "agent"}}},
	}
	h.create(repl)
	repl.Status.Phase = corev1.PodRunning
	if err := k8s.Status().Update(h.ctx, repl); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(5 * time.Second)
	h.reconcile()
	if h.cloud.instanceOf("eni-1") != "i-ro-1" || h.pod("agent-ro-1-new").Annotations[v1.AnnotationGateway] == "" {
		t.Fatal("the replacement agent did not take over the slot")
	}

	// An agent that does not come back within the grace loses the slot.
	if err := k8s.Delete(h.ctx, repl); err != nil {
		t.Fatal(err)
	}
	h.reconcile()
	if h.cloud.instanceOf("eni-1") != "i-ro-1" {
		t.Fatal("the slot moved at once")
	}
	h.now = h.now.Add(AgentRestartGrace + time.Second)
	h.reconcile()
	if h.cloud.instanceOf("eni-1") == "i-ro-1" {
		t.Fatal("the slot stayed past the grace")
	}
}

func TestCloudErrorNamesTheIdentity(t *testing.T) {
	h := newHarness(t, "errors")
	h.create(&v1.EgressPool{ObjectMeta: metav1.ObjectMeta{Name: "errors"}})
	pool := func() *v1.EgressPool {
		p := &v1.EgressPool{}
		if err := k8s.Get(h.ctx, client.ObjectKey{Name: "errors"}, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	h.cloud.failNext = errors.New("UnauthorizedOperation")
	_, err := h.r.Reconcile(h.ctx, request)
	if err == nil || !strings.Contains(err.Error(), "system:serviceaccount:natterjack-system:natterjack-controller") {
		t.Fatalf("error %v", err)
	}
	if h.r.Health.Check(nil) == nil {
		t.Fatal("readiness must fail while the cloud API fails")
	}
	// The pool carries the same message, so kubectl and doctor show it.
	c := meta.FindStatusCondition(pool().Status.Conditions, v1.ConditionCloudAccess)
	if c == nil || c.Status != metav1.ConditionFalse || c.Message != err.Error() {
		t.Fatalf("cloud access condition %+v, want false with %q", c, err)
	}
	h.reconcile()
	if h.r.Health.Check(nil) != nil {
		t.Fatal("readiness must recover")
	}
	if c := meta.FindStatusCondition(pool().Status.Conditions, v1.ConditionCloudAccess); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("cloud access condition %+v, want true after recovery", c)
	}
}

func TestPolicyAcceptance(t *testing.T) {
	r := &PolicyReconciler{Client: k8s}
	ctx := context.Background()
	pol := &v1.EgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns}, Spec: v1.EgressPolicySpec{PoolName: "accept", PodSelector: &metav1.LabelSelector{}}}
	if err := k8s.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8s.Delete(ctx, pol) })
	req := client.ObjectKeyFromObject(pol)

	check := func(want metav1.ConditionStatus, reason string) {
		t.Helper()
		if _, err := r.reconcileNamespaced(ctx, reconcile.Request{NamespacedName: req}); err != nil {
			t.Fatal(err)
		}
		got := &v1.EgressPolicy{}
		if err := k8s.Get(ctx, req, got); err != nil {
			t.Fatal(err)
		}
		c := meta.FindStatusCondition(got.Status.Conditions, v1.ConditionAccepted)
		if c == nil || c.Status != want || c.Reason != reason {
			t.Fatalf("accepted %+v", c)
		}
	}
	check(metav1.ConditionFalse, "PoolNotFound")
	p := &v1.EgressPool{ObjectMeta: metav1.ObjectMeta{Name: "accept"}}
	if err := k8s.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8s.Delete(ctx, p) })
	if got := r.namespacedFor(ctx, p); len(got) != 1 || got[0].NamespacedName != req {
		t.Fatalf("pool change did not map to the policy: %v", got)
	}
	check(metav1.ConditionTrue, "PoolFound")

	cp := &v1.ClusterEgressPolicy{ObjectMeta: metav1.ObjectMeta{Name: "nodes"}, Spec: v1.ClusterEgressPolicySpec{PoolName: "accept", NodeTraffic: true}}
	if err := k8s.Create(ctx, cp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8s.Delete(ctx, cp) })
	if _, err := r.reconcileCluster(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cp)}); err != nil {
		t.Fatal(err)
	}
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(cp), cp); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(cp.Status.Conditions, v1.ConditionAccepted) {
		t.Fatalf("cluster policy %+v", cp.Status)
	}
}

func TestUnclaimedSlotOnClusterNodeIsDetached(t *testing.T) {
	h := newHarness(t, "unclaimed")
	h.node("uc-1", "us-east-2b")
	h.agent("unclaimed", "uc-1")
	// Tagged for a pool that does not exist, and attached to a cluster node.
	h.cloud.slots["eni-orphan"] = &cloud.Slot{
		ID: "eni-orphan", Zone: "us-east-2b", Instance: "i-uc-1", InstanceInCluster: true,
		Tags: map[string]string{v1.TagPool: "deleted"},
	}
	h.reconcile()
	if h.cloud.instanceOf("eni-orphan") != "" {
		t.Fatal("a slot no EgressPool claims must not stay on a cluster node")
	}
}
